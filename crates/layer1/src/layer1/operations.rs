use std::collections::HashMap;
use std::rc::Rc;
use once_cell::sync::Lazy;
use sha3::digest::consts::U2;
use crate::layer1::vm::{Evm,Context, Substate, ExecuteResult};
use crate::layer1::world_state::{WorldStateTrie, AccountState};
use anyhow::Result;
use bytes::Bytes;
use ethereum_types::{Address, H256, U256};

type ExecutionFunc = fn(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> ExecuteResult;
type GasCostFunc = fn(evm: &Evm, context: &Context) -> Result<U256>;
type MemorySizeFunc = fn(evm: &Evm, context: &Context) -> Result<usize>;

pub mod opcodes {
    pub const STOP: u8 = 0x00;
    pub const ADD: u8 = 0x01;
    pub const SSTORE: u8 = 0x55;
    pub const CREATE: u8 = 0xF0;
    pub const CALL: u8 = 0xF1;
    pub const SELFDESTRUCT: u8 = 0xFF;
}


pub struct Operation {
    pub opcode: u8,
    pub execute: ExecutionFunc,
    pub constant_gas: u64,
    pub dynamic_gas: Option<GasCostFunc>,
    pub min_stack: usize,
    pub max_stack: usize,
    pub memory_size: Option<MemorySizeFunc>,
}

impl Operation {
    pub fn new(
        opcode: u8,
        execute: ExecutionFunc,
        constant_gas: u64,
        dynamic_gas: Option<GasCostFunc>,
        min_stack: usize,
        max_stack: usize,
        memory_size: Option<MemorySizeFunc>,
    ) -> Self {
        Operation {
            opcode,
            execute,
            constant_gas,
            dynamic_gas,
            min_stack,
            max_stack,
            memory_size,
        }
    }
}


pub type JumpTable = HashMap<u8, Operation>; // map opcode to operation

fn op_add(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> ExecuteResult {
    let a = evm.stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?;
    let b = evm.stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?;
    let result = a.checked_add(b).ok_or(anyhow::anyhow!("Addition overflow"))?;
    evm.stack.push(result);
    Ok(None)
}

fn op_call(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> ExecuteResult {
    let temp_gas = evm.stack.pop().unwrap(); // Like in geth, we also do not use the gas input in stack.
    let callee_256: U256 = evm.stack.pop().unwrap();
    let bytes = callee_256.to_big_endian();
    let callee = Address::from_slice(&bytes);
    let value = evm.stack.pop().unwrap();
    let in_offset = evm.stack.pop().unwrap();
    let in_size = evm.stack.pop().unwrap();
    let out_offset = evm.stack.pop().unwrap();
    let out_size = evm.stack.pop().unwrap();
    // 好奇怪啊，context 为啥没用上
    let input = evm.get_memory_slice(in_offset, in_size)?; // TODO

    let caller = context.contract_addr;

    if evm.call_depth >= 1024 { // CallCreateDepth = 1024
        return Err(anyhow::anyhow!("Call depth exceeded"));
    }

    if value > worldstate.get_balance(&caller).unwrap() {
        return Err(anyhow::anyhow!("Insufficient balance"));
    }
    if is_precompile(&callee) {
        let precompiled_contracts = precompiled_contracts_berlin();
        let precompile = precompiled_contracts.get(&callee).unwrap();
        let gas_cost = precompile.gas_cost(evm, context);

        if gas_cost > evm.gas_remaining {
            return Err(anyhow::anyhow!("Out of gas"));
        }
        evm.gas_remaining -= gas_cost;
        let output = precompile.execute(evm, context);
        if output.is_err() {
            return Err(output.err().unwrap());
        }
        return output;
    }
    if worldstate.account_exists(&callee) == false {
        if value == U256::zero() { // EIP-158
            return Ok(None);
        }
        let account = AccountState::new(context.code.to_vec().as_ref());
        worldstate.insert(&callee, account);
    }

    // transfer
    if value > U256::zero() {
        worldstate.set_balance(&caller, worldstate.get_balance(&caller).unwrap() - value);
        worldstate.set_balance(&callee, worldstate.get_balance(&callee).unwrap() + value);
    }
    
    let output = evm.run(context, worldstate, substate);

    if let Err(e) = output {
        if e.to_string().contains("Revert") {
            // refund gas
            
        }
        worldstate.rollback()?;
        return Err(e);
    }
    
    return output;
}

pub static JUMP_TABLE: Lazy<HashMap<u8, Operation>> = Lazy::new(|| {
    let mut table = HashMap::new();

    // add
    table.insert(
        0x01,
        Operation::new(
            opcodes::ADD,
            op_add,
            3,     // constant gas
            None,  // no dynamic gas
            2,     // min stack
            1024,  // max stack
            None,  // no memory size
        ),
    );

    table
});

/* -------------------------------------------------------------------------- */
/*                                 precompile                                 */
/* -------------------------------------------------------------------------- */
trait Precompile {
    fn execute(&self, evm: &mut Evm, context: &Context) -> ExecuteResult;
    fn gas_cost(&self, evm: &Evm, context: &Context) -> U256;
}


pub struct Ecrecover;
impl Precompile for Ecrecover {
    fn execute(&self, _evm: &mut Evm, _context: &Context) -> ExecuteResult {
        Ok(Some(Bytes::from(vec![0u8; 32])))
    }

    fn gas_cost(&self, _evm: &Evm, _context: &Context) -> U256 {
        U256::from(3000)
    }
}
pub struct Sha256Hash;
impl Precompile for Sha256Hash {
    fn execute(&self, _evm: &mut Evm, context: &Context) -> ExecuteResult {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&context.input);
        let hash = hasher.finalize();
        Ok(Some(Bytes::copy_from_slice(&hash)))
    }

    fn gas_cost(&self, _evm: &Evm, context: &Context) -> U256 {
        let l = context.input.len();
        U256::from(60 + ((l + 31) / 32) * 12) // basegas:60, gas per word: 12
    }
}
pub struct DataCopy;
impl Precompile for DataCopy {
    fn execute(&self, _evm: &mut Evm, context: &Context) -> ExecuteResult {
        Ok(Some(context.input.clone()))
    }

    fn gas_cost(&self, _evm: &Evm, context: &Context) -> U256 {
        let l = context.input.len();
        U256::from(15 + ((l + 31) / 32) * 3) // basegas:15, gas per word: 3
    }
}
pub struct UnimplementedPrecompile;
impl Precompile for UnimplementedPrecompile {
    fn execute(&self, _evm: &mut Evm, _context: &Context) -> ExecuteResult {
        Err(anyhow::anyhow!("Unimplemented precompile"))
    }

    fn gas_cost(&self, _evm: &Evm, _context: &Context) -> U256 {
        U256::zero()
    }
}

pub type PrecompiledContracts = HashMap<Address, Box<dyn Precompile>>;

pub fn precompiled_contracts_berlin() -> PrecompiledContracts {
    let mut contracts: PrecompiledContracts = HashMap::new();
    contracts.insert(Address::from_low_u64_be(0x01), Box::new(Ecrecover));
    contracts.insert(Address::from_low_u64_be(0x02), Box::new(Sha256Hash));
    contracts.insert(Address::from_low_u64_be(0x03), Box::new(UnimplementedPrecompile));
    contracts.insert(Address::from_low_u64_be(0x04), Box::new(DataCopy));
    contracts.insert(Address::from_low_u64_be(0x05), Box::new(UnimplementedPrecompile));
    contracts.insert(Address::from_low_u64_be(0x06), Box::new(UnimplementedPrecompile));
    contracts.insert(Address::from_low_u64_be(0x07), Box::new(UnimplementedPrecompile));
    contracts.insert(Address::from_low_u64_be(0x08), Box::new(UnimplementedPrecompile));
    contracts.insert(Address::from_low_u64_be(0x09), Box::new(UnimplementedPrecompile));
    contracts
}

fn is_precompile(address: &Address) -> bool {
    let precompiled_contracts = precompiled_contracts_berlin();
    precompiled_contracts.contains_key(address)
}

