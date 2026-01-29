use std::collections::HashMap;
use once_cell::sync::Lazy;
use crate::layer1::vm::{Machine,Context, Substate, ExecuteResult, EvmError};
use crate::layer1::world_state::{WorldStateTrie, AccountState};
use bytes::Bytes;
use ethereum_types::{Address, U256};
use sha3::{Digest, Keccak256};

type ExecutionFunc = fn(evm: &mut Machine, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> ExecuteResult;
type GasCostFunc = fn(evm: &Machine, context: &Context) -> Result<U256, EvmError>;
type MemorySizeFunc = fn(evm: &Machine, context: &Context) -> Result<usize, EvmError>;

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


fn op_add(evm: &mut Machine, _context: &Context, _worldstate: &mut WorldStateTrie, _substate: &mut Substate) -> ExecuteResult {
    let a = evm.stack_pop()?;
    let b = evm.stack_pop()?;
    let (result, _overflow) = a.overflowing_add(b);
    evm.stack_push(result)?;
    Ok(())
}

fn op_call(evm: &mut Machine, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> ExecuteResult {
    let _temp_gas = evm.stack_pop()?; // Like in geth, we also do not use the gas input in stack.
    let callee_256 = evm.stack_pop()?;
    let mut bytes = [0u8; 20];
    let callee_bytes = callee_256.to_big_endian();
    bytes[20 - callee_bytes.len()..].copy_from_slice(&callee_bytes);
    let callee = Address::from_slice(&bytes);
    let value = evm.stack_pop()?;
    let _in_offset = evm.stack_pop()?;
    let _in_size = evm.stack_pop()?;
    let _out_offset = evm.stack_pop()?;
    let _out_size = evm.stack_pop()?;

    let caller = context.contract_addr.unwrap_or(context.sender);

    if evm.call_depth >= 1024 { // CallCreateDepth = 1024
        return Err(EvmError::CallDepthExceeded);
    }

    if value > worldstate.get_balance(&caller).unwrap_or(U256::zero()) {
        return Err(EvmError::InsufficientBalance);
    }

    // Check precompile
    if is_precompile(&callee) {
        let precompiled_contracts = precompiled_contracts_berlin();
        let precompile = precompiled_contracts.get(&callee).unwrap();
        let gas_cost = precompile.gas_cost(evm, context);

        if gas_cost > evm.gas_remaining {
            return Err(EvmError::OutOfGas);
        }
        evm.gas_remaining -= gas_cost;
        let _output = precompile.execute(evm, context)?;
        // Push success (1) to stack
        evm.stack_push(U256::from(1))?;
        return Ok(());
    }

    // Create account if needed (EIP-158)
    if !worldstate.account_exists(&callee) {
        if value == U256::zero() {
            evm.stack_push(U256::zero())?; // Return 0 for failure
            return Ok(());
        }
        let account = AccountState::new(&vec![]);
        worldstate.insert(&callee, account);
    }

    // Transfer value
    if value > U256::zero() {
        let caller_balance = worldstate.get_balance(&caller).unwrap_or(U256::zero());
        let callee_balance = worldstate.get_balance(&callee).unwrap_or(U256::zero());
        worldstate.set_balance(&caller, caller_balance - value);
        worldstate.set_balance(&callee, callee_balance + value);
    }

    // Get callee code
    let callee_code = worldstate.get_code(&callee).cloned().unwrap_or_default();
    
    // Create new context for callee
    let callee_context = Context {
        contract_addr: Some(callee),
        origin_sender: context.origin_sender,
        gas_price: context.gas_price,
        input: context.input.clone(),
        sender: caller,
        value,
        code: callee_code.clone(),
        block: context.block,
        depth: context.depth + 1,
        allow_writes: true,
    };

    // Create new machine for callee
    let mut callee_evm = Machine {
        memory: Bytes::new(),
        stack: vec![],
        pc: 0,
        gas_remaining: evm.gas_remaining,
        call_depth: evm.call_depth + 1,
    };

    // Execute callee
    worldstate.checkpoint();
    let result = callee_evm.run(&callee_context, worldstate, substate);
    
    if result.is_err() {
        let _ = worldstate.rollback(); // Ignore rollback errors
        evm.stack_push(U256::zero())?; // Return 0 for failure
        return Ok(());
    }

    // Update gas remaining
    evm.gas_remaining = callee_evm.gas_remaining;
    
    // Push success (1) to stack
    evm.stack_push(U256::from(1))?;
    Ok(())
}

fn op_create(evm: &mut Machine, context: &Context, worldstate: &mut WorldStateTrie, _substate: &mut Substate) -> ExecuteResult {
    let value = evm.stack_pop()?;
    let offset = evm.stack_pop()?;
    let size = evm.stack_pop()?;

    let caller = context.contract_addr.unwrap_or(context.sender);

    if evm.call_depth >= 1024 {
        return Err(EvmError::CallDepthExceeded);
    }

    if value > worldstate.get_balance(&caller).unwrap_or(U256::zero()) {
        return Err(EvmError::InsufficientBalance);
    }

    // Get init code from memory
    let offset_usize = offset.as_usize();
    let size_usize = size.as_usize();
    if offset_usize + size_usize > evm.memory.len() {
        return Err(EvmError::MemoryOutOfBounds);
    }
    let init_code = evm.memory.slice(offset_usize..offset_usize + size_usize).to_vec();

    // Calculate contract address (simplified: use nonce)
    let nonce = worldstate.get_nonce(&caller).unwrap_or(0);
    let mut address_bytes = [0u8; 20];
    let mut hasher = Keccak256::new();
    hasher.update(caller.as_bytes());
    hasher.update(&nonce.to_be_bytes());
    let hash = hasher.finalize();
    address_bytes.copy_from_slice(&hash[12..]);
    let contract_addr = Address::from_slice(&address_bytes);

    // Create account
    let account = AccountState::new(&init_code);
    worldstate.insert(&contract_addr, account);
    worldstate.set_nonce(&caller, nonce + 1);

    // Transfer value
    if value > U256::zero() {
        let caller_balance = worldstate.get_balance(&caller).unwrap_or(U256::zero());
        let contract_balance = worldstate.get_balance(&contract_addr).unwrap_or(U256::zero());
        worldstate.set_balance(&caller, caller_balance - value);
        worldstate.set_balance(&contract_addr, contract_balance + value);
    }

    // Execute init code (simplified: just set the code)
    // In real EVM, init code execution would return the contract code
    // For simplicity, we use the init code as the contract code
    worldstate.set_code(&contract_addr, init_code);

    // Push contract address to stack
    let addr_u256 = U256::from_big_endian(contract_addr.as_bytes());
    evm.stack_push(addr_u256)?;

    Ok(())
}

pub static JUMP_TABLE: Lazy<HashMap<u8, Operation>> = Lazy::new(|| {
    let mut table = HashMap::new();

    // ADD
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

    // CALL
    table.insert(
        opcodes::CALL,
        Operation::new(
            opcodes::CALL,
            op_call,
            100,   // base gas cost
            None,  // dynamic gas calculated in operation
            7,     // min stack (gas, addr, value, in_offset, in_size, out_offset, out_size)
            1024,  // max stack
            None,  // memory size calculated in operation
        ),
    );

    // CREATE
    table.insert(
        opcodes::CREATE,
        Operation::new(
            opcodes::CREATE,
            op_create,
            32000, // base gas cost
            None,  // dynamic gas calculated in operation
            3,     // min stack (value, offset, size)
            1024,  // max stack
            None,  // memory size calculated in operation
        ),
    );

    table
});

/* -------------------------------------------------------------------------- */
/*                                 precompile                                 */
/* -------------------------------------------------------------------------- */
trait Precompile {
    fn execute(&self, evm: &mut Machine, context: &Context) -> Result<Option<Bytes>, EvmError>;
    fn gas_cost(&self, evm: &Machine, context: &Context) -> U256;
}


pub struct Ecrecover;
impl Precompile for Ecrecover {
    fn execute(&self, _evm: &mut Machine, _context: &Context) -> Result<Option<Bytes>, EvmError> {
        Ok(Some(Bytes::from(vec![0u8; 32])))
    }

    fn gas_cost(&self, _evm: &Machine, _context: &Context) -> U256 {
        U256::from(3000)
    }
}
pub struct Sha256Hash;
impl Precompile for Sha256Hash {
    fn execute(&self, _evm: &mut Machine, context: &Context) -> Result<Option<Bytes>, EvmError> {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&context.input);
        let hash = hasher.finalize();
        Ok(Some(Bytes::copy_from_slice(&hash)))
    }

    fn gas_cost(&self, _evm: &Machine, context: &Context) -> U256 {
        let l = context.input.len();
        U256::from(60 + ((l + 31) / 32) * 12) // basegas:60, gas per word: 12
    }
}
pub struct DataCopy;
impl Precompile for DataCopy {
    fn execute(&self, _evm: &mut Machine, context: &Context) -> Result<Option<Bytes>, EvmError> {
        Ok(Some(context.input.clone()))
    }

    fn gas_cost(&self, _evm: &Machine, context: &Context) -> U256 {
        let l = context.input.len();
        U256::from(15 + ((l + 31) / 32) * 3) // basegas:15, gas per word: 3
    }
}
pub struct UnimplementedPrecompile;
impl Precompile for UnimplementedPrecompile {
    fn execute(&self, _evm: &mut Machine, _context: &Context) -> Result<Option<Bytes>, EvmError> {
        Err(EvmError::ExecutionFailed)
    }

    fn gas_cost(&self, _evm: &Machine, _context: &Context) -> U256 {
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

