use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use crate::layer1::vm::{Evm,Context, Substate};
use crate::layer1::world_state::{WorldStateTrie};
use anyhow::Result;
use bytes::Bytes;
use ethereum_types::{Address, H256, U256};

type ExecutionFunc = fn(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> Result<Bytes>;
type GasCost = fn(evm: &Evm, context: &Context) -> Result<U256>;
type MemorySize = fn(evm: &Evm, context: &Context) -> Result<usize>;

pub struct Operation {
    pub execute: Option<ExecutionFunc>,
    pub constant_gas: u64,
    pub dynamic_gas: Option<GasFunc>,
    pub min_stack: usize,
    pub max_stack: usize,
    pub memory_size: Option<MemorySizeFunc>,
    pub name: String,
}

impl Operation {
    pub fn new(
        execute: Option<ExecutionFunc>,
        constant_gas: u64,
        dynamic_gas: Option<GasFunc>,
        min_stack: usize,
        max_stack: usize,
        memory_size: Option<MemorySizeFunc>,
        name: String
    ) -> Self {
        Operation {
            execute,
            constant_gas,
            dynamic_gas,
            min_stack,
            max_stack,
            memory_size,
            name,
        }
    }
}

pub type JumpTable = HashMap<u8, Operation>; // map opcode to operation

fn op_add(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> Result<Bytes> {
    let a = evm.stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?;
    let b = evm.stack.pop().ok_or(anyhow::anyhow!("Stack underflow"))?;
    let result = a.checked_add(b).ok_or(anyhow::anyhow!("Addition overflow"))?;
    evm.stack.push(result);
    Ok(Bytes::new())
}

fn op_call(evm: &mut Evm, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) -> Result<Bytes> {
    
}

pub static JUMP_TABLE: Lazy<HashMap<u8, Operation>> = Lazy::new(|| {
    let mut table = HashMap::new();

    // add
    table.insert(
        0x01,
        Operation::new(
            Some(op_add),
            3,     // constant gas
            None,  // no dynamic gas
            2,     // min stack
            1024,  // max stack
            None,  // no memory size
            "ADD".to_string(),
        ),
    );

    table
});