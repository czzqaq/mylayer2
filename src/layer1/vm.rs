/// implemented a run framework for the vm. Support ADD, CALL, CREATE, STOP

use crate::layer1::transaction::Transaction1or2;
use anyhow::Result;
use either::Either;
use ethereum_types::{Address, H256, U256};
use bytes::Bytes;

use crate::layer1::world_state::WorldStateTrie;
use crate::layer1::block::Block;
use crate::layer1::operations::{JUMP_TABLE, opcodes};

pub type ExecuteResult = Result<Option<Bytes>>; // output


fn to_word_size(size: usize) -> usize {
    if size % 32 == 0 {
        size / 32
    } else {
        size / 32 + 1
    }
}

fn intrinsic_gas(tx: &Transaction1or2) -> u64 {
    let mut gas = 0;

    if tx.is_creation() {
        gas += 53000; // base gas for contract creation
    } else {
        gas += 21000; // base gas for standard tx
    }

    // EIP-2028: Count zero and non-zero bytes
    let zeros = tx.data.iter().filter(|&&b| b == 0).count();
    let non_zeros = tx.data.len() - zeros;
    gas += (non_zeros * 16 + zeros * 4) as u64;

    // Extra cost for contract creation: 2 gas per "word" (32 bytes)
    if tx.is_creation() {
        gas += 2 * to_word_size(tx.data.len()) as u64;
    }

    // Access list gas (EIP-2930)
    let access_list_gas = tx.access_list.len() as u64 * 2400;
    let storage_key_gas: u64 = tx
        .access_list
        .iter()
        .map(|item| item.storage_keys.len() as u64 * 1900)
        .sum();

    gas += access_list_gas + storage_key_gas;

    gas
}

// correspond to python-evm validate_frontier_transaction
fn check_valid_transaction(tx: &Transaction1or2, state: &WorldStateTrie, block: &Block) -> Result<()> {
    let sender = tx.get_sender()?;

    // nonce check and sender valid
    if let Some(st_nonce) = state.get_nonce(&sender) {
        if st_nonce != tx.nonce {
            return Err(anyhow::anyhow!("nonce mismatch"));
        }
    } else {
        return Err(anyhow::anyhow!("sender not found"));
    }

    // EIP-3607: make sure sender is EOA
    let code = state.get_code(&sender).unwrap();
    if code.is_empty() == false {
        return Err(anyhow::anyhow!("sender is a EOA"));
    }

    // intrinsic gas
    let intrinsic_gas = intrinsic_gas(tx);
    if tx.gas_limit < intrinsic_gas {
        return Err(anyhow::anyhow!("gas limit too low"));
    }

    // sufficient account balance
    let upfront_cost = tx.effective_gas_price(block.header.base_fee) * U256::from(tx.gas_limit) + tx.value;
    if state.get_balance(&sender).unwrap() < upfront_cost {
        return Err(anyhow::anyhow!("insufficient balance"));
    }

    if tx.tx_type == 2 {
        let (max_priority_fee, max_fee) = tx.gas_price_or_dynamic_fee.right().unwrap();
        if max_fee < max_priority_fee {
            return Err(anyhow::anyhow!("max fee per gas less than max priority fee"));
        }
        if max_fee < block.header.base_fee {
            return Err(anyhow::anyhow!("max fee per gas too low"));
        }
    }

    if tx.is_creation() {
        let data_len = tx.data.len();
        if data_len > 49152 {
            return Err(anyhow::anyhow!("data length too long"));
        }
    }

    if U256::from(tx.gas_limit) > (block.header.gas_limit - block.header.gas_used) {
        return Err(anyhow::anyhow!("gas limit exceeds block gas limit"));
    }

    Ok(())
}

fn tx_execute(
    tx: &Transaction1or2,
    state: &mut WorldStateTrie,
    block: &Block,
) -> Result<()> {
    // check transaction validity
    check_valid_transaction(tx, state, block)?;

    // Checkpoint State
    let sender = tx.get_sender()?;
    state.set_nonce(&sender, tx.nonce + 1);

    let cost = U256::from(tx.gas_limit) * tx.effective_gas_price(block.header.base_fee);
    state.set_balance(&sender, state.get_balance(&sender).unwrap() - cost);

    state.checkpoint();

    // substate
    // EIP-7702 not implemented
    // todo: access list


    // todo: create Evm
    let mut evm = Evm {
        memory: Bytes::new(),
        stack: vec![],
        pc: 0,
        code: tx.data.clone(),
        call_depth: 0,
        gas_remaining: U256::from(tx.gas_limit),
    };

    // refund 

    // finalize worldstate


    Ok(())
}

pub struct Evm {
    pub memory: Bytes, 
    pub stack: Vec<U256>,
    pub pc: usize,
    pub code: Bytes,
    pub call_depth: u64,
    pub gas_remaining: U256,
}

pub struct Context<'a> {
    pub contract_addr: Address,
    pub origin_sender: Address,
    pub gas_price: U256,
    pub input: Bytes,
    pub sender: Address,
    pub value: U256,
    pub code: Bytes,
    pub block: &'a Block,
    pub depth: u64,
    pub allow_writes: bool,
}

// todo: substate，not in geth
pub struct Substate {
    pub self_destruct: Address,
    // journals: Vec<JournalEntry>,
    pub touched_accounts: Vec<Address>,
    pub refund_fee: U256,
    pub access_list_accounts: Vec<Address>,
    pub access_list_storage: Vec<(Address, U256)>,
}

impl Evm {
    /// Execute a transaction. Modify substate and state. Return the remaining gas and output.
    pub fn call(
        &mut self,
        state: &mut WorldStateTrie,
        substate: &mut Substate,
        context: &Context,
        remain_gas: U256) -> Result<(Bytes, U256)> 
    {
        let op = JUMP_TABLE.get(&opcodes::CALL).unwrap();
        todo!()
    }

    pub fn create(
        &mut self,
        state: &mut WorldStateTrie,
        substate: &mut Substate,
        context: &Context,
        remain_gas: U256) -> Result<(Bytes, U256)> 
    {
        let op = JUMP_TABLE.get(&opcodes::CREATE).unwrap();
        todo!()
    }

    pub fn get_memory_slice(&self, offset: U256, size: U256) -> Result<Bytes> {
        let offset = offset.as_usize();
        let size = size.as_usize();
        if offset + size > self.memory.len() {
            return Err(anyhow::anyhow!("Memory out of bounds"));
        }
        Ok(self.memory.slice(offset..offset + size))
    }

    pub fn run(&mut self, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) 
        -> ExecuteResult 
    {
        loop {
            let opcode = self.get_opcode();
            let operation = JUMP_TABLE.get(&opcode).ok_or(format!("Invalid opcode: 0x{:x}", opcode));
            if operation.is_err() {
                return Err(anyhow::anyhow!("Invalid opcode: 0x{:x}", opcode));
            }
            let operation = operation.unwrap();

            // stack check
            let stack_size = self.stack.len();
            if stack_size < operation.min_stack {
                return Err(anyhow::anyhow!("Stack underflow"));
            }
            if stack_size > operation.max_stack {
                return Err(anyhow::anyhow!("Stack overflow"));
            }
            // memory overflow check
            if let Some(memory_size) = operation.memory_size {
                let size = memory_size(self, context)?;
                if size > self.memory.len() {
                    // todo: expandable memory
                    panic!("Not enough memory");
                }
            }
            // gas
            let cost = operation.constant_gas;
            if U256::from(cost) > self.gas_remaining {
                return Err(anyhow::anyhow!("Out of gas"));
            }
            self.gas_remaining -= U256::from(cost);
            if let Some(dynamic_gas) = operation.dynamic_gas {
                let dynamic_cost = dynamic_gas(self, context)?;
                if dynamic_cost > self.gas_remaining {
                    return Err(anyhow::anyhow!("Out of gas"));
                }
                self.gas_remaining -= U256::from(dynamic_cost);
            }
            // write limit, jumpdest,return data length, is checked for specific operation

            let output = (operation.execute)(self, context, worldstate, substate)?;
            self.pc += 1;
        }
    }

    fn get_opcode(&self) -> u8 {
        if self.pc >= self.code.len() {
            return opcodes::STOP;
        }

        self.code[self.pc]
    }
}

/* -------------------------------------------------------------------------- */
/*                                 precompiles                                */
/* -------------------------------------------------------------------------- */

