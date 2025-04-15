/// implemented a run framework for the vm. Support ADD, CALL, CREATE, STOP

use crate::layer1::transaction::BlobTransaction;
use anyhow::Result;
use ethereum_types::{Address, H256, U256};
use bytes::Bytes

use crate::layer1::world_state::WorldStateTrie;
use crate::layer1::block::Block;

fn to_word_size(size: usize) -> usize {
    if size % 32 == 0 {
        size / 32
    } else {
        size / 32 + 1
    }
}

fn intrinsic_gas(tx: &BlobTransaction) -> u64 {
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

fn check_valid_transaction(tx: &BlobTransaction, state: &WorldStateTrie, block: &Block) -> Result<()> {
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
    let upfront_cost = tx.max_fee_per_gas * U256::from(tx.gas_limit) 
                            + tx.value
                            + tx.cost_cap_on_blob();
    if state.get_balance(&sender).unwrap() < upfront_cost {
        return Err(anyhow::anyhow!("insufficient balance"));
    }
    
    if tx.max_fee_per_gas < block.base_fee{
        return Err(anyhow::anyhow!("max fee per gas too low"));
    }
    if tx.max_fee_per_gas < tx.max_priority_fee_per_gas {
        return Err(anyhow::anyhow!("max fee per gas less than max priority fee"));
    }

    if tx.is_creation() {
        let data_len = tx.data.len();
        if data_len > 49152 {
            return Err(anyhow::anyhow!("data length too long"));
        }
    }

    if U256::from(tx.gas_limit) > (block.gas_limit - block.gas_used) {
        return Err(anyhow::anyhow!("gas limit exceeds block gas limit"));
    }

    if tx.cost_cap_on_blob() > U256::from(786432) { // MAX_BLOB_GAS_PER_BLOCK
        return Err(anyhow::anyhow!("blob gas limit exceeds block limit"));
    }

    if block.get_base_fee_per_blob_gas() > tx.max_fee_per_blob_gas {
        return Err(anyhow::anyhow!("blob gas limit exceeds max fee"));
    }

    Ok(())
}

fn tx_execute(
    tx: &BlobTransaction,
    state: &mut WorldStateTrie,
    block: &Block,
) -> Result<()> {
    // check transaction validity
    check_valid_transaction(tx, state, block)?;

    // Checkpoint State
    let sender = tx.get_sender()?;
    state.set_nonce(&sender, tx.nonce + 1);

    let cost = U256::from(tx.gas_limit) * tx.effective_gas_price(block.base_fee);
    // eip-4844
    let blob_fee = tx.cost_cap_on_blob() * block.get_base_fee_per_blob_gas();
    state.set_balance(&sender, 
        state.get_balance(&sender).unwrap() - cost - blob_fee);

    state.checkpoint();

    // substate
    // EIP-7702 not implemented
    // todo: access list


    run_evm(tx, state, block)?;

    // refund 

    // finalize


    Ok(())
}

pub struct Evm {
    pub memory: Bytes,
    pub stack: Vec<U256>,
    pub pc: u64,
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
    pub fn evm_call(
        &mut self,
        state: &mut WorldStateTrie,
        substate: &mut Substate,
        context: &Context,
        remain_gas: U256) -> Result<(Bytes, U256)> 
    {
        todo!()
        // evm_call(state, substate, context, remain_gas)
    }
}




    todo!()
}