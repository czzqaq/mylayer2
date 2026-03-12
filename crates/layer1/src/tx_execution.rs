use std::vec;

/// implemented a run framework for the vm. Support ADD, CALL, CREATE, STOP

use crate::transaction::Transaction1or2;
use ethereum_types::{Address, U256,H256};
use bytes::Bytes;

use crate::world_state::{WorldStateTrie, AccountState};
use crate::block::Block;
use crate::operations::{JUMP_TABLE, opcodes};
use crate::receipts::{Log, Receipt};


#[derive(Debug)]
pub enum EvmError {
    StackUnderflow,
    StackOverflow,
    InvalidOpcode,
    OutOfGas,
    CallDepthExceeded,
    InsufficientBalance,
    MemoryOutOfBounds,
    ExecutionFailed,
    // Many other errors

    // special operations, not the actual errors
    ExplicitStop, //by STOP opcode
    Return(Bytes), // by RETURN opcode
    Revert(Bytes), // by REVERT opcode
    SelfDestruct, // by SELFDESTRUCT opcode
}

impl std::fmt::Display for EvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EvmError::StackUnderflow => write!(f, "Stack underflow"),
            EvmError::StackOverflow => write!(f, "Stack overflow"),
            EvmError::InvalidOpcode => write!(f, "Invalid opcode"),
            EvmError::OutOfGas => write!(f, "Out of gas"),
            EvmError::CallDepthExceeded => write!(f, "Call depth exceeded"),
            EvmError::InsufficientBalance => write!(f, "Insufficient balance"),
            EvmError::MemoryOutOfBounds => write!(f, "Memory out of bounds"),
            EvmError::ExecutionFailed => write!(f, "Execution failed"),
            EvmError::ExplicitStop => write!(f, "Explicit stop"),
            EvmError::Return(_) => write!(f, "Return"),
            EvmError::Revert(_) => write!(f, "Revert"),
            EvmError::SelfDestruct => write!(f, "Self destruct"),
        }
    }
}

impl std::error::Error for EvmError {}

pub type ExecuteResult = Result<Bytes, EvmError>;

pub struct Machine {
    pub memory: Bytes, 
    pub stack: Vec<U256>,
    pub pc: usize,
    pub gas_remaining: U256,
    pub call_depth: u64,
}

pub struct Context<'a> {
    pub contract_addr: Option<Address>,
    pub origin_sender: Address,
    pub gas_price: U256,
    pub input: Bytes,
    pub sender: Address,
    pub value: U256,
    pub code: Vec<u8>,
    pub block: &'a Block,
    pub depth: u64,
    pub allow_writes: bool,
}

pub struct Substate {
    pub self_destruct: Vec<Address>,
    pub logs: Vec<Log>,
    pub touched_accounts: Vec<Address>,
    pub refund_fee: U256,
    pub access_list_accounts: Vec<Address>,
    pub access_list_storage: Vec<(Address, H256)>, // (address, storage_key)
}

impl Machine {
    pub fn stack_pop(&mut self) -> Result<U256, EvmError> {
        self.stack.pop().ok_or(EvmError::StackUnderflow)
    }

    pub fn stack_push(&mut self, val: U256) -> Result<(), EvmError> {
        if self.stack.len() >= 1024 {
            return Err(EvmError::StackOverflow);
        }
        self.stack.push(val);
        Ok(())
    }
}


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
fn check_valid_transaction(tx: &Transaction1or2, state: &WorldStateTrie, block: &Block) -> Result<(), anyhow::Error> {
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
    let base_fee = block.header.base_fee.unwrap_or(U256::zero());
    let upfront_cost = tx.upfront_cost(base_fee);
    if state.get_balance(&sender).unwrap() < upfront_cost {
        return Err(anyhow::anyhow!("insufficient balance"));
    }
   
    // gas price ceiling >= base fee, m = T_p (type 0/1) or T_m (type 2)
    let m = if tx.tx_type == 2 {
        let (_, max_fee) = tx.gas_price_or_dynamic_fee.right().unwrap();
        max_fee
    } else {
        tx.gas_price_or_dynamic_fee.left().unwrap_or_default()
    };
    if m < base_fee {
        return Err(anyhow::anyhow!("gas price ceiling {} is below base fee {}", m, base_fee));
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

    if tx.tx_type == 2 {
        let (max_priority, max_fee) = tx.gas_price_or_dynamic_fee.right().unwrap();
        if max_fee < max_priority {
            return Err(anyhow::anyhow!(
                "maxFeePerGas {} < maxPriorityFeePerGas {}",
                max_fee, max_priority
            ));
        }
    }

    Ok(())
}

pub fn tx_execute(
    tx: &Transaction1or2,
    state: &mut WorldStateTrie,
    block: &mut Block,
) -> Result<(), anyhow::Error> {
    // check transaction validity
    check_valid_transaction(tx, state, block)?;

    // Preparation: Checkpoint State
    let sender = tx.get_sender()?;
    let base_fee = block.header.base_fee.unwrap_or(U256::zero());
    let g_0 = intrinsic_gas(tx);
    let eff_price = tx.effective_gas_price(base_fee); // p
    
    state.set_nonce(&sender, tx.nonce + 1);

    //   σ_0[S(T)]_b ← b − T_g · p
    let gas_prepayment = U256::from(tx.gas_limit) * eff_price;
    let sender_bal     = state.get_balance(&sender).unwrap(); // the sender is EOA, so the account must exist
    state.set_balance(&sender, sender_bal - gas_prepayment);

    state.checkpoint();

    // ── Step 2: build initial substate A* ────────────────────────────────────
    //   A*_a = {precompiles} ∪ {sender} ∪ {beneficiary} ∪ {to} ∪ {AL addrs}
    let mut warm_accounts = vec![sender];
    warm_accounts.push(block.header.beneficiary);
    if let Some(to) = &tx.to {
        warm_accounts.push(*to);
    }
    for item in &tx.access_list {
        warm_accounts.push(item.address);
    }
    for item in &tx.access_list {
        warm_accounts.push(item.address);
    }
    // TODO: push precompiles to warm_accounts

    // A*_K = all storage slots of access list }
    let mut warm_storage: Vec<(Address, H256)> = vec![];
    for item in &tx.access_list {
        for &slot in &item.storage_keys {
            warm_storage.push((item.address, slot));
        }
    }

    let mut substate = Substate {
        self_destruct:        vec![],
        logs:                 vec![],
        touched_accounts:     vec![],
        refund_fee:           U256::zero(),
        access_list_accounts: warm_accounts,
        access_list_storage:  warm_storage,
    };

    let mut evm = Machine {
        memory: Bytes::new(),
        stack: vec![],
        pc: 0,
        call_depth: 0,
        gas_remaining: U256::from(tx.gas_limit) - U256::from(g_0),
    };

    let code:Vec<u8>  = if let Some(to) = &tx.to {
        state.get_code(to).unwrap_or_default()
    } else { // CREATE transaction
        tx.data.to_vec()
    };
    
    let context = Context {
        contract_addr: tx.to,
        origin_sender: sender,
        gas_price: tx.effective_gas_price(base_fee),
        input: tx.data.clone(),
        sender,
        value: tx.value,
        code,
        block,
        depth: 0, // initial depth
        allow_writes: true, // always allow writes for now
    };

    // run evm
    let output_result = evm.run(&context, state, &mut substate);

    // TODO: RETURN handle 
    // Execution failed
    if output_result.is_err() {
        println!("Execution failed, result: {:?}", output_result);

        let _ = state.rollback(); // Rollback on error
        // receipt
        let receipt = Receipt::new(
            tx.tx_type,
            0, // 0 for failure
            U256::from(tx.gas_limit) - evm.gas_remaining,
            vec![], // 失败时没有 logs
        );
        block.receipts.push(receipt);
        return Ok(()); // Return Ok even on execution failure (transaction failed but was processed)
    }

    // ── Step 6: refund  ──────────────────
    //   compute g*  (total gas to return to sender)
    //   g'  = evm.gas_remaining   (gas left after EVM execution)
    //   g*  = g' + min( ⌊(T_g − g') / 5⌋,  A_r )    EIP-3529
    let g_prime           = evm.gas_remaining;
    let gas_consumed      = U256::from(tx.gas_limit) - g_prime;  // T_g − g'
    let refund_cap        = gas_consumed / 5;                     // ⌊(T_g − g') / 5⌋
    let storage_refund    = substate.refund_fee.min(refund_cap);  // A_r, capped
    let g_star            = g_prime + storage_refund;             // total gas returned

    // Step 7 : state finalization
    // \sigma^*[S(T)]_b \equiv \sigma_P[S(T)]_b + g^* \cdot p
    let sender_refund     = g_star * eff_price;
    let sender_bal_now    = state.get_balance(&sender).unwrap_or(U256::zero());
    state.set_balance(&sender, sender_bal_now + sender_refund);

    // beneficiary reward
    // \sigma^*[B_{H_c}]_b \equiv \sigma_P[B_{H_c}]_b + (T_g - g^*) \cdot f
    if state.get_account(&block.header.beneficiary).is_none() {
        state.insert(&block.header.beneficiary, AccountState::default());
    }
    let f                 = tx.priority_fee_per_gas(base_fee);
    let beneficiary_reward = (U256::from(tx.gas_limit) - g_star) * f;
    let bene_bal          = state.get_balance(&block.header.beneficiary).unwrap_or(U256::zero());
    state.set_balance(&block.header.beneficiary, bene_bal + beneficiary_reward);
    
    // step 8: finalize worldstate
    for addr in substate.self_destruct {
        state.delete(&addr);
    }
     //   Delete touched-but-empty accounts  (A_t)  — EIP-161
     for addr in &substate.touched_accounts {
        if !state.account_exists(addr) {
            continue;
        }
        let bal  = state.get_balance(addr).unwrap_or(U256::zero());
        let n    = state.get_nonce(addr).unwrap_or(0);
        let code = state.get_code(addr).unwrap_or_default();
        if bal.is_zero() && n == 0 && code.is_empty() {
            state.delete(addr);
        }
    }
    
    // Commit checkpoint on success
    state.commit();
    
    // receipt
    let gas_used_final = U256::from(tx.gas_limit) - g_star;
    block.header.gas_used += gas_used_final;
    let receipt = Receipt::new(
        tx.tx_type,
        1, // 1 for success
        gas_used_final,
        substate.logs,
    );
    block.receipts.push(receipt);

    Ok(())
}



impl Machine {
    /// Execute a transaction. Modify substate and state. Return the remaining gas and output.
    pub fn call(
        &mut self,
        _state: &mut WorldStateTrie,
        _substate: &mut Substate,
        _context: &Context,
        _remain_gas: U256) -> Result<(Bytes, U256), EvmError> 
    {
        let _op = JUMP_TABLE.get(&opcodes::CALL).unwrap();
        todo!()
    }

    pub fn run(&mut self, context: &Context, worldstate: &mut WorldStateTrie, substate: &mut Substate) 
        -> Result<Bytes, EvmError> 
    {
        loop {
            let opcode = self.get_opcode(context);
            let operation = JUMP_TABLE.get(&opcode).ok_or(EvmError::InvalidOpcode)?;

            // stack check
            let stack_size = self.stack.len();
            if stack_size < operation.min_stack {
                return Err(EvmError::StackUnderflow);
            }
            if stack_size > operation.max_stack {
                return Err(EvmError::StackOverflow);
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
                return Err(EvmError::OutOfGas);
            }
            self.gas_remaining -= U256::from(cost);
            if let Some(dynamic_gas) = operation.dynamic_gas {
                let dynamic_cost = dynamic_gas(self, context)?;
                if dynamic_cost > self.gas_remaining {
                    return Err(EvmError::OutOfGas);
                }
                self.gas_remaining -= U256::from(dynamic_cost);
            }
            // write limit, jumpdest,return data length, is checked for specific operation

            let output_result = (operation.execute)(self, context, worldstate, substate);
            
            match output_result {
                Ok(_bytes) => {
                    // Normal execution, just continue
                }
                Err(EvmError::ExplicitStop) => { 
                    return Ok(Bytes::new());
                }
                Err(EvmError::Return(data)) => {
                    return Ok(data);
                }
                Err(EvmError::Revert(data)) => {
                    return Err(EvmError::Revert(data));
                }
                Err(EvmError::SelfDestruct) => {
                    return Ok(Bytes::new()); // the Eth transfer and A_s changes are done in operation.execute
                }
                Err(e) => { // all the unexpected errors
                    self.gas_remaining = U256::zero();
                    return Err(e);
                }
            }
            
            self.pc += 1;
        }
    }

    fn get_opcode(&self, context: &Context) -> u8 {
        if self.pc >= context.code.len() {
            return opcodes::STOP;
        }

        context.code[self.pc]
    }

    #[allow(dead_code)]
    fn get_memory_slice(&self, offset: U256, size: U256) -> Result<Bytes, anyhow::Error> {
        let offset = offset.as_usize();
        let size = size.as_usize();
        if offset + size > self.memory.len() {
            return Err(anyhow::anyhow!("Memory out of bounds"));
        }
        Ok(self.memory.slice(offset..offset + size))
    }
}