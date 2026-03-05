use crate::block::Block;
use crate::world_state::WorldStateTrie;
use crate::tx_execution::tx_execute;
use crate::withdraws::Withdrawal;
use ethereum_types::U256;
use anyhow::Result;

pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub state: WorldStateTrie,
}

impl Blockchain {
    /// 创建一个新的空 blockchain（从 genesis 开始）
    pub fn new() -> Self {
        Self {
            blocks: vec![],
            state: WorldStateTrie::new(),
        }
    }

    /// 从指定的初始 state 创建 blockchain
    pub fn with_state(state: WorldStateTrie) -> Self {
        Self {
            blocks: vec![],
            state,
        }
    }

    /// 从已有的 blocks 和 state 创建 blockchain
    pub fn with_blocks_and_state(blocks: Vec<Block>, state: WorldStateTrie) -> Self {
        Self {
            blocks,
            state,
        }
    }

    pub fn add_block(&mut self, mut block: Block) -> Result<()> {
        // 1. header_validity_check
        let parent = self.blocks.last();
        block.header.header_validity_check(parent)?;

        // 2. 加载旧 WorldStateTrie (使用当前的 self.state)
        // 注意：这里我们直接使用 self.state，因为它是当前的世界状态

        // 3. 执行所有交易
        // 先克隆 transactions 以避免借用冲突
        let transactions = block.transactions.clone();
        let mut cumulative_gas_used = U256::zero();
        
        for tx in &transactions {
            tx_execute(tx, &mut self.state, &mut block)?;
            
            // 更新累计 gas_used
            // tx_execute 中 receipt 的 cumulative_gas_used 只是该交易的 gas_used
            // 我们需要将其更新为累计值
            if let Some(last_receipt) = block.receipts.last_mut() {
                let tx_gas_used = last_receipt.cumulative_gas_used;
                cumulative_gas_used += tx_gas_used;
                last_receipt.cumulative_gas_used = cumulative_gas_used;
            }
        }
        block.header.gas_used = cumulative_gas_used;

        // 4. 处理withdraw (留好接口，todo)
        self.process_withdrawals(&block.withdrawals)?;

        // 5. holistic_validity_check
        // 先更新 state_root
        block.header.state_root = self.state.root_hash();
        block.holistic_validity_check(&self.state)?;
        println!("Block added: {:?}", block.header.hash().to_string());

        self.blocks.push(block);

        Ok(())
    }

    /// 处理 withdrawals
    /// TODO: 实现具体的 withdrawal 处理逻辑
    fn process_withdrawals(&mut self, withdrawals: &[Withdrawal]) -> Result<()> {
        for withdrawal in withdrawals {
            // TODO: 实现 withdrawal 处理逻辑
            // 例如：将 withdrawal.amount 添加到 withdrawal.recipient 的余额中
            let recipient = withdrawal.recipient;
            let amount = U256::from(withdrawal.amount.as_u64());
            
            // 如果账户不存在，需要创建
            if !self.state.account_exists(&recipient) {
                use crate::world_state::AccountState;
                let account = AccountState::default();
                self.state.insert(&recipient, account);
            }
            
            // 增加余额
            let current_balance = self.state.get_balance(&recipient).unwrap_or(U256::zero());
            self.state.set_balance(&recipient, current_balance + amount);
        }
        Ok(())
    }

    pub fn get_latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }
}

