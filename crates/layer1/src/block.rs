use ethereum_types::{Address, H64, H256, U256};
use rlp::{Encodable, Decodable, Rlp, DecoderError};
use crate::transaction::{Transaction1or2, hash_transactions};
use crate::receipts::{Receipt, hash_receipts, merge_bloom};
use crate::withdraws::{Withdrawal, hash_withdrawals};
use anyhow::Result;
use crate::world_state::WorldStateTrie;
use crate::common::constants::hashes;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

const TARGET_BLOB_GAS_PER_BLOCK:u64 = 393216;
const MIN_BASE_FEE_PER_BLOB_GAS:u64 = 1;
const BLOB_BASE_FEE_UPDATE_FRACTION:u64 = 3338477;

pub struct BlockHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256, // always KEC((RLP(())))
    pub beneficiary: Address,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: [u8; 256], // 2048 bits
    pub difficulty: U256, // always 0
    pub number: u64,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub prev_randao: H256, // or mix_hash, the random number on parent block of beacon chain
    pub nonce: H64,
    // RLP 扩展字段（index 15..=19），均为 Option
    pub base_fee: Option<U256>,
    pub withdrawals_root: Option<H256>,
    pub excess_blob_gas: Option<U256>,
    pub blob_gas_used: Option<U256>,
    pub parent_beacon_block_root: Option<H256>, // index 19, 最后一个
}

pub struct Block {
    pub header: BlockHeader,

    // block body
    pub transactions: Vec<Transaction1or2>,
    pub receipts: Vec<Receipt>,
    pub withdrawals: Vec<Withdrawal>,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            header: BlockHeader {
                parent_hash: H256::zero(),
                ommers_hash: hashes::EMPTY_LIST_HASH,
                beneficiary: Address::zero(),
                state_root: H256::zero(),
                transactions_root: hashes::EMPTY_TRIE_HASH,
                receipts_root: hashes::EMPTY_TRIE_HASH,
                logs_bloom: [0u8; 256],
                difficulty: U256::zero(),
                number: 0,
                gas_limit: U256::zero(),
                gas_used: U256::zero(),
                timestamp: 0,
                extra_data: vec![],
                prev_randao: H256::zero(),
                nonce: H64::zero(),
                base_fee: Some(U256::zero()),
                withdrawals_root: Some(hashes::EMPTY_TRIE_HASH),
                excess_blob_gas: Some(U256::zero()),
                blob_gas_used: Some(U256::zero()),
                parent_beacon_block_root: None,
            },
            transactions: vec![],
            receipts: vec![],
            withdrawals: vec![],
        }
    }
}


fn fake_exponential(factor: U256, numerator: U256, denominator: U256) -> U256 {
    let mut i = U256::one();
    let mut output = U256::zero();
    let mut numerator_accum = factor * denominator;
    while numerator_accum > U256::zero() {
        output += numerator_accum;
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += U256::one();
    }
    output // denominator
}

// header.excess_blob_gas = calc_excess_blob_gas(parent)
pub fn calc_excess_blob_gas(parent: &BlockHeader) -> U256 {
    let excess = parent.excess_blob_gas.unwrap_or(U256::zero());
    let used = parent.blob_gas_used.unwrap_or(U256::zero());
    if excess + used < U256::from(TARGET_BLOB_GAS_PER_BLOCK) {
        U256::zero()
    } else {
        excess + used - U256::from(TARGET_BLOB_GAS_PER_BLOCK)
    }
}

impl Block {
    pub fn get_base_fee_per_blob_gas(&self) -> U256 {
        fake_exponential(
            U256::from(MIN_BASE_FEE_PER_BLOB_GAS),
            self.header.excess_blob_gas.unwrap_or(U256::zero()),
            U256::from(BLOB_BASE_FEE_UPDATE_FRACTION)
        )
    }
    pub fn holistic_validity_check(&self, state:&WorldStateTrie) -> Result<()> {
        if self.header.state_root != state.root_hash() {
            return Err(anyhow::anyhow!("state_root not match"));
        }
        if self.header.ommers_hash != hashes::EMPTY_LIST_HASH {
            return Err(anyhow::anyhow!("ommers_hash not match"));
        }
        if self.header.transactions_root != hash_transactions(&self.transactions) {
            return Err(anyhow::anyhow!("transactions_root not match"));
        }
        if self.header.receipts_root != hash_receipts(&self.receipts) {
            return Err(anyhow::anyhow!("receipts_root not match"));
        }
        let expected_wr = hash_withdrawals(&self.withdrawals);
        if self.header.withdrawals_root.as_ref().copied().unwrap_or(hashes::EMPTY_TRIE_HASH) != expected_wr {
            return Err(anyhow::anyhow!("withdrawals_root not match"));
        }
        if self.header.logs_bloom != merge_bloom(&self.receipts) {
            return Err(anyhow::anyhow!("logs_bloom not match"));
        }

        Ok(())
    }

    pub fn hash(&self) -> H256 {
        let encoding = rlp::encode(self);
        let hash = Keccak256::digest(&encoding);
        H256::from_slice(&hash)
    }

    pub fn add_transaction(&mut self, tx: Transaction1or2) {
        self.transactions.push(tx);
        self.header.transactions_root = hash_transactions(&self.transactions);
    }

    pub fn add_transactions(&mut self, txs: Vec<Transaction1or2>) {
        self.transactions.extend(txs);
        self.header.transactions_root = hash_transactions(&self.transactions);
    }

    pub fn add_receipts(&mut self, receipts: Vec<Receipt>) {
        self.receipts.extend(receipts);
        self.header.receipts_root = hash_receipts(&self.receipts);

        // update logs bloom
        self.header.logs_bloom = merge_bloom(&self.receipts);
    }

    pub fn add_withdrawals(&mut self, withdrawals: Vec<Withdrawal>) {
        self.withdrawals.extend(withdrawals);
        self.header.withdrawals_root = Some(hash_withdrawals(&self.withdrawals));
    }
}

impl BlockHeader {
    /// 验证区块头的有效性
    pub fn header_validity_check(&self, parent: Option<&Block>) -> Result<()> {
        // 1. 静态规则检查（不依赖父区块）
        
        // H_g <= H_l: 已使用的 Gas 必须不超过 gas limit
        if self.gas_used > self.gas_limit {
            return Err(anyhow::anyhow!("Gas used ({}) exceeds gas limit ({})", self.gas_used, self.gas_limit));
        }

        // ||H_x|| <= 32: extraData 长度不能超过 32 字节
        if self.extra_data.len() > 32 {
            return Err(anyhow::anyhow!("Extra data exceeds 32 bytes (actual: {})", self.extra_data.len()));
        }

        // H_o = KEC(RLP(())): 空列表的 RLP 编码 (0xc0) 的 Keccak256 哈希
        // 预计算的哈希值: 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
        let empty_list_hash = H256::from_slice(
            &hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()
        );
        if self.ommers_hash != empty_list_hash {
            return Err(anyhow::anyhow!("Invalid ommers hash (must be KEC(RLP(())))"));
        }

        // H_d = 0: 巴黎升级后 Difficulty 恒为 0
        if self.difficulty != U256::zero() {
            return Err(anyhow::anyhow!("Difficulty must be 0 (post-Paris)"));
        }

        // H_n = 0x0000000000000000: 巴黎升级后 Nonce 恒为 0
        if self.nonce != H64::zero() {
            return Err(anyhow::anyhow!("Nonce must be zero (post-Paris)"));
        }

        // H_a = PREVRANDAO(): 理论上需要信标链状态验证，此处仅做结构占位
        // (在实际客户端中，这里会调用共识层的接口来验证 prev_randao)

        // 2. 动态规则检查（依赖父区块）
        if let Some(parent_block) = parent {
            let p_header = &parent_block.header;

            // 验证父哈希是否匹配 (隐式包含在 P(H) 的定义中)
            if self.parent_hash != parent_block.hash() {
                return Err(anyhow::anyhow!("Parent hash not match"));
            }

            // H_i = P(H)_{H_i} + 1: 区块高度必须是父区块高度 + 1
            if self.number != p_header.number + 1 {
                return Err(anyhow::anyhow!("Invalid block number: expected {}, got {}", p_header.number + 1, self.number));
            }

            // H_s > P(H)_{H_s}: 时间戳必须严格大于父区块
            if self.timestamp <= p_header.timestamp {
                return Err(anyhow::anyhow!("Timestamp ({}) must be strictly greater than parent's ({})", self.timestamp, p_header.timestamp));
            }

            // H_l 限制: Gas Limit 变化范围及下限
            let limit_delta = p_header.gas_limit / 1024;
            if self.gas_limit >= p_header.gas_limit + limit_delta {
                return Err(anyhow::anyhow!("Gas limit too high compared to parent"));
            }
            if self.gas_limit <= p_header.gas_limit - limit_delta {
                return Err(anyhow::anyhow!("Gas limit too low compared to parent"));
            }
            if self.gas_limit < U256::from(5000) {
                return Err(anyhow::anyhow!("Gas limit below minimum 5000"));
            }

            // H_f = F(H): 基础 Gas 费 (Base Fee) 计算与验证
            if let (Some(base_fee), Some(p_base_fee)) = (self.base_fee, p_header.base_fee) {
                let p_gas_used = p_header.gas_used;
                let target = p_header.gas_limit / 2; // tau = P(H)_{H_l} / 2

                let expected_base_fee = if p_gas_used == target {
                    p_base_fee
                } else if p_gas_used < target {
                    // nu* = P(H)_{H_f} * (tau - P(H)_{H_g}) / tau
                    let delta = target - p_gas_used;
                    let nu_star = (p_base_fee * delta) / target;
                    // nu = floor(nu* / 8)
                    let nu = nu_star / 8;
                    p_base_fee - nu
                } else {
                    // nu* = P(H)_{H_f} * (P(H)_{H_g} - tau) / tau
                    let delta = p_gas_used - target;
                    let nu_star = (p_base_fee * delta) / target;
                    // nu = max(floor(nu* / 8), 1)
                    let nu = std::cmp::max(nu_star / 8, U256::from(1));
                    p_base_fee + nu
                };

                if base_fee != expected_base_fee {
                    return Err(anyhow::anyhow!("Invalid base fee: expected {}, got {}", expected_base_fee, base_fee));
                }
            } 
            // 注意：如果是刚好发生伦敦升级的那个区块，父区块没有 base_fee 但当前区块有，
            // 这里的逻辑需要根据具体的硬分叉高度配置来放行。这里仅做基础的同构检查。
        } else { // genesis block
            if self.number != 0 {
                return Err(anyhow::anyhow!("Non-genesis block must have a parent"));
            }
        }
    
        Ok(())
    }
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        let n_optional = [
            self.base_fee.is_some(),
            self.withdrawals_root.is_some(),
            self.excess_blob_gas.is_some(),
            self.blob_gas_used.is_some(),
            self.parent_beacon_block_root.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        s.begin_list(15 + n_optional);

        s.append(&self.parent_hash);         // 0 H_p
        s.append(&self.ommers_hash);         // 1 H_o
        s.append(&self.beneficiary);         // 2 H_c
        s.append(&self.state_root);          // 3 H_r
        s.append(&self.transactions_root);   // 4 H_t
        s.append(&self.receipts_root);       // 5 H_e
        s.append(&self.logs_bloom.as_ref()); // 6 H_b
        s.append(&self.difficulty);          // 7 H_d
        s.append(&self.number);              // 8 H_i
        s.append(&self.gas_limit);           // 9 H_l
        s.append(&self.gas_used);            // 10 H_g
        s.append(&self.timestamp);           // 11 H_s
        s.append(&self.extra_data);          // 12 H_x
        s.append(&self.prev_randao);         // 13 H_a
        s.append(&self.nonce);               // 14 H_n
        if let Some(v) = self.base_fee {
            s.append(&v);                    // 15 H_f
        }
        if let Some(v) = &self.withdrawals_root {
            s.append(v);                     // 16 H_w
        }
        if let Some(v) = &self.excess_blob_gas {
            s.append(v);                     // 17 H_z
        }
        if let Some(v) = &self.blob_gas_used {
            s.append(v);                     // 18 H_y
        }
        if let Some(v) = &self.parent_beacon_block_root {
            s.append(v);                     // 19 parent_beacon_block_root
        }
    }
}

impl Decodable for BlockHeader {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let count = rlp.item_count()?;
        if !rlp.is_list() || count < 15 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let bloom_bytes: bytes::Bytes = rlp.val_at(6)?;
        if bloom_bytes.len() != 256 {
            return Err(DecoderError::Custom("logs_bloom length != 256"));
        }
        let mut logs_bloom = [0u8; 256];
        logs_bloom.copy_from_slice(&bloom_bytes);

        println!("going to decode block header, count: {}", count);

        // INSERT_YOUR_CODE
        // 挨个逐字段 decode + println，方便定位哪一步出错（val_at 需显式类型参数）
        let parent_hash = match rlp.val_at::<H256>(0) {
            Ok(v) => { println!("parent_hash ok"); v },
            Err(e) => { println!("parent_hash err: {:?}", e); return Err(e); }
        };
        let ommers_hash = match rlp.val_at::<H256>(1) {
            Ok(v) => { println!("ommers_hash ok"); v },
            Err(e) => { println!("ommers_hash err: {:?}", e); return Err(e); }
        };
        let beneficiary = match rlp.val_at::<Address>(2) {
            Ok(v) => { println!("beneficiary ok"); v },
            Err(e) => { println!("beneficiary err: {:?}", e); return Err(e); }
        };
        let state_root = match rlp.val_at::<H256>(3) {
            Ok(v) => { println!("state_root ok"); v },
            Err(e) => { println!("state_root err: {:?}", e); return Err(e); }
        };
        let transactions_root = match rlp.val_at::<H256>(4) {
            Ok(v) => { println!("transactions_root ok"); v },
            Err(e) => { println!("transactions_root err: {:?}", e); return Err(e); }
        };
        let receipts_root = match rlp.val_at::<H256>(5) {
            Ok(v) => { println!("receipts_root ok"); v },
            Err(e) => { println!("receipts_root err: {:?}", e); return Err(e); }
        };
        // logs_bloom 已经解析
        let difficulty = match rlp.val_at::<U256>(7) {
            Ok(v) => { println!("difficulty ok"); v },
            Err(e) => { println!("difficulty err: {:?}", e); return Err(e); }
        };
        let number = match rlp.val_at::<u64>(8) {
            Ok(v) => { println!("number ok"); v },
            Err(e) => { println!("number err: {:?}", e); return Err(e); }
        };
        let gas_limit = match rlp.val_at::<U256>(9) {
            Ok(v) => { println!("gas_limit ok"); v },
            Err(e) => { println!("gas_limit err: {:?}", e); return Err(e); }
        };
        let gas_used = match rlp.val_at::<U256>(10) {
            Ok(v) => { println!("gas_used ok"); v },
            Err(e) => { println!("gas_used err: {:?}", e); return Err(e); }
        };
        let timestamp = match rlp.val_at::<u64>(11) {
            Ok(v) => { println!("timestamp ok"); v },
            Err(e) => { println!("timestamp err: {:?}", e); return Err(e); }
        };
        let extra_data = match rlp.val_at::<Vec<u8>>(12) {
            Ok(v) => { println!("extra_data ok"); v },
            Err(e) => { println!("extra_data err: {:?}", e); return Err(e); }
        };
        let prev_randao = match rlp.val_at::<H256>(13) {
            Ok(v) => { println!("prev_randao ok"); v },
            Err(e) => { println!("prev_randao err: {:?}", e); return Err(e); }
        };
        let nonce = match rlp.val_at::<H64>(14) {
            Ok(v) => { println!("nonce ok"); v },
            Err(e) => { println!("nonce err: {:?}", e); return Err(e); }
        };
        let base_fee = if count > 15 {
            match rlp.val_at::<U256>(15) {
                Ok(v) => { println!("base_fee ok"); Some(v) },
                Err(e) => { println!("base_fee err: {:?}", e); return Err(e); }
            }
        } else {
            None
        };
        let withdrawals_root = if count > 16 {
            match rlp.val_at::<H256>(16) {
                Ok(v) => { println!("withdrawals_root ok"); Some(v) },
                Err(e) => { println!("withdrawals_root err: {:?}", e); return Err(e); }
            }
        } else {
            None
        };
        let excess_blob_gas = if count > 17 {
            match rlp.val_at::<U256>(17) {
                Ok(v) => { println!("excess_blob_gas ok"); Some(v) },
                Err(e) => { println!("excess_blob_gas err: {:?}", e); return Err(e); }
            }
        } else {
            None
        };
        let blob_gas_used = if count > 18 {
            match rlp.val_at::<U256>(18) {
                Ok(v) => { println!("blob_gas_used ok"); Some(v) },
                Err(e) => { println!("blob_gas_used err: {:?}", e); return Err(e); }
            }
        } else {
            None
        };
        let parent_beacon_block_root = if count > 19 {
            match rlp.val_at::<H256>(19) {
                Ok(v) => { println!("parent_beacon_block_root ok"); Some(v) },
                Err(e) => { println!("parent_beacon_block_root err: {:?}", e); return Err(e); }
            }
        } else {
            None
        };


        Ok(Self {
            parent_hash,
            ommers_hash,
            beneficiary,
            state_root,
            transactions_root,
            receipts_root,
            logs_bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            prev_randao,
            nonce,
            base_fee,
            withdrawals_root,
            excess_blob_gas,
            blob_gas_used,
            parent_beacon_block_root,
        })
    }
}
impl Encodable for Block {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);

        s.append(&self.header);

        s.begin_list(self.transactions.len());
        for tx in &self.transactions {
            let item = tx.encode_block_rlp_item();
            s.append_raw(&item, 1);
        }

        s.begin_list(0); // Ommers (B_U) - 已弃用的叔块头数组，内容为空数组

        s.begin_list(self.withdrawals.len());
        for w in &self.withdrawals {
            s.append(w);
        }
    }
}

impl Decodable for Block {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 4 {
            println!("rlp.item_count() != 4?, count: {}", rlp.item_count()?);
            return Err(DecoderError::RlpIncorrectListLen);
        }

        // 1. BlockHeader (B_H)
        let header = BlockHeader::decode(&rlp.at(0)?)?;
        println!("decoded header");
        
        // 2. Transactions (B_T)
        let tx_list = rlp.at(1)?;
        println!("decoded tx_list, is_list: {}, item_count: {:?}", tx_list.is_list(), tx_list.item_count());
        let mut transactions = Vec::new();
        for i in 0..tx_list.item_count()? {
            transactions.push(Transaction1or2::decode(&tx_list.at(i)?)?);
        }
        println!("decoded transactions");

        // 3. Ommers (B_U) - 已弃用的叔块头数组，应该为空数组
        let ommers_list = rlp.at(2)?;
        assert!(ommers_list.item_count()? == 0, "ommers_list should be empty");

        // 4. Withdrawals (B_W)
        let withdrawal_list = rlp.at(3)?;
        let mut withdrawals = Vec::new();
        for i in 0..withdrawal_list.item_count()? {
            withdrawals.push(Withdrawal::decode(&withdrawal_list.at(i)?)?);
        }

        let receipts = Vec::new(); // TODO: we will get receipts by executing transactions

        Ok(Self {
            header,
            transactions,
            receipts,
            withdrawals,
        })
    }
}

