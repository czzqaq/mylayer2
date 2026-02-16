use ethereum_types::{U256, H256, Address};
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
    pub nonce: u64, // always 0
    pub base_fee: U256, 
    pub withdrawals_root: H256, 
    pub excess_blob_gas: U256,
    pub blob_gas_used: U256,
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
                nonce: 0,
                base_fee: U256::zero(),
                withdrawals_root: hashes::EMPTY_TRIE_HASH,
                excess_blob_gas: U256::zero(),
                blob_gas_used: U256::zero(),
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
    if U256::from(parent.excess_blob_gas) + parent.blob_gas_used < U256::from(TARGET_BLOB_GAS_PER_BLOCK) {
        U256::zero()
    } else {
        U256::from(parent.excess_blob_gas) + parent.blob_gas_used - U256::from(TARGET_BLOB_GAS_PER_BLOCK)
    }
}

impl Block {
    pub fn get_base_fee_per_blob_gas(&self) -> U256 {
        fake_exponential(
            U256::from(MIN_BASE_FEE_PER_BLOB_GAS), 
            self.header.excess_blob_gas,
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
        if self.header.withdrawals_root != hash_withdrawals(&self.withdrawals) {
            return Err(anyhow::anyhow!("withdrawals_root not match"));
        }
        if self.header.logs_bloom != merge_bloom(&self.receipts) {
            return Err(anyhow::anyhow!("logs_bloom not match"));
        }

        Ok(())
    }
    pub fn header_validity_check(&self, parent:&Block) -> Result<()> {
        if self.header.parent_hash != parent.hash() {
            return Err(anyhow::anyhow!("parent_hash mismatch"));
        }
        if self.header.number != parent.header.number + 1 {
            return Err(anyhow::anyhow!("number not match"));
        }
        if self.header.gas_limit == U256::zero() {
            return Err(anyhow::anyhow!("gas_limit is zero"));
        }
        if self.header.timestamp == 0 {
            return Err(anyhow::anyhow!("timestamp is zero"));
        }
        if self.header.base_fee == U256::zero() {
            return Err(anyhow::anyhow!("base_fee is zero"));
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
        self.header.withdrawals_root = hash_withdrawals(&self.withdrawals);
    }
}


impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(19);

        s.append(&self.parent_hash);         // H_p
        s.append(&self.ommers_hash);         // H_o
        s.append(&self.beneficiary);         // H_c
        s.append(&self.state_root);          // H_r
        s.append(&self.transactions_root);   // H_t
        s.append(&self.receipts_root);       // H_e
        s.append(&self.logs_bloom.as_ref()); // H_b
        s.append(&self.difficulty);          // H_d
        s.append(&self.number);              // H_i
        s.append(&self.gas_limit);           // H_l
        s.append(&self.gas_used);            // H_g
        s.append(&self.timestamp);           // H_s
        s.append(&self.extra_data);          // H_x
        s.append(&self.prev_randao);         // H_a
        s.append(&self.nonce);               // H_n
        s.append(&self.base_fee);            // H_f
        s.append(&self.withdrawals_root);    // H_w
        s.append(&self.excess_blob_gas);     // H_z
        s.append(&self.blob_gas_used);       // H_y
    }
}

impl Decodable for BlockHeader {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let count = rlp.item_count()?;
        if !rlp.is_list() || count < 15 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        // logs_bloom 需要 index 6 存在；count >= 15 已保证
        let bloom_bytes: bytes::Bytes = rlp.val_at(6)?;
        if bloom_bytes.len() != 256 {
            return Err(DecoderError::Custom("logs_bloom length != 256"));
        }
        let mut logs_bloom = [0u8; 256];
        logs_bloom.copy_from_slice(&bloom_bytes);

        Ok(Self {
            parent_hash: rlp.val_at(0)?,
            ommers_hash: rlp.val_at(1)?,
            beneficiary: rlp.val_at(2)?,
            state_root: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            receipts_root: rlp.val_at(5)?,
            logs_bloom,
            difficulty: rlp.val_at(7)?,
            number: rlp.val_at(8)?,
            gas_limit: rlp.val_at(9)?,
            gas_used: rlp.val_at(10)?,
            timestamp: rlp.val_at(11)?,
            extra_data: rlp.val_at(12)?,
            prev_randao: rlp.val_at(13)?,
            nonce: rlp.val_at(14)?,

            // 可选字段：不存在就给默认值；存在就读；多出来的(>=19/20/...)自动忽略
            base_fee: if count > 15 { rlp.val_at(15)? } else { U256::zero() },
            withdrawals_root: if count > 16 { rlp.val_at(16)? } else { hashes::EMPTY_TRIE_HASH },
            excess_blob_gas: if count > 17 { rlp.val_at(17)? } else { U256::zero() },
            blob_gas_used: if count > 18 { rlp.val_at(18)? } else { U256::zero() },
        })
    }
}

impl Encodable for Block {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);

        // 1. BlockHeader
        s.append(&self.header);

        // 2. Transactions (EIP-2718 typed txs handled by Transaction1or2::Encodable)
        s.begin_list(self.transactions.len());
        for tx in &self.transactions {
            s.append(tx); // already Encodable with type prefix
        }

        // 3. Receipts
        s.begin_list(self.receipts.len());
        for receipt in &self.receipts {
            if receipt.tx_type == 0 {
                s.append(receipt);
            } else {
                // type-prefixed receipt
                let mut envelope = vec![receipt.tx_type];
                envelope.extend_from_slice(&rlp::encode(receipt));
                s.append(&envelope.as_slice());
            }
        }

        // 4. Withdrawals
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

        let header = BlockHeader::decode(&rlp.at(0)?)?;
        let tx_list = rlp.at(1)?;
        let receipt_list = rlp.at(2)?;
        let withdrawal_list = rlp.at(3)?;

        let mut transactions = Vec::new();
        for i in 0..tx_list.item_count()? {
            transactions.push(Transaction1or2::decode(&tx_list.at(i)?)?);
        }

        let mut receipts = Vec::new();
        for i in 0..receipt_list.item_count()? {
            let item = receipt_list.at(i)?;
            if item.is_list() {
                let mut r: Receipt = rlp::Decodable::decode(&item)?;
                r.tx_type = 0;
                receipts.push(r);
            } else {
                let data: bytes::Bytes = item.as_val()?;
                if data.is_empty() {
                    return Err(DecoderError::Custom("Empty receipt data"));
                }
                let tx_type = data[0];
                let payload = &data[1..];
                let inner_rlp = Rlp::new(payload);
                let mut r: Receipt = rlp::Decodable::decode(&inner_rlp)?;
                r.tx_type = tx_type;
                receipts.push(r);
            }
        }

        let mut withdrawals = Vec::new();
        for i in 0..withdrawal_list.item_count()? {
            withdrawals.push(Withdrawal::decode(&withdrawal_list.at(i)?)?);
        }

        Ok(Self {
            header,
            transactions,
            receipts,
            withdrawals,
        })
    }
}

