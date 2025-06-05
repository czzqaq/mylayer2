use std::collections::HashMap;
use ethereum_types::{Address, U256, H256};
use serde::Deserialize;
use hex::FromHex;
use sha3::{Digest, Keccak256};
use k256::ecdsa::SigningKey;

// 假设你已有这些类型
use crate::layer1::world_state::{AccountState, WorldStateTrie, StorageTrie};
use crate::layer1::transaction::Transaction1or2;
use crate::layer1::block::{Block, BlockHeader};

#[derive(Debug, Deserialize)]
pub struct RawAccount { // for "pre" field
    pub nonce: String,
    pub balance: String,
    pub code: String,
    pub storage: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Env { // for "env" field
    #[serde(rename = "currentCoinbase")]
    pub coinbase: String,
    #[serde(rename = "currentDifficulty")]
    pub difficulty: String,
    #[serde(rename = "currentGasLimit")]
    pub gas_limit: String,
    #[serde(rename = "currentNumber")]
    pub number: String,
    #[serde(rename = "currentTimestamp")]
    pub timestamp: String,
    #[serde(rename = "currentBaseFee")]
    pub base_fee: String,
    #[serde(rename = "currentRandom")]
    pub random: String,
    #[serde(rename = "currentExcessBlobGas")]
    pub excess_blob_gas: String,
}

#[derive(Debug, Deserialize)]
pub struct RawTxJson {
    pub data: Vec<String>,
    #[serde(rename = "gasLimit")]
    pub gas_limit: Vec<String>,
    #[serde(rename = "gasPrice")]
    pub gasPrice: String,
    pub nonce: String,
    pub secretKey: String,
    pub sender: String,
    pub to: String,
    pub value: Vec<String>,
}


pub fn parse_u256(s: &str) -> U256 {
    if let Some(stripped) = s.strip_prefix("0x") {
        U256::from_str_radix(stripped, 16).unwrap()
    } else {
        U256::from_dec_str(s).unwrap()
    }
}

pub fn parse_bytes(s: &str) -> Vec<u8> {
    if let Some(stripped) = s.strip_prefix("0x") {
        Vec::from_hex(stripped).unwrap()
    } else {
        panic!("Invalid hex string: {}", s);
    }
}

pub fn parse_address(s: &str) -> Address {
    let bytes = parse_bytes(s);
    assert_eq!(bytes.len(), 20);
    Address::from_slice(&bytes)
}

pub fn build_world_state_from_test(pre: &HashMap<String, RawAccount>) -> WorldStateTrie {
    let mut state = WorldStateTrie::default();

    for (addr_str, raw_account) in pre {
        // 1. 解析地址
        let address = parse_address(addr_str);

        // 2. 解析 balance 和 nonce
        let balance = parse_u256(&raw_account.balance);
        let nonce = parse_u256(&raw_account.nonce);

        // 3. 解析 code
        let code = parse_bytes(&raw_account.code);

        // 4. 构建 storage trie
        let mut storage_trie = StorageTrie::default();
        for (k, v) in &raw_account.storage {
            let key = parse_u256(k);
            let value = parse_u256(v);
            storage_trie.insert(key, value);
        }

        // 5. 构建 AccountState
        let mut account = AccountState {
            nonce,
            balance,
            code,
            storage: storage_trie,
            storage_root: H256::zero(),
            code_hash: H256::zero(), 
        };

        account.update_code_hash();
        account.update_storage_root();

        state.insert(&address, account);
    }

    state
}

pub fn build_block_from_env(env: &Env) -> Block {
    let mut block = Block::default();

    block.header.beneficiary = parse_address(&env.coinbase);
    block.header.difficulty = parse_u256(&env.difficulty);
    block.header.gas_limit = parse_u256(&env.gas_limit);
    block.header.number = parse_u64(&env.number);
    block.header.timestamp = parse_u64(&env.timestamp);
    block.header.base_fee = parse_u256(&env.base_fee);
    block.header.prev_randao = parse_h256(&env.random);
    block.header.excess_blob_gas = parse_u256(&env.excess_blob_gas);

    block
}

pub fn build_blob_transactions_from_json(
    raw: &RawTxJson,
    chain_id: u64,
) -> Vec<Transaction1or2> {
    let secret_key_bytes = parse_bytes(&raw.secretKey);
    let signing_key = SigningKey::from_bytes(&secret_key_bytes).expect("Invalid secret key");

    let to = if raw.to.trim().is_empty() {
        None
    } else {
        Some(parse_address(&raw.to))
    };

    let nonce = parse_u64(&raw.nonce);
    let gas_price = parse_u256(&raw.gasPrice);

    let mut result = vec![];

    for i in 0..raw.data.len() {
        let data = parse_bytes(&raw.data[i]);
        let gas_limit = parse_u64(&raw.gas_limit[i.min(raw.gas_limit.len() - 1)]);
        let value = parse_u256(&raw.value[i.min(raw.value.len() - 1)]);

        let mut tx = Transaction1or2 {
            tx_type: 3, // EIP-4844 blob transaction
            nonce,
            gas_limit,
            to: to.clone(),
            value,
            data: data.into(),
            v: H256::zero(),
            r: H256::zero(),
            s: H256::zero(),
            chain_id,
            max_priority_fee_per_gas: gas_price,
            max_fee_per_gas: gas_price,
            access_list: vec![], // empty for now
            max_fee_per_blob_gas: 0.into(),
            blob_versioned_hashes: vec![],
        };

        let message_hash = tx.get_message_hash();
        let (r, s, v) = sign_message_hash(message_hash, &signing_key);

        tx.r = r;
        tx.s = s;
        tx.v = H256::from_low_u64_be(v as u64);

        result.push(tx);
    }

    result
}