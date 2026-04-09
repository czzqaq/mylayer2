//! Blockchain 测试：加载、RLP 编解码、链成长（block 验证 + pre->post 状态转移）

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use sha3::{Digest, Keccak256};

use layer1::block::Block;
use layer1::blockchain::Blockchain;

// ============================================
// 测试数据加载结构（与 JSON 格式匹配）
// ============================================

#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainTest {
    #[serde(rename = "_info")]
    pub info: serde_json::Value,
    pub blocks: Vec<BlockJson>,
    pub config: ChainConfig,
    #[serde(rename = "genesisBlockHeader")]
    pub genesis_block_header: BlockHeaderJson,
    #[serde(rename = "genesisRLP")]
    pub genesis_rlp: String,
    pub lastblockhash: String,
    pub network: String,
    #[serde(rename = "postState")]
    pub post_state: HashMap<String, AccountStateJson>,
    pub pre: HashMap<String, AccountStateJson>,
    #[serde(rename = "sealEngine")]
    pub seal_engine: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockJson {
    #[serde(rename = "blockHeader")]
    pub block_header: BlockHeaderJson,
    pub blocknumber: String,
    /// RLP 编码的 block（十六进制，可选）
    #[serde(default)]
    pub rlp: Option<String>,
    pub transactions: Vec<TransactionJson>,
    pub withdrawals: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeaderJson {
    #[serde(rename = "baseFeePerGas")]
    pub base_fee_per_gas: String,
    #[serde(rename = "blobGasUsed")]
    pub blob_gas_used: String,
    pub bloom: String,
    pub coinbase: String,
    pub difficulty: String,
    #[serde(rename = "excessBlobGas")]
    pub excess_blob_gas: String,
    #[serde(rename = "extraData")]
    pub extra_data: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    pub hash: String,
    #[serde(rename = "mixHash")]
    pub mix_hash: String,
    pub nonce: String,
    pub number: String,
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    #[serde(rename = "receiptTrie")]
    pub receipt_trie: String,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    pub timestamp: String,
    #[serde(rename = "transactionsTrie")]
    pub transactions_trie: String,
    #[serde(rename = "withdrawalsRoot")]
    pub withdrawals_root: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionJson {
    pub data: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    pub nonce: String,
    pub r: String,
    pub s: String,
    pub sender: String,
    pub to: String,
    pub v: String,
    pub value: String,
    #[serde(rename = "type")]
    pub tx_type: Option<String>,
    #[serde(rename = "chainId")]
    pub chain_id: Option<String>,
    #[serde(rename = "accessList")]
    pub access_list: Option<Vec<AccessListEntryJson>>,
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessListEntryJson {
    pub address: String,
    #[serde(rename = "storageKeys")]
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountStateJson {
    pub balance: String,
    pub code: String,
    pub nonce: String,
    pub storage: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    pub chainid: String,
    pub network: String,
}

// ============================================
// 测试加载与辅助
// ============================================

fn load_blockchain_tests(json_path: &str) -> Result<HashMap<String, BlockchainTest>, String> {
    let content = fs::read_to_string(json_path)
        .map_err(|e| format!("Failed to read file {}: {}", json_path, e))?;
    let tests: HashMap<String, BlockchainTest> = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    Ok(tests)
}

mod common;
use common::parsers::build_world_state_from_test;
use common::parsers::RawAccount;
use layer1::common::serde_helper;

fn parse_hex_u256(s: &str) -> ethereum_types::U256 {
    serde_helper::parse_u256_from_str(s).unwrap()
}

fn parse_hex_u64(s: &str) -> u64 {
    serde_helper::parse_u64_from_str(s).unwrap()
}

fn parse_hex_address(s: &str) -> ethereum_types::Address {
    serde_helper::parse_address(s).unwrap()
}

fn parse_hex_h256(s: &str) -> ethereum_types::H256 {
    serde_helper::parse_h256(s).unwrap()
}

/// 从十六进制 RLP 字符串解码为 `Block`。
fn decode_block_rlp(rlp_hex: &str) -> Result<Block, String> {
    let hex_str = rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex);
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {}", e))?;
    let block: Block = rlp::decode(bytes.as_ref()).map_err(|e| format!("rlp decode: {:?}", e))?;
    Ok(block)
}

/// 对单个 block 的 RLP 做往返测试，并与 JSON 中的关键字段对比：
/// 1. RLP decode -> Block -> RLP encode，断言与原始 RLP 字节一致；
/// 2. 解码后的 block 的 number、parent_hash、transactions_root 等与 JSON blockHeader 一致。
pub fn assert_block_rlp_roundtrip_and_matches_json(block_json: &BlockJson) -> Result<(), String> {
    let rlp_hex = block_json
        .rlp
        .as_deref()
        .ok_or("block 缺少 rlp 字段")?;

    let hex_str = rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex);
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode: {}", e))?;

    let decoded: Block =
        rlp::decode(bytes.as_ref()).map_err(|e| format!("rlp decode: {:?}", e))?;

    // 1. 往返：重新编码后应与原始字节一致
    let re_encoded = rlp::encode(&decoded);
    if re_encoded.as_ref() != bytes.as_slice() {
        return Err(format!(
            "block number {}: RLP 往返不一致（decode -> encode 与原始 RLP 不同）",
            decoded.header.number
        ));
    }

    // 2. 与 JSON 中的 blockHeader 关键字段对比
    let h = &decoded.header;
    let j = &block_json.block_header;

    if h.number != parse_hex_u64(&j.number) {
        return Err(format!(
            "block number 不一致: decoded={} json={}",
            h.number,
            j.number
        ));
    }
    if h.parent_hash != parse_hex_h256(&j.parent_hash) {
        return Err(format!(
            "block {} parent_hash 不一致",
            h.number
        ));
    }
    if h.state_root != parse_hex_h256(&j.state_root) {
        return Err(format!("block {} state_root 不一致", h.number));
    }
    if h.transactions_root != parse_hex_h256(&j.transactions_trie) {
        return Err(format!(
            "block {} transactions_root 不一致",
            h.number
        ));
    }
    if h.receipts_root != parse_hex_h256(&j.receipt_trie) {
        return Err(format!("block {} receipts_root 不一致", h.number));
    }
    if h.gas_used != parse_hex_u256(&j.gas_used) {
        return Err(format!("block {} gas_used 不一致", h.number));
    }
    if h.gas_limit != parse_hex_u256(&j.gas_limit) {
        return Err(format!("block {} gas_limit 不一致", h.number));
    }
    if decoded.transactions.len() != block_json.transactions.len() {
        return Err(format!(
            "block {} transactions 数量不一致: decoded={} json={}",
            h.number,
            decoded.transactions.len(),
            block_json.transactions.len()
        ));
    }

    Ok(())
}

fn account_state_json_to_raw(acc: &AccountStateJson) -> RawAccount {
    RawAccount {
        nonce: acc.nonce.clone(),
        balance: acc.balance.clone(),
        code: acc.code.clone(),
        storage: acc.storage.clone(),
    }
}

fn assert_account_derived_fields_consistent(state: &layer1::world_state::WorldStateTrie, label: &str) {
    for (addr, account) in state.iter() {
        let expected_code_hash = ethereum_types::H256::from_slice(&Keccak256::digest(&account.code));
        assert_eq!(
            account.code_hash,
            expected_code_hash,
            "{}: code_hash mismatch at {:?}",
            label,
            addr
        );
        assert_eq!(
            account.storage_root,
            account.storage.root_hash(),
            "{}: storage_root mismatch at {:?}",
            label,
            addr
        );
    }
}

const TEST_FILE_PATH: &str = "tests/data/transType.json";
const TEST_NAME: &str = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";

#[test]
fn test_load_blockchain_tests() {
    let tests = load_blockchain_tests(TEST_FILE_PATH).expect("Failed to load test file");
    assert!(tests.contains_key(TEST_NAME), "Test case not found");
    let test = &tests[TEST_NAME];
    assert_eq!(test.network, "Cancun");
    assert_eq!(test.blocks.len(), 3);
    assert_eq!(test.seal_engine, "NoProof");
}

/// 对每个 block_json：1. decode  2. 与 JSON benchmark 对比  3. encode 与原始 RLP 对比
#[test]
fn test_block_rlp_roundtrip() {
    let tests = load_blockchain_tests(TEST_FILE_PATH).expect("Failed to load test file");

    for (name, test) in &tests {
        for (idx, block_json) in test.blocks.iter().enumerate() {
            let Some(_) = block_json.rlp.as_deref() else { continue };

            assert_block_rlp_roundtrip_and_matches_json(block_json).unwrap_or_else(|e| {
                panic!(
                    "test case '{}' block index {} (number {}): {}",
                    name,
                    idx,
                    block_json.blocknumber,
                    e
                );
            });
        }
    }
}

/// 从 RLP decode 出的每个 transaction 用 get_sender() 恢复 sender，与 JSON 中该 tx 的 sender 字段对比。
#[test]
fn test_transaction_sender_from_rlp() {
    let tests = load_blockchain_tests(TEST_FILE_PATH).expect("Failed to load test file");
    let test = &tests[TEST_NAME];

    for (block_idx, block_json) in test.blocks.iter().enumerate() {
        let rlp_hex = match &block_json.rlp {
            Some(h) => h.as_str(),
            None => continue,
        };
        let block = decode_block_rlp(rlp_hex).expect("decode block from fixture rlp");

        assert_eq!(
            block.transactions.len(),
            block_json.transactions.len(),
            "block {} tx count mismatch",
            block_idx
        );

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let recovered = tx.get_sender().unwrap_or_else(|e| {
                panic!(
                    "block {} tx {} get_sender failed: {:?}",
                    block_idx, tx_idx, e
                );
            });
            let expected = parse_hex_address(&block_json.transactions[tx_idx].sender);
            assert_eq!(
                recovered, expected,
                "block {} tx {} sender mismatch: recovered {:?} != expected {:?}",
                block_idx, tx_idx, recovered, expected
            );
        }
    }
}

#[test]
fn test_trans_type() {
    // start to read test file
    let tests = load_blockchain_tests(TEST_FILE_PATH).expect("Failed to load test file");
    let test = &tests[TEST_NAME];
    let pre_raw: HashMap<String, RawAccount> = test
        .pre
        .iter()
        .map(|(k, v)| (k.clone(), account_state_json_to_raw(v)))
        .collect();
    println!("reading pre state");
    let initial_state = build_world_state_from_test(&pre_raw);
    assert_account_derived_fields_consistent(&initial_state, "initial_state");

    let post_raw: HashMap<String, RawAccount> = test
        .post_state
        .iter()
        .map(|(k, v)| (k.clone(), account_state_json_to_raw(v)))
        .collect();
    println!("reading post state");
    let expected_state = build_world_state_from_test(&post_raw);
    assert_account_derived_fields_consistent(&expected_state, "expected_state");

    let genesis_rlp_hex = test.genesis_rlp.as_str();
    let genesis_block = decode_block_rlp(genesis_rlp_hex).expect("Failed to decode genesis block from RLP");
    let mut blockchain = Blockchain::with_blocks_and_state(vec![genesis_block], initial_state);

    // start to test
    for block_json in &test.blocks {
        let rlp_hex = block_json.rlp.as_deref().unwrap();
        let block = decode_block_rlp(rlp_hex).expect("Failed to decode block from RLP");

        if let Err(e) = blockchain.add_block(block) {
            panic!("Failed to add block {}: {:?}", block_json.blocknumber, e);
        }
    }

    // compare final state
    assert_account_derived_fields_consistent(&blockchain.state, "actual_state");
    common::evaluations::compare_world_states(&expected_state, &blockchain.state)
        .expect("Pre->Post state mismatch");
}
