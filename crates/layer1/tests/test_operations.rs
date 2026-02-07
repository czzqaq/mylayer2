use std::collections::HashMap;
use ethereum_types::{Address, U256, H256};
use serde::Deserialize;
use hex::FromHex;
use sha3::{Digest, Keccak256};
use k256::ecdsa::SigningKey;

use layer1::world_state::{AccountState, WorldStateTrie, StorageTrie};
use layer1::transaction::Transaction1or2;
use layer1::block::{Block, BlockHeader};
use layer1::vm::tx_execute;
use serde_json::Value;
use anyhow::Result;

mod common;
use common::parsers::{build_world_state_from_test, build_block_from_env, build_blob_transactions_from_json, RawAccount, RawTxJson, Env};
use common::evaluations::compare_world_states;

#[derive(Debug, Deserialize)]
struct PostState {
    indexes: PostStateIndexes,
    state: HashMap<String, RawAccount>,
}

#[derive(Debug, Deserialize)]
struct PostStateIndexes {
    data: usize,
}

fn test_tx_execution_against_post_state(raw_json: &Value) -> Result<()> {
    // 1. 获取 test case
    let test = &raw_json["add"];

    // 2. 解析字段
    let env: Env = serde_json::from_value(test["env"].clone())?;
    let pre: HashMap<String, RawAccount> = serde_json::from_value(test["pre"].clone())?;
    let tx_data: RawTxJson = serde_json::from_value(test["transaction"].clone())?;

    // 3. 获取执行目标状态（以 Cancun 分叉为例）
    let post_states: Vec<PostState> = serde_json::from_value(test["post"]["Cancun"].clone())?;
    for (i, post_state) in post_states.iter().enumerate() {
        println!("Running post state index: {}", i);

        // 4. 构建交易、状态、区块
        let txs = build_blob_transactions_from_json(&tx_data, 1); // chain_id = 1
        let tx = &txs[post_state.indexes.data];

        let mut state = build_world_state_from_test(&pre);
        let mut block = build_block_from_env(&env);

        // 5. 执行交易
        tx_execute(tx, &mut state, &mut block)?;

        // 6. 构建预期状态
        let expected_state = build_world_state_from_test(&post_state.state);

        // 7. 比较状态树
        compare_world_states(&expected_state, &state)?;
    }

    Ok(())
}

#[test]
fn test_add_json() -> Result<()> {
    let json_str = std::fs::read_to_string("tests/data/add.json")?;
    let json: Value = serde_json::from_str(&json_str)?;
    test_tx_execution_against_post_state(&json)
}