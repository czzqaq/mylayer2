use std::collections::HashMap;
use serde::Deserialize;
use layer1::transaction::Transaction1or2;
use layer1::tx_execution::tx_execute;
use serde_json::Value;
use anyhow::Result;

mod common;
use common::parsers::{build_world_state_from_test, build_block_from_env, RawAccount, Env};
use common::evaluations::compare_world_states;

#[derive(Debug, Deserialize)]
struct PostState {
    indexes: PostStateIndexes,
    state: HashMap<String, RawAccount>,
    txbytes: String,
}

#[derive(Debug, Deserialize)]
struct PostStateIndexes {
    data: usize,
}

fn test_tx_execution_against_post_state(raw_json: &Value, case_name: &str) -> Result<()> {
    // 1. 获取 test case
    let test = &raw_json[case_name];

    // 2. 解析字段
    let env: Env = serde_json::from_value(test["env"].clone())?;
    let pre: HashMap<String, RawAccount> = serde_json::from_value(test["pre"].clone())?;

    // 3. 获取执行目标状态（以 Cancun 分叉为例）
    let post_states: Vec<PostState> = serde_json::from_value(test["post"]["Cancun"].clone())?;
    for (i, post_state) in post_states.iter().enumerate() {
        println!("Running post state index: {}", i);

        let _data_index = post_state.indexes.data;
        let tx_hex = post_state.txbytes.strip_prefix("0x").unwrap_or(&post_state.txbytes);
        let tx_bytes = hex::decode(tx_hex)?;
        let tx = Transaction1or2::deserialization(&tx_bytes)
            .map_err(|e| anyhow::anyhow!("decode txbytes failed: {:?}", e))?;

        let mut state = build_world_state_from_test(&pre);
        let mut block = build_block_from_env(&env);

        // 5. 执行交易
        tx_execute(&tx, &mut state, &mut block)?;

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
    test_tx_execution_against_post_state(&json, "add")
}

#[test]
fn test_create_contract_sstore_during_init_json() -> Result<()> {
    let json_str = std::fs::read_to_string("tests/data/CREATE_ContractSSTOREDuringInit.json")?;
    let json: Value = serde_json::from_str(&json_str)?;
    test_tx_execution_against_post_state(
        &json,
        "GeneralStateTests/stCreateTest/CREATE_ContractSSTOREDuringInit.json::CREATE_ContractSSTOREDuringInit-fork_[Cancun-Prague]-d0g0v0",
    )
}