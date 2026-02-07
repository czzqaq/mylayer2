use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// ============================================
// 数据结构定义
// ============================================

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockchainTest {
    #[serde(rename = "_info")]
    pub info: serde_json::Value,
    pub blocks: Vec<Block>,
    pub config: ChainConfig,
    #[serde(rename = "genesisBlockHeader")]
    pub genesis_block_header: BlockHeader,
    #[serde(rename = "genesisRLP")]
    pub genesis_rlp: String,
    pub lastblockhash: String,
    pub network: String,
    #[serde(rename = "postState")]
    pub post_state: HashMap<String, AccountState>,
    pub pre: HashMap<String, AccountState>,
    #[serde(rename = "sealEngine")]
    pub seal_engine: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Block {
    #[serde(rename = "blockHeader")]
    pub block_header: BlockHeader,
    pub blocknumber: String,
    pub chainname: String,
    pub rlp: String,
    pub transactions: Vec<Transaction>,
    #[serde(rename = "uncleHeaders")]
    pub uncle_headers: Vec<BlockHeader>,
    pub withdrawals: Vec<Withdrawal>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockHeader {
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
    #[serde(rename = "parentBeaconBlockRoot")]
    pub parent_beacon_block_root: String,
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    #[serde(rename = "receiptTrie")]
    pub receipt_trie: String,
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    pub timestamp: String,
    #[serde(rename = "transactionsTrie")]
    pub transactions_trie: String,
    #[serde(rename = "uncleHash")]
    pub uncle_hash: String,
    #[serde(rename = "withdrawalsRoot")]
    pub withdrawals_root: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Transaction {
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
    pub access_list: Option<Vec<AccessListEntry>>,
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: Option<String>,
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessListEntry {
    pub address: String,
    #[serde(rename = "storageKeys")]
    pub storage_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Withdrawal {
    // Cancun withdrawals fields if needed
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountState {
    pub balance: String,
    pub code: String,
    pub nonce: String,
    pub storage: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    #[serde(rename = "blobSchedule")]
    pub blob_schedule: Option<HashMap<String, BlobConfig>>,
    pub chainid: String,
    pub network: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobConfig {
    #[serde(rename = "baseFeeUpdateFraction")]
    pub base_fee_update_fraction: String,
    pub max: String,
    pub target: String,
}

// ============================================
// 被测试的接口（伪代码/TODO）
// ============================================

pub mod evm {
    use super::*;

    /// 初始化 EVM 状态
    /// TODO: 实现从 pre state 初始化世界状态
    pub fn init_state(_pre_state: &HashMap<String, AccountState>) -> Result<StateDB, EVMError> {
        todo!("Initialize state from pre state")
    }

    /// 执行区块
    /// TODO: 实现区块执行逻辑
    pub fn execute_block(
        _state: &mut StateDB,
        _block: &Block,
        _config: &ChainConfig,
    ) -> Result<ExecutionResult, EVMError> {
        todo!("Execute block with transactions")
    }

    /// 解码 RLP 编码的区块
    /// TODO: 实现 RLP 解码
    pub fn decode_block_rlp(_rlp: &str) -> Result<Block, EVMError> {
        todo!("Decode RLP encoded block")
    }

    /// 计算状态根
    /// TODO: 实现状态根计算
    pub fn compute_state_root(_state: &StateDB) -> Result<String, EVMError> {
        todo!("Compute state root hash")
    }

    /// 计算交易根
    /// TODO: 实现交易根计算
    pub fn compute_transactions_root(_transactions: &[Transaction]) -> Result<String, EVMError> {
        todo!("Compute transactions trie root")
    }

    /// 计算收据根
    /// TODO: 实现收据根计算
    pub fn compute_receipts_root(_receipts: &[Receipt]) -> Result<String, EVMError> {
        todo!("Compute receipts trie root")
    }

    /// 验证区块头
    /// TODO: 实现区块头验证
    pub fn verify_block_header(
        _header: &BlockHeader,
        _parent_header: Option<&BlockHeader>,
        _config: &ChainConfig,
    ) -> Result<bool, EVMError> {
        todo!("Verify block header")
    }

    /// 获取账户状态
    /// TODO: 实现账户状态获取
    pub fn get_account_state(_state: &StateDB, _address: &str) -> Result<AccountState, EVMError> {
        todo!("Get account state")
    }

    /// 获取所有账户状态（用于后置状态比较）
    /// TODO: 实现获取所有账户状态
    pub fn get_all_account_states(_state: &StateDB) -> Result<HashMap<String, AccountState>, EVMError> {
        todo!("Get all account states")
    }

    // 辅助类型定义
    #[derive(Debug)]
    pub struct StateDB {
        // TODO: 实现状态数据库
    }

    #[derive(Debug)]
    pub struct ExecutionResult {
        pub state_root: String,
        pub receipts_root: String,
        pub gas_used: u64,
        pub logs_bloom: String,
    }

    #[derive(Debug)]
    pub struct Receipt {
        pub status: bool,
        pub cumulative_gas_used: u64,
        pub logs: Vec<Log>,
    }

    #[derive(Debug)]
    pub struct Log {
        pub address: String,
        pub topics: Vec<String>,
        pub data: String,
    }

    #[derive(Debug)]
    pub enum EVMError {
        InvalidRLP(String),
        ExecutionFailed(String),
        InvalidState(String),
        InvalidBlock(String),
    }
}

// ============================================
// 测试辅助函数
// ============================================

fn parse_hex_to_u64(hex_str: &str) -> u64 {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    u64::from_str_radix(hex_str, 16).unwrap_or(0)
}

fn normalize_hex(hex_str: &str) -> String {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    format!("0x{}", hex_str.to_lowercase())
}

fn compare_account_states(
    expected: &HashMap<String, AccountState>,
    actual: &HashMap<String, AccountState>,
) -> Vec<String> {
    let mut errors = Vec::new();

    for (address, expected_state) in expected {
        let normalized_address = normalize_hex(address);
        match actual.get(&normalized_address).or_else(|| actual.get(address)) {
            Some(actual_state) => {
                if normalize_hex(&expected_state.balance) != normalize_hex(&actual_state.balance) {
                    errors.push(format!(
                        "Account {} balance mismatch: expected {}, got {}",
                        address, expected_state.balance, actual_state.balance
                    ));
                }
                if normalize_hex(&expected_state.nonce) != normalize_hex(&actual_state.nonce) {
                    errors.push(format!(
                        "Account {} nonce mismatch: expected {}, got {}",
                        address, expected_state.nonce, actual_state.nonce
                    ));
                }
                if normalize_hex(&expected_state.code) != normalize_hex(&actual_state.code) {
                    errors.push(format!(
                        "Account {} code mismatch: expected {}, got {}",
                        address, expected_state.code, actual_state.code
                    ));
                }
                // 比较 storage
                for (key, expected_value) in &expected_state.storage {
                    match actual_state.storage.get(key) {
                        Some(actual_value) => {
                            if normalize_hex(expected_value) != normalize_hex(actual_value) {
                                errors.push(format!(
                                    "Account {} storage[{}] mismatch: expected {}, got {}",
                                    address, key, expected_value, actual_value
                                ));
                            }
                        }
                        None => {
                            errors.push(format!(
                                "Account {} storage[{}] missing, expected {}",
                                address, key, expected_value
                            ));
                        }
                    }
                }
            }
            None => {
                errors.push(format!("Account {} missing in actual state", address));
            }
        }
    }

    errors
}

fn compare_block_headers(expected: &BlockHeader, actual: &BlockHeader) -> Vec<String> {
    let mut errors = Vec::new();

    macro_rules! compare_field {
        ($field:ident) => {
            if normalize_hex(&expected.$field) != normalize_hex(&actual.$field) {
                errors.push(format!(
                    "Block header {} mismatch: expected {}, got {}",
                    stringify!($field),
                    expected.$field,
                    actual.$field
                ));
            }
        };
    }

    compare_field!(state_root);
    compare_field!(transactions_trie);
    compare_field!(receipt_trie);
    compare_field!(gas_used);
    compare_field!(bloom);
    compare_field!(base_fee_per_gas);

    errors
}

// ============================================
// 测试执行器
// ============================================

pub struct BlockchainTestRunner {
    test_name: String,
    test_data: BlockchainTest,
}

impl BlockchainTestRunner {
    pub fn new(test_name: String, test_data: BlockchainTest) -> Self {
        Self {
            test_name,
            test_data,
        }
    }

    pub fn run(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        println!("Running test: {}", self.test_name);
        println!("Network: {}", self.test_data.network);
        println!("Number of blocks: {}", self.test_data.blocks.len());

        // Step 1: 初始化状态
        let mut state = match evm::init_state(&self.test_data.pre) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("Failed to initialize state: {:?}", e));
                return Err(errors);
            }
        };

        // Step 2: 验证创世区块头
        println!("Verifying genesis block header...");
        if let Err(e) = evm::verify_block_header(
            &self.test_data.genesis_block_header,
            None,
            &self.test_data.config,
        ) {
            errors.push(format!("Genesis block header verification failed: {:?}", e));
        }

        // Step 3: 依次执行每个区块
        let mut parent_header = Some(&self.test_data.genesis_block_header);
        
        for (idx, block) in self.test_data.blocks.iter().enumerate() {
            println!(
                "Executing block {} (number: {})...",
                idx + 1,
                block.blocknumber
            );
            println!("  Transactions: {}", block.transactions.len());

            // 验证区块头
            if let Err(e) = evm::verify_block_header(
                &block.block_header,
                parent_header,
                &self.test_data.config,
            ) {
                errors.push(format!(
                    "Block {} header verification failed: {:?}",
                    block.blocknumber, e
                ));
            }

            // 可选：验证 RLP 解码
            match evm::decode_block_rlp(&block.rlp) {
                Ok(decoded_block) => {
                    // 比较解码后的区块与预期区块
                    if decoded_block.block_header.hash != block.block_header.hash {
                        errors.push(format!(
                            "Block {} RLP decode mismatch: hash differs",
                            block.blocknumber
                        ));
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "Block {} RLP decode failed: {:?}",
                        block.blocknumber, e
                    ));
                }
            }

            // 执行区块
            match evm::execute_block(&mut state, block, &self.test_data.config) {
                Ok(result) => {
                    // 验证执行结果
                    if normalize_hex(&result.state_root) != normalize_hex(&block.block_header.state_root) {
                        errors.push(format!(
                            "Block {} state root mismatch: expected {}, got {}",
                            block.blocknumber, block.block_header.state_root, result.state_root
                        ));
                    }
                    if normalize_hex(&result.receipts_root) != normalize_hex(&block.block_header.receipt_trie) {
                        errors.push(format!(
                            "Block {} receipts root mismatch: expected {}, got {}",
                            block.blocknumber, block.block_header.receipt_trie, result.receipts_root
                        ));
                    }
                    if result.gas_used != parse_hex_to_u64(&block.block_header.gas_used) {
                        errors.push(format!(
                            "Block {} gas used mismatch: expected {}, got {}",
                            block.blocknumber, block.block_header.gas_used, result.gas_used
                        ));
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "Block {} execution failed: {:?}",
                        block.blocknumber, e
                    ));
                }
            }

            parent_header = Some(&block.block_header);
        }

        // Step 4: 验证最终区块哈希
        if let Some(last_block) = self.test_data.blocks.last() {
            if normalize_hex(&last_block.block_header.hash) != normalize_hex(&self.test_data.lastblockhash) {
                errors.push(format!(
                    "Last block hash mismatch: expected {}, got {}",
                    self.test_data.lastblockhash, last_block.block_header.hash
                ));
            }
        }

        // Step 5: 验证后置状态
        println!("Verifying post state...");
        match evm::get_all_account_states(&state) {
            Ok(actual_state) => {
                let state_errors = compare_account_states(&self.test_data.post_state, &actual_state);
                errors.extend(state_errors);
            }
            Err(e) => {
                errors.push(format!("Failed to get final state: {:?}", e));
            }
        }

        if errors.is_empty() {
            println!("Test {} PASSED", self.test_name);
            Ok(())
        } else {
            println!("Test {} FAILED with {} errors", self.test_name, errors.len());
            for error in &errors {
                println!("  - {}", error);
            }
            Err(errors)
        }
    }
}

// ============================================
// 测试加载函数
// ============================================

fn load_blockchain_tests(json_path: &str) -> Result<HashMap<String, BlockchainTest>, String> {
    let content = fs::read_to_string(json_path)
        .map_err(|e| format!("Failed to read file {}: {}", json_path, e))?;

    let tests: HashMap<String, BlockchainTest> = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    Ok(tests)
}

// ============================================
// 单元测试
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE_PATH: &str = "tests/fixtures/transType.json";

    #[test]
    fn test_load_trans_type_cancun() {
        // 加载测试文件
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");

        // 验证测试用例存在
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        assert!(tests.contains_key(test_name), "Test case not found");

        let test = &tests[test_name];
        
        // 验证基本结构
        assert_eq!(test.network, "Cancun");
        assert_eq!(test.blocks.len(), 3);
        assert_eq!(test.seal_engine, "NoProof");
    }

    #[test]
    fn test_genesis_block_header() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 验证创世区块头
        let genesis = &test.genesis_block_header;
        assert_eq!(genesis.number, "0x00");
        assert_eq!(genesis.base_fee_per_gas, "0x03e8");
        assert_eq!(genesis.gas_used, "0x00");
        assert_eq!(
            genesis.hash,
            "0x410e5db3df1973feddf7ccaf2cf268b005417cd48244b4c3416e89e2de77733d"
        );
    }

    #[test]
    fn test_block_transactions() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 验证区块 1 的交易
        let block1 = &test.blocks[0];
        assert_eq!(block1.transactions.len(), 3);

        // Legacy transaction (type 0)
        let tx0 = &block1.transactions[0];
        assert!(tx0.tx_type.is_none());
        assert_eq!(tx0.gas_price, Some("0x03e8".to_string()));

        // EIP-2930 transaction (type 1)
        let tx1 = &block1.transactions[1];
        assert_eq!(tx1.tx_type, Some("0x01".to_string()));
        assert!(tx1.access_list.is_some());

        // EIP-1559 transaction (type 2)
        let tx2 = &block1.transactions[2];
        assert_eq!(tx2.tx_type, Some("0x02".to_string()));
        assert_eq!(tx2.max_fee_per_gas, Some("0x03e8".to_string()));
        assert_eq!(tx2.max_priority_fee_per_gas, Some("0x64".to_string()));
    }

    #[test]
    fn test_pre_state() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 验证预置状态
        assert_eq!(test.pre.len(), 4);

        // 验证 beacon roots 合约
        let beacon_contract = test.pre.get("0x000f3df6d732807ef1319fb7b8bb8522d0beac02")
            .expect("Beacon roots contract not found");
        assert_eq!(beacon_contract.nonce, "0x01");
        assert!(!beacon_contract.code.is_empty());

        // 验证发送者账户
        let sender = test.pre.get("0xd02d72e067e77158444ef2020ff2d325f929b363")
            .expect("Sender account not found");
        assert_eq!(sender.balance, "0x010000000000000000");
        assert_eq!(sender.nonce, "0x01");
    }

    #[test]
    fn test_post_state() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 验证后置状态
        assert_eq!(test.post_state.len(), 5);

        // 验证发送者 nonce 增加
        let sender = test.post_state.get("0xd02d72e067e77158444ef2020ff2d325f929b363")
            .expect("Sender account not found in post state");
        assert_eq!(sender.nonce, "0x08"); // 执行了 7 笔交易后 nonce 从 1 变为 8

        // 验证 coinbase 收到了矿工费
        let coinbase = test.post_state.get("0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba")
            .expect("Coinbase account not found");
        assert_ne!(coinbase.balance, "0x00");
    }

    #[test]
    fn test_access_list_parsing() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 区块 3 包含带有 storage keys 的 access list
        let block3 = &test.blocks[2];
        let tx0 = &block3.transactions[0];
        
        let access_list = tx0.access_list.as_ref().expect("Access list should exist");
        assert_eq!(access_list.len(), 1);
        assert_eq!(
            access_list[0].address,
            "0xcccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(access_list[0].storage_keys.len(), 1);
        assert_eq!(
            access_list[0].storage_keys[0],
            "0x00000000000000000000000000000000000000000000000000000000000060a7"
        );
    }

    #[test]
    fn test_base_fee_changes() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = &tests[test_name];

        // 验证 base fee 随区块变化
        let genesis_base_fee = parse_hex_to_u64(&test.genesis_block_header.base_fee_per_gas);
        let block1_base_fee = parse_hex_to_u64(&test.blocks[0].block_header.base_fee_per_gas);
        let block2_base_fee = parse_hex_to_u64(&test.blocks[1].block_header.base_fee_per_gas);
        let block3_base_fee = parse_hex_to_u64(&test.blocks[2].block_header.base_fee_per_gas);

        // Genesis: 0x03e8 (1000)
        assert_eq!(genesis_base_fee, 1000);
        // Block 1: 0x036b (875) - 下降
        assert_eq!(block1_base_fee, 875);
        // Block 2: 0x02fe (766) - 继续下降
        assert_eq!(block2_base_fee, 766);
        // Block 3: 0x029f (671) - 继续下降
        assert_eq!(block3_base_fee, 671);

        // 验证 base fee 是递减的（因为区块 gas 使用量较低）
        assert!(block1_base_fee < genesis_base_fee);
        assert!(block2_base_fee < block1_base_fee);
        assert!(block3_base_fee < block2_base_fee);
    }

    #[test]
    #[ignore] // 需要实现 EVM 后才能运行
    fn test_run_full_blockchain_test() {
        let tests = load_blockchain_tests(TEST_FILE_PATH)
            .expect("Failed to load test file");
        
        let test_name = "BlockchainTests/ValidBlocks/bcEIP1559/transType.json::transType_Cancun";
        let test = tests[test_name].clone();

        let runner = BlockchainTestRunner::new(test_name.to_string(), test);
        
        match runner.run() {
            Ok(()) => println!("All tests passed!"),
            Err(errors) => {
                panic!("Test failed with errors: {:?}", errors);
            }
        }
    }

    // 辅助测试：验证 hex 解析
    #[test]
    fn test_hex_parsing() {
        assert_eq!(parse_hex_to_u64("0x03e8"), 1000);
        assert_eq!(parse_hex_to_u64("0x00"), 0);
        assert_eq!(parse_hex_to_u64("0xf618"), 62_488);
        assert_eq!(parse_hex_to_u64("0x02540be400"), 10_000_000_000);
    }

    #[test]
    fn test_hex_normalization() {
        assert_eq!(normalize_hex("0x03E8"), "0x03e8");
        assert_eq!(normalize_hex("03e8"), "0x03e8");
        assert_eq!(normalize_hex("0x00"), "0x00");
    }
}

// ============================================
// 主函数（用于直接运行测试）
// ============================================

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let test_file = if args.len() > 1 {
        &args[1]
    } else {
        "tests/fixtures/transType.json"
    };

    println!("Loading blockchain tests from: {}", test_file);
    
    match load_blockchain_tests(test_file) {
        Ok(tests) => {
            println!("Loaded {} test(s)", tests.len());
            
            let mut passed = 0;
            let mut failed = 0;

            for (name, test_data) in tests {
                let runner = BlockchainTestRunner::new(name.clone(), test_data);
                match runner.run() {
                    Ok(()) => passed += 1,
                    Err(_) => failed += 1,
                }
                println!();
            }

            println!("========================================");
            println!("Results: {} passed, {} failed", passed, failed);
            
            if failed > 0 {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}