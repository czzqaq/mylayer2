

use ethereum_types::{Address, H256, U256};
use bytes::Bytes;


/// 访问列表项
#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

/// EIP-4844 Blob-carrying Transaction
#[derive(Debug, Clone)]
pub struct BlobTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListItem>,
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<H256>, // VersionedHash = H256
    pub signature: Signature,
}

/// 签名结构
#[derive(Debug, Clone)]
pub struct Signature {
    pub v: u8,
    pub r: H256,
    pub s: H256,
}

/* -------------------------------------------------------------------------- */
/*                                traffic sign                                */
/* -------------------------------------------------------------------------- */



