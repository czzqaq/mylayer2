

use ethereum_types::{Address, H256, U256};
use bytes::Bytes;
use crate::common::crypto::{recover_address_from_signature};
use anyhow::Result;
use rlp::{Encodable, RlpStream};
use sha3::{Digest, Keccak256};

/// 访问列表项
#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

/// EIP-4844 Blob-carrying Transaction
#[derive(Debug, Clone)]
pub struct BlobTransaction {
    pub tx_type: u8,
    pub nonce: U256,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub r: H256,
    pub s: H256,

    pub data: Bytes,

    pub v: u8, // used as parity
    pub chain_id: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub access_list: Vec<AccessListItem>,
    
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<H256>, // VersionedHash = H256
}



impl BlobTransaction {
    pub fn get_sender(&self) -> Result<Address> {
        recover_address_from_signature(
            self.get_message_hash(),
            self.r,
            self.s,
            self.v,
        )
    }

    pub fn get_message_hash(&self) -> H256 {
        let mut stream = RlpStream::new_list(11);
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);
        stream.begin_list(self.access_list.len());
        for item in &self.access_list {
            stream.append(item);
        }
        stream.append(&self.max_fee_per_blob_gas);
        stream.begin_list(self.blob_versioned_hashes.len());
        for hash in &self.blob_versioned_hashes {
            stream.append(hash);
        }

        let rlp_encoded = stream.out();

        // Add transaction type prefix (0x03)
        let mut payload = vec![self.tx_type];
        payload.extend_from_slice(&rlp_encoded);

        let hash = Keccak256::digest(&payload);
        H256::from_slice(&hash) 
    }

    pub fn is_creation(&self) -> bool {
        self.to.is_none()
    }

    pub fn effective_gas_price(&self, base_fee:U256) -> U256 {
        // For EIP-1559 transactions
        std::cmp::min(
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas + base_fee,
        )
    }

    pub fn cost_cap_on_blob(&self) -> U256 {
        // Add the cost of the blob data, EIP-4844
        let gas_per_blob:U256 = U256::from(1 << 17);

        gas_per_blob * U256::from(self.blob_versioned_hashes.len())
    }
}

impl Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2); // AccessListItem is a 2-item list: [address, storage_keys]
        s.append(&self.address);

        // storage_keys is a list of H256
        s.begin_list(self.storage_keys.len());
        for key in &self.storage_keys {
            s.append(key);
        }
    }
}