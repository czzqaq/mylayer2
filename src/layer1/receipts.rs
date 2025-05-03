use ethereum_types::{Address, H256, U256};
use bytes::Bytes;
use rlp::{Encodable, RlpStream};
use sha3::{Digest, Keccak256};
use crate::common::trie::{MockTrie, TrieCodec};

pub struct ReceiptTrieCodec;
pub type ReceiptTrie = MockTrie<usize, Receipt, ReceiptTrieCodec>;


#[derive(Debug, Clone)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub tx_type: u8,              // R_x
    pub status_code: u8,          // R_z
    pub cumulative_gas_used: U256, // R_u
    pub logs_bloom: [u8; 256],    // R_b
    pub logs: Vec<Log>,           // R_l
}

impl Encodable for Log {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.address);

        // topics: list of H256
        s.begin_list(self.topics.len());
        for topic in &self.topics {
            s.append(topic);
        }

        s.append(&self.data);
    }
}

impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4); // Exclude tx_type in serialization
        s.append(&self.status_code);
        s.append(&self.cumulative_gas_used);
        s.append(&self.logs_bloom.as_ref());

        // logs
        s.begin_list(self.logs.len());
        for log in &self.logs {
            s.append(log);
        }
    }
}


impl TrieCodec<usize, Receipt> for ReceiptTrieCodec {
    fn encode_pair(key: &usize, value: &Receipt) -> (Vec<u8>, Vec<u8>) {
        // key
        let mut key_stream = RlpStream::new();
        key_stream.append(&(*key as u64));
        let key_bytes = key_stream.out().to_vec();

        //value
        let mut value_bytes = Vec::new();
        let encoded_body = rlp::encode(value);
        if value.tx_type == 0 {
            value_bytes = encoded_body.to_vec();
        } else { // Rx · RLP(L(R))
            value_bytes.push(value.tx_type);
            value_bytes.extend_from_slice(&encoded_body);
        }

        (key_bytes, value_bytes)
    }
}

pub fn hash_receipts(receipts: &[Receipt]) -> H256 {
    let mut trie = ReceiptTrie::new(ReceiptTrieCodec);
    for (i, receipt) in receipts.iter().enumerate() {
        trie.insert(i, receipt.clone());
    }

    trie.root_hash()
}

pub fn bloom_filter(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];

    for log in logs.iter() {
        let address_bytes: &[u8] = log.address.as_bytes();
        let topic_bytes_iter = log.topics.iter().map(|t| t.as_bytes());

        for item in std::iter::once(address_bytes).chain(topic_bytes_iter) {
            let hash = Keccak256::digest(item).to_vec();

            for i in [0, 2, 4] {
                let bit_index = ((hash[i] as usize) << 8 | (hash[i + 1] as usize)) % 2048;
                let byte_index = 255 - (bit_index / 8); // `255 -`` : Bloom is big-endian, so 255 is the first byte 
                let bit_in_byte = bit_index % 8;
                bloom[byte_index] |= 1 << bit_in_byte;
            }
        }
    }

    bloom
}

pub fn merge_bloom(receipts: &[Receipt]) -> [u8; 256] {
    let mut merged = [0u8; 256];

    for receipt in receipts {
        for i in 0..256 {
            merged[i] |= receipt.logs_bloom[i];
        }
    }

    merged
}

impl Receipt {
    pub fn new(
        tx_type: u8,
        status_code: u8,
        cumulative_gas_used: U256,
        logs: Vec<Log>,
    ) -> Self {
        let logs_bloom = bloom_filter(&logs);
        Self {
            tx_type,
            status_code,
            cumulative_gas_used,
            logs_bloom,
            logs,
        }
    }
}