use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Decodable, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use crate::common::trie::{MyTrie, TrieCodec};
pub struct ReceiptTrieCodec;
pub type ReceiptTrie = MyTrie<usize, Receipt, ReceiptTrieCodec>;

#[derive(Debug, Clone, PartialEq)]
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
        s.begin_list(self.topics.len());
        for topic in &self.topics {
            s.append(topic);
        }
        s.append(&self.data);
    }
}

impl Decodable for Log {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 3 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(Self {
            address: rlp.val_at(0)?,
            topics: rlp.list_at(1)?,
            data: rlp.val_at(2)?,
        })
    }
}

/* ---------------- Receipt Implementation ---------------- */

// Encodable 只负责编码 RLP 内容部分 (Payload)
impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.status_code);
        s.append(&self.cumulative_gas_used);
        s.append(&self.logs_bloom.as_ref());
        s.begin_list(self.logs.len());
        for log in &self.logs {
            s.append(log);
        }
    }
}

// 修改 2: Decodable 只负责解码 RLP 内容部分
impl Decodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        
        let bloom_bytes: Bytes = rlp.val_at(2)?;
        let mut bloom = [0u8; 256];
        if bloom_bytes.len() == 256 {
            bloom.copy_from_slice(&bloom_bytes);
        } else {
             return Err(DecoderError::Custom("Invalid bloom length"));
        }

        Ok(Self {
            tx_type: 0, // 默认值，外部调用者需要根据前缀修正它
            status_code: rlp.val_at(0)?,
            cumulative_gas_used: rlp.val_at(1)?,
            logs_bloom: bloom,
            logs: rlp.list_at(3)?,
        })
    }
}

impl Receipt {
    pub fn serialization(&self) -> Vec<u8> {
        let payload = rlp::encode(self); // 调用上面的 Encodable，得到 RLP List
        if self.tx_type == 0 {
            // Legacy: 直接是 RLP List
            payload.to_vec()
        } else {
            // Typed: TypeByte + RLP List
            let mut buf = Vec::with_capacity(payload.len() + 1);
            buf.push(self.tx_type);
            buf.extend_from_slice(&payload);
            buf
        }
    }

    pub fn deserialization(bytes: &[u8]) -> Result<Self, DecoderError> {
        if bytes.is_empty() {
            return Err(DecoderError::RlpIsTooShort);
        }

        // EIP-2718: 
        // Legacy 交易的 RLP List 第一个字节必然 >= 0xc0
        // Typed 交易的第一个字节是 Type (0x00 ~ 0x7f)
        let first = bytes[0];
        
        let (tx_type, rlp_bytes) = if first <= 0x7f {
            // Typed Receipt
            (first, &bytes[1..])
        } else {
            // Legacy Receipt
            (0, bytes)
        };

        let rlp = Rlp::new(rlp_bytes);
        let mut receipt: Receipt = rlp.as_val()?; // 调用上面的 Decodable
        receipt.tx_type = tx_type; // 修正类型
        Ok(receipt)
    }
}

impl TrieCodec<usize, Receipt> for ReceiptTrieCodec {
    fn encode_key(key: &usize) -> Vec<u8> {
        rlp::encode(key).to_vec()
    }

    fn decode_key(encoded: &[u8]) -> usize {
        rlp::decode(encoded).expect("invalid key rlp")
    }

    fn encode_value(value: &Receipt) -> Vec<u8> {
        value.serialization()
    }

    fn decode_value(encoded: &[u8]) -> Receipt {
        Receipt::deserialization(encoded).expect("invalid value rlp")
    }
}

/* ---------------- Helper Functions ---------------- */

pub fn hash_receipts(receipts: &[Receipt]) -> H256 {
    let mut trie = ReceiptTrie::new();
    for (i, receipt) in receipts.iter().enumerate() {
        trie.insert(&i, &receipt);
    }
    trie.root_hash()
}

pub fn bloom_logs(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];
    for log in logs {
        let address_bytes = log.address.as_bytes();
        // Address hash
        bloom_add(&mut bloom, address_bytes);
        // Topics hash
        for topic in &log.topics {
            bloom_add(&mut bloom, topic.as_bytes());
        }
    }
    bloom
}

fn bloom_add(bloom: &mut [u8; 256], data: &[u8]) {
    let hash = Keccak256::digest(data);
    // 取哈希的前6个字节（3对）来设置3个位
    // 规范: The first 3 pairs of bytes of the Keccak-256 hash
    for i in 0..3 {
        let start = i * 2;
        // big-endian u16
        let bit_index = ((hash[start] as usize) << 8 | (hash[start + 1] as usize)) & 0x07ff; // % 2048
        
        // Ethereum Bloom Filter bit mapping:
        // byte_index = 255 - (bit_index / 8)
        // bit_offset = bit_index % 8
        let byte_index = 255 - (bit_index / 8);
        let bit_in_byte = bit_index % 8;
        
        bloom[byte_index] |= 1 << bit_in_byte;
    }
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
        let logs_bloom = bloom_logs(&logs);
        Self {
            tx_type,
            status_code,
            cumulative_gas_used,
            logs_bloom,
            logs,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_serialization() {
        const ENCODED:&str = "01f901650101b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002f85ef85c942d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2df842a00000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000004829999";
        let encoded_bytes = hex::decode(ENCODED).expect("Failed to decode hex string");
        let receipt = Receipt::deserialization(&encoded_bytes).expect("Failed to deserialize receipt");
        
        assert_eq!(receipt.tx_type, 0x01);
        assert_eq!(receipt.status_code, 1);
        assert_eq!(receipt.cumulative_gas_used, U256::from(0x1));
        
        let mut benchmark_bloom = [0u8; 256];
        benchmark_bloom[255] = 0x02; 
        assert_eq!(receipt.logs_bloom, benchmark_bloom);
        
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].address, Address::from([0x2d; 20]));
        assert_eq!(receipt.logs[0].topics, vec![H256::from_low_u64_be(3), H256::from_low_u64_be(4)]);
        assert_eq!(receipt.logs[0].data, Bytes::from(vec![0x99, 0x99]));

        let serialized = receipt.serialization();
        assert_eq!(hex::encode(&serialized), ENCODED);
    }
}