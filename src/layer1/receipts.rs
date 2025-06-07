use bytes::Bytes;
use ethereum_types::{Address, H256, U256};
use rlp::{DecoderError, Decodable, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use crate::common::trie::{MyTrie, TrieCodec};
pub struct ReceiptTrieCodec;
pub type ReceiptTrie = MyTrie<usize, Receipt, ReceiptTrieCodec>;


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

/* ---------------- Receipt ---------------- */
impl Encodable for Receipt {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);                 // Exclude tx_type in serialization
        s.append(&self.status_code);
        s.append(&self.cumulative_gas_used);
        s.append(&self.logs_bloom.as_ref());

        s.begin_list(self.logs.len());   // logs
        for log in &self.logs {
            s.append(log);
        }
    }
}

impl Decodable for Receipt {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let bloom_bytes: Bytes = rlp.val_at(2)?;
        if bloom_bytes.len() != 256 {
            return Err(DecoderError::Custom("logs bloom length != 256"));
        }
        let mut bloom = [0u8; 256];
        bloom.copy_from_slice(&bloom_bytes);

        Ok(Self {
            tx_type: 0, // filled later in deserialization
            status_code: rlp.val_at(0)?,
            cumulative_gas_used: rlp.val_at(1)?,
            logs_bloom: bloom,
            logs: rlp.list_at(3)?,
        })
    }
}

impl Receipt {
    pub fn serialization(&self) -> Vec<u8> {
        let body = rlp::encode(self);
        if self.tx_type == 0 {
            body.to_vec()
        } else {
            let mut out = Vec::with_capacity(1 + body.len());
            out.push(self.tx_type);
            out.extend_from_slice(&body);
            out
        }
    }

    pub fn deserialization(bytes: &[u8]) -> Result<Self, DecoderError> {
        let (tx_type, payload) = match bytes.first() {
            Some(0x01) | Some(0x02) => (bytes[0], &bytes[1..]),
            _ => (0u8, bytes), // legacy
        };
        let rlp = Rlp::new(payload);
        let mut r: Receipt = rlp.as_val()?;
        r.tx_type = tx_type;
        Ok(r)
    }
}

impl TrieCodec<usize, Receipt> for ReceiptTrieCodec {
    /* ------- key（交易索引） ------- */
    fn encode_key(key: &usize) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.append(&(*key as u64));
        s.out().to_vec()
    }

    fn decode_key(encoded: &[u8]) -> usize {
        Rlp::new(encoded)
            .as_val::<u64>()
            .expect("invalid key rlp") as usize
    }

    /* ------- value（Receipt） ------- */
    fn encode_value(value: &Receipt) -> Vec<u8> {
        value.serialization()
    }

    fn decode_value(encoded: &[u8]) -> Receipt {
        Receipt::deserialization(encoded).expect("invalid value rlp")
    }
}

pub fn hash_receipts(receipts: &[Receipt]) -> H256 {
    let mut trie = ReceiptTrie::new();
    for (i, receipt) in receipts.iter().enumerate() {
        trie.insert(&i, &receipt);
    }
    trie.root_hash()
}

pub fn bloom_filter(logs: &[Log]) -> [u8; 256] {
    let mut bloom = [0u8; 256];

    for log in logs {
        let address_bytes = log.address.as_bytes();
        let iter = std::iter::once(address_bytes).chain(log.topics.iter().map(|t| t.as_bytes()));

        for bytes in iter {
            let hash = Keccak256::digest(bytes);
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
        assert_eq!(serialized, encoded_bytes);
    }
}