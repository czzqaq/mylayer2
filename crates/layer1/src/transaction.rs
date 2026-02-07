use ethereum_types::{Address, H256, U256};
use bytes::Bytes;
use anyhow::Result;
use sha3::{Digest, Keccak256};
use rlp::{Encodable, RlpStream, Rlp, Decodable, DecoderError};
use crate::common::trie::{MyTrie, TrieCodec};
use crate::common::crypto::{recover_address_from_signature};
use either::Either;

fn decode_to(rlp: &Rlp, idx: usize) -> Result<Option<Address>, DecoderError> {
    let bytes: Bytes = rlp.val_at(idx)?;
    if bytes.is_empty() {
        Ok(None)
    } else if bytes.len() == 20 {
        Ok(Some(Address::from_slice(&bytes)))
    } else {
        Err(DecoderError::Custom("Invalid 'to' length"))
    }
}

#[derive(Debug, Clone,  PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction1or2 {
    pub tx_type: u8,
    pub nonce: u64,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub r: U256,
    pub s: U256,

    pub data: Bytes,

    pub v: u8, // used as parity
    pub chain_id: u64,
    pub gas_price_or_dynamic_fee: Either<U256, (U256, U256)>, // For backward compatibility, this can be either gas_price or (max_priority_fee_per_gas, max_fee_per_gas)
    // pub max_priority_fee_per_gas: U256,
    // pub max_fee_per_gas: U256,
    pub access_list: Vec<AccessListItem>,
}

pub struct TransactionTrieCodec;
pub type TransactionTrie = MyTrie<usize, Transaction1or2, TransactionTrieCodec>;

impl TrieCodec<usize, Transaction1or2> for TransactionTrieCodec {
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

    fn encode_value(value: &Transaction1or2) -> Vec<u8> {
        value.serialization()
    }

    fn decode_value(_encoded: &[u8]) -> Transaction1or2 {
        Transaction1or2::deserialization(_encoded)
            .expect("invalid value rlp")
    }
}

pub fn hash_transactions(transactions: &[Transaction1or2]) -> H256 {
    let mut trie = TransactionTrie::new();
    for (i, tx) in transactions.iter().enumerate() {
        trie.insert(&i, tx);
    }

    trie.root_hash()
}

impl Transaction1or2 {
    pub fn get_sender(&self) -> Result<Address> {
        recover_address_from_signature(
            self.get_message_hash(),
            self.r,
            self.s,
            self.v,
        )
    }

    pub fn get_message_hash(&self) -> H256 {
        let payload = self.serialization();
        
        let hash = Keccak256::digest(&payload);
        H256::from_slice(&hash) 
    }

    pub fn is_creation(&self) -> bool {
        self.to.is_none()
    }

    pub fn effective_gas_price(&self, base_fee:U256) -> U256 {
        let (max_priority_fee_per_gas, max_fee_per_gas) = match &self.gas_price_or_dynamic_fee {
            Either::Left(gas_price) => (*gas_price, *gas_price),
            Either::Right((max_priority_fee, max_fee)) => (*max_priority_fee, *max_fee),
        };
        std::cmp::min(
            max_priority_fee_per_gas + base_fee,
            max_fee_per_gas,
        )
    }

    // Tx·RLP(L(T)), where L(T) is(according to EIP-4844)
    pub fn serialization(&self) -> Vec<u8> {
        let payload = rlp::encode(self);

        let mut out = vec![self.tx_type];
        out.extend_from_slice(&payload);
        out
    }

    pub fn deserialization(bytes: &[u8]) -> Result<Self, DecoderError> {
        let tx_type = bytes[0];
        let payload = &bytes[1..];
        let rlp = Rlp::new(payload);

        let tx = match tx_type {
            0x01 => {
                // EIP-2930 Type 1: 11 fields [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
                if !rlp.is_list() || rlp.item_count()? != 11 {
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Transaction1or2 {
                    tx_type: 0x01,
                    chain_id: rlp.val_at(0)?,
                    nonce: rlp.val_at(1)?,
                    gas_price_or_dynamic_fee: Either::Left(rlp.val_at(2)?),
                    gas_limit: rlp.val_at(3)?,
                    to: decode_to(&rlp, 4)?,
                    value: rlp.val_at(5)?,
                    data: rlp.val_at(6)?,
                    access_list: rlp.list_at(7)?,
                    v: rlp.val_at(8)?,
                    r: rlp.val_at(9)?,
                    s: rlp.val_at(10)?,
                }
            }
            0x02 => {
                // EIP-1559 Type 2: 12 fields [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]
                if !rlp.is_list() || rlp.item_count()? != 12 {
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Transaction1or2 {
                    tx_type: 0x02,
                    chain_id: rlp.val_at(0)?,
                    nonce: rlp.val_at(1)?,
                    gas_price_or_dynamic_fee: Either::Right((rlp.val_at(2)?, rlp.val_at(3)?)),
                    gas_limit: rlp.val_at(4)?,
                    to: decode_to(&rlp, 5)?,
                    value: rlp.val_at(6)?,
                    data: rlp.val_at(7)?,
                    access_list: rlp.list_at(8)?,
                    v: rlp.val_at(9)?,
                    r: rlp.val_at(10)?,
                    s: rlp.val_at(11)?,
                }
            }
            _ => return Err(DecoderError::Custom("Unsupported transaction type, only type 1 and 2 are supported")),
        };

        Ok(tx)
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

impl Decodable for AccessListItem {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let address: Address = rlp.val_at(0)?;
        let storage_keys: Vec<H256> = rlp.list_at(1)?;

        Ok(AccessListItem {
            address,
            storage_keys,
        })
    }
}

impl Encodable for Transaction1or2 {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.tx_type {
            0x01 => {
                // EIP-2930 Type 1: 11 fields
                s.begin_list(11);
                s.append(&self.chain_id);
                s.append(&self.nonce);
                match &self.gas_price_or_dynamic_fee {
                    Either::Left(gas_price) => { s.append(gas_price); }
                    Either::Right(_) => panic!("Type 1 transaction must use gas_price"),
                }
                s.append(&self.gas_limit);
                if let Some(to) = &self.to {
                    s.append(to);
                } else {
                    s.append(&Bytes::new());
                }
                s.append(&self.value);
                s.append(&self.data);
                s.begin_list(self.access_list.len());
                for a in &self.access_list {
                    s.append(a);
                }
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            0x02 => {
                // EIP-1559 Type 2: 12 fields
                s.begin_list(12);
                s.append(&self.chain_id);
                s.append(&self.nonce);
                match &self.gas_price_or_dynamic_fee {
                    Either::Left(_) => panic!("Type 2 transaction must use dynamic fee"),
                    Either::Right((max_priority_fee, max_fee)) => {
                        s.append(max_priority_fee);
                        s.append(max_fee);
                    }
                }
                s.append(&self.gas_limit);
                if let Some(to) = &self.to {
                    s.append(to);
                } else {
                    s.append(&Bytes::new());
                }
                s.append(&self.value);
                s.append(&self.data);
                s.begin_list(self.access_list.len());
                for a in &self.access_list {
                    s.append(a);
                }
                s.append(&self.v);
                s.append(&self.r);
                s.append(&self.s);
            }
            _ => panic!("Unsupported transaction type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize};
    use crate::common::serde_helper as sh;
    use std::fs;
    use serde_json::Value;

    #[derive(Deserialize,Clone)]
    struct AccessListItemHelper {
        #[serde(deserialize_with = "sh::de_addr")]
        address: Address,
        #[serde(rename = "storageKeys", deserialize_with = "sh::de_vec_h256")]
        storage_keys: Vec<H256>,
        // #[serde(skip)]
        // _phantom: std::marker::PhantomData<&'a ()>,
    }

    impl From<AccessListItemHelper> for AccessListItem {
        fn from(h: AccessListItemHelper) -> Self {
            Self { address: h.address, storage_keys: h.storage_keys }
        }
    }

    #[derive(Deserialize)]
    struct TxHelper<'a> {
        #[serde(rename = "maxPriorityFeePerGas", default)]
        max_priority_fee_per_gas: Option<u64>,
        #[serde(rename = "maxFeePerGas", default)]
        max_fee_per_gas: Option<u64>,
        #[serde(rename = "gasPrice",    default)]
        gas_price: Option<u64>, // For backward compatibility

        #[serde(rename = "chainId")]
        chain_id: u64,
        nonce: u64,

        #[serde(rename = "gasLimit")]
        gas_limit: u64,
        #[serde(deserialize_with = "sh::de_addr")]
        to: Address,
        #[serde(deserialize_with = "sh::de_u256")]
        value: U256,
        #[serde(deserialize_with = "sh::de_bytes")]
        data: Bytes,
        #[serde(rename = "accessList", default)]
        access_list: Vec<AccessListItemHelper>,
        v: u8,
        #[serde(deserialize_with = "sh::de_u256")]
        r: U256,
        #[serde(deserialize_with = "sh::de_u256")]
        s: U256,
        #[serde(skip)]
        _phantom: std::marker::PhantomData<&'a ()>,
    }

    impl<'de> serde::Deserialize<'de> for Transaction1or2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
        {
            let h = TxHelper::deserialize(deserializer)?;
            // Type 1: gasPrice present, Type 2: maxPriorityFeePerGas + maxFeePerGas
            let (tx_type, gas_price_or_dynamic_fee) = if h.max_priority_fee_per_gas.is_some() || h.max_fee_per_gas.is_some() {
                let max_priority_fee_per_gas = h.max_priority_fee_per_gas
                    .map(U256::from)
                    .unwrap_or_else(|| U256::from(0));
                let max_fee_per_gas = h.max_fee_per_gas
                    .map(U256::from)
                    .unwrap_or_else(|| U256::from(0));
                (0x02u8, Either::Right((max_priority_fee_per_gas, max_fee_per_gas)))
            } else {
                let gas_price = h.gas_price
                    .map(U256::from)
                    .unwrap_or_else(|| U256::from(0));
                (0x01u8, Either::Left(gas_price))
            };

            Ok(Transaction1or2 {
                tx_type,
                chain_id: h.chain_id,
                nonce: h.nonce,
                gas_price_or_dynamic_fee,
                gas_limit: h.gas_limit,
                to: Some(h.to),
                value: h.value,
                data: h.data,
                access_list: h.access_list.into_iter().map(|a| a.into()).collect(),
                v: h.v,
                r: h.r,
                s: h.s,
            })
        }
    }

    fn get_tx_serialization(json_str: &String) -> Vec<u8> {
        // 读取 JSON 文件内容   
        let v: Value = serde_json::from_str(json_str)
            .expect("Failed to parse JSON");

        let txbytes_hex = v.as_object().unwrap().get("signed").unwrap().as_str().unwrap();
        let txbytes = hex::decode(txbytes_hex.trim_start_matches("0x")).unwrap();

        txbytes
    }

    fn get_tx(file_content: &String) -> Transaction1or2 {
        // 读取 JSON 文件内容   
        let json_value: Value = serde_json::from_str(&file_content).expect("Failed to parse JSON");

        let transaction_value = json_value.get("transaction").unwrap();
        let transaction_json = transaction_value.to_string();
        println!("Transaction JSON: {}", transaction_json);

        let transaction: Transaction1or2 = serde_json::from_str(&transaction_json)
            .expect("Failed to deserialize transaction");
        transaction
    }


    #[test]
    fn test_transaction_serialization_type1() {
        let src_file = "test_data/accessListAddress.json";
        let json_str = fs::read_to_string(src_file)
            .expect("Failed to read JSON file");
        let benchmark = get_tx(&json_str);

        let encoding = get_tx_serialization(&json_str);
        println!("encoding is: {:?}", encoding);
        let deserialized: Transaction1or2 = Transaction1or2::deserialization(&encoding).expect("Failed to deserialize transaction");

        assert_eq!(benchmark, deserialized, "Deserialized transaction does not match the original");

        let encoding_test = deserialized.serialization();
        assert_eq!(encoding, encoding_test, "Serialization does not match the original encoding");
    }
}