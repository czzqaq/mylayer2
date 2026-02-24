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
    /// Type 1/2 必填；Legacy 上无此字段，为 None（或由 v 推导出 EIP-155 时为 Some）
    pub chain_id: Option<u64>,
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

    /// 用于验签/恢复发送者。Type 0 不能直接用 serialization()：签名的消息不含 v,r,s，为 RLP(6 项) 或 EIP-155 的 RLP(9 项)。
    pub fn get_message_hash(&self) -> H256 {
        let payload: Vec<u8> = if self.tx_type == 0 {
            // Legacy: 签名的消息不含 v,r,s。EIP-155 为 [..., chainId, 0, 0]，否则为 [...,] 共 6 项
            let mut s = RlpStream::new();
            let use_eip155 = self.chain_id.map_or(false, |c| c != 0);
            if use_eip155 {
                s.begin_list(9);
            } else {
                s.begin_list(6);
            }
            s.append(&self.nonce);
            match &self.gas_price_or_dynamic_fee {
                Either::Left(gp) => s.append(gp),
                Either::Right(_) => panic!("Type 0 must use gas_price"),
            };
            s.append(&self.gas_limit);
            if let Some(to) = &self.to {
                s.append(to);
            } else {
                s.append(&Bytes::new());
            }
            s.append(&self.value);
            s.append(&self.data);
            if use_eip155 {
                s.append(&self.chain_id.unwrap());
                s.append(&0u8);
                s.append(&0u8);
            }
            s.out().to_vec()
        } else {
            self.serialization()
        };
        H256::from_slice(&Keccak256::digest(&payload))
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

    // Type 0 (legacy): RLP([...]) 无类型前缀；Type 1/2: tx_type || RLP(...)
    pub fn serialization(&self) -> Vec<u8> {
        // Returns the RLP-encoded transaction item that can be directly placed in block.transactions list
        match self.tx_type {
            0 => {
                // legacy：本身就是 RLP list item [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
                let mut stream = RlpStream::new();
                stream.begin_list(9);
                stream.append(&self.nonce);
                match &self.gas_price_or_dynamic_fee {
                    Either::Left(gp) => stream.append(gp),
                    _ => panic!("Legacy transaction must use gas_price"),
                };
                stream.append(&self.gas_limit);
                if let Some(to) = &self.to {
                    stream.append(to);
                } else {
                    stream.append(&Bytes::new());
                }
                stream.append(&self.value);
                stream.append(&self.data);
                // v = 35 + 2*chain_id + recid (EIP-155) or v = 27 + recid (pre-EIP-155)
                let v = Self::chain_id_and_recid_to_legacy_v(self.chain_id, self.v);
                stream.append(&v);
                stream.append(&self.r);
                stream.append(&self.s);
                stream.out().to_vec()
            }
            0x01 | 0x02 => {
                // typed：block 里元素是 RLP string，其内容是 type_byte || RLP(payload)
                let envelope = self.encode_typed_envelope(); // 02 f8...
                rlp::encode(&envelope).to_vec()              // b8.. 02 f8...
            }
            _ => panic!("unsupported tx type"),
        }
    }

    /// 从 legacy 交易的 v 值解析出 chain_id 和 recovery id (EIP-155: v = 35 + 2*chain_id + recid; 否则 v = 27+recid)
    fn legacy_v_to_chain_id_and_recid(v: u64) -> (u64, u8) {
        if v >= 35 {
            let recid = ((v - 35) % 2) as u8;
            let chain_id = (v - 35) / 2;
            (chain_id, recid)
        } else {
            let recid = (v - 27) as u8; // 27 -> 0, 28 -> 1
            (0, recid)
        }
    }

    /// 将 chain_id 和 recovery id 编码为 legacy 的 v 值
    fn chain_id_and_recid_to_legacy_v(chain_id: Option<u64>, recid: u8) -> u64 {
        match chain_id {
            None | Some(0) => 27 + u64::from(recid),
            Some(id) => 35 + 2 * id + u64::from(recid),
        }
    }

    pub fn deserialization(bytes: &[u8]) -> Result<Self, DecoderError> {
        if bytes.is_empty() {
            return Err(DecoderError::Custom("Empty transaction bytes"));
        }
        let first = bytes[0];
        let (tx_type, payload): (u8, &[u8]) = if first == 0x01 && bytes.len() > 1 {
            (0x01, &bytes[1..])
        } else if first == 0x02 && bytes.len() > 1 {
            (0x02, &bytes[1..])
        } else {
            // Legacy (type 0): 整个 bytes 为 RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
            let rlp = Rlp::new(bytes);
            if !rlp.is_list() || rlp.item_count()? != 9 {
                return Err(DecoderError::Custom("Legacy transaction must be RLP list of 9 elements"));
            }
            let v_raw: u64 = rlp.val_at(6)?;
            let (chain_id_val, recid) = Self::legacy_v_to_chain_id_and_recid(v_raw);
            let chain_id = if v_raw >= 35 {
                Some(chain_id_val)
            } else {
                None
            };
            let tx = Transaction1or2 {
                tx_type: 0,
                chain_id,
                nonce: rlp.val_at(0)?,
                gas_price_or_dynamic_fee: Either::Left(rlp.val_at(1)?),
                gas_limit: rlp.val_at(2)?,
                to: decode_to(&rlp, 3)?,
                value: rlp.val_at(4)?,
                data: rlp.val_at(5)?,
                access_list: vec![],
                v: recid,
                r: rlp.val_at(7)?,
                s: rlp.val_at(8)?,
            };
            return Ok(tx);
        };

        let rlp = Rlp::new(payload);

        let tx = match tx_type {
            0x01 => {
                // EIP-2930 Type 1: 11 fields [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
                if !rlp.is_list() || rlp.item_count()? != 11 {
                    return Err(DecoderError::RlpIncorrectListLen);
                }
                Transaction1or2 {
                    tx_type: 0x01,
                    chain_id: Some(rlp.val_at(0)?),
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
                    chain_id: Some(rlp.val_at(0)?),
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
            _ => return Err(DecoderError::Custom("Unsupported transaction type")),
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

impl Transaction1or2 {
    /// 仅返回 EIP-2718 envelope：type_byte || RLP(payload)
    fn encode_typed_envelope(&self) -> Vec<u8> {
        let mut body_stream = RlpStream::new();
        match self.tx_type {
            0x01 => {
                body_stream.begin_list(11);
                body_stream.append(&self.chain_id.expect("type 1 must have chain_id"));
                body_stream.append(&self.nonce);
                match &self.gas_price_or_dynamic_fee {
                    either::Either::Left(gp) => body_stream.append(gp),
                    _ => panic!("type 1 must use gas_price"),
                };
                body_stream.append(&self.gas_limit);
                if let Some(to) = &self.to { body_stream.append(to); } else { body_stream.append(&bytes::Bytes::new()); }
                body_stream.append(&self.value);
                body_stream.append(&self.data);
                body_stream.append_list(&self.access_list);
                body_stream.append(&self.v);
                body_stream.append(&self.r);
                body_stream.append(&self.s);
            }
            0x02 => {
                body_stream.begin_list(12);
                body_stream.append(&self.chain_id.expect("type 2 must have chain_id"));
                body_stream.append(&self.nonce);
                match &self.gas_price_or_dynamic_fee {
                    either::Either::Right((tip, fee)) => { body_stream.append(tip); body_stream.append(fee); }
                    _ => panic!("type 2 must use dynamic fee"),
                };
                body_stream.append(&self.gas_limit);
                if let Some(to) = &self.to { body_stream.append(to); } else { body_stream.append(&bytes::Bytes::new()); }
                body_stream.append(&self.value);
                body_stream.append(&self.data);
                body_stream.append_list(&self.access_list);
                body_stream.append(&self.v);
                body_stream.append(&self.r);
                body_stream.append(&self.s);
            }
            _ => unreachable!(),
        }

        let body = body_stream.out().to_vec();
        let mut envelope = Vec::with_capacity(1 + body.len());
        envelope.push(self.tx_type);
        envelope.extend_from_slice(&body);
        envelope
    }
}

impl Decodable for Transaction1or2 {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // Handle EIP-2718 typed transactions: Type 1/2 are byte sequences [type_byte, RLP(...)]
        // Type 0 (Legacy) is a direct RLP list
        if rlp.is_list() {
            // Legacy transaction: decode as RLP list
            let count = rlp.item_count()?;
            let tx_type = match count {
                9 => 0,   // Legacy
                11 => 0x01,
                12 => 0x02,
                _ => return Err(DecoderError::Custom("Transaction list must have 9 (legacy), 11 (type 1), or 12 (type 2) elements")),
            };
            let payload = rlp.as_raw();
            if tx_type == 0 {
                Self::deserialization(payload)
            } else {
                let mut bytes = vec![tx_type];
                bytes.extend_from_slice(payload);
                Self::deserialization(&bytes)
            }
        } else {
            // Type 1/2 transaction: byte sequence with type prefix
            let data: Bytes = rlp.as_val()?;
            Self::deserialization(&data)
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
                chain_id: Some(h.chain_id),
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