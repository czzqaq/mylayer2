use ethereum_types::{Address, U64, H256};
use rlp::{Encodable, Decodable, Rlp, RlpStream, DecoderError};
use crate::common::trie::{MyTrie, TrieCodec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    pub global_index: U64,     // W_g
    pub validator_index: U64,  // W_v
    pub recipient: Address,    // W_r
    pub amount: U64,           // W_a (in Gwei)
}

impl Encodable for Withdrawal {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.global_index);
        s.append(&self.validator_index);
        s.append(&self.recipient);
        s.append(&self.amount);
    }
}

impl Decodable for Withdrawal {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if !rlp.is_list() || rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(Self {
            global_index: rlp.val_at(0)?,
            validator_index: rlp.val_at(1)?,
            recipient: rlp.val_at(2)?,
            amount: rlp.val_at(3)?,
        })
    }
}

pub struct WithdrawalTrieCodec;

impl TrieCodec<usize, Withdrawal> for WithdrawalTrieCodec {
    fn encode_key(key: &usize) -> Vec<u8> {
        let mut s = RlpStream::new();
        s.append(&(*key as u64));
        s.out().to_vec()
    }

    fn encode_value(value: &Withdrawal) -> Vec<u8> {
        rlp::encode(value).to_vec()
    }

    fn decode_key(encoded: &[u8]) -> usize {
        rlp::decode::<u64>(encoded).expect("invalid withdrawal key rlp") as usize
    }

    fn decode_value(encoded: &[u8]) -> Withdrawal {
        rlp::decode(encoded).expect("invalid withdrawal value rlp")
    }
}

pub type WithdrawalTrie = MyTrie<usize, Withdrawal, WithdrawalTrieCodec>;

pub fn hash_withdrawals(withdrawals: &[Withdrawal]) -> H256 {
    let mut trie = WithdrawalTrie::new();
    for (i, w) in withdrawals.iter().enumerate() {
        trie.insert(&i, w);
    }

    trie.root_hash()
}