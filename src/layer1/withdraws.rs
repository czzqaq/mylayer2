use ethereum_types::{Address, U64, H256};
use rlp::{Encodable, RlpStream};
use crate::common::trie::{MockTrie, TrieCodec};

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

pub struct WithdrawalTrieCodec;
pub type WithdrawalTrie = MockTrie<usize, Withdrawal, WithdrawalTrieCodec>;

impl TrieCodec<usize, Withdrawal> for WithdrawalTrieCodec {
    fn encode_pair(key: &usize, value: &Withdrawal) -> (Vec<u8>, Vec<u8>) {
        // Key: RLP(k)
        let mut key_stream = RlpStream::new();
        key_stream.append(&(*key as u64));
        let key_bytes = key_stream.out().to_vec();

        // Value: RLP(L_W(W))
        let value_bytes = rlp::encode(value).to_vec();

        (key_bytes, value_bytes)
    }
}

pub fn hash_withdrawals(withdrawals: &[Withdrawal]) -> H256 {
    let mut trie = WithdrawalTrie::new(WithdrawalTrieCodec);
    for (i, w) in withdrawals.iter().enumerate() {
        trie.insert(i, w.clone());
    }

    trie.root_hash()
}