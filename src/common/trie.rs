use std::collections::BTreeMap;
use sha3::{Digest, Keccak256};
use ethereum_types::H256;

/// Codec trait：define the function to collect key-value pairs. 
pub trait TrieCodec<K, V> {
    fn encode_pair(key: &K, value: &V) -> (Vec<u8>, Vec<u8>);
}

/// provide the same functionalities as the MPT. Use BTreeMap as the storage
#[derive(Debug, Clone)]
pub struct MockTrie<K, V, C: TrieCodec<K, V>> {
    data: BTreeMap<K, V>,
    codec: C,
}

impl<K, V, C> MockTrie<K, V, C>
where
    K: Ord,
    C: TrieCodec<K, V>,
{
    pub fn new(codec: C) -> Self {
        Self {
            data: BTreeMap::new(),
            codec,
        }
    }
    
    /// insert or update a key-value pair
    pub fn insert(&mut self, key: K, value: V) {
        self.data.insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.data.get_mut(key)
    }

    pub fn delete(&mut self, key: &K) {
        self.data.remove(key);
    }

    pub fn root_hash(&self) -> H256 {
        let mut hasher = Keccak256::new();

        for (k, v) in &self.data {
            let (encoded_k, encoded_v) = C::encode_pair(k, v);
            hasher.update(encoded_k);
            hasher.update(encoded_v);
        }

        H256::from_slice(&hasher.finalize())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.data.iter()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_trie() {
        struct MockCodec;

        impl TrieCodec<H256, Vec<u8>> for MockCodec {
            fn encode_pair(key: &H256, value: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
                (key.as_bytes().to_vec(), value.clone())
            }
        }

        let mut trie = MockTrie::new(MockCodec);
        let key = H256::from_low_u64_be(1);
        let value = vec![1, 2, 3];

        trie.insert(key, value.clone());
        assert_eq!(trie.get(&key), Some(&value));

        let root_hash = trie.root_hash();
        println!("Root hash: {:?}", root_hash);
    }
}