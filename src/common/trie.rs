use ethereum_types::H256;
use core::hash;
use std::collections::BTreeMap;
use sha3::{Digest, Keccak256};
use rlp::RlpStream;
use crate::common::constants::hashes;

/// Codec trait: defines how to encode/decode keys and values
pub trait MockTrieCodec<K, V> {
    fn encode_pair(key: &K, value: &V) -> (Vec<u8>, Vec<u8>);
}

/// provide the same functionalities as the MPT. Use BTreeMap as the storage
#[derive(Debug, Clone)]
pub struct MockTrie<K, V, C: MockTrieCodec<K, V>> {
    data: BTreeMap<K, V>,
    codec: C,
}
impl<K, V, C> MockTrie<K, V, C>
where
    K: Ord,
    C: MockTrieCodec<K, V>,
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

/* -------------------------------------------------------------------------- */
/*                        the real trie implementation                        */
/* -------------------------------------------------------------------------- */
#[derive(Debug, Clone)]
struct LeafNode {
    key_nibbles: Vec<u8>, // 0~15 for 0-9 and a-f
    value: Vec<u8>, // bytes
}

#[derive(Debug, Clone)]
struct ExtensionNode {
    key_nibbles: Vec<u8>, // 0~15 for 0-9 and a-f
    child: Box<TrieNodeType>,
}

#[derive(Debug, Clone)]
struct BranchNode {
    children: [Option<Box<TrieNodeType>>; 16],
    value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum TrieNodeType {
    Leaf(LeafNode),
    Extension(ExtensionNode),
    Branch(BranchNode),
}

trait TrieNodeEncodable {
    fn rlp_append(&self, s: &mut RlpStream);
}

impl TrieNodeType {
    fn hash(&self) -> H256 {
        let mut rlp_stream = RlpStream::new();
        self.rlp_append(&mut rlp_stream);
        let encode_rlp = rlp_stream.out();

        let hash = Keccak256::digest(encode_rlp);
        H256::from_slice(&hash)
    }

    /// the composition function `c` defined in yellow paper
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            TrieNodeType::Leaf(node) => node.rlp_append(s),
            TrieNodeType::Extension(node) => node.rlp_append(s),
            TrieNodeType::Branch(node) => node.rlp_append(s),
        }
    }
}


fn get_prefix(key: &[u8], is_leaf: bool) -> u8 {
    let flag = if is_leaf { 2 } else { 0 };

    if key.len() % 2 == 1 {
        ((flag + 1) << 4) | key[0]
    } else {
        flag << 4
    }
}

fn hex_prefix_encode(key: &[u8], is_leaf: bool) -> Vec<u8> {
    let mut encoded = Vec::new();
    let prefix = get_prefix(key, is_leaf);
    encoded.push(prefix);

    let start = if key.len() % 2 == 1 { 1 } else { 0 };

    for i in (start..key.len()).step_by(2) {
        let byte = (key[i] << 4) | key[i + 1];
        encoded.push(byte);
    }

    encoded
}

impl TrieNodeEncodable for LeafNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        let path = hex_prefix_encode(&self.key_nibbles, true);
        s.begin_list(2);
        s.append(&path);
        s.append(&self.value);
    }
}

impl TrieNodeEncodable for ExtensionNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        let path = hex_prefix_encode(&self.key_nibbles, false);

        // Node cap
        let mut child_stream = RlpStream::new();
        self.child.rlp_append(&mut child_stream);
        let child_rlp = child_stream.out();

        s.begin_list(2);
        s.append(&path);

        if child_rlp.len() < 32 {
            // inline structure
            s.append_raw(&child_rlp, 1); // 1 = item
        } else {
            let hash = Keccak256::digest(child_rlp);
            let hash = H256::from_slice(&hash);
            s.append(&hash.as_bytes());
        }
    }
}

impl TrieNodeEncodable for BranchNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(17);

        for child in &self.children {
            if let Some(child_node) = child {
                let mut child_stream = RlpStream::new();
                child_node.rlp_append(&mut child_stream);
                let encoded = child_stream.out();
                if encoded.len() < 32 {
                    s.append_raw(&encoded, 1);
                } else {
                    let hash = Keccak256::digest(encoded);
                    let hash = H256::from_slice(&hash);
                    s.append(&hash.as_bytes());
                }
            } else {
                s.append_empty_data();
            }
        }

        s.append(&self.value);
    }
}

pub struct ModifiedTrie {
    root: Option<TrieNodeType>,
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::new();
    for byte in bytes {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0F);
    }
    nibbles
}

impl ModifiedTrie {
    pub fn new() -> Self {
        Self {
            root: None,
        }
    }
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let nibbles = bytes_to_nibbles(&key);
        if let Some(inner) = self.root.take() {
            self.root = Some(_insert_at(
                inner,
                nibbles.as_slice(),
                value,
            ));
        } else {
            self.root = Some(TrieNodeType::Leaf(LeafNode {
                key_nibbles: nibbles,
                value,
            }));
        }
    }
    pub fn delete(&mut self, key: Vec<u8>) {
        let nibbles = bytes_to_nibbles(&key);
        if let Some(inner) = self.root.take() {
            self.root = _delete_at(inner, nibbles.as_slice());
        }
    }
    pub fn root_hash(&self) -> H256 {
        if let Some(root) = &self.root {
            root.hash()
        } else {
            hashes::EMPTY_TRIE_HASH
        }
    }
}

fn shared_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let mut len = 0;
    while len < a.len() && len < b.len() && a[len] == b[len] {
        len += 1;
    }

    len
}

fn _insert_at(
    node: TrieNodeType,
    nibbles: &[u8],
    value: Vec<u8>,
) -> TrieNodeType {
    match node {
        TrieNodeType::Leaf(leaf) => {
            let common_prefix = shared_prefix_len(&leaf.key_nibbles, &nibbles);
            if common_prefix == leaf.key_nibbles.len() && common_prefix == nibbles.len() {
                let new_leaf = LeafNode {
                    key_nibbles: nibbles.to_vec(),
                    value,
                };
                return TrieNodeType::Leaf(new_leaf);
            }
            // partial match, split to branch node
            let mut new_branch = BranchNode {
                children: Default::default(),
                value: None,
            };

            let suffix_old = leaf.key_nibbles[common_prefix..].as_ref();
            if suffix_old.len() == 0 {
                new_branch.value = Some(leaf.value.clone());
            } else {
                let new_leaf = LeafNode {
                    key_nibbles: suffix_old[1..].to_vec(),
                    value: leaf.value.clone(),
                };
                new_branch.children[suffix_old[0] as usize] =
                    Some(Box::new(TrieNodeType::Leaf(new_leaf)));
            }

            let suffix_new = nibbles[common_prefix..].as_ref();
            if suffix_new.len() == 0 {
                new_branch.value = Some(value);
            } else {
                let new_leaf = LeafNode {
                    key_nibbles: suffix_new[1..].to_vec(),
                    value,
                };
                new_branch.children[suffix_new[0] as usize] =
                    Some(Box::new(TrieNodeType::Leaf(new_leaf)));
            }

            if common_prefix == 0 {
                return TrieNodeType::Branch(new_branch);
            } else {
                let new_extension = ExtensionNode {
                    key_nibbles: leaf.key_nibbles[0..common_prefix].to_vec(),
                    child: Box::new(TrieNodeType::Branch(new_branch)),
                };
                return TrieNodeType::Extension(new_extension);
            }
        }

        TrieNodeType::Extension(extension) => {
            let common_prefix = shared_prefix_len(&extension.key_nibbles, &nibbles);
            if common_prefix == extension.key_nibbles.len() { // go deeper
                let child = _insert_at(
                    *extension.child,
                    &nibbles[common_prefix..],
                    value,
                );
                return TrieNodeType::Extension(ExtensionNode {
                    key_nibbles: extension.key_nibbles.clone(),
                    child: Box::new(child),
                });
            }
            
            // Split the extension
            let mut new_branch = BranchNode {
                children: Default::default(),
                value: None,
            };

            let suffix_old = extension.key_nibbles[common_prefix..].as_ref();
            if suffix_old.len() == 1 {
                new_branch.children[suffix_old[0] as usize] =
                    Some(extension.child);
            } else { // suffix_old.len() > 1, since == 0 case is handled above
                let new_child = ExtensionNode {
                    key_nibbles: suffix_old[1..].to_vec(),
                    child: extension.child,
                };
                new_branch.children[suffix_old[0] as usize] =
                    Some(Box::new(TrieNodeType::Extension(new_child)));
            }

            let suffix_new = nibbles[common_prefix..].as_ref();
            if suffix_new.len() == 0 {
                new_branch.value = Some(value);
            } else {
                let new_leaf = LeafNode {
                    key_nibbles: suffix_new[1..].to_vec(),
                    value,
                };
                new_branch.children[suffix_new[0] as usize] =
                    Some(Box::new(TrieNodeType::Leaf(new_leaf)));
            }

            if common_prefix == 0 {
                return TrieNodeType::Branch(new_branch);
            } else {
                let new_extension = ExtensionNode {
                    key_nibbles: extension.key_nibbles[0..common_prefix].to_vec(),
                    child: Box::new(TrieNodeType::Branch(new_branch)),
                };
                return TrieNodeType::Extension(new_extension);
            }
        }

        TrieNodeType::Branch(mut branch) => {
            if nibbles.len() == 0 {
                branch.value = Some(value);
                return TrieNodeType::Branch(branch);
            } 

            let child_index = nibbles[0] as usize;
            if let Some(child_node) = branch.children[child_index as usize].take() {
                let new_child_node = _insert_at(
                    *child_node,
                    &nibbles[1..].to_vec(),
                    value,
                );
                branch.children[child_index] = Some(Box::new(new_child_node));
            } else {
                let new_leaf = LeafNode {
                    key_nibbles: nibbles[1..].to_vec(),
                    value,
                };
                branch.children[child_index] =
                    Some(Box::new(TrieNodeType::Leaf(new_leaf)));
            }

            return TrieNodeType::Branch(branch);
        }
    }
}

fn _delete_at(
    node: TrieNodeType,
    nibbles: &[u8],
) -> Option<TrieNodeType> {
    match node {
        TrieNodeType::Leaf(ref leaf) => {
            if leaf.key_nibbles == nibbles {
                return None;
            } else {
                return Some(node);
            }
        }

        TrieNodeType::Extension(extension) => {
            if nibbles[0..extension.key_nibbles.len()] == extension.key_nibbles {
                let child_node = _delete_at(
                    *extension.child,
                    &nibbles[extension.key_nibbles.len()..],
                );
                if let Some(new_child) = child_node {
                    match new_child {
                        TrieNodeType::Leaf(child) => {
                            let mut new_key_nibbles = extension.key_nibbles.clone();
                            new_key_nibbles.extend(child.key_nibbles);
                            return Some(TrieNodeType::Leaf(LeafNode {
                                key_nibbles: new_key_nibbles,
                                value: child.value,
                            }));
                        }
                        TrieNodeType::Extension(child) => {
                            let mut new_key_nibbles = extension.key_nibbles.clone();
                            new_key_nibbles.extend(child.key_nibbles);
                            return Some(TrieNodeType::Extension(ExtensionNode {
                                key_nibbles: new_key_nibbles,
                                child: child.child,
                            }));
                        }
                        TrieNodeType::Branch(branch) => {
                            return Some(TrieNodeType::Extension(ExtensionNode {
                                key_nibbles: extension.key_nibbles,
                                child: Box::new(TrieNodeType::Branch(branch)),
                            }));
                        }
                    }
                } else { // delete the child
                    return None;
                }
            } else { 
                return Some(TrieNodeType::Extension(extension));
            }
        }

        TrieNodeType::Branch(mut branch) => {
            if nibbles.len() == 0 {
                branch.value = None;
            } else {
                let child_index = nibbles[0] as usize;
                let new_child = _delete_at(
                    *branch.children[child_index].take().unwrap(),
                    &nibbles[1..],
                );
                branch.children[child_index] = new_child.map(|c| Box::new(c));
            }

            // rearrange the branch node
            let n_children = branch.children.iter().
                filter(|c| c.is_some()).count();

            if branch.value.is_some() {
                if n_children == 0 {
                    return Some(TrieNodeType::Leaf(LeafNode {
                        key_nibbles: vec![],
                        value: vec![],
                    }));
                } else {
                    return Some(TrieNodeType::Branch(branch));
                }
            }

            if n_children == 0{
                return None;
            }
            if n_children > 1 {
                return Some(TrieNodeType::Branch(branch));
            }

            let indexed_nibble = branch.children.iter()
                .position(|c| c.is_some()).unwrap();
            let the_only_child = *branch.children[indexed_nibble].take().unwrap();
            let mut extended_key_nibbles = vec![indexed_nibble as u8];
            match the_only_child {
                TrieNodeType::Leaf(leaf) => {
                    extended_key_nibbles.extend(leaf.key_nibbles);
                    return Some(TrieNodeType::Leaf(LeafNode {
                        key_nibbles: extended_key_nibbles,
                        value: leaf.value,
                    }));
                }
                TrieNodeType::Extension(extension) => {
                    extended_key_nibbles.extend(extension.key_nibbles);
                    return Some(TrieNodeType::Extension(ExtensionNode {
                        key_nibbles: extended_key_nibbles,
                        child: extension.child,
                    }));
                }
                TrieNodeType::Branch(branch) => {
                    return Some(TrieNodeType::Branch(branch));
                }
            }
        }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::hashes;
    use hex_literal::hex;

    #[derive(Debug, Clone)]
    struct SimpleCodec;

    impl MockTrieCodec<Vec<u8>, Vec<u8>> for SimpleCodec {
        fn encode_pair(key: &Vec<u8>, value: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
            (key.clone(), value.clone())
        }
    }

    #[test]
    fn test_mock_trie() {
        let mut trie = MockTrie::new(SimpleCodec);
        let key = vec![1, 2, 3];
        let value = vec![4, 5, 6];
        trie.insert(key.clone(), value.clone());
        assert_eq!(trie.get(&key), Some(&value));
        assert_eq!(trie.root_hash(), hashes::EMPTY_TRIE_HASH);
    }
}