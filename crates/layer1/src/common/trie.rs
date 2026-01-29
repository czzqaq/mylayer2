use ethereum_types::H256;
use std::{collections::{BTreeMap, VecDeque}, fmt::Debug, marker::PhantomData};
use sha3::{Digest, Keccak256};
use rlp::RlpStream;
use crate::common::constants::hashes;
use anyhow::Result;
use std::collections::HashMap;
use hex::encode as hex_encode;

const EMPTY_BYTES: Vec<u8> = vec![];

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
        let binding = EMPTY_BYTES.clone();
        let value = self.value.as_ref().unwrap_or(&binding);
        s.append(value);
    }
}

#[derive(Debug, Clone)]
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

fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in nibbles.chunks(2) {
        let byte = if chunk.len() == 2 {
            (chunk[0] << 4) | chunk[1]
        } else {
            chunk[0] << 4
        };
        bytes.push(byte);
    }
    bytes
}

impl ModifiedTrie {
    fn new() -> Self {
        Self {
            root: None,
        }
    }
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
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
    fn delete(&mut self, key: Vec<u8>) {
        let nibbles = bytes_to_nibbles(&key);
        if let Some(inner) = self.root.take() {
            self.root = _delete_at(inner, nibbles.as_slice());
        }
    }
    fn root_hash(&self) -> H256 {
        if let Some(root) = &self.root {
            root.hash()
        } else {
            hashes::EMPTY_TRIE_HASH
        }
    }
    fn get_mut(&mut self, key: &[u8]) -> Option<&mut Vec<u8>> {
        let nibbles = bytes_to_nibbles(key);
        if let Some(root) = &mut self.root {
            _get_at(root, nibbles.as_slice())
        } else {
            None
        }
    }
    /// by layer order, return (path, &value)
    fn iter(&self) -> MyTrieIter {
        MyTrieIter::new(self)
    }

    pub fn print_trie(&self) {
        if self.root.is_none() {
            println!("Trie is empty.");
            return;
        }

        let mut queue: VecDeque<(String, Vec<u8>, &TrieNodeType)> = VecDeque::new();
        queue.push_back((
            "root".to_string(),
            Vec::new(),
            self.root.as_ref().unwrap(),
        ));

        while let Some((path_str, path_nibbles, node)) = queue.pop_front() {
            // 统一用 node.hash()
            let hash_hex = hex_encode(node.hash().as_bytes());

            match node {
                TrieNodeType::Leaf(leaf) => {
                    let mut full_key = path_nibbles.clone();
                    full_key.extend(&leaf.key_nibbles);
                    let key_repr: String = full_key.iter().map(|n| format!("{:x}", n)).collect();
                    let leaf_nibbles: String =
                        leaf.key_nibbles.iter().map(|n| format!("{:x}", n)).collect();

                    println!(
                        "[LeafNode]     Path: {:<15} | Key: {:<20} | Value: {:?} | key_nibbles: {:<8} | hash: {}",
                        path_str,
                        key_repr,
                        leaf.value,
                        leaf_nibbles,
                        hash_hex,
                    );
                }

                TrieNodeType::Extension(extension) => {
                    let ext_nibbles: String =
                        extension.key_nibbles.iter().map(|n| format!("{:x}", n)).collect();

                    println!(
                        "[ExtensionNode] Path: {:<15} | key_nibbles: {:<8} | hash: {}",
                        path_str,
                        ext_nibbles,
                        hash_hex,
                    );

                    let mut new_path = path_nibbles.clone();
                    new_path.extend(&extension.key_nibbles);
                    let next_path_str = format!("{}/{}", path_str, ext_nibbles);
                    queue.push_back((next_path_str, new_path, &extension.child));
                }

                TrieNodeType::Branch(branch) => {
                    let key_repr: String =
                        path_nibbles.iter().map(|n| format!("{:x}", n)).collect();
                    let value_repr = branch
                        .value
                        .as_ref()
                        .map(|v| format!("{:?}", v))
                        .unwrap_or_else(|| "None".to_string());

                    println!(
                        "[BranchNode]    Path: {:<15} | Key: {:<20} | Value: {:<6} | hash: {}",
                        path_str,
                        key_repr,
                        value_repr,
                        hash_hex,
                    );

                    for (i, child_opt) in branch.children.iter().enumerate() {
                        if let Some(child_node) = child_opt {
                            let nibble_char = format!("{:x}", i);
                            let mut new_path = path_nibbles.clone();
                            new_path.push(i as u8);
                            let next_path_str = format!("{}/{}", path_str, nibble_char);
                            queue.push_back((next_path_str, new_path, child_node));
                        }
                    }
                }
            }
        }
    }
}

struct MyTrieIter<'a> {
    stack: Vec<(&'a TrieNodeType, Vec<u8>)>,
}

impl<'a> MyTrieIter<'a> {
    fn new(trie: &'a ModifiedTrie) -> Self {
        let mut stack = Vec::new();
        if let Some(root) = &trie.root {
            stack.push((root, vec![]));
        }
        Self { stack }
    }
}

impl<'a> Iterator for MyTrieIter<'a> {
    type Item = (Vec<u8>, &'a Vec<u8>); // （path, &value）

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((node, path)) = self.stack.pop() {
            match node {
                TrieNodeType::Leaf(leaf) => {
                    let mut full_path = path;
                    full_path.extend(leaf.key_nibbles.iter());
                    return Some((nibbles_to_bytes(&full_path), &leaf.value));
                }
                TrieNodeType::Extension(extension) => {
                    let mut new_path = path;
                    new_path.extend(extension.key_nibbles.iter());
                    self.stack.push((&extension.child, new_path));
                }
                TrieNodeType::Branch(branch) => {
                    for (i, child) in branch.children.iter().enumerate().rev() {
                        if let Some(child_node) = child {
                            let mut new_path = path.clone();
                            new_path.push(i as u8);
                            self.stack.push((child_node, new_path));
                        }
                    }
                }
            }
        }
        None
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
                // if branch.children[child_index].is_some() {
                //     let new_child = _delete_at(
                //         *branch.children[child_index].take().unwrap(),
                //         &nibbles[1..],
                //     );
                //     branch.children[child_index] = new_child.map(|c| Box::new(c));
                // }
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
                    return Some(TrieNodeType::Extension(ExtensionNode {
                        key_nibbles: extended_key_nibbles,
                        child: Box::new(TrieNodeType::Branch(branch)),
                    }));
                }
            }
        }
    }
}

fn _get_at<'a>(node: &'a mut TrieNodeType, nibbles: &[u8]) ->  Option<&'a mut Vec<u8>> {
    match node {
        TrieNodeType::Leaf(leaf) => {
            if leaf.key_nibbles == nibbles {
                return Some(&mut leaf.value);
            } else {
                return None;
            }
        }

        TrieNodeType::Extension(extension) => {
            if extension.key_nibbles == nibbles[0..extension.key_nibbles.len()] {
                return _get_at(&mut (*extension.child), &nibbles[extension.key_nibbles.len()..]);
            } else {
                return None;
            }
        }

        TrieNodeType::Branch(branch) => {
            if nibbles.len() == 0 {
                return branch.value.as_mut();
            } else {
                let child_index = nibbles[0] as usize;
                if let Some(child_node) = &mut branch.children[child_index] {
                    return _get_at(&mut (*child_node), &nibbles[1..]);
                } else {
                    return None;
                }
            }
        }
    }
}

/// Codec trait: defines how to encode/decode keys and values
pub trait TrieCodec<K, V> {
    fn encode_key(key: &K) -> Vec<u8>;
    fn encode_value(value: &V) -> Vec<u8>;
    fn decode_key(encoded: &[u8]) -> K;
    fn decode_value(encoded: &[u8]) -> V;
}

#[derive(Debug, Clone)]
pub struct MyTrie<K, V, C: TrieCodec<K, V>> {
    inner: ModifiedTrie,
    _marker: PhantomData<(K, V, C)>,
}
impl<K, V, C> MyTrie<K, V, C>
where
    C: TrieCodec<K, V>,
{
    pub fn new() -> Self {
        Self {
            inner: ModifiedTrie::new(),
            _marker: PhantomData,
        }
    }
    
    /// insert or update a key-value pair
    pub fn insert(&mut self, key: &K, value: &V) {
        let encoded_key = C::encode_key(&key);
        let encoded_value = C::encode_value(&value);
        self.inner.insert(encoded_key, encoded_value);
    }

    pub fn get(&mut self, key: &K) -> Option<V> {
        let encoded_key = C::encode_key(key);

        if let Some(encoded_value) = self.inner.get_mut(&encoded_key) {
            Some(C::decode_value(&encoded_value))
        } else {
            None
        }
    }

    pub fn set(&mut self, key: &K, value: &V) -> Result<()> {
        let encoded_key = C::encode_key(key);

        if let Some(old_encoded_value) = self.inner.get_mut(&encoded_key) {
            let encoded_value = C::encode_value(value);
            *old_encoded_value = encoded_value;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Key not found"))
        }
    }

    pub fn delete(&mut self, key: &K) {
        let encoded_key = C::encode_key(key);
        self.inner.delete(encoded_key);
    }

    pub fn root_hash(&self) -> H256 {
        self.inner.root_hash()
    }

    pub fn iter(&self) -> impl Iterator<Item = (K, V)> {
        self.inner.iter().map(|(k, v)| {
            let decoded_key = C::decode_key(&k);
            let decoded_value = C::decode_value(v);
            (decoded_key, decoded_value)
        })
    }

    pub fn print_trie(&self) {
        self.inner.print_trie();
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants::hashes;
    use hex::FromHex;
    use serde::Deserialize;
    use std::{fs, str::FromStr};

    pub struct StringCodec;

    impl TrieCodec<String, String> for StringCodec {
        fn encode_key(key: &String) -> Vec<u8> {
            key.as_bytes().to_vec()
        }

        fn encode_value(value: &String) -> Vec<u8> {
            value.as_bytes().to_vec()
        }

        fn decode_key(encoded: &[u8]) -> String {
            String::from_utf8(encoded.to_vec()).unwrap()
        }

        fn decode_value(encoded: &[u8]) -> String {
            String::from_utf8(encoded.to_vec()).unwrap()
        }
    }

    pub struct HexCodec;

    impl TrieCodec<String, String> for HexCodec {
        fn encode_key(key: &String) -> Vec<u8> {
            let hex_str = key.strip_prefix("0x").unwrap_or(key);
            hex::decode(hex_str).unwrap()
        }

        fn encode_value(value: &String) -> Vec<u8> {
            if value.starts_with("0x") {
                let hex_str = value.strip_prefix("0x").unwrap_or(value);
                hex::decode(hex_str).unwrap()
            } else {
                value.as_bytes().to_vec()
            }
        }

        fn decode_key(encoded: &[u8]) -> String {
            let hex_str = hex::encode(encoded);
            format!("0x{}", hex_str)
        }

        fn decode_value(encoded: &[u8]) -> String { // some value may not be hex, because it's just test, don't care
            let hex_str = hex::encode(encoded);
            format!("0x{}", hex_str)
        }
    }

    #[derive(Debug, Deserialize)]
    struct TestCaseAnyOrder {
        #[serde(rename = "in")] // `in`` is the keyword in rust, rename it
        input: HashMap<String, String>,
        root: String,
    }

    #[derive(Debug, Deserialize)]
    struct TestCaseList {
        #[serde(rename = "in")] // in is the keyword in rust, rename it
        input: Vec<(String, Option<String>)>,
        root: String,
    }


    #[test]
    fn test_empty() {
        let mut trie: MyTrie<String, String, StringCodec> = MyTrie::new();
        assert_eq!(trie.root_hash(), hashes::EMPTY_TRIE_HASH);

        trie.insert(&"key1".to_string(), &"value1".to_string());
        trie.delete(&"key1".to_string());
        assert_eq!(trie.root_hash(), hashes::EMPTY_TRIE_HASH);

        let count = trie.iter().count();
        assert_eq!(count, 0, "Trie should be empty after deletion");
    }

    #[test]
    fn test_get_and_iter() {
        let mut trie: MyTrie<String, String, StringCodec> = MyTrie::new();
        trie.insert(&"key1".to_string(), &"value1".to_string());
        trie.insert(&"key2".to_string(), &"value2".to_string());

        let value = trie.get(&"key1".to_string()).unwrap();
        assert_eq!(value, "value1");

        trie.print_trie();

        let mut iter = trie.iter();
        assert_eq!(iter.next().unwrap(), ("key1".to_string(), "value1".to_string()));
        assert_eq!(iter.next().unwrap(), ("key2".to_string(), "value2".to_string()));
    }

    #[test]
    fn test_marginal() {
        let mut trie: MyTrie<String, String, StringCodec> = MyTrie::new();
        trie.insert(&"key1".to_string(), &"value1".to_string());

        let value = trie.get(&"key2".to_string());
        assert_eq!(value, None);

        trie.delete(&"key2".to_string()); // nothing happens
        let value = trie.get(&"key1".to_string());
        assert_eq!(value, Some("value1".to_string()));
        let size = trie.iter().count();
        assert_eq!(size, 1, "Trie should have one element");

        trie.insert(&"key1".to_string(), &"value2".to_string()); // to update
        let value = trie.get(&"key1".to_string());
        assert_eq!(value, Some("value2".to_string()));

        let size = trie.iter().count();
        assert_eq!(size, 1, "Trie should have one element");
    }

    #[test]
    fn test_anyorder() {
        let file_path = "test_data/trieanyorder.json";
        let file_content = fs::read_to_string(file_path).expect("Failed to read JSON file");
        let tests: HashMap<String, TestCaseAnyOrder> = serde_json::from_str(&file_content).expect("Invalid JSON format");
        for (name, case) in tests {
            println!("Running test case: {}", name);
            let actual_root;
            if name.contains("hex") {
                let mut trie: MyTrie<String, String, HexCodec> = MyTrie::new();
                for (key, value) in &case.input {
                    trie.insert(key, value);
                }

                actual_root = trie.root_hash();
            } else {
                let mut trie: MyTrie<String, String, StringCodec> = MyTrie::new();
                for (key, value) in &case.input {
                    trie.insert(key, value);
                }

                actual_root = trie.root_hash();
            }
            
            let expected_root = H256::from_slice(&hex::decode(&case.root.trim_start_matches("0x")).unwrap());
            assert_eq!(actual_root, expected_root, "Root hash mismatch for test case: {}", name);
        }
    }

    #[test]
    fn test_with_delete() {
        let file_path = "test_data/trietest.json";
        let file_content = fs::read_to_string(file_path).expect("Failed to read JSON file");
        let tests: HashMap<String, TestCaseList> = serde_json::from_str(&file_content).expect("Invalid JSON format");
        for (name, case) in tests {
            println!("Running test case: {}", name);
            let actual_root;
            if name.contains("hex") {
                let mut trie: MyTrie<String, String, HexCodec> = MyTrie::new();
                for (key, value) in &case.input {
                    if let Some(v) = value {
                        trie.insert(key, v);
                    } else {
                        trie.delete(key);
                    }
                }

                actual_root = trie.root_hash();
            } else {
                let mut trie: MyTrie<String, String, StringCodec> = MyTrie::new();
                for (key, value) in &case.input {
                    if let Some(v) = value {
                        trie.insert(key, v);
                    } else {
                        trie.delete(key);
                    }
                }

                actual_root = trie.root_hash();
            }
            let expected_root = H256::from_slice(&hex::decode(&case.root.trim_start_matches("0x")).unwrap());
            assert_eq!(actual_root, expected_root, "Root hash mismatch for test case: {}", name);
        }
    }

}