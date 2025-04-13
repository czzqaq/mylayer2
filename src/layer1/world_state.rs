use ethereum_types::{U256, H256, Address};
use sha3::{Digest, Keccak256};
use rlp::{Encodable, RlpStream};

use crate::common::trie::{MockTrie, TrieCodec};


type StorageTrie = MockTrie<U256, U256, StorageCodec>;
/// state object. the σ(a)
#[derive(Debug, Clone)]
pub struct AccountState {
    pub nonce: U256,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,

    // none-yellow paper fields. Not encoded in RLP
    pub code: Vec<u8>,
    pub storage: StorageTrie,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            nonce: U256::zero(),
            balance: U256::zero(),
            storage_root: H256::zero(),
            code_hash: H256::zero(),
            code: vec![],
            storage: MockTrie::new(StorageCodec),
        }
    }
}

impl Encodable for AccountState {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.nonce);
        s.append(&self.balance);
        s.append(&self.storage_root.as_bytes());
        s.append(&self.code_hash.as_bytes());
    }
}

impl AccountState {
    pub fn update_storage_root(&mut self) {
        self.storage_root = self.storage.root_hash();
    }
}

#[derive(Debug, Clone)]
struct StorageCodec;
impl TrieCodec<U256, U256> for StorageCodec {
    fn encode_pair(key: &U256, value: &U256) -> (Vec<u8>, Vec<u8>) {
        let key_bytes = key.to_big_endian();
        let key_hash = Keccak256::digest(&key_bytes).to_vec();

        let mut s = RlpStream::new();
        s.append(value);
        let rlp_value = s.out().to_vec();

        (key_hash, rlp_value)
    }
}

struct StateCodec;
impl TrieCodec<Address, AccountState> for StateCodec {
    fn encode_pair(key: &Address, value: &AccountState) -> (Vec<u8>, Vec<u8>) {
        let key_hash = Keccak256::digest(key.as_bytes()).to_vec();
        let mut s = RlpStream::new();
        s.append(value);
        let rlp_value = s.out().to_vec();
        (key_hash, rlp_value)
    }
}

pub struct WorldStateTrie {
    inner: MockTrie<Address, AccountState, StateCodec>,
}

impl WorldStateTrie {
    pub fn new() -> Self {
        Self {
            inner: MockTrie::new(StateCodec),
        }
    }

    pub fn insert(&mut self, address: Address, account: AccountState) {
        self.inner.insert(address, account);
    }

    pub fn get_account(&self, address: &Address) -> Option<&AccountState> {
        self.inner.get(address)
    }

    pub fn get_account_mut(&mut self, address: &Address) -> Option<&mut AccountState> {
        self.inner.get_mut(address)
    }

    pub fn set_nonce(&mut self, address: &Address, nonce: U256) {
        if let Some(account) = self.inner.get_mut(address) {
            account.nonce = nonce;
        }
    }

    pub fn get_nonce(&self, address: &Address) -> Option<U256> {
        self.inner.get(address).map(|a| a.nonce)
    }

    pub fn set_balance(&mut self, address: &Address, balance: U256) {
        if let Some(account) = self.inner.get_mut(address) {
            account.balance = balance;
        }
    }

    pub fn get_balance(&self, address: &Address) -> Option<U256> {
        self.inner.get(address).map(|a| a.balance)
    }

    pub fn set_storage(&mut self, address: &Address, key: U256, value: U256) {
        if let Some(account) = self.inner.get_mut(address) {
            account.storage.insert(key, value);
            account.update_storage_root();
        }
    }

    pub fn set_code(&mut self, address: &Address, code: Vec<u8>) {
        if let Some(account) = self.inner.get_mut(address) {
            account.code_hash = H256::from_slice(&Keccak256::digest(&code));
            account.code = code;
        }
    }

    pub fn get_code(&self, address: &Address) -> Option<&Vec<u8>> {
        self.inner.get(address).map(|a| &a.code)
    }

    pub fn get_storage(&self, address: &Address, key: U256) -> Option<U256> {
        self.inner
            .get(address)
            .and_then(|a| a.storage.get(&key).cloned())
    }

    pub fn delete(&mut self, address: &Address) {
        self.inner.delete(address);
    }

    pub fn root_hash(&self) -> H256 {
        self.inner.root_hash()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Address, &AccountState)> {
        self.inner.iter()
    }
}