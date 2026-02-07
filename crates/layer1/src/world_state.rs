use ethereum_types::{U256, H256, Address};
use sha3::{Digest, Keccak256};
use rlp::{Encodable, RlpStream};
use anyhow::Result;

use crate::common::trie::{MyTrie, TrieCodec};

pub type StorageTrie = MyTrie<U256, U256, StorageCodec>;

#[derive(Debug, Clone)]
enum JournalEntry {
    BalanceChange {
        address: Address,
        old_value: U256,
    },
    NonceChange {
        address: Address,
        old_value: u64,
    },
    StorageChange {
        address: Address,
        key: U256,
        old_value: Option<U256>,
    },
    CodeChange {
        address: Address,
        old_code: Vec<u8>,
        old_code_hash: H256,
    },
    AccountCreated {
        address: Address,
    },
    AccountDeleted {
        address: Address,
        old_account: AccountState,
    },
}

/// state object. the σ(a)
#[derive(Debug, Clone)]
pub struct AccountState {
    pub nonce: u64,
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
            nonce: 0,
            balance: U256::zero(),
            storage_root: H256::zero(),
            code_hash: H256::zero(),
            code: vec![],
            storage: StorageTrie::default(),
        }
    }
}

impl Encodable for AccountState {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.nonce);
        s.append(&self.balance);
        s.append(&self.storage_root);
        s.append(&self.code_hash);
    }
}

impl AccountState {
    pub fn update_storage_root(&mut self) {
        self.storage_root = self.storage.root_hash();
    }

    pub fn update_code_hash(&mut self) {
        self.code_hash = H256::from_slice(&Keccak256::digest(&self.code));
    }

    pub fn new(code: &Vec<u8>) -> Self {
        let mut account = Self::default();
        account.code = code.clone();
        account.update_code_hash();
        account
    }
}

#[derive(Debug, Clone)]
pub struct StorageCodec;
impl TrieCodec<U256, U256> for StorageCodec {
    fn encode_key(key: &U256) -> Vec<u8> {
        key.to_big_endian().to_vec()
    }
    fn encode_value(value: &U256) -> Vec<u8> {
        rlp::encode(value).to_vec()
    }
    fn decode_key(encoded: &[u8]) -> U256 {
        U256::from_big_endian(encoded)
    }
    fn decode_value(encoded: &[u8]) -> U256 {
        rlp::decode(encoded).expect("invalid storage value rlp")
    }
}

struct StateCodec;
impl TrieCodec<Address, AccountState> for StateCodec {
    fn encode_key(key: &Address) -> Vec<u8> {
        key.as_bytes().to_vec()
    }
    fn encode_value(value: &AccountState) -> Vec<u8> {
        rlp::encode(value).to_vec()
    }
    fn decode_key(encoded: &[u8]) -> Address {
        Address::from_slice(encoded)
    }
    fn decode_value(encoded: &[u8]) -> AccountState {
        rlp::decode(encoded).expect("invalid account state rlp")
    }
}

pub struct WorldStateTrie {
    inner: MyTrie<Address, AccountState, StateCodec>,
    journal: Option<Vec<JournalEntry>>,
}
impl WorldStateTrie {
    pub fn new() -> Self {
        Self {
            inner: MyTrie::new(),
            journal: None,
        }
    }

    /// 创建 checkpoint。如果 journal 已存在，则报错。
    pub fn checkpoint(&mut self) {
        if self.journal.is_some() {
            panic!("Checkpoint already exists");
        }
        self.journal = Some(Vec::new());
    }

    /// 回滚到 checkpoint，撤销所有变更。
    pub fn rollback(&mut self) -> Result<()> {
        if let Some(journal) = self.journal.take() {
            for entry in journal.iter().rev() {
                self.revert_journal_entry(entry);
            }
            Ok(())
        } else {
            Err(anyhow::anyhow!("No checkpoint to rollback to"))
        }
    }

    /// clear journal
    pub fn commit(&mut self) -> Result<()> {
        if self.journal.is_none() {
            panic!("No checkpoint to commit");
        }
        self.journal = None;
        Ok(())
    }

    fn push_journal(&mut self, entry: JournalEntry) {
        if let Some(journal) = &mut self.journal {
            journal.push(entry);
        }
    }

    fn revert_journal_entry(&mut self, entry: &JournalEntry) {
        match entry {
            JournalEntry::BalanceChange { address, old_value } => {
                let mut account = self.inner.get(address).unwrap();
                account.balance = *old_value;
                self.inner.insert(address, &account);
            },
            JournalEntry::NonceChange { address, old_value } => {
                let mut account = self.inner.get(address).unwrap();
                account.nonce = *old_value;
                self.inner.insert(address, &account);
            },
            JournalEntry::StorageChange { address, key, old_value } => {
                let mut account = self.inner.get(address).unwrap();
                match old_value {
                    Some(value) => account.storage.insert(&key, &value),
                    None => account.storage.delete(&key),
                };
                account.update_storage_root();
                self.inner.insert(address, &account);
            },
            JournalEntry::CodeChange { address, old_code, old_code_hash } => {
                let mut account = self.inner.get(address).unwrap();
                account.code = old_code.clone();
                account.code_hash = *old_code_hash;
                self.inner.insert(address, &account);
            },
            JournalEntry::AccountCreated { address } => {
                self.inner.delete(address);
            },
            JournalEntry::AccountDeleted { address, old_account } => {
                self.inner.insert(address, &old_account);
            },
        }
    }

    pub fn insert(&mut self, address: &Address, account: AccountState) {
        if self.inner.get_ref(address).is_none() {
            self.push_journal(JournalEntry::AccountCreated {
                address: *address,
            });
        } else {
            let old_account = self.inner.get(address).unwrap().clone();
            self.push_journal(JournalEntry::AccountDeleted {
                address: *address,
                old_account,
            });
        }
        self.inner.insert(address, &account);
    }

    pub fn set_nonce(&mut self, address: &Address, nonce: u64) {
        let mut account = self.inner.get(address).unwrap();
        let old_nonce = account.nonce;
        if old_nonce != nonce {
            self.push_journal(JournalEntry::NonceChange {
                address: *address,
                old_value: old_nonce,
            });
            account.nonce = nonce;
            self.inner.insert(address, &account);
        }
    }

    pub fn set_balance(&mut self, address: &Address, balance: U256) {
        let mut account = self.inner.get(address).unwrap();
        let old_balance = account.balance;
        if old_balance != balance {
            self.push_journal(JournalEntry::BalanceChange {
                address: *address,
                old_value: old_balance,
            });
            account.balance = balance;
            self.inner.insert(address, &account);
        }
    }

    pub fn set_storage(&mut self, address: &Address, key: U256, value: U256) {
        let mut account = self.inner.get(address).unwrap();
        let old_value = account.storage.get_ref(&key);
        if old_value != Some(value) {
            self.push_journal(JournalEntry::StorageChange {
                address: *address,
                key,
                old_value: old_value,
            });
            account.storage.insert(&key, &value);
            account.update_storage_root();
            self.inner.insert(address, &account);
        }
    }

    pub fn set_code(&mut self, address: &Address, code: Vec<u8>) {
        let mut account = self.inner.get(address).unwrap();
        let old_code = account.code.clone();
        let old_code_hash = account.code_hash;

        if old_code != code {
            self.push_journal(JournalEntry::CodeChange {
                address: *address,
                old_code,
                old_code_hash,
            });
            account.code = code;
            account.update_code_hash();
            self.inner.insert(address, &account);
        }
    }

    pub fn delete(&mut self, address: &Address) {
        if let Some(account) = self.inner.get(address) {
            let old_account = account.clone();
            self.push_journal(JournalEntry::AccountDeleted {
                address: *address,
                old_account,
            });
            self.inner.delete(address);
        }
    }

    pub fn get_account(&self, address: &Address) -> Option<AccountState> {
        self.inner.get_ref(address)
    }

    pub fn get_nonce(&self, address: &Address) -> Option<u64> {
        self.inner.get_ref(address).map(|a| a.nonce)
    }

    pub fn get_balance(&self, address: &Address) -> Option<U256> {
        self.inner.get_ref(address).map(|a| a.balance)
    }

    pub fn get_code(&self, address: &Address) -> Option<Vec<u8>> {
        self.inner.get_ref(address).map(|a| a.code)
    }

    pub fn get_storage(&self, address: &Address, key: U256) -> Option<U256> {
        self.inner
            .get_ref(address)
            .and_then(|a| a.storage.get_ref(&key))
    }

    pub fn root_hash(&self) -> H256 {
        self.inner.root_hash()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Address, AccountState)> + '_ {
        self.inner.iter()
    }

    pub fn account_exists(&self, address: &Address) -> bool {
        self.inner.get_ref(address).is_some()
    }
}