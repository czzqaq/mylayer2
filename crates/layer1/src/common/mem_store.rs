//! 基于内存的 KV 存储，模拟持久化的 storage 和 code 存储。
//! 不修改 trie 实现，仅提供按 storage_root / code_hash 的存取模拟。

use ethereum_types::{H256, U256};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// 解码 AccountState 时若设置，则用其填充 code 与 storage
    static DECODE_BACKEND: RefCell<Option<MemBackend>> = RefCell::new(None);
}

/// 在指定 backend 上下文中执行 f，期间对 AccountState 的 decode 会从该 backend 填充 code/storage
pub fn with_decode_backend<F, R>(backend: &MemBackend, f: F) -> R
where
    F: FnOnce() -> R,
{
    DECODE_BACKEND.with(|cell| {
        *cell.borrow_mut() = Some(backend.clone());
        let r = f();
        *cell.borrow_mut() = None;
        r
    })
}

/// 取当前“解码用” backend（仅在 with_decode_backend 的闭包内为 Some）
pub fn current_decode_backend() -> Option<MemBackend> {
    DECODE_BACKEND.with(|cell| cell.borrow().clone())
}

/// 按 storage root 存取的 storage 快照：slot -> value
pub type StorageSnapshot = HashMap<U256, U256>;

/// 模拟持久化 storage：根据 storage_root 得到具体 key-value 表
#[derive(Default, Clone)]
pub struct MemStorageStore {
    by_root: HashMap<H256, StorageSnapshot>,
}

impl MemStorageStore {
    pub fn new() -> Self {
        Self {
            by_root: HashMap::new(),
        }
    }

    /// 根据 storage root 取出该账户的 storage 快照
    pub fn get(&self, storage_root: H256) -> Option<&StorageSnapshot> {
        self.by_root.get(&storage_root)
    }

    /// 根据 storage root 取出可修改的 storage 快照（若不存在则返回 None）
    pub fn get_mut(&mut self, storage_root: H256) -> Option<&mut StorageSnapshot> {
        self.by_root.get_mut(&storage_root)
    }

    /// 以 storage_root 为键写入/覆盖 storage 快照
    pub fn put(&mut self, storage_root: H256, snapshot: StorageSnapshot) {
        self.by_root.insert(storage_root, snapshot);
    }

    /// 在已有快照上按 root 插入单条 (slot, value)；若该 root 尚无快照则先建空表再插入
    pub fn put_slot(&mut self, storage_root: H256, slot: U256, value: U256) {
        self.by_root
            .entry(storage_root)
            .or_default()
            .insert(slot, value);
    }

    /// 根据 storage_root 取指定 slot 的值
    pub fn get_slot(&self, storage_root: H256, slot: U256) -> Option<U256> {
        self.by_root.get(&storage_root).and_then(|m| m.get(&slot)).copied()
    }
}

/// 模拟持久化 code 存储：根据 code_hash 得到合约字节码
#[derive(Default, Clone)]
pub struct MemCodeStore {
    by_hash: HashMap<H256, Vec<u8>>,
}

impl MemCodeStore {
    pub fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
        }
    }

    /// 根据 code_hash 取出 code
    pub fn get(&self, code_hash: H256) -> Option<Vec<u8>> {
        self.by_hash.get(&code_hash).cloned()
    }

    /// 以 code_hash 为键写入/覆盖 code
    pub fn put(&mut self, code_hash: H256, code: Vec<u8>) {
        self.by_hash.insert(code_hash, code);
    }
}

/// 合并的模拟后端：同时提供 storage 与 code 的按根/按 hash 存取
#[derive(Default, Clone)]
pub struct MemBackend {
    pub storage: MemStorageStore,
    pub code: MemCodeStore,
}

impl MemBackend {
    pub fn new() -> Self {
        Self {
            storage: MemStorageStore::new(),
            code: MemCodeStore::new(),
        }
    }

    pub fn get_storage(&self, storage_root: H256) -> Option<&StorageSnapshot> {
        self.storage.get(storage_root)
    }

    pub fn put_storage(&mut self, storage_root: H256, snapshot: StorageSnapshot) {
        self.storage.put(storage_root, snapshot);
    }

    pub fn get_code(&self, code_hash: H256) -> Option<Vec<u8>> {
        self.code.get(code_hash)
    }

    pub fn put_code(&mut self, code_hash: H256, code: Vec<u8>) {
        self.code.put(code_hash, code);
    }
}
