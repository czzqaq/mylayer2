
pub mod hashes {
    use ethereum_types::{H256};
    use hex_literal::hex;
    // key(rlp( [] ))
    pub const EMPTY_LIST_HASH: H256 = H256(hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"));
    // kec(rlp(b''))
    pub const EMPTY_TRIE_HASH: H256 = H256(hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"));
}

