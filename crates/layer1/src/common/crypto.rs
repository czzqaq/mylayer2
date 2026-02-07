use k256::ecdsa::{Signature, RecoveryId, VerifyingKey,SigningKey};
use sha3::{Digest, Keccak256};
use ethereum_types::{Address, H256, U256};
use anyhow::Result;

pub fn public_key_to_eth_address(pubkey: &VerifyingKey) -> Address {
    let pubkey_encoded = pubkey.to_encoded_point(false); // uncompressed, starts with 0x04
    let pubkey_bytes = &pubkey_encoded.as_bytes()[1..]; // remove 0x04 prefix

    let hash = Keccak256::digest(pubkey_bytes);
    Address::from_slice(&hash[12..]) // only the last 20 bytes from 32 bytes
}

pub fn recover_address_from_signature(msg_hash: H256, r: U256, s: U256, parity: u8) 
    -> Result<Address> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_big_endian());
    sig_bytes[32..].copy_from_slice(&s.to_big_endian());
    let signature = Signature::try_from(&sig_bytes[..])?;

    let recovery_id = RecoveryId::try_from(parity)?;

    let recovered_key = VerifyingKey::recover_from_digest(Keccak256::new_with_prefix(msg_hash), &signature, recovery_id)?;

    Ok(public_key_to_eth_address(&recovered_key))
}

pub fn sign_message_hash(message_hash: H256, signing_key: &SigningKey) -> (H256, H256, u8) {
    let digest = Keccak256::new_with_prefix(message_hash);
    let (signature, recovery_id): (Signature, RecoveryId) = signing_key.sign_digest_recoverable(digest).unwrap();

    let sig_bytes = signature.to_bytes();
    let r = H256::from_slice(&sig_bytes[..32]);
    let s = H256::from_slice(&sig_bytes[32..]);
    let v = recovery_id.to_byte();

    (r, s, v)
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use k256::ecdsa::SigningKey;
    use k256::SecretKey;

    #[test]
    fn test_sign_and_recover_eth_address() {
        // from my wallet
        let secret_key_bytes = hex!(
            "94b3cfc00cc864b9551741db8389388aa51ba3110b47f502553d07a8d3da0e6f"
        );
        let expected_address = Address::from(hex!(
            "29Dbf1731c2Dd59069983c7b953e5C4aBE0CbB1A"
        ));

        let secret_key = SecretKey::from_bytes((&secret_key_bytes).into()).unwrap();
        let signing_key = SigningKey::from(secret_key);

        let msg = b"example message";
        let hash_array: [u8; 32] = Keccak256::digest(msg).into();
        let msg_hash = H256::from(hash_array);

        let (r, s, v) = sign_message_hash(msg_hash, &signing_key);

        // 恢复地址 (H256 -> U256: 黄皮书中 r,s 为 big_endian_int)
        let recovered_address = recover_address_from_signature(
            msg_hash,
            U256::from_big_endian(r.as_bytes()),
            U256::from_big_endian(s.as_bytes()),
            v,
        )
            .expect("Failed to recover address");

        assert_eq!(recovered_address, expected_address);
    }
}