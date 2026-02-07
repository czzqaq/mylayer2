use layer1::world_state::{AccountState, WorldStateTrie, StorageTrie};
use ethereum_types::U256;
use anyhow::Result;

pub fn compare_world_states(expected: &WorldStateTrie, actual: &WorldStateTrie) -> Result<()> {
    for (addr, expected_account) in expected.iter() {
        let actual_account = actual.get_account(addr)
            .ok_or_else(|| anyhow::anyhow!("Missing account: {:?}", addr))?;

        if actual_account.balance != expected_account.balance {
            anyhow::bail!("Balance mismatch at {:?}: expected {}, got {}", addr, expected_account.balance, actual_account.balance);
        }

        if actual_account.nonce != expected_account.nonce {
            anyhow::bail!("Nonce mismatch at {:?}: expected {}, got {}", addr, expected_account.nonce, actual_account.nonce);
        }

        if actual_account.code != expected_account.code {
            anyhow::bail!("Code mismatch at {:?}:\n expected: 0x{}\n actual:   0x{}",
                addr,
                hex::encode(&expected_account.code),
                hex::encode(&actual_account.code)
            );
        }

        for (key, expected_val) in expected_account.storage.iter() {
            let actual_val = actual_account.storage.get_ref(&key).unwrap_or(U256::zero());
            if actual_val != expected_val {
                anyhow::bail!(
                    "Storage mismatch at {:?}[{}]: expected {}, got {}",
                    addr, key, expected_val, actual_val
                );
            }
        }
    }

    Ok(())
}