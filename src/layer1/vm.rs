/// implemented a run framework for the vm. Support ADD, CALL, CREATE, STOP

use crate::layer1::transaction::BlobTransaction;

fn intrinsic_gas(tx: &BlobTransaction) -> u64 {
    let sender = tx.get_sender();
}

fn run() {
    // precheck:
    transaction.get_sender(), 合法
    sender 非 EOA。
    transaction 的
}