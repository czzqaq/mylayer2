use ethereum_types::{U256, H256, Address};

const TARGET_BLOB_GAS_PER_BLOCK:u64 = 393216;
const MIN_BASE_FEE_PER_BLOB_GAS:u64 = 1;
const BLOB_BASE_FEE_UPDATE_FRACTION:u64 = 3338477;

pub struct Block {
    pub base_fee: U256, // use_fixed_fee
    pub gas_limit: U256,
    pub gas_used: U256,
    pub excess_blob_gas: U256,
    pub blob_gas_used: U256,
}

fn fake_exponential(factor: U256, numerator: U256, denominator: U256) -> U256 {
    let mut i = U256::one();
    let mut output = U256::zero();
    let mut numerator_accum = factor * denominator;
    while numerator_accum > U256::zero() {
        output += numerator_accum;
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += U256::one();
    }
    output // denominator
}

// def calc_excess_blob_gas(parent: Header) -> int:
//     if parent.excess_blob_gas + parent.blob_gas_used < TARGET_BLOB_GAS_PER_BLOCK:
//         return 0
//     else:
//         return parent.excess_blob_gas + parent.blob_gas_used - TARGET_BLOB_GAS_PER_BLOCK

// header.excess_blob_gas = calc_excess_blob_gas(parent)
pub fn calc_excess_blob_gas(parent: &Block) -> U256 {
    if U256::from(parent.excess_blob_gas) + parent.blob_gas_used < U256::from(TARGET_BLOB_GAS_PER_BLOCK) {
        U256::zero()
    } else {
        U256::from(parent.excess_blob_gas) + parent.blob_gas_used - U256::from(TARGET_BLOB_GAS_PER_BLOCK)
    }
}

impl Block {
    pub fn get_base_fee_per_blob_gas(&self) -> U256 {
        fake_exponential(
            U256::from(MIN_BASE_FEE_PER_BLOB_GAS), 
            self.excess_blob_gas,
            U256::from(BLOB_BASE_FEE_UPDATE_FRACTION)
        )
    }
}

// def fake_exponential(factor: int, numerator: int, denominator: int) -> int:
//     i = 1
//     output = 0
//     numerator_accum = factor * denominator
//     while numerator_accum > 0:
//         output += numerator_accum
//         numerator_accum = (numerator_accum * numerator) // (denominator * i)
//         i += 1
//     return output // denominator

// def get_base_fee_per_blob_gas(header: Header) -> int:
//     return fake_exponential(
//         1, //MIN_BASE_FEE_PER_BLOB_GAS,
//         header.excess_blob_gas,
//         3338477 // BLOB_BASE_FEE_UPDATE_FRACTION
//     )