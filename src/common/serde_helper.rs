use serde::{Deserialize, Deserializer};
use std::num::ParseIntError;

use bytes::Bytes;
use hex::FromHex;
use ethereum_types::{Address, H256, U256};

/* ------------ 前面的一些 strip / parse_* 保持不变 ------------ */
fn strip_pref(s: &str) -> &str {
    s.strip_prefix("0x:bigint ")
        .or_else(|| s.strip_prefix("0x"))
        .unwrap_or(s)
}

pub fn parse_address(s: &str) -> Result<Address, String> {
    let bytes = <[u8; 20]>::from_hex(strip_pref(s)).map_err(|e| e.to_string())?;
    Ok(Address::from(bytes))
}
pub fn parse_h256(s: &str) -> Result<H256, String> {
    let bytes = <[u8; 32]>::from_hex(strip_pref(s)).map_err(|e| e.to_string())?;
    Ok(H256::from(bytes))
}
pub fn parse_u64_from_str(s: &str) -> Result<u64, ParseIntError> {
    if s.starts_with("0x") { u64::from_str_radix(strip_pref(s), 16) } else { s.parse() }
}
pub fn parse_u256_from_str(s: &str) -> Result<U256, String> {
    U256::from_str_radix(strip_pref(s), 16).map_err(|e| e.to_string())
}

pub fn parse_u8_from_str(s: &str) -> Result<u8, ParseIntError> {
    if s.starts_with("0x") { u8::from_str_radix(strip_pref(s), 16) } else { s.parse() }
}

macro_rules! de_from_str {
    ($name:ident, $target:ty, $parser:expr) => {
        pub fn $name<'de, D>(d: D) -> Result<$target, D::Error>
        where D: Deserializer<'de>,
        {
            let s: &str = Deserialize::deserialize(d)?;
            $parser(s).map_err(serde::de::Error::custom)
        }
    };
}

macro_rules! de_opt_from_str {
    ($name:ident, $target:ty, $parser:expr) => {
        pub fn $name<'de, D>(d: D) -> Result<Option<$target>, D::Error>
        where D: Deserializer<'de>,
        {
            let opt: Option<&str> = Option::deserialize(d)?;
            match opt {
                None               => Ok(None),
                Some(s) if s.is_empty() => Ok(None),
                Some(s)            => $parser(s).map(Some).map_err(serde::de::Error::custom),
            }
        }
    };
}

de_from_str!(de_addr,  Address, parse_address);
de_from_str!(de_h256,  H256,    parse_h256);
de_from_str!(de_u64,   u64,     parse_u64_from_str);
de_from_str!(de_u256,  U256,    parse_u256_from_str);
de_from_str!(de_u8,   u8,      parse_u8_from_str);

de_opt_from_str!(de_opt_addr, Address, parse_address);
de_opt_from_str!(de_opt_h256, H256,    parse_h256);
de_opt_from_str!(de_opt_u64,  u64,     parse_u64_from_str);
de_opt_from_str!(de_opt_u256, U256,    parse_u256_from_str);

/* ------------ Vec<H256> & Bytes，同样给 Option 版 ------------ */
pub fn de_vec_h256<'de, D>(d: D) -> Result<Vec<H256>, D::Error>
where D: Deserializer<'de>,
{
    let v: Vec<&str> = Deserialize::deserialize(d)?;
    v.into_iter()
        .map(|s| parse_h256(s).map_err(serde::de::Error::custom))
        .collect()
}

pub fn de_opt_vec_h256<'de, D>(d: D) -> Result<Option<Vec<H256>>, D::Error>
where D: Deserializer<'de>,
{
    let opt: Option<Vec<&str>> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(list) => list.into_iter()
                          .map(|s| parse_h256(s).map_err(serde::de::Error::custom))
                          .collect::<Result<Vec<_>, _>>()
                          .map(Some),
    }
}

pub fn de_bytes<'de, D>(d: D) -> Result<Bytes, D::Error>
where D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(d)?;
    Ok(if s.is_empty() { Bytes::new() }
       else { Bytes::from(Vec::<u8>::from_hex(strip_pref(s)).map_err(serde::de::Error::custom)?) })
}

pub fn de_opt_bytes<'de, D>(d: D) -> Result<Option<Bytes>, D::Error>
where D: Deserializer<'de>,
{
    let opt: Option<&str> = Option::deserialize(d)?;
    match opt {
        None | Some("") => Ok(None),
        Some(s) => {
            let raw = Vec::<u8>::from_hex(strip_pref(s)).map_err(serde::de::Error::custom)?;
            Ok(Some(Bytes::from(raw)))
        }
    }
}