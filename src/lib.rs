use fawkes_crypto::{
    backend::bellman_groth16::{engines::Engine, prover::Proof},
    ff_uint::Num,
};
use serde::{Deserialize, Serialize};

pub mod evm;
pub mod near;
pub mod substrate;
mod utils;
pub mod waves;

// TODO: Custom error type

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[repr(u16)]
pub enum TxType {
    #[serde(rename = "0000")]
    Deposit = 0,
    #[serde(rename = "0001")]
    Transfer = 1,
    #[serde(rename = "0002")]
    Withdraw = 2,
}

impl TryFrom<u16> for TxType {
    type Error = std::io::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TxType::Deposit),
            1 => Ok(TxType::Transfer),
            2 => Ok(TxType::Withdraw),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid tx type",
            )),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TxData<E: Engine> {
    pub tx_type: TxType,
    pub proof: Proof<E>,
    pub tree_proof: Proof<E>,
    pub root_after: Num<E::Fr>,
    pub delta: Num<E::Fr>,
    pub out_commit: Num<E::Fr>,
    pub nullifier: Num<E::Fr>,
    pub memo: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub token_id: String,
}
