use std::fmt::Debug;

use fawkes_crypto::ff_uint::{Num, PrimeField};
use serde::{Deserialize, Serialize};

use crate::proof::{DebugProof, Proof};

pub mod evm;
pub mod near;
pub mod proof;
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
pub struct TxData<Fr: PrimeField, P: Proof> {
    pub tx_type: TxType,
    pub proof: P,
    pub tree_proof: P,
    pub root_after: Num<Fr>,
    pub delta: Num<Fr>,
    pub out_commit: Num<Fr>,
    pub nullifier: Num<Fr>,
    pub memo: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub token_id: String,
}

impl<Fr: PrimeField, P: Proof> Debug for TxData<Fr, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxData")
            .field("tx_type", &self.tx_type)
            .field("proof", &DebugProof(&self.proof))
            .field("tree_proof", &DebugProof(&self.tree_proof))
            .field("root_after", &self.root_after)
            .field("delta", &self.delta)
            .field("out_commit", &self.out_commit)
            .field("nullifier", &self.nullifier)
            .field("memo", &self.memo)
            .field("extra_data", &self.extra_data)
            .field("token_id", &self.token_id)
            .finish()
    }
}

impl<Fr: PrimeField, P: Proof> Clone for TxData<Fr, P> {
    fn clone(&self) -> Self {
        Self {
            tx_type: self.tx_type,
            proof: self.proof.my_clone(),
            tree_proof: self.tree_proof.my_clone(),
            root_after: self.root_after.clone(),
            delta: self.delta.clone(),
            out_commit: self.out_commit.clone(),
            nullifier: self.nullifier.clone(),
            memo: self.memo.clone(),
            extra_data: self.extra_data.clone(),
            token_id: self.token_id.clone(),
        }
    }
}

impl<Fr: PrimeField, P: Proof> PartialEq for TxData<Fr, P> {
    fn eq(&self, other: &Self) -> bool {
        self.tx_type == other.tx_type
            && self.proof.my_eq(&other.proof)
            && self.tree_proof.my_eq(&other.tree_proof)
            && self.root_after == other.root_after
            && self.delta == other.delta
            && self.out_commit == other.out_commit
            && self.nullifier == other.nullifier
            && self.memo == other.memo
            && self.extra_data == other.extra_data
    }
}

impl<Fr: PrimeField, P: Proof> Eq for TxData<Fr, P> {}
