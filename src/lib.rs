use std::fmt::Debug;
use fawkes_crypto::{
    backend::bellman_groth16::{engines::Engine, prover::Proof},
    ff_uint::Num,
};
use fawkes_crypto::backend::bellman_groth16::group::{G1Point, G2Point};
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

struct DebugProof<'a, E: Engine>(&'a Proof<E>);

impl<'a, E: Engine> Debug for DebugProof<'a, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("a", &(self.0.a.0, self.0.a.1))
            .field("b", &(self.0.b.0.0, self.0.b.0.1, self.0.b.1.0, self.0.b.1.1))
            .field("c", &(self.0.c.0, self.0.c.1))
            .finish()
    }
}

impl<E: Engine> Debug for TxData<E> {
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

impl<E: Engine> Clone for TxData<E> {
    fn clone(&self) -> Self {
        Self {
            tx_type: self.tx_type,
            proof: Proof {
                a: G1Point(self.proof.a.0, self.proof.a.1),
                b: G2Point(self.proof.b.0, self.proof.b.1),
                c: G1Point(self.proof.c.0, self.proof.c.1),
            },
            tree_proof: Proof {
                a: G1Point(self.tree_proof.a.0, self.tree_proof.a.1),
                b: G2Point(self.tree_proof.b.0, self.tree_proof.b.1),
                c: G1Point(self.tree_proof.c.0, self.tree_proof.c.1),
            },
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