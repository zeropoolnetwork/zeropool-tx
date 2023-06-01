use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::{
    backend::bellman_groth16::{engines::Engine, prover::Proof},
    ff_uint::{Num, PrimeField},
};
use serde::{Deserialize, Serialize};

use crate::utils::{read_num, read_proof, write_num, write_proof};

mod evm;
mod near;
mod substrate;
mod utils;
mod waves;

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

#[derive(Serialize, Deserialize)]
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
}

// TODO: Split into separate modules?
impl<E: Engine> TxData<E> {
    pub fn read_evm<R: Read>(r: &mut R) -> Result<Self> {
        // TODO: Validate selector
        let _ = r.read_u32::<BigEndian>()?;

        let nullifier = read_num::<BigEndian, _, E::Fr>(r)?;
        let out_commit = read_num::<BigEndian, _, E::Fr>(r)?;
        let delta = read_num::<BigEndian, _, E::Fr>(r)?;
        let proof = read_proof::<BigEndian, _, E>(r)?;
        let root_after = read_num::<BigEndian, _, E::Fr>(r)?;
        let tree_proof = read_proof::<BigEndian, _, E>(r)?;
        let tx_type = r.read_u16::<BigEndian>()?;
        let memo_len = r.read_u16::<BigEndian>()?;
        let mut memo = vec![0u8; memo_len as usize];
        r.read_exact(&mut memo)?;
        let mut extra_data = vec![];
        r.read_to_end(&mut extra_data)?;

        // TODO: Consider using FromPrimitive
        let tx_type = match tx_type {
            0 => TxType::Deposit,
            1 => TxType::Transfer,
            2 => TxType::Withdraw,
            _ => return Err(Error::new(ErrorKind::InvalidData, "invalid tx type")),
        };

        Ok(TxData {
            nullifier,
            out_commit,
            delta,
            proof,
            root_after,
            tree_proof,
            tx_type,
            memo,
            extra_data,
        })
    }

    pub fn write_evm<W: Write>(&self, w: &mut W) -> Result<()> {
        const SELECTOR: &[u8] = &[0x8a, 0x40, 0x68, 0xdd];
        w.write_all(SELECTOR)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.nullifier)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.out_commit)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.delta)?;
        write_proof::<BigEndian, _, E>(w, &self.proof)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.root_after)?;
        write_proof::<BigEndian, _, E>(w, &self.tree_proof)?;
        w.write_u16::<BigEndian>(self.tx_type as u16)?;
        w.write_u16::<BigEndian>(self.memo.len() as u16)?;
        w.write_all(&self.memo)?;
        w.write_all(&self.extra_data)?;

        Ok(())
    }

    pub fn read_waves<R: Read>(r: &mut R) -> Result<Self> {
        let nullifier = read_num::<BigEndian, _, E::Fr>(r)?;
        let out_commit = read_num::<BigEndian, _, E::Fr>(r)?;
        let mut asset_id = [0u8; 32];
        r.read_exact(&mut asset_id)?;
        let delta = read_num::<BigEndian, _, E::Fr>(r)?;
        let tx_proof = read_proof::<BigEndian, _, E>(r)?;
        let tree_proof = read_proof::<BigEndian, _, E>(r)?;
        let root_after = read_num::<BigEndian, _, E::Fr>(r)?;
        let tx_type = r.read_u16::<BigEndian>()?;

        let mut memo_data = vec![];
        r.read_to_end(&mut memo_data)?;

        let tx_type = match tx_type {
            0 => TxType::Deposit,
            1 => TxType::Transfer,
            2 => TxType::Withdraw,
            _ => return Err(Error::new(ErrorKind::InvalidData, "invalid tx type")),
        };

        let (memo, extra_data) = if tx_type == TxType::Deposit {
            (memo_data, Vec::new())
        } else {
            let memo = memo_data[..memo_data.len() - 64 - 32].to_vec();
            let extra_data = memo_data[memo_data.len() - 64 - 32..].to_vec();
            (memo, extra_data)
        };

        Ok(TxData {
            tx_type,
            proof: tx_proof,
            tree_proof,
            root_after,
            delta,
            out_commit,
            nullifier,
            memo: memo.to_vec(),
            extra_data: extra_data.to_vec(),
        })
    }

    pub fn write_waves<W: Write>(&self, w: &mut W) -> Result<()> {
        // # nullifier          32 bytes
        // # outCommit         32 bytes
        // # assetId           32 bytes
        // # delta             32 bytes
        // #     nativeAmount   8 bytes
        // #     nativeEnergy  14 bytes
        // #     txIndex        6 bytes
        // #     poolId         3 bytes
        // # txProof          256 bytes
        // # treeProof        256 bytes
        // # rootAfter         32 bytes
        // # txType             2 bytes
        // # memo               dynamic bytes
        // # depositPk          optional 32 bytes
        // # depositSignature   optional 64 bytes
        let mut buf = vec![];

        write_num::<BigEndian, _, _>(w, &self.nullifier)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.out_commit)?;
        write_num::<BigEndian, _, E::Fr>(w, &Num::<E::Fr>::ZERO)?; // TODO: Change once support for different asset ids is added
        write_num::<BigEndian, _, E::Fr>(w, &self.delta)?;
        write_proof::<BigEndian, _, E>(w, &self.proof)?;
        write_proof::<BigEndian, _, E>(w, &self.tree_proof)?;
        write_num::<BigEndian, _, E::Fr>(w, &self.root_after)?;
        buf.write_u16::<BigEndian>(self.tx_type as u16)?;
        buf.write_all(&self.memo)?;
        buf.write_all(&self.extra_data)?;

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use std::io::Cursor;

//     use super::*;

//     #[test]
//     fn test_read_write_evm() {
//         let mut rng = rand::thread_rng();

//         let nullifier = Fr::random(&mut rng);
//         let out_commit = Fr::random(&mut rng);
//         let delta = Fr::random(&mut rng);
//         let proof = Proof::rng(&mut rng);
//         let root_after = Fr::random(&mut rng);
//         let tree_proof = Proof::random(&mut rng);
//         let tx_type = TxType::Deposit;
//         let memo = b"hello world".to_vec();
//         let extra_data = b"extra data".to_vec();

//         let tx_data = TxData {
//             nullifier,
//             out_commit,
//             delta,
//             proof,
//             root_after,
//             tree_proof,
//             tx_type,
//             memo: memo.clone(),
//             extra_data: extra_data.clone(),
//         };

//         let mut buf = Cursor::new(Vec::new());
//         tx_data.write_evm(&mut buf).unwrap();

//         buf.set_position(0);
//         let tx_data2 = TxData::read_evm(&mut buf).unwrap();

//         assert_eq!(tx_data.nullifier, tx_data2.nullifier);
//         assert_eq!(tx_data.out_commit, tx_data2.out_commit);
//         assert_eq!(tx_data.delta, tx_data2.delta);
//         assert_eq!(tx_data.proof, tx_data2.proof);
//         assert_eq!(tx_data.root_after, tx_data2.root_after);
//         assert_eq!(tx_data.tree_proof, tx_data2.tree_proof);
//         assert_eq!(tx_data.tx_type, tx_data2.tx_type);
//         assert_eq!(tx_data.memo, tx_data2.memo);
//         assert_eq!(tx_data.extra_data, tx_data2.extra_data);
//     }
// }
