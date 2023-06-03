use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::backend::bellman_groth16::engines::Engine;

use crate::{
    utils::{read_num, read_proof, write_num, write_proof},
    TxData, TxType,
};

const SELECTOR: &[u8] = &[0x8a, 0x40, 0x68, 0xdd];

pub fn read<R: Read, E: Engine>(r: &mut R) -> Result<TxData<E>> {
    let mut selector = [0u8; 4];
    r.read_exact(&mut selector)?;

    if selector != SELECTOR {
        return Err(Error::new(ErrorKind::InvalidData, "invalid selector"));
    }

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

    let tx_type = TxType::try_from(tx_type)?;

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
        token_id: String::new(),
    })
}

pub fn write<W: Write, E: Engine>(data: &TxData<E>, w: &mut W) -> Result<()> {
    w.write_all(SELECTOR)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.nullifier)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.out_commit)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.delta)?;
    write_proof::<BigEndian, _, E>(w, &data.proof)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.root_after)?;
    write_proof::<BigEndian, _, E>(w, &data.tree_proof)?;
    w.write_u16::<BigEndian>(data.tx_type as u16)?;
    w.write_u16::<BigEndian>(data.memo.len() as u16)?;
    w.write_all(&data.memo)?;
    w.write_all(&data.extra_data)?;

    Ok(())
}
