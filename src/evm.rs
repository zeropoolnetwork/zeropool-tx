use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::ff_uint::PrimeField;

use crate::{
    proof::Proof,
    utils::{read_num, write_num},
    TxData, TxType,
};

const SELECTOR: &[u8] = &[0x8a, 0x40, 0x68, 0xdd];

pub fn read<R: Read, Fr: PrimeField, P: Proof>(r: &mut R) -> Result<TxData<Fr, P>> {
    let mut selector = [0u8; 4];
    r.read_exact(&mut selector)?;

    if selector != SELECTOR {
        return Err(Error::new(ErrorKind::InvalidData, "invalid selector"));
    }

    let nullifier = read_num::<BigEndian, _, Fr>(r)?;
    let out_commit = read_num::<BigEndian, _, Fr>(r)?;
    let delta = read_num::<BigEndian, _, Fr>(r)?;
    let proof = P::read::<BigEndian, _>(r)?;
    let root_after = read_num::<BigEndian, _, Fr>(r)?;
    let tree_proof = P::read::<BigEndian, _>(r)?;
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

pub fn write<W: Write, Fr: PrimeField, P: Proof>(data: &TxData<Fr, P>, w: &mut W) -> Result<()> {
    w.write_all(SELECTOR)?;
    write_num::<BigEndian, _, Fr>(w, &data.nullifier)?;
    write_num::<BigEndian, _, Fr>(w, &data.out_commit)?;
    write_num::<BigEndian, _, Fr>(w, &data.delta)?;
    data.proof.write::<BigEndian, _>(w)?;
    write_num::<BigEndian, _, Fr>(w, &data.root_after)?;
    data.tree_proof.write::<BigEndian, _>(w)?;
    w.write_u16::<BigEndian>(data.tx_type as u16)?;
    w.write_u16::<BigEndian>(data.memo.len() as u16)?;
    w.write_all(&data.memo)?;
    w.write_all(&data.extra_data)?;

    Ok(())
}
