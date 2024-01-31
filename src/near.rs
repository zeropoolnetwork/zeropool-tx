use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::ff_uint::{Num, PrimeField};

use crate::{
    proof::Proof,
    utils::{read_num, write_num},
    TxData, TxType,
};

pub fn read<R: Read, Fr: PrimeField, P: Proof>(r: &mut R) -> Result<TxData<Fr, P>> {
    let nullifier = read_num::<LittleEndian, _, Fr>(r)?;
    let out_commit = read_num::<LittleEndian, _, Fr>(r)?;
    let token_id = read_borsh_string(r)?;
    let delta = read_num::<LittleEndian, _, Fr>(r)?;
    let tx_proof = P::read::<LittleEndian, _>(r)?;
    let root_after = read_num::<LittleEndian, _, Fr>(r)?;
    let tree_proof = P::read::<LittleEndian, _>(r)?;
    let tx_type = r.read_u8()?;

    let tx_type = TxType::try_from(tx_type as u16)?;

    let memo = read_borsh_array(r)?;
    let mut extra_data = vec![];
    r.read_to_end(&mut extra_data)?;

    Ok(TxData {
        tx_type,
        proof: tx_proof,
        tree_proof,
        root_after,
        delta,
        out_commit,
        nullifier,
        memo,
        extra_data,
        token_id,
    })
}

pub fn write<W: Write, Fr: PrimeField, P: Proof>(data: &TxData<Fr, P>, w: &mut W) -> Result<()> {
    let mut buf = vec![];

    write_num::<LittleEndian, _, _>(w, &data.nullifier)?;
    write_num::<LittleEndian, _, Fr>(w, &data.out_commit)?;
    write_borsh_string(w, &data.token_id)?;
    write_num::<LittleEndian, _, Fr>(w, &data.delta)?;
    data.proof.write::<LittleEndian, _>(w)?;
    write_num::<LittleEndian, _, Fr>(w, &data.root_after)?;
    data.tree_proof.write::<LittleEndian, _>(w)?;
    buf.write_u8(data.tx_type as u8)?;
    write_borsh_array(w, &data.memo)?;
    buf.write_all(&data.extra_data)?;

    Ok(())
}

fn read_borsh_string<R: Read>(r: &mut R) -> Result<String> {
    let len = r.read_u32::<LittleEndian>()?;
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf).map_err(|_| Error::new(ErrorKind::InvalidData, "invalid utf8"))?)
}

fn write_borsh_string<W: Write>(w: &mut W, s: &str) -> Result<()> {
    w.write_u32::<LittleEndian>(s.len() as u32)?;
    w.write_all(s.as_bytes())?;
    Ok(())
}

fn read_borsh_array<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u32::<LittleEndian>()?;
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_borsh_array<W: Write>(w: &mut W, s: &[u8]) -> Result<()> {
    w.write_u32::<LittleEndian>(s.len() as u32)?;
    w.write_all(s)?;
    Ok(())
}
