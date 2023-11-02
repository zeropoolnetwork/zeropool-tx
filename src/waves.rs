use std::io::{Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::{backend::bellman_groth16::engines::Engine, ff_uint::Num};

use crate::{
    utils::{read_num, read_proof, write_num, write_proof},
    TxData, TxType,
};

pub fn read<R: Read, E: Engine>(r: &mut R) -> Result<TxData<E>> {
    let mut selector = [0u8; 4];
    r.read_exact(&mut selector)?;

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

    write_num::<BigEndian, _, _>(w, &data.nullifier)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.out_commit)?;
    write_num::<BigEndian, _, E::Fr>(w, &Num::<E::Fr>::ZERO)?; // TODO: Change once support for different asset ids is added
    write_num::<BigEndian, _, E::Fr>(w, &data.delta)?;
    write_proof::<BigEndian, _, E>(w, &data.proof)?;
    write_proof::<BigEndian, _, E>(w, &data.tree_proof)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.root_after)?;
    buf.write_u16::<BigEndian>(data.tx_type as u16)?;
    buf.write_all(&data.memo)?;
    buf.write_all(&data.extra_data)?;

    Ok(())
}
