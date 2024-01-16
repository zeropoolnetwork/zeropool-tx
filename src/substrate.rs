use std::io::{Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::ff_uint::PrimeField;

use crate::{
    proof::Proof,
    utils::{read_num, write_num},
    TxData, TxType,
};

pub fn read<R: Read, Fr: PrimeField, P: Proof>(r: &mut R) -> Result<TxData<Fr, P>> {
    let nullifier = read_num::<BigEndian, _, Fr>(r)?;
    let out_commit = read_num::<BigEndian, _, Fr>(r)?;
    let mut asset_id = [0u8; 32];
    r.read_exact(&mut asset_id)?;
    let delta = read_num::<BigEndian, _, Fr>(r)?;
    let tx_proof = P::read::<BigEndian, _>(r)?;
    let tree_proof = P::read::<BigEndian, _>(r)?;
    let root_after = read_num::<BigEndian, _, Fr>(r)?;
    let tx_type = r.read_u16::<BigEndian>()?;

    let mut memo_data = vec![];
    r.read_to_end(&mut memo_data)?;

    let tx_type = TxType::try_from(tx_type)?;

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
        memo,
        extra_data,
        token_id: String::new(), // FIXME
    })
}

pub fn write<W: Write, Fr: PrimeField, P: Proof>(data: &TxData<Fr, P>, w: &mut W) -> Result<()> {
    const SELECTOR: &[u8] = &[0, 0, 0, 0];

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
