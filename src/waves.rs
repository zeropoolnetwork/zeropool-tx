use std::io::{Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::{backend::bellman_groth16::engines::Engine, ff_uint::Num};

use crate::{
    utils::{read_num, read_proof, write_num, write_proof},
    TxData, TxType,
};

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

pub fn read<R: Read, E: Engine>(r: &mut R) -> Result<TxData<E>> {
    let nullifier = read_num::<BigEndian, _, E::Fr>(r)?;
    let out_commit = read_num::<BigEndian, _, E::Fr>(r)?;
    let _asset_id = read_num::<BigEndian, _, E::Fr>(r)?;
    let delta = read_num::<BigEndian, _, E::Fr>(r)?;
    let proof = read_proof::<BigEndian, _, E>(r)?;
    let tree_proof = read_proof::<BigEndian, _, E>(r)?;
    let root_after = read_num::<BigEndian, _, E::Fr>(r)?;
    let tx_type = r.read_u16::<BigEndian>()?;

    let tx_type = TxType::try_from(tx_type)?;

    let (memo, extra_data) = if tx_type == TxType::Deposit {
        let mut buf = vec![];
        r.read_to_end(&mut buf)?;
        let deposit_data_size = 32 + 64;
        let memo_size = buf.len() - deposit_data_size;
        let memo = buf[..memo_size].to_vec();
        let extra_data = buf[memo_size..].to_vec();
        (memo, extra_data)
    } else {
        let mut memo = vec![];
        r.read_to_end(&mut memo)?;
        (memo, vec![])
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
        token_id: String::new(),
    })
}

pub fn write<W: Write, E: Engine>(data: &TxData<E>, w: &mut W) -> Result<()> {
    write_num::<BigEndian, _, _>(w, &data.nullifier)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.out_commit)?;
    write_num::<BigEndian, _, E::Fr>(w, &Num::<E::Fr>::ZERO)?; // TODO: Change once support for different asset ids is added
    write_num::<BigEndian, _, E::Fr>(w, &data.delta)?;
    write_proof::<BigEndian, _, E>(w, &data.proof)?;
    write_proof::<BigEndian, _, E>(w, &data.tree_proof)?;
    write_num::<BigEndian, _, E::Fr>(w, &data.root_after)?;
    w.write_u16::<BigEndian>(data.tx_type as u16)?;
    w.write_all(&data.memo)?;
    w.write_all(&data.extra_data)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use fawkes_crypto::backend::bellman_groth16::{
        engines::Bn256,
        group::{G1Point, G2Point},
        prover::Proof,
    };

    use super::*;

    #[test]
    fn test_waves_write_read_deposit() {
        use std::io::Cursor;

        let data = TxData::<Bn256> {
            nullifier: Num::from(1u64),
            out_commit: Num::from(2u64),
            delta: Num::from(3u64),
            proof: zero_proof(),
            root_after: Num::from(4u64),
            tree_proof: zero_proof(),
            tx_type: TxType::Deposit,
            memo: vec![5u8, 6u8],
            extra_data: vec![9; 32 + 64],
            token_id: String::new(),
        };

        let mut buf = vec![];
        write(&data, &mut buf).unwrap();

        assert_eq!(
            buf.len(),
            32 + 32 + 32 + 32 + 256 + 256 + 32 + 2 + 2 + 32 + 64
        );

        let mut cursor = Cursor::new(buf);
        let data2 = read::<_, Bn256>(&mut cursor).unwrap();

        assert_eq!(data, data2);
    }

    #[test]
    fn test_waves_write_read() {
        use std::io::Cursor;

        let data = TxData::<Bn256> {
            nullifier: Num::from(1u64),
            out_commit: Num::from(2u64),
            delta: Num::from(3u64),
            proof: zero_proof(),
            root_after: Num::from(4u64),
            tree_proof: zero_proof(),
            tx_type: TxType::Transfer,
            memo: vec![5u8, 6u8],
            extra_data: vec![],
            token_id: String::new(),
        };

        let mut buf = vec![];
        write(&data, &mut buf).unwrap();

        assert_eq!(buf.len(), 32 + 32 + 32 + 32 + 256 + 256 + 32 + 2 + 2);

        let mut cursor = Cursor::new(buf);
        let data2 = read::<_, Bn256>(&mut cursor).unwrap();

        assert_eq!(data, data2);
    }

    fn zero_proof<E: Engine>() -> Proof<E> {
        Proof {
            a: G1Point(Num::ZERO, Num::ZERO),
            b: G2Point((Num::ZERO, Num::ZERO), (Num::ZERO, Num::ZERO)),
            c: G1Point(Num::ZERO, Num::ZERO),
        }
    }
}
