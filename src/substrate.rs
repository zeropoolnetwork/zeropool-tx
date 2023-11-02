use std::io::{Read, Result, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use fawkes_crypto::{backend::bellman_groth16::engines::Engine};

use crate::{
    utils::{read_num, read_proof, write_num, write_proof},
    TxData, TxType,
};

pub fn read<R: Read, E: Engine>(r: &mut R) -> Result<TxData<E>> {
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

pub fn write<W: Write, E: Engine>(data: &TxData<E>, w: &mut W) -> Result<()> {
    const SELECTOR: &[u8] = &[0, 0, 0, 0];

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

// // Sizes
// const NUM_SIZE: usize = 32;
// const PROOF_SIZE: usize = NUM_SIZE * 8;
// const DELTA_SIZE: usize = 28;
// const BALANCE_SIZE: usize = 8;
// const ADDRESS_SIZE: usize = 32;
// const SIGNATURE_SIZE: usize = 64;
// const MEMO_META_SIZE: usize = 8;

// // Offsets
// // const SELECTOR: usize = 0;
// const NULLIFIER: usize = 4;
// const OUT_COMMIT: usize = NULLIFIER + NUM_SIZE;
// const TRANSFER_INDEX: usize = OUT_COMMIT + NUM_SIZE;
// const ENERGY_AMOUNT: usize = TRANSFER_INDEX + 6;
// const TOKEN_AMOUNT: usize = ENERGY_AMOUNT + 14;
// const TRANSACT_PROOF: usize = TOKEN_AMOUNT + 8;
// const ROOT_AFTER: usize = TRANSACT_PROOF + PROOF_SIZE;
// const TREE_PROOF: usize = ROOT_AFTER + NUM_SIZE;
// const TX_TYPE: usize = TREE_PROOF + PROOF_SIZE;
// const MEMO_SIZE: usize = TX_TYPE + 2;
// const MEMO: usize = MEMO_SIZE + 2;
// const MEMO_FEE: usize = MEMO;
// const MEMO_NATIVE_AMOUNT: usize = MEMO_FEE + 8;
// const MEMO_ADDRESS: usize = MEMO_NATIVE_AMOUNT + 8;

// #[derive(Debug, PartialEq, Eq, BorshDeserialize, FromPrimitive)]
// #[repr(u16)]
// pub enum TxType {
//     Deposit = 0,
//     Transfer = 1,
//     Withdraw = 2,
// }
// pub struct TxDecoder<'a> {
//     data: &'a [u8],
// }

// impl<'a> TxDecoder<'a> {
//     pub fn new(data: &'a [u8]) -> Self {
//         TxDecoder { data }
//     }

//     #[inline]
//     pub fn nullifier(&self) -> U256 {
//         U256::from_big_endian(&self.data[NULLIFIER..(NULLIFIER + NUM_SIZE)])
//     }

//     #[inline]
//     pub fn nullifier_bytes(&self) -> &[u8] {
//         &self.data[NULLIFIER..(NULLIFIER + NUM_SIZE)]
//     }

//     #[inline]
//     pub fn out_commit(&self) -> U256 {
//         U256::from_big_endian(&self.data[OUT_COMMIT..(OUT_COMMIT + NUM_SIZE)])
//     }

//     #[inline]
//     pub fn transfer_index(&self) -> U256 {
//         U256::from_big_endian(&self.data[TRANSFER_INDEX..(TRANSFER_INDEX + 6)])
//     }

//     #[inline]
//     pub fn energy_amount(&self) -> U256 {
//         let num = U256::from_big_endian(&self.data[ENERGY_AMOUNT..(ENERGY_AMOUNT + 14)]);
//         ensure_twos_complement(num, 112)
//     }

//     #[inline]
//     pub fn token_amount(&self) -> U256 {
//         let num = U256::from_big_endian(&self.data[TOKEN_AMOUNT..(TOKEN_AMOUNT + 8)]);
//         ensure_twos_complement(num, 64)
//     }

//     #[inline]
//     pub fn delta(&self) -> U256 {
//         let delta: [u8; DELTA_SIZE] =
//             self.data[TRANSFER_INDEX..(TRANSFER_INDEX + DELTA_SIZE)].try_into().unwrap();
//         U256::from_big_endian(&delta)
//     }

//     #[inline]
//     pub fn transact_proof(&self) -> Proof {
//         decode_proof(&self.data[TRANSACT_PROOF..(TRANSACT_PROOF + PROOF_SIZE)])
//     }

//     #[inline]
//     pub fn root_after(&self) -> U256 {
//         U256::from_big_endian(&self.data[ROOT_AFTER..(ROOT_AFTER + NUM_SIZE)])
//     }

//     #[inline]
//     pub fn tree_proof(&self) -> Proof {
//         decode_proof(&self.data[TREE_PROOF..(TREE_PROOF + PROOF_SIZE)])
//     }

//     #[inline]
//     pub fn tx_type(&self) -> TxType {
//         let bytes = self.data[TX_TYPE..(TX_TYPE + 2)].try_into().unwrap();
//         let num = u16::from_be_bytes(bytes);
//         TxType::from_u16(num).unwrap()
//     }

//     #[inline]
//     pub fn memo_size(&self) -> usize {
//         u16::from_be_bytes(self.data[MEMO_SIZE..(MEMO_SIZE + 2)].try_into().unwrap()) as usize
//     }

//     #[inline]
//     pub fn memo_message(&self) -> &'a [u8] {
//         &self.data[MEMO..(MEMO + self.memo_size())]
//     }

//     #[inline]
//     pub fn memo_fee(&self) -> U256 {
//         U256::from_big_endian(&self.data[MEMO_FEE..(MEMO_FEE + BALANCE_SIZE)])
//     }

//     #[inline]
//     pub fn memo_native_amount(&self) -> U256 {
//         U256::from_big_endian(&self.data[MEMO_NATIVE_AMOUNT..(MEMO_NATIVE_AMOUNT + BALANCE_SIZE)])
//     }

//     #[inline]
//     pub fn memo_address(&self) -> &[u8] {
//         &self.data[MEMO_ADDRESS..(MEMO_ADDRESS + ADDRESS_SIZE)]
//     }

//     #[inline]
//     pub fn ciphertext(&self) -> &[u8] {
//         let offset = if self.tx_type() == TxType::Withdraw {
//             MEMO_ADDRESS + ADDRESS_SIZE
//         } else {
//             MEMO_FEE + BALANCE_SIZE
//         };

//         let data_size = offset - MEMO;

//         &self.data[offset..(offset + self.memo_size() - data_size)]
//     }

//     #[inline]
//     pub fn deposit_address(&self) -> &[u8] {
//         let offset = MEMO + self.memo_size();
//         &self.data[offset..(offset + ADDRESS_SIZE)]
//     }

//     #[inline]
//     pub fn deposit_signature(&self) -> &[u8] {
//         let offset = MEMO + self.memo_size() + ADDRESS_SIZE;
//         &self.data[offset..(offset + SIGNATURE_SIZE)]
//     }
// }
