use std::{
    fmt::{Debug, Formatter},
    io::{Read, Write},
};

use byteorder::{ReadBytesExt, WriteBytesExt};
#[cfg(feature = "groth16")]
use fawkes_crypto::backend::bellman_groth16::{
    engines::Engine as Groth16Engine, group::G1Point as Groth16G1Point,
    group::G2Point as Groth16G2Point, prover::Proof as Groth16Proof,
};
#[cfg(feature = "plonk")]
use fawkes_crypto::backend::plonk::prover::Proof as PlonkProof;
use serde::{Deserialize, Serialize};

use crate::utils::ByteOrderExt;
#[cfg(feature = "groth16")]
use crate::utils::{read_num, write_num};

// TODO: Find a more elegant way to do this or just implement this in fawkes-crypto.
pub trait Proof: Serialize + for<'a> Deserialize<'a> {
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result;
    fn my_clone(&self) -> Self;
    fn my_eq(&self, other: &Self) -> bool;
    fn write<O: ByteOrderExt, W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    fn read<O: ByteOrderExt, R: Read>(r: &mut R) -> std::io::Result<Self>;
}

pub struct DebugProof<'a, P: Proof>(pub &'a P);

impl<'a, P: Proof> Debug for DebugProof<'a, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.debug_fmt(f)
    }
}

#[cfg(feature = "groth16")]
impl<E: Groth16Engine> Proof for Groth16Proof<E> {
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("a", &(self.a.0, self.a.1))
            .field("b", &(self.b.0 .0, self.b.0 .1, self.b.1 .0, self.b.1 .1))
            .field("c", &(self.c.0, self.c.1))
            .finish()
    }

    fn my_clone(&self) -> Self {
        Self {
            a: Groth16G1Point(self.a.0, self.a.1),
            b: Groth16G2Point(self.b.0, self.b.1),
            c: Groth16G1Point(self.c.0, self.c.1),
        }
    }

    fn my_eq(&self, other: &Self) -> bool {
        self.a.0 == other.a.0
            && self.a.1 == other.a.1
            && self.b.0 .0 == other.b.0 .0
            && self.b.0 .1 == other.b.0 .1
            && self.b.1 .0 == other.b.1 .0
            && self.b.1 .1 == other.b.1 .1
            && self.c.0 == other.c.0
            && self.c.1 == other.c.1
    }

    fn write<O: ByteOrderExt, W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        let mut bytes = [0u8; 32 * 8];

        {
            let w = &mut &mut bytes[..];
            write_num::<O, _, E::Fq>(w, &self.a.0)?;
            write_num::<O, _, E::Fq>(w, &self.a.1)?;

            write_num::<O, _, E::Fq>(w, &self.b.0 .0)?;
            write_num::<O, _, E::Fq>(w, &self.b.0 .1)?;
            write_num::<O, _, E::Fq>(w, &self.b.1 .0)?;
            write_num::<O, _, E::Fq>(w, &self.b.1 .1)?;

            write_num::<O, _, E::Fq>(w, &self.c.0)?;
            write_num::<O, _, E::Fq>(w, &self.c.1)?;
        }

        w.write_all(&bytes)
    }

    fn read<O: ByteOrderExt, R: Read>(r: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32 * 8];
        r.read_exact(&mut bytes)?;

        let mut r = &bytes[..];
        let a = Groth16G1Point(
            read_num::<O, _, E::Fq>(&mut r)?,
            read_num::<O, _, E::Fq>(&mut r)?,
        );
        let b = Groth16G2Point(
            (
                read_num::<O, _, E::Fq>(&mut r)?,
                read_num::<O, _, E::Fq>(&mut r)?,
            ),
            (
                read_num::<O, _, E::Fq>(&mut r)?,
                read_num::<O, _, E::Fq>(&mut r)?,
            ),
        );
        let c = Groth16G1Point(
            read_num::<O, _, E::Fq>(&mut r)?,
            read_num::<O, _, E::Fq>(&mut r)?,
        );

        Ok(Self { a, b, c })
    }
}

#[cfg(feature = "plonk")]
impl Proof for PlonkProof {
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }

    fn my_clone(&self) -> Self {
        self.clone()
    }

    fn my_eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    fn write<O: ByteOrderExt, W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u32::<O>(self.0.len() as u32)?;
        w.write_all(&self.0)?;

        Ok(())
    }

    fn read<O: ByteOrderExt, R: Read>(r: &mut R) -> std::io::Result<Self> {
        let len = r.read_u32::<O>()?;
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;

        Ok(Self(buf))
    }
}
