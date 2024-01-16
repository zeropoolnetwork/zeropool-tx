use std::io::{Error, ErrorKind, Read, Result, Write};

use byteorder::ByteOrder;
use fawkes_crypto::ff_uint::{Num, NumRepr, PrimeField, Uint};

#[derive(Eq, PartialEq)]
pub enum Endianness {
    Little,
    Big,
}

pub trait ByteOrderExt: ByteOrder {
    const ENDIANNESS: Endianness;
}

impl ByteOrderExt for byteorder::LittleEndian {
    const ENDIANNESS: Endianness = Endianness::Little;
}

impl ByteOrderExt for byteorder::BigEndian {
    const ENDIANNESS: Endianness = Endianness::Big;
}

pub fn read_num<O: ByteOrderExt, R: Read, P: PrimeField>(r: &mut R) -> Result<Num<P>> {
    let mut bytes = [0u8; 32];
    r.read_exact(&mut bytes)?;

    let uint = if O::ENDIANNESS == Endianness::Little {
        P::Inner::from_little_endian(&bytes)
    } else {
        P::Inner::from_big_endian(&bytes)
    };

    Num::from_uint(NumRepr(uint))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid field element"))
}

pub fn write_num<O: ByteOrderExt, W: Write, P: PrimeField>(
    buf: &mut W,
    num: &Num<P>,
) -> Result<()> {
    let mut bytes = [0u8; 32];
    let uint = num.to_uint().0;

    if O::ENDIANNESS == Endianness::Little {
        uint.put_little_endian(&mut bytes);
    } else {
        uint.put_big_endian(&mut bytes);
    }

    buf.write_all(&bytes)
}
