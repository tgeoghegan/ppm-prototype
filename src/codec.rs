//! TLS encoding routines cribbed from rustls.
//!
//! # Opaque byte strings
//!
//! TLS syntax supports [variable length vectors](https://datatracker.ietf.org/doc/html/rfc8446#section-3.4)
//! of objects. The wire encoding is to write the number of objects in the vector and then the
//! concatenated objects. TLS also defines an [`opaque`](https://datatracker.ietf.org/doc/html/rfc8446#section-3.2)
//! type for opaque bytes.
//!
//! The `encode_vec_*` and `read_vec_*` functions in this module are intended for reading and
//! writing sequences of encodable or decodable objects as _opaque byte strings_. Even though they
//! operate on slices or vectors of objects that implement [`prio::codec::Decode`] or
//! [`prio::codec::Encode`], they will treat the length prefix at the beginning of an encoded vector
//! as a count of _bytes_, not a count of encoded objects.

use prio::codec::{Decode, Encode};
use std::{convert::TryInto, io::Cursor};

/// Encode the `items` into `bytes` as an opaque byte string of maximum length
/// `0xff`.
pub fn encode_vec_u8<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    let len_offset = bytes.len();
    bytes.push(0);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 1;
    debug_assert!(len <= 0xff);
    bytes[len_offset] = len as u8;
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as an opaque
/// byte string of maximum length `0xff`.
pub fn decode_vec_u8<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    // Read one byte to get length of opaque byte vector
    let length = usize::from(u8::decode(&(), bytes)?);

    decode_vec(length, decoding_parameter, bytes)
}

/// Encode the `items` into `bytes` as an opaque byte string of maximum length
/// `0xffff`.
pub fn encode_vec_u16<E: Encode>(bytes: &mut Vec<u8>, items: &[E]) {
    let len_offset = bytes.len();
    bytes.extend(&[0, 0]);

    for i in items {
        i.encode(bytes);
    }

    let len = bytes.len() - len_offset - 2;
    debug_assert!(len <= 0xffff);
    let out: &mut [u8; 2] = (&mut bytes[len_offset..len_offset + 2]).try_into().unwrap();
    *out = u16::to_be_bytes(len as u16);
}

/// Decode `bytes` into a vector of `D` values, treating `bytes` as an opaque
/// byte string of maximum length `0xffff`.
pub fn decode_vec_u16<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    // Read two bytes to get length of opaque byte vector
    let length = usize::from(u16::decode(&(), bytes)?);

    decode_vec(length, decoding_parameter, bytes)
}

fn decode_vec<P, E: From<std::io::Error>, D: Decode<P, Error = E>>(
    length: usize,
    decoding_parameter: &P,
    bytes: &mut Cursor<&[u8]>,
) -> Result<Vec<D>, D::Error> {
    let mut decoded: Vec<D> = Vec::new();
    let initial_position = bytes.position() as usize;

    // Create cursor over specified portion of provided cursor to ensure we
    // can't read past len
    let mut sub = Cursor::new(&bytes.get_ref()[initial_position..initial_position + length]);

    while sub.position() < length as u64 {
        decoded.push(D::decode(decoding_parameter, &mut sub)?);
    }

    Ok(decoded)
}
