pub mod aggregate;
pub mod client;
pub mod collect;
mod error;
pub mod helper;
pub mod hpke;
pub mod leader;
pub mod parameters;
pub mod report;
pub mod trace;

use chrono::{DurationRound, TimeZone, Utc};
use directories::ProjectDirs;
use prio::codec::{CodecError, Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    io::Cursor,
    path::PathBuf,
};
use warp::Filter;

/// Seconds elapsed since start of UNIX epoch
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Time(pub u64);

impl Time {
    /// Determine the start of the aggregation window that this report falls in,
    /// assuming the provided minimum batch duration
    fn interval_start(self, min_batch_duration: Duration) -> Self {
        Self(
            Utc.timestamp(self.0 as i64, 0)
                .duration_trunc(chrono::Duration::seconds(min_batch_duration.0 as i64))
                .unwrap()
                .timestamp() as u64,
        )
    }

    fn add(self, duration: Duration) -> Self {
        Self(self.0 + duration.0)
    }

    /// Returns the batch interval that this instant falls into, based on the
    /// provided minimum batch duration.
    pub(crate) fn batch_interval(&self, min_batch_duration: Duration) -> Interval {
        Interval {
            start: self.interval_start(min_batch_duration),
            duration: min_batch_duration,
        }
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for Time {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Time {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// Seconds elapsed between two instances
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Duration(pub u64);

impl Duration {
    pub fn multiple(self, factor: u64) -> Self {
        Self(self.0 * factor)
    }
}

impl Display for Duration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for Duration {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.0.encode(bytes);
    }
}

impl Decode for Duration {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

/// Nonce used to uniquely identify a PPM report
//
// Deriving [`PartialOrd`] yields a "lexicographic ordering based on the
// top-to-bottom declaration order of the struct's members."
// https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Nonce {
    /// Time at which the report was generated
    pub time: Time,
    /// Randomly generated value
    pub rand: u64,
}

impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.time, self.rand)
    }
}

impl Encode for Nonce {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.time.encode(bytes);
        self.rand.encode(bytes);
    }
}

impl Decode for Nonce {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let time = Time::decode(bytes)?;
        let rand = u64::decode(bytes)?;

        Ok(Self { time, rand })
    }
}

/// Interval of time.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Interval {
    /// Start of the interval, included.
    pub start: Time,
    /// Length of the interval. `start + duration` is excluded.
    pub duration: Duration,
}

impl Interval {
    /// Construct the HPKE AEAD associated data for the interval.
    pub(crate) fn associated_data(&self) -> Vec<u8> {
        [self.start.0.to_be_bytes(), self.duration.0.to_be_bytes()].concat()
    }

    /// Compute how many times an interval of length `duration` would fit in
    /// this interval.
    pub(crate) fn intervals_in_interval(&self, duration: Duration) -> u64 {
        self.duration.0 / duration.0
    }
}

impl Display for Interval {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[{} - {})", self.start, self.start.add(self.duration))
    }
}

impl Encode for Interval {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.start.encode(bytes);
        self.duration.encode(bytes);
    }
}

impl Decode for Interval {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let start = Time::decode(bytes)?;
        let duration = Duration::decode(bytes)?;

        Ok(Self { start, duration })
    }
}

/// The roles that protocol participants can adopt
#[derive(Copy, Clone, Debug, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Collector = 0x00,
    Client = 0x01,
    Leader = 0x02,
    Helper = 0x03,
}

impl Role {
    /// Returns the index into protocol message vectors at which this role's
    /// entry can be found. e.g., the leader's input share in a `Report` is
    /// `Report.encrypted_input_shares[Role::Leader.index()]`.
    pub fn index(self) -> usize {
        // TODO: this doesn't make sense anymore
        match self {
            Role::Leader => 0,
            Role::Helper => 1,
            r => panic!("unexpected role {:?}", r),
        }
    }
}

/// Path relative to which configuration files may be found.
pub(crate) fn config_path() -> PathBuf {
    let project_path = ProjectDirs::from("org", "isrg", "ppm-prototype").unwrap();
    project_path.config_dir().to_path_buf()
}

/// Injects a clone of the provided value into the warp filter, making it
/// available to the filter's map() or and_then() handler.
pub fn with_shared_value<T: Clone + Sync + Send>(
    value: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || value.clone())
}

mod base64 {
    //! Custom serialization module used to serialize byte sequences to base64
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize_bytes<V: AsRef<[u8]>, S: Serializer>(v: &V, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&base64::encode(&v), s)
    }

    pub fn deserialize_bytes<'de, D: Deserializer<'de>, V: From<Vec<u8>>>(
        d: D,
    ) -> Result<V, D::Error> {
        let bytes = base64::decode(String::deserialize(d)?.as_bytes()).map_err(Error::custom)?;
        let v = V::from(bytes);
        Ok(v)
    }

    pub fn serialize_bytes_vec<V: AsRef<[u8]>, S: Serializer>(
        v: &[V],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let b64_strings: Vec<String> = v.iter().map(base64::encode).collect();

        <Vec<String>>::serialize(&b64_strings, s)
    }

    pub fn deserialize_bytes_vec<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let b64_strings = <Vec<String>>::deserialize(d)?;

        let b64_vecs = b64_strings
            .iter()
            .map(|s| base64::decode(s).map_err(Error::custom))
            .collect::<Result<_, _>>()?;

        Ok(b64_vecs)
    }

    pub fn serialize_bytes_option<V: AsRef<[u8]>, S: Serializer>(
        v: &Option<V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => String::serialize(&base64::encode(&v), s),
            None => <Option<Vec<u8>>>::serialize(&None, s),
        }
    }

    pub fn deserialize_bytes_option<'de, D: Deserializer<'de>, V: From<Vec<u8>>>(
        d: D,
    ) -> Result<Option<V>, D::Error> {
        let bytes = base64::decode(String::deserialize(d)?.as_bytes()).map_err(Error::custom)?;
        let v = V::from(bytes);
        Ok(Some(v))
    }
}
