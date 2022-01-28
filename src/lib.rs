pub mod aggregate;
pub mod client;
pub mod collect;
mod error;
pub mod helper;
pub mod hpke;
pub mod leader;
pub mod parameters;
pub mod trace;
pub mod upload;

use chrono::{DateTime, DurationRound, TimeZone, Utc};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    path::PathBuf,
};
use warp::Filter;

/// Seconds elapsed since start of UNIX epoch
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub struct Time(pub u64);

impl Time {
    /// Determine the start of the aggregation window that this report falls in,
    /// assuming the provided minimum batch duration
    fn interval_start(self, min_batch_duration: Duration) -> DateTime<Utc> {
        Utc.timestamp(self.0 as i64, 0)
            .duration_trunc(chrono::Duration::seconds(min_batch_duration.0 as i64))
            .unwrap()
    }

    fn add(self, duration: Duration) -> Self {
        Self(self.0 + duration.0)
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Seconds elapsed between two instances
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub struct Duration(pub u64);

impl Display for Duration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Nonce used to uniquely identify a PPM report
//
// Deriving [`PartialOrd`] yields a "lexicographic ordering based on the
// top-to-bottom declaration order of the struct's members."
// https://doc.rust-lang.org/std/cmp/trait.PartialOrd.html#derivable
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
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

impl Nonce {
    /// Construct HPKE AEAD associated data for the nonce
    pub fn associated_data(&self) -> Vec<u8> {
        [self.time.0.to_be_bytes(), self.rand.to_be_bytes()].concat()
    }
}

/// Interval of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
