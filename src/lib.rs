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
    cmp::Ordering,
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
            .duration_trunc(chrono::Duration::seconds(min_batch_duration as i64))
            .unwrap()
    }
}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Timestamp as included in a Report, AggregateSubReq, etc.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Timestamp {
    pub time: Time,
    pub nonce: u64,
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        // Comparison per RFCXXXX §4.4.2
        if other.time == self.time && other.nonce == self.nonce {
            return Ordering::Equal;
        }

        if other.time > self.time || (other.time == self.time && other.nonce > self.nonce) {
            return Ordering::Less;
        }

        Ordering::Greater
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.time, self.nonce)
    }
}

impl Timestamp {
    pub(crate) fn associated_data(&self) -> Vec<u8> {
        [self.time.0.to_be_bytes(), self.nonce.to_be_bytes()].concat()
    }
}

/// Seconds elapsed between two instants
pub type Duration = u64;

/// Interval of time between two instants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    /// Start of the interval, included.
    pub start: Time,
    /// End of the interval, excluded.
    pub end: Time,
}

impl Interval {
    pub(crate) fn associated_data(&self) -> Vec<u8> {
        [self.start.0.to_be_bytes(), self.end.0.to_be_bytes()].concat()
    }

    pub(crate) fn min_intervals_in_interval(&self, min_batch_duration: Duration) -> u64 {
        (self.end.0 - self.start.0) / min_batch_duration
    }
}

impl Display for Interval {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "[{} - {})", self.start, self.end)
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
