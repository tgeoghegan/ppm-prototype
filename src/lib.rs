pub mod aggregate;
pub mod client;
pub mod collect;
pub mod helper;
pub mod hpke;
pub mod leader;
pub mod parameters;
pub mod trace;
pub mod upload;

use chrono::{DateTime, DurationRound, TimeZone, Utc};
use directories::ProjectDirs;
use http::StatusCode;
use http_api_problem::HttpApiProblem;
use prio::field::FieldElement;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    convert::Infallible,
    fmt::{self, Display, Formatter},
    path::PathBuf,
};
use warp::{reject::Rejection, Filter};

/// Seconds elapsed since start of UNIX epoch
pub type Time = u64;

pub trait IntervalStart {
    fn interval_start(self, min_batch_duration: Duration) -> DateTime<Utc>;
}

impl IntervalStart for Time {
    /// Determine the start of the aggregation window that this report falls in,
    /// assuming the provided minimum batch duration
    fn interval_start(self, min_batch_duration: Duration) -> DateTime<Utc> {
        Utc.timestamp(self as i64, 0)
            .duration_trunc(chrono::Duration::seconds(min_batch_duration as i64))
            .unwrap()
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
        [self.time.to_be_bytes(), self.nonce.to_be_bytes()].concat()
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
        [self.start.to_be_bytes(), self.end.to_be_bytes()].concat()
    }
}

/// Path relative to which configuration files may be found.
pub(crate) fn config_path() -> PathBuf {
    let project_path = ProjectDirs::from("org", "isrg", "ppm-prototype").unwrap();
    project_path.config_dir().to_path_buf()
}

// Injects a clone of the provided value into the warp filter, making it
// available to the filter's map() or and_then() handler.
pub fn with_shared_value<T: Clone + Sync + Send>(
    value: T,
) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || value.clone())
}

/// Sums `other_vector` into `accumulator`, iff they have the same length.
/// Returns Ok(()) if the vectors were merged, Err otherwise.
pub fn merge_vector<F: FieldElement>(
    accumulator: &mut [F],
    other_vector: &[F],
) -> Result<(), &'static str> {
    if accumulator.len() != other_vector.len() {
        return Err("vector length mismatch");
    }
    for (a, o) in accumulator.iter_mut().zip(other_vector.iter()) {
        *a += *o;
    }

    Ok(())
}

/// warp rejection handler that can be tacked on to routes to construct a
/// warp::Reply with appropriate status code and JSON body for an HTTP problem
/// document.
pub(crate) async fn handle_rejection(rejection: Rejection) -> Result<impl warp::Reply, Infallible> {
    // All our warp rejections should wrap a problem document, so crash if we
    // can't find one.
    let problem_document = rejection.find::<HttpApiProblem>().unwrap();

    Ok(warp::reply::with_status(
        warp::reply::json(problem_document),
        problem_document
            .status
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
    ))
}
