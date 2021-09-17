pub mod aggregate;
pub mod collect;
pub mod hpke;
pub mod parameters;
pub mod trace;
pub mod upload;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use warp::Filter;

/// Seconds elapsed since start of UNIX epoch
pub type Time = u64;

/// Seconds elapsed between two instants
pub type Duration = u64;

/// Interval of time between two instants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    /// Start of the interval, included.
    pub start: Time,
    /// End of the interval, excluded.
    pub end: Time,
}

/// Path relative to which configuration files may be found.
pub(crate) fn config_path() -> PathBuf {
    let project_path = ProjectDirs::from("org", "isrg", "ppm-prototype").unwrap();
    project_path.config_dir().to_path_buf()
}

// Injects a clone of the provided value into the warp filter, making it
// available to the filter's map() or and_then() handler.
pub fn with_shared_value<T: Sync + Send>(
    value: Arc<Mutex<T>>,
) -> impl Filter<Extract = (Arc<Mutex<T>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || value.clone())
}
