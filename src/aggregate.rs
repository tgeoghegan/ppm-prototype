//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    parameters::TaskId,
    upload::{EncryptedInputShare, ReportExtension},
    Timestamp,
};
use chrono::{DateTime, Utc};
use prio::vdaf::{prio3::Prio3VerifyParam, suite::Key};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use tracing::info;

/// Returns a fixed vector of randomness to be used in the Prio3 VDAF,
/// in anticipation of cjpatton working out how aggregators will negotiate
/// query randomness.
pub(crate) fn prio3_verify_parameter(role: crate::hpke::Role) -> Prio3VerifyParam {
    Prio3VerifyParam {
        query_rand_init: Key::Blake3([1; 32]),
        aggregator_id: role.index() as u8,
    }
}

/// A verify start request sent to a leader from a helper
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyStartRequest {
    pub task_id: TaskId,
    pub helper_state: Vec<u8>,
    // Aggregation parameter is not used in prio3
    #[serde(skip_serializing_if = "Option::is_none", rename = "aggregation_param")]
    pub aggregation_parameter: Option<Vec<u8>>,
    #[serde(rename = "seq")]
    pub sub_requests: Vec<VerifyStartSubRequest>,
}

/// Sub-request in a verify start request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyStartSubRequest {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    pub extensions: Vec<ReportExtension>,
    // For prio3, this is a `serde_json` encoded `vdaf::VerifyMessage`. For
    // Hits, ???
    pub verify_message: Vec<u8>,
    pub helper_share: EncryptedInputShare,
}

/// The response to a verify start request (and verify next, but that is not
/// used in prio3)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub helper_state: Vec<u8>,
    pub sub_responses: Vec<VerifySubResponse>,
}

/// Sub-response in a verify response
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifySubResponse {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    // For prio3, this is a `serde_json` encoded `vdaf::VerifyMessage`. For
    // Hits, ???
    pub verification_message: Vec<u8>,
}

/// Accumulator for some aggregation interval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Accumulator<S> {
    /// The value accumulated thus far. S will be some VDAF's OutputShare type.
    pub(crate) accumulated: S,
    /// How many contributions are included
    pub(crate) contributions: u64,
    /// Privacy budget for the aggregation interval. Measured in number of
    /// queries.
    pub(crate) privacy_budget: u64,
}

pub(crate) fn dump_accumulators<S: Debug>(accumulators: &HashMap<DateTime<Utc>, Accumulator<S>>) {
    for (interval_start, accumulated) in accumulators {
        info!(
            interval_start = ?interval_start,
            accumulated = ?accumulated,
            "accumulated value for interval"
        );
    }
}
