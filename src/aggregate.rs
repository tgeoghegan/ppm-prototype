//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    parameters::TaskId,
    upload::{EncryptedInputShare, ReportExtension},
    Timestamp,
};
use chrono::{DateTime, Utc};
use prio::{
    field::Field64,
    pcp::types::Boolean,
    vdaf::{suite::Key, VerifyParam},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use tracing::info;

/// Returns a fixed vector of randomness to be used in Boolean<Field64> values,
/// in anticipation of cjpatton working out how aggregators will negotiate
/// query randomness.
pub(crate) fn boolean_verify_parameter(role: crate::hpke::Role) -> VerifyParam<Boolean<Field64>> {
    VerifyParam {
        value_param: (),
        query_rand_init: Key::Aes128CtrHmacSha256([1; 32]),
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
pub(crate) struct Accumulator {
    /// The value accumulated thus far
    pub(crate) accumulated: Vec<Field64>,
    /// How many contributions are included
    pub(crate) contributions: u64,
    /// Privacy budget for the aggregation interval. Measured in number of
    /// queries.
    pub(crate) privacy_budget: u64,
}

pub(crate) fn dump_accumulators(accumulators: &HashMap<DateTime<Utc>, Accumulator>) {
    for (interval_start, accumulated) in accumulators {
        info!(
            interval_start = ?interval_start,
            accumulated = ?accumulated,
            "accumulated value for interval"
        );
    }
}
