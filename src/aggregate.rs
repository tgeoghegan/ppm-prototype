//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    parameters::TaskId,
    upload::{EncryptedInputShare, ReportExtension},
    Timestamp,
};
use chrono::{DateTime, Utc};
use prio::{
    field::{Field64, FieldElement},
    ppm::VerifierMessage,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use tracing::info;

/// Returns a fixed vector of randomness to be used in Boolean<Field64> values,
/// in anticipation of cjpatton working out how aggregators will negotiate
/// query randomness.
pub(crate) fn boolean_query_randomness() -> Vec<u8> {
    vec![1; 32]
}

/// An aggregate request sent to a leader from a helper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateRequest<F: FieldElement> {
    pub task_id: TaskId,
    pub helper_state: Vec<u8>,
    #[serde(rename = "seq")]
    pub sub_requests: Vec<AggregateSubRequest<F>>,
}

/// Sub-request in an aggregate request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateSubRequest<F: FieldElement> {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    pub extensions: Vec<ReportExtension>,
    pub helper_share: EncryptedInputShare,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolAggregateSubRequestFields<F>,
}

/// The protocol specific portions of AggregateSubRequest
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ProtocolAggregateSubRequestFields<F: FieldElement> {
    /// Prio-specific parameters
    Prio {
        /// Message containing the leader's proof/verifier share.
        leader_verifier_message: VerifierMessage<F>,
    },
    Hits {},
}

/// The response to an aggregation request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateResponse<F: FieldElement> {
    pub helper_state: Vec<u8>,
    pub sub_responses: Vec<AggregateSubResponse<F>>,
}

/// Sub-response in an aggregation response
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateSubResponse<F: FieldElement> {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolAggregateSubResponseFields<F>,
}

/// The protocol specific portions of AggregateSubResponse
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ProtocolAggregateSubResponseFields<F: FieldElement> {
    /// Prio-specific parameters
    Prio {
        /// If the helper was able to verify the proof using the leader's
        /// verifier share, this will be the helper's verifier/proof share. If
        /// the proof verification failed, this will be None.
        helper_verifier_message: Option<VerifierMessage<F>>,
    },
    Hits {},
}

/// Accumulator for some aggregation interval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Accumulator {
    /// The value accumulated thus far
    pub(crate) accumulated: Vec<Field64>,
    /// How many contributions are included
    pub(crate) contributions: usize,
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
