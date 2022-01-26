//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    collect::{EncryptedOutputShare, OutputShare},
    error::{IntoHttpApiProblem, ProblemDocumentType},
    hpke::Role,
    parameters::{Parameters, TaskId},
    upload::{EncryptedInputShare, ReportExtension},
    Interval, Timestamp,
};
use ::hpke::Serializable;
use chrono::{DateTime, TimeZone, Utc};
use prio::vdaf::{prio3::Prio3VerifyParam, suite::Key, Aggregatable, Aggregator};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error {0}")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error {0}")]
    Encryption(#[from] crate::hpke::Error),
    #[error("VDAF error {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("invalid batch interval {0}")]
    InvalidBatchInterval(Interval),
    #[error("insufficient batch size {0}")]
    InsufficientBatchSize(u64),
    #[error("request exceeds the batch's privacy budget")]
    PrivacyBudgetExceeded,
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        match self {
            Self::JsonParse(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            Self::Encryption(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            Self::InvalidBatchInterval(_) => Some(ProblemDocumentType::InvalidBatchInterval),
            Self::InsufficientBatchSize(_) => Some(ProblemDocumentType::InsufficientBatchSize),
            Self::PrivacyBudgetExceeded => Some(ProblemDocumentType::PrivacyBudgetExceeded),
            _ => None,
        }
    }
}

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
    /// The value accumulated thus far. S will be some VDAF's AggregateShare type.
    pub(crate) accumulated: S,
    /// How many contributions are included
    pub(crate) contributions: u64,
    /// Consumed privacy budget for the aggregation interval. Measured in number
    /// of queries.
    pub(crate) consumed_privacy_budget: u64,
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

pub(crate) fn aggregate_report<A: Aggregator>(
    aggregator: &A,
    parameters: &Parameters,
    accumulators: &mut HashMap<DateTime<Utc>, Accumulator<A::AggregateShare>>,
    aggregation_parameter: &A::AggregationParam,
    timestamp: Timestamp,
    prepare_state: A::PrepareStep,
    leader_prepare_message: A::PrepareMessage,
    helper_prepare_message: A::PrepareMessage,
) -> Result<(), Error> {
    info!(
        ?timestamp,
        ?leader_prepare_message,
        ?helper_prepare_message,
        "verifying proof"
    );

    let prepare_message =
        aggregator.prepare_preprocess([leader_prepare_message, helper_prepare_message])?;

    let output_share = match aggregator.prepare_finish(prepare_state, prepare_message) {
        Ok(output_share) => output_share,
        // Log errors but don't return them as the caller will want to process
        // all the other reports
        Err(e) => {
            warn!(
                time = ?timestamp,
                error = ?e,
                "proof did not check out for report"
            );
            return Ok(());
        }
    };

    // Proof checked out. Now accumulate the output share into the accumulator
    // for the batch interval corresponding to the report timestamp.
    let interval_start = timestamp.time.interval_start(parameters.min_batch_duration);

    if let Some(accumulator) = accumulators.get_mut(&interval_start) {
        accumulator.accumulated.accumulate(&output_share)?;
        accumulator.contributions += 1;
    } else {
        // This is the first input we have seen for this batch interval.
        // Initialize the accumulator.
        accumulators.insert(
            interval_start,
            Accumulator {
                accumulated: aggregator.aggregate(aggregation_parameter, [output_share])?,
                contributions: 1,
                consumed_privacy_budget: 0,
            },
        );
    }

    Ok(())
}

pub(crate) fn extract_output_share<A: Aggregator>(
    role: Role,
    parameters: &Parameters,
    batch_interval: Interval,
    accumulators: &mut HashMap<DateTime<Utc>, Accumulator<A::AggregateShare>>,
) -> Result<EncryptedOutputShare, Error> {
    if !parameters.validate_batch_interval(batch_interval) {
        return Err(Error::InvalidBatchInterval(batch_interval));
    }

    let num_intervals_in_request =
        batch_interval.min_intervals_in_interval(parameters.min_batch_duration);

    let first_interval = batch_interval
        .start
        .interval_start(parameters.min_batch_duration);

    let mut aggregate_shares = vec![];
    let mut total_contributions = 0;

    for i in 0..num_intervals_in_request {
        let interval_start = Utc.timestamp(
            first_interval.timestamp() + (i * parameters.min_batch_duration) as i64,
            0,
        );
        match accumulators.get_mut(&interval_start) {
            Some(accumulator) => {
                if accumulator.consumed_privacy_budget == parameters.max_batch_lifetime {
                    return Err(Error::PrivacyBudgetExceeded);
                }
                aggregate_shares.push(accumulator.accumulated.clone());

                accumulator.consumed_privacy_budget += 1;
                total_contributions += accumulator.contributions;
            }
            None => {
                // Most likely there are no contributions for this batch interval yet
                warn!(
                    "no accumulator found for interval start {:?}",
                    interval_start
                );
                continue;
            }
        }
    }

    if total_contributions < parameters.min_batch_size {
        return Err(Error::InsufficientBatchSize(total_contributions));
    }

    // Merge aggregate shares into a single aggregate share
    let remaining_shares = aggregate_shares.split_off(1);
    for aggregate_share in remaining_shares.into_iter() {
        aggregate_shares[0].merge(&aggregate_share)?;
    }

    let output_share: OutputShare<A> = OutputShare {
        sum: aggregate_shares.swap_remove(0),
        contributions: total_contributions,
    };

    // TODO use TLS serialization
    let json_output_share = serde_json::to_vec(&output_share)?;

    let hpke_sender = parameters
        .collector_config
        .output_share_sender(&parameters.task_id, role)?;

    let (payload, encapped) =
        hpke_sender.encrypt_output_share(batch_interval, &json_output_share)?;

    Ok(EncryptedOutputShare {
        collector_hpke_config_id: parameters.collector_config.id,
        encapsulated_context: encapped.to_bytes().to_vec(),
        payload,
    })
}
