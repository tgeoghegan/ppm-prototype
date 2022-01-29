//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    collect::{EncryptedOutputShare, OutputShare},
    error::{IntoHttpApiProblem, ProblemDocumentType},
    parameters::{Parameters, TaskId},
    upload::{EncryptedInputShare, ReportExtension},
    Interval, Nonce, Role,
};
use ::hpke::Serializable;
use chrono::{DateTime, TimeZone, Utc};
use prio::vdaf::{
    self, poplar1::Poplar1VerifyParam, prio3::Prio3VerifyParam, suite::Key, Aggregatable, Vdaf,
};
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
    pub timestamp: Nonce,
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
    pub timestamp: Nonce,
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

/// This trait is implemented on the `VerifyParam` associated type on
/// `prio::vdaf::Vdaf` implementations so that we can generically get fake
/// verification randomness in anticipation of working out how aggregators will
/// negotiate it.
pub(crate) trait DefaultVerifyParam {
    fn default(role: Role) -> Self;
}

impl DefaultVerifyParam for Prio3VerifyParam {
    fn default(role: Role) -> Self {
        Self {
            query_rand_init: Key::Blake3([1; 32]),
            aggregator_id: role.index() as u8,
        }
    }
}

impl DefaultVerifyParam for Poplar1VerifyParam {
    fn default(role: Role) -> Self {
        Self::new(&Key::Blake3([1; 32]), role == Role::Leader)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Aggregator<A: vdaf::Aggregator> {
    role: Role,
    aggregator: A,
    task_parameters: Parameters,
    aggregation_parameter: A::AggregationParam,
    /// Accumulated sums over inputs that have been verified in conjunction with
    /// the helper. The key is the start of the batch window.
    accumulators: HashMap<DateTime<Utc>, Accumulator<A::AggregateShare>>,
}

impl<A> Aggregator<A>
where
    A: vdaf::Aggregator,
    <A as Vdaf>::VerifyParam: DefaultVerifyParam,
{
    pub(crate) fn new(
        role: Role,
        aggregator: A,
        task_parameters: Parameters,
        aggregation_parameter: A::AggregationParam,
        accumulators: HashMap<DateTime<Utc>, Accumulator<A::AggregateShare>>,
    ) -> Self {
        // TODO: construct accumulators here once we stop storing them in
        // state blob
        // TODO: construct aggregator here from task_parameters
        Self {
            role,
            aggregator,
            task_parameters,
            aggregation_parameter,
            accumulators,
        }
    }

    pub(crate) fn prepare_message(
        &self,
        timestamp: Nonce,
        input_share: &A::InputShare,
    ) -> Result<(A::PrepareStep, A::PrepareMessage), Error> {
        let step = self.aggregator.prepare_init(
            &A::VerifyParam::default(self.role),
            &self.aggregation_parameter,
            &timestamp.associated_data(),
            input_share,
        )?;

        Ok(self.aggregator.prepare_start(step)?)
    }

    pub(crate) fn aggregate_report<I: IntoIterator<Item = A::PrepareMessage>>(
        &mut self,
        timestamp: Nonce,
        step: A::PrepareStep,
        prepare_messages: I,
    ) -> Result<(), Error> {
        info!(?timestamp, "verifying proof");

        let prepare_message = self.aggregator.prepare_preprocess(prepare_messages)?;

        let output_share = match self.aggregator.prepare_finish(step, prepare_message) {
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
        let interval_start = timestamp
            .time
            .interval_start(self.task_parameters.min_batch_duration);

        if let Some(accumulator) = self.accumulators.get_mut(&interval_start) {
            accumulator.accumulated.accumulate(&output_share)?;
            accumulator.contributions += 1;
        } else {
            // This is the first input we have seen for this batch interval.
            // Initialize the accumulator.
            self.accumulators.insert(
                interval_start,
                Accumulator {
                    accumulated: self
                        .aggregator
                        .aggregate(&self.aggregation_parameter, [output_share])?,
                    contributions: 1,
                    consumed_privacy_budget: 0,
                },
            );
        }

        Ok(())
    }

    pub(crate) fn extract_output_share(
        &mut self,
        batch_interval: Interval,
    ) -> Result<EncryptedOutputShare, Error> {
        if !self.task_parameters.validate_batch_interval(batch_interval) {
            return Err(Error::InvalidBatchInterval(batch_interval));
        }

        let num_intervals_in_request =
            batch_interval.intervals_in_interval(self.task_parameters.min_batch_duration);

        let first_interval = batch_interval
            .start
            .interval_start(self.task_parameters.min_batch_duration);

        let mut aggregate_shares = vec![];
        let mut total_contributions = 0;

        for i in 0..num_intervals_in_request {
            let interval_start = Utc.timestamp(
                first_interval.timestamp() + (i * self.task_parameters.min_batch_duration.0) as i64,
                0,
            );
            match self.accumulators.get_mut(&interval_start) {
                Some(accumulator) => {
                    if accumulator.consumed_privacy_budget
                        == self.task_parameters.max_batch_lifetime
                    {
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

        if total_contributions < self.task_parameters.min_batch_size {
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

        let hpke_sender = self
            .task_parameters
            .collector_config
            .output_share_sender(&self.task_parameters.task_id, self.role)?;

        let (payload, encapped) =
            hpke_sender.encrypt_output_share(batch_interval, &json_output_share)?;

        Ok(EncryptedOutputShare {
            collector_hpke_config_id: self.task_parameters.collector_config.id.0,
            encapsulated_context: encapped.to_bytes().to_vec(),
            payload,
        })
    }

    pub(crate) fn dump_accumulators(&self) {
        dump_accumulators(&self.accumulators)
    }

    // hack so we can reconstruct helper state
    // TODO: delete this once we get rid of helper state
    pub(crate) fn clone_accumulators(
        &self,
    ) -> HashMap<DateTime<Utc>, Accumulator<A::AggregateShare>> {
        self.accumulators.clone()
    }
}
