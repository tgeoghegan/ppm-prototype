//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
    error::{IntoHttpApiProblem, ProblemDocumentType},
    hpke,
    parameters::{Parameters, TaskId},
    report::{self, Report},
    Interval, Nonce, Role,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode},
    pcp::Type,
    vdaf::{self, prio3::Prio3VerifyParam, suite::Key, Aggregatable, PrepareTransition},
};
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt::Debug,
    io::{Cursor, Read},
};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error {0}")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error {0}")]
    Encryption(#[from] crate::hpke::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("Report error")]
    Report(#[from] crate::report::Error),
    #[error("VDAF error {0}")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("invalid batch interval {0}")]
    InvalidBatchInterval(Interval),
    #[error("insufficient batch size {0}")]
    InsufficientBatchSize(u64),
    #[error("request exceeds the batch's privacy budget")]
    PrivacyBudgetExceeded,
    #[error("Codec error {0}")]
    Codec(String),
    #[error("Parameters error")]
    Parameters(#[from] crate::parameters::Error),
    #[error("Stale report: {0}")]
    StaleReport(Nonce),
    #[error("unknown HPKE config ID {0:?}")]
    UnknownHpkeConfig(hpke::ConfigId),
    #[error("unrecognized task ID")]
    UnrecognizedTask(TaskId),
    #[error("Codec error")]
    CodecError(#[from] prio::codec::CodecError),
    #[error("unexpected prepare state transition: {0}")]
    UnexpectedStateTransition(String),
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        match self {
            Self::JsonParse(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            Self::Encryption(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            Self::InvalidBatchInterval(_) => Some(ProblemDocumentType::InvalidBatchInterval),
            Self::InsufficientBatchSize(_) => Some(ProblemDocumentType::InsufficientBatchSize),
            Self::PrivacyBudgetExceeded => Some(ProblemDocumentType::PrivacyBudgetExceeded),
            Self::StaleReport(_) => Some(ProblemDocumentType::StaleReport),
            Self::UnknownHpkeConfig(_) => Some(ProblemDocumentType::OutdatedConfig),
            Self::UnrecognizedTask(_) => Some(ProblemDocumentType::UnrecognizedTask),
            _ => None,
        }
    }
}

impl From<Error> for TransitionError {
    fn from(e: Error) -> Self {
        match e {
            Error::StaleReport(_) => TransitionError::BatchCollected,
            Error::UnknownHpkeConfig(_) => TransitionError::HpkeUnknownConfigId,
            Error::Encryption(_) => TransitionError::HpkeDecryptError,
            Error::Vdaf(_) => TransitionError::VdafPrepError,
            unhandled_error => {
                warn!(?unhandled_error, "unhandled error!");
                TransitionError::ReportDropped
            }
        }
    }
}

/// A report share transmitted from a leader to a helper
#[derive(Clone, Debug)]
pub struct ReportShare {
    pub nonce: Nonce,
    pub extensions: Vec<report::Extension>,
    pub encrypted_input_share: hpke::Ciphertext,
}

impl Encode for ReportShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &self.extensions);
        self.encrypted_input_share.encode(bytes);
    }
}

impl Decode<()> for ReportShare {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(&(), bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_share = hpke::Ciphertext::decode(&(), bytes)?;

        Ok(Self {
            nonce,
            extensions,
            encrypted_input_share,
        })
    }
}

/// Enum describing the possible contents of [`TransitionMessage`]
#[derive(Clone, Debug)]
pub enum Transition {
    Continued { payload: Vec<u8> },
    Finished,
    Failed { error: TransitionError },
}

impl Encode for Transition {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // We encode the union discriminant and then the encoding of the
        // variant. Since there are fewer than 255 variants of [`Transition`],
        // its discriminant is encoded in one byte.
        match self {
            Self::Continued { payload } => {
                0u8.encode(bytes);
                encode_u16_items(bytes, payload);
            }
            Self::Finished => 1u8.encode(bytes),
            Self::Failed { error } => {
                2u8.encode(bytes);
                u8::from(*error).encode(bytes);
            }
        }
    }
}

impl Decode<()> for Transition {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let discriminant = u8::decode(&(), bytes)?;
        let value = match discriminant {
            0u8 => Self::Continued {
                payload: decode_u16_items(&(), bytes)?,
            },
            1u8 => Self::Finished,
            2u8 => Self::Failed {
                error: TransitionError::try_from(u8::decode(&(), bytes)?)
                    .map_err(|e| CodecError::Other(Box::new(e)))?,
            },
            d => {
                return Err(CodecError::Other(Box::new(Error::Codec(format!(
                    "unexpected Transition discriminant {}",
                    d
                )))))
            }
        };

        Ok(value)
    }
}

/// Errors that may occur in a `Transition::Failed` message
// There are fewer than 255 possible values of `TransitionError`, and so per RFC
// 8446 a value occupies one byte on the wire.
// https://datatracker.ietf.org/doc/html/rfc8446#section-3.5
#[derive(Clone, Copy, Debug, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum TransitionError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    UnrecognizedNonce = 6,
}

/// A state transition message exchanged between leader and helper
#[derive(Clone, Debug)]
pub struct TransitionMessage {
    pub(crate) nonce: Nonce,
    pub(crate) transition: Transition,
}

impl Encode for TransitionMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        self.transition.encode(bytes);
    }
}

impl Decode<()> for TransitionMessage {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(&(), bytes)?;
        let transition = Transition::decode(&(), bytes)?;

        Ok(Self { nonce, transition })
    }
}

/// Enum describing the possible contents of [`AggregateMessage`].
#[derive(Clone, Debug)]
pub enum Aggregate {
    Initialize(AggregateInitReq),
    Request(AggregateReq),
    Response(AggregateResp),
    ShareRequest(AggregateShareReq),
    ShareResponse(hpke::Ciphertext),
}

impl Encode for Aggregate {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // We encode the union discriminant and then the encoding of the
        // variant. Since there are fewer than 255 variants of [`Aggregate`],
        // its discriminant is encoded in one byte.
        match self {
            Self::Initialize(init_req) => {
                0u8.encode(bytes);
                init_req.encode(bytes);
            }
            Self::Request(req) => {
                1u8.encode(bytes);
                req.encode(bytes);
            }
            Self::Response(resp) => {
                2u8.encode(bytes);
                resp.encode(bytes);
            }
            Self::ShareRequest(req) => {
                3u8.encode(bytes);
                req.encode(bytes);
            }
            Self::ShareResponse(ciphertext) => {
                4u8.encode(bytes);
                ciphertext.encode(bytes);
            }
        }
    }
}

impl Decode<()> for Aggregate {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let discriminant = u8::decode(&(), bytes)?;
        let value = match discriminant {
            0u8 => Self::Initialize(AggregateInitReq::decode(&(), bytes)?),
            1u8 => Self::Request(AggregateReq::decode(&(), bytes)?),
            2u8 => Self::Response(AggregateResp::decode(&(), bytes)?),
            3u8 => Self::ShareRequest(AggregateShareReq::decode(&(), bytes)?),
            4u8 => Self::ShareResponse(hpke::Ciphertext::decode(&(), bytes)?),
            d => {
                return Err(CodecError::Other(Box::new(Error::Codec(format!(
                    "unexpected Aggregate discriminant {}",
                    d
                )))))
            }
        };

        Ok(value)
    }
}

/// AggregateInitReq message
#[derive(Clone, Debug)]
pub struct AggregateInitReq {
    pub task_id: TaskId,
    pub aggregation_parameter: Vec<u8>,
    pub report_shares: Vec<ReportShare>,
}

impl Encode for AggregateInitReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        encode_u16_items(bytes, &self.aggregation_parameter);
        encode_u16_items(bytes, &self.report_shares);
    }
}

impl Decode<()> for AggregateInitReq {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(&(), bytes)?;
        let aggregation_parameter = decode_u16_items(&(), bytes)?;
        let report_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            aggregation_parameter,
            report_shares,
        })
    }
}

/// AggregateReq message
#[derive(Clone, Debug)]
pub struct AggregateReq {
    pub task_id: TaskId,
    pub helper_state: Vec<u8>,
    pub transitions: Vec<TransitionMessage>,
}

impl Encode for AggregateReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        encode_u16_items(bytes, &self.helper_state);
        encode_u16_items(bytes, &self.transitions);
    }
}

impl Decode<()> for AggregateReq {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(&(), bytes)?;
        let helper_state = decode_u16_items(&(), bytes)?;
        let transitions = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            helper_state,
            transitions,
        })
    }
}

/// AggregateResp message
#[derive(Clone, Debug)]
pub struct AggregateResp {
    pub(crate) helper_state: Vec<u8>,
    pub(crate) transitions: Vec<TransitionMessage>,
}

impl Encode for AggregateResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &self.helper_state);
        encode_u16_items(bytes, &self.transitions);
    }
}

impl Decode<()> for AggregateResp {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let helper_state = decode_u16_items(&(), bytes)?;
        let transitions = decode_u16_items(&(), bytes)?;

        Ok(Self {
            helper_state,
            transitions,
        })
    }
}

/// AggregateShareReq message sent from leader to helper
#[derive(Clone, Debug)]
pub struct AggregateShareReq {
    pub task_id: TaskId,
    pub batch_interval: Interval,
}

impl Encode for AggregateShareReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
    }
}

impl Decode<()> for AggregateShareReq {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(&(), bytes)?;
        let batch_interval = Interval::decode(&(), bytes)?;

        Ok(Self {
            task_id,
            batch_interval,
        })
    }
}

/// Aggregate message exchanged between aggregators
#[derive(Clone, Debug)]
pub struct AggregateMessage {
    pub aggregate: Aggregate,
    /// HMAC-SHA256 tag over the serialized message
    // TODO: better type for this
    pub tag: [u8; 32],
}

impl Encode for AggregateMessage {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.aggregate.encode(bytes);
        bytes.extend_from_slice(&self.tag);
    }
}

impl Decode<()> for AggregateMessage {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let aggregate = Aggregate::decode(&(), bytes)?;
        let mut tag = [0u8; 32];
        bytes.read_exact(&mut tag)?;

        Ok(Self { aggregate, tag })
    }
}

/// Accumulator for some batch interval
#[derive(Clone, Debug)]
pub(crate) struct Accumulator<S> {
    /// The value accumulated thus far. S will be some VDAF's AggregateShare type.
    pub(crate) accumulated: S,
    /// How many contributions are included
    pub(crate) contributions: u64,
    /// Consumed privacy budget for the aggregation interval. Measured in number
    /// of queries.
    pub(crate) consumed_privacy_budget: u64,
}

pub(crate) fn dump_accumulators<S: Debug>(accumulators: &HashMap<Interval, Accumulator<S>>) {
    if accumulators.is_empty() {
        info!("accumulators are empty");
    }
    for (interval, accumulated) in accumulators {
        info!(?interval, ?accumulated, "accumulated value for interval");
    }
}

/// This trait is implemented on the `VerifyParam` associated type on
/// `prio::vdaf::Vdaf` implementations so that we can generically get fake
/// verification randomness in anticipation of working out how aggregators will
/// negotiate it.
pub trait DefaultVerifyParam {
    fn default<T: Type>(role: Role, typ: &T) -> Self;
}

impl DefaultVerifyParam for Prio3VerifyParam {
    fn default<T: Type>(role: Role, typ: &T) -> Self {
        Self {
            query_rand_init: Key::Blake3([1; 32]),
            aggregator_id: role.index() as u8,
            input_len: typ.input_len(),
            proof_len: typ.proof_len(),
            joint_rand_len: typ.joint_rand_len(),
        }
    }
}

// impl DefaultVerifyParam for Poplar1VerifyParam {
//     fn default(role: Role) -> Self {
//         Self::new(&Key::Blake3([1; 32]), role == Role::Leader)
//     }
// }

#[derive(Clone, Debug)]
pub(crate) struct Aggregator<A: vdaf::Aggregator> {
    role: Role,
    hpke_config: hpke::Config,
    pub aggregator: A,
    pub verify_parameter: A::VerifyParam,
    aggregation_parameter: A::AggregationParam,
    /// The batch intervals for which this aggregator has received either a
    /// collect request or an aggregate share request, depending on the role.
    collected_batch_intervals: HashSet<Interval>,
    task_parameters: Parameters,
    /// Accumulated sums over inputs that have been verified in conjunction with
    /// the helper. The key is the batch interval.
    accumulators: HashMap<Interval, Accumulator<A::AggregateShare>>,
}

impl<A: vdaf::Aggregator> Aggregator<A> {
    pub(crate) fn new(
        role: Role,
        hpke_config: &hpke::Config,
        aggregator: &A,
        verify_parameter: &A::VerifyParam,
        aggregation_parameter: &A::AggregationParam,
        task_parameters: &Parameters,
    ) -> Self {
        // TODO: construct accumulators here once we stop storing them in
        // state blob
        // TODO: construct aggregator here from task_parameters
        Self {
            role,
            hpke_config: hpke_config.clone(),
            aggregator: aggregator.clone(),
            collected_batch_intervals: HashSet::new(),
            verify_parameter: verify_parameter.clone(),
            task_parameters: task_parameters.clone(),
            aggregation_parameter: aggregation_parameter.clone(),
            accumulators: HashMap::new(),
        }
    }

    #[tracing::instrument(skip(self, extensions, report_share), err)]
    pub(crate) fn prepare_message(
        &self,
        report_task_id: TaskId,
        nonce: Nonce,
        extensions: &[report::Extension],
        report_share: &hpke::Ciphertext,
    ) -> Result<(A::PrepareStep, A::PrepareMessage), Error> {
        if self.task_parameters.task_id != report_task_id {
            return Err(Error::UnrecognizedTask(report_task_id));
        }

        if self.collected_batch_intervals.contains(
            &nonce
                .time
                .batch_interval(self.task_parameters.min_batch_duration),
        ) {
            return Err(Error::StaleReport(nonce));
        }

        if report_share.config_id != self.hpke_config.id {
            return Err(Error::UnknownHpkeConfig(report_share.config_id));
        }

        let hpke_recipient = self.hpke_config.recipient(
            &self.task_parameters.task_id,
            hpke::Label::InputShare,
            Role::Client,
            self.role,
            &report_share.encapsulated_context,
        )?;

        let plaintext =
            hpke_recipient.open(report_share, &Report::associated_data(nonce, extensions))?;
        info!(plaintext_len = ?plaintext.len(), "decoding input share");
        let input_share = A::InputShare::get_decoded(&self.verify_parameter, &plaintext)?;
        info!("decoded input share");

        let step = self.aggregator.prepare_init(
            &self.verify_parameter,
            &self.aggregation_parameter,
            &nonce.get_encoded(),
            &input_share,
        )?;

        match self.aggregator.prepare_step(step, None) {
            PrepareTransition::Continue(step, message) => Ok((step, message)),
            PrepareTransition::Finish(f) => {
                Err(Error::UnexpectedStateTransition(format!("{:?}", f)))
            }
            PrepareTransition::Fail(err) => Err(Error::Vdaf(err)),
        }
    }

    pub(crate) fn accumulate_report(
        &mut self,
        timestamp: Nonce,
        output_share: A::OutputShare,
    ) -> Result<(), Error> {
        // Proof checked out. Now accumulate the output share into the accumulator
        // for the batch interval corresponding to the report timestamp.
        let interval = timestamp
            .time
            .batch_interval(self.task_parameters.min_batch_duration);

        if let Some(accumulator) = self.accumulators.get_mut(&interval) {
            accumulator.accumulated.accumulate(&output_share)?;
            accumulator.contributions += 1;
        } else {
            // This is the first input we have seen for this batch interval.
            // Initialize the accumulator.
            self.accumulators.insert(
                interval,
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

    pub(crate) fn extract_aggregate_share(
        &mut self,
        requested_task_id: TaskId,
        batch_interval: Interval,
    ) -> Result<hpke::Ciphertext, Error> {
        if self.task_parameters.task_id != requested_task_id {
            return Err(Error::UnrecognizedTask(requested_task_id));
        }

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
            let current_interval = first_interval
                .add(self.task_parameters.min_batch_duration.multiple(i))
                .batch_interval(self.task_parameters.min_batch_duration);

            self.collected_batch_intervals.insert(current_interval);

            match self.accumulators.get_mut(&current_interval) {
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
                    warn!("no accumulator found for interval {:?}", current_interval);
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

        let hpke_sender = self.task_parameters.collector_config.sender(
            &self.task_parameters.task_id,
            hpke::Label::AggregateShare,
            self.role,
            Role::Collector,
        )?;

        Ok(hpke_sender.seal(
            &aggregate_shares[0].get_encoded(),
            &batch_interval.associated_data(),
        )?)
    }

    pub(crate) fn dump_accumulators(&self) {
        dump_accumulators(&self.accumulators)
    }
}
