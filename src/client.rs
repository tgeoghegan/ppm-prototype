use crate::{
    hpke::{self, Role},
    parameters::{Parameters, PrioField, PrioType, ProtocolParameters},
    upload::{EncryptedInputShare, Report},
    Time, Timestamp,
};
use ::hpke::Serializable;
use color_eyre::eyre::{eyre, Result};
use http::StatusCode;
use prio::{
    field::Field64,
    pcp::types::Boolean,
    vdaf::{prio3_input, suite::Suite},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

pub struct Client {
    http_client: reqwest::Client,
    parameters: Parameters,
    leader_hpke_config: hpke::Config,
    helper_hpke_config: hpke::Config,
}

impl Client {
    pub async fn new(ppm_parameters: &Parameters) -> Result<Self, Error> {
        let http_client = reqwest::Client::builder()
            .user_agent(CLIENT_USER_AGENT)
            .build()?;
        let leader_hpke_config = ppm_parameters
            .hpke_config(Role::Leader, &http_client)
            .await?;
        let helper_hpke_config = ppm_parameters
            .hpke_config(Role::Helper, &http_client)
            .await?;

        Ok(Self {
            http_client,
            parameters: ppm_parameters.clone(),
            leader_hpke_config,
            helper_hpke_config,
        })
    }

    pub async fn do_upload(&self, count: u64, input: Boolean<Field64>) -> Result<()> {
        // TODO(timg): I don't like partially constructing the Report and then
        // filling in `encrypted_input_shares` later. Maybe impl Default on Report.
        let mut report = Report {
            timestamp: Timestamp {
                time: Time(1631907500 + count),
                nonce: rand::random(),
            },
            task_id: self.parameters.task_id,
            extensions: vec![],
            encrypted_input_shares: vec![],
        };

        match self.parameters.protocol_parameters {
            ProtocolParameters::Prio {
                field: PrioField::Field64,
                prio_type: PrioType::Boolean,
            } => (),
            _ => return Err(eyre!("only Prio is supported")),
        }

        // Generate a Prio input and proof. The serialized format is input share
        // then proof share.
        let upload_messages = prio3_input(Suite::Aes128CtrHmacSha256, &input, 2)?;

        // `Report.EncryptedInputShare.payload` is the encryption of a serialized
        // Prio `Upload[Message]`. Eventually we will implement serialization to
        // TLS presentation language, but for the time being we use JSON, hence
        // these explicit serde_json::to_vec calls. This is probably brittle because
        // we're depending on Serde to emit a "canonical" JSON encoding of a
        // message.
        let json_leader_share = serde_json::to_vec(&upload_messages[Role::Leader.index()])?;
        let json_helper_share = serde_json::to_vec(&upload_messages[Role::Helper.index()])?;

        // We have to create a new HPKE context for each message, or the nonces
        // won't line up with the recipient.
        let leader_hpke_sender = self
            .leader_hpke_config
            .report_sender(&self.parameters.task_id, Role::Leader)?;

        let helper_hpke_sender = self
            .helper_hpke_config
            .report_sender(&self.parameters.task_id, Role::Helper)?;

        let (leader_payload, leader_encapped_key) =
            leader_hpke_sender.encrypt_input_share(&report, &json_leader_share)?;
        let (helper_payload, helper_encapped_key) =
            helper_hpke_sender.encrypt_input_share(&report, &json_helper_share)?;
        report.encrypted_input_shares = vec![
            EncryptedInputShare {
                aggregator_config_id: self.leader_hpke_config.id,
                encapsulated_context: leader_encapped_key.to_bytes().to_vec(),
                payload: leader_payload,
            },
            EncryptedInputShare {
                aggregator_config_id: self.helper_hpke_config.id,
                encapsulated_context: helper_encapped_key.to_bytes().to_vec(),
                payload: helper_payload,
            },
        ];

        let status = self
            .http_client
            .post(self.parameters.upload_endpoint()?)
            .json(&report)
            .send()
            .await?
            .status();
        if status != StatusCode::OK {
            return Err(eyre!(
                "unexpected HTTP status in upload request {:?}",
                status
            ));
        }

        Ok(())
    }
}
