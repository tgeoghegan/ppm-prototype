use crate::{
    hpke,
    parameters::Parameters,
    upload::{EncryptedInputShare, Report},
    Nonce, Role, Time,
};
use ::hpke::Serializable;
use http::StatusCode;
use prio::vdaf::{
    prio3::Prio3Sum64,
    suite::{Key, Suite},
    Client,
};
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("VDAF error")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("Suite error")]
    Suite(#[from] prio::vdaf::suite::SuiteError),
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
    #[error("Unspecified error: {0}")]
    Unspecified(String),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

#[derive(Debug)]
pub struct PpmClient {
    http_client: reqwest::Client,
    parameters: Parameters,
    leader_hpke_config: hpke::Config,
    helper_hpke_config: hpke::Config,
    // TODO: make PpmClient generic over `Vdaf`, or has-a Box<dyn Vdaf>
    vdaf: Prio3Sum64,
    pub tamper_with_helper_proof: bool,
    pub tamper_with_leader_proof: bool,
}

impl PpmClient {
    #[tracing::instrument(err)]
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

        info!(?leader_hpke_config);

        Ok(Self {
            http_client,
            parameters: ppm_parameters.clone(),
            leader_hpke_config,
            helper_hpke_config,
            vdaf: Prio3Sum64::new(Suite::Blake3, 2, 63)?,
            tamper_with_helper_proof: false,
            tamper_with_leader_proof: false,
        })
    }

    pub async fn do_upload(&self, time: u64, input: u128) -> Result<(), Error> {
        let timestamp = Nonce {
            time: Time(time),
            rand: rand::random(),
        };

        // Generate a Prio input and proof. The serialized format is input share
        // then proof share.
        let mut upload_messages = self.vdaf.shard(&(), &input)?;

        // If requested, tamper with joint randomness seed hint, which will
        // cause proof verification to fail
        if self.tamper_with_leader_proof {
            upload_messages[Role::Leader.index()].joint_rand_seed_hint =
                Key::generate(Suite::Aes128CtrHmacSha256)?;
        }

        if self.tamper_with_helper_proof {
            upload_messages[Role::Helper.index()].joint_rand_seed_hint =
                Key::generate(Suite::Aes128CtrHmacSha256)?;
        }

        // `Report.EncryptedInputShare.payload` is the encryption of a serialized
        // Prio `Upload[Message]`. Eventually we will implement serialization to
        // TLS presentation language, but for the time being we use JSON, hence
        // these explicit serde_json::to_vec calls. This is probably brittle because
        // we're depending on Serde to emit a "canonical" JSON encoding of a
        // message.
        let json_leader_share: &[u8] = todo!(); //serde_json::to_vec(&upload_messages[Role::Leader.index()])?;
        let json_helper_share: &[u8] = todo!(); //serde_json::to_vec(&upload_messages[Role::Helper.index()])?;

        // We have to create a new HPKE context for each message, or the nonces
        // won't line up with the recipient.
        let leader_hpke_sender = self
            .leader_hpke_config
            .report_sender(&self.parameters.task_id, Role::Leader)?;

        let helper_hpke_sender = self
            .helper_hpke_config
            .report_sender(&self.parameters.task_id, Role::Helper)?;

        let (leader_payload, leader_encapped_key) =
            leader_hpke_sender.encrypt_input_share(timestamp, &json_leader_share)?;
        let (helper_payload, helper_encapped_key) =
            helper_hpke_sender.encrypt_input_share(timestamp, &json_helper_share)?;

        let report = Report {
            timestamp,
            task_id: self.parameters.task_id,
            encrypted_input_shares: vec![
                EncryptedInputShare {
                    aggregator_config_id: self.leader_hpke_config.id.0,
                    encapsulated_context: leader_encapped_key.to_bytes().to_vec(),
                    payload: leader_payload,
                },
                EncryptedInputShare {
                    aggregator_config_id: self.helper_hpke_config.id.0,
                    encapsulated_context: helper_encapped_key.to_bytes().to_vec(),
                    payload: helper_payload,
                },
            ],
            extensions: vec![],
        };

        let status = self
            .http_client
            .post(self.parameters.upload_endpoint()?)
            .json(&report)
            .send()
            .await?
            .status();
        if status != StatusCode::OK {
            return Err(Error::Unspecified(format!(
                "unexpected HTTP status in upload request {:?}",
                status
            )));
        }

        Ok(())
    }
}
