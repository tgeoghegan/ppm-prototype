use ::hpke::Serializable;
use color_eyre::eyre::{eyre, Result};
use ppm_prototype::{
    hpke::{self, Role},
    parameters::{Parameters, PrioField, PrioType, ProtocolParameters},
    trace,
    upload::{EncryptedInputShare, Report},
    Timestamp,
};
use prio::{
    field::Field64,
    pcp::types::Boolean,
    vdaf::{dist_input, suite::Suite},
};
use reqwest::Client;
use tracing::info;

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

async fn do_upload(
    count: u64,
    http_client: &Client,
    ppm_parameters: &Parameters,
    leader_hpke_config: &hpke::Config,
    helper_hpke_config: &hpke::Config,
) -> Result<()> {
    // TODO(timg): I don't like partially constructing the Report and then
    // filling in `encrypted_input_shares` later. Maybe impl Default on Report.
    let mut report = Report {
        timestamp: Timestamp {
            time: 1631907500 + count,
            nonce: rand::random(),
        },
        task_id: ppm_parameters.task_id,
        extensions: vec![],
        encrypted_input_shares: vec![],
    };

    match ppm_parameters.protocol_parameters {
        ProtocolParameters::Prio {
            field: PrioField::Field64,
            prio_type: PrioType::Boolean,
        } => (),
        _ => return Err(eyre!("only Prio is supported")),
    }

    // Generate a Prio input and proof. The serialized format is input share
    // then proof share.
    let input: Boolean<Field64> = Boolean::new(true);
    let upload_messages = dist_input(Suite::Aes128CtrHmacSha256, &input, 2)?;

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
    let leader_hpke_sender =
        leader_hpke_config.report_sender(&ppm_parameters.task_id, Role::Leader)?;

    let helper_hpke_sender =
        helper_hpke_config.report_sender(&ppm_parameters.task_id, Role::Helper)?;

    let (leader_payload, leader_encapped_key) =
        leader_hpke_sender.encrypt_input_share(&report, &json_leader_share)?;
    let (helper_payload, helper_encapped_key) =
        helper_hpke_sender.encrypt_input_share(&report, &json_helper_share)?;
    report.encrypted_input_shares = vec![
        EncryptedInputShare {
            aggregator_config_id: leader_hpke_config.id,
            encapsulated_context: leader_encapped_key.to_bytes().to_vec(),
            payload: leader_payload,
        },
        EncryptedInputShare {
            aggregator_config_id: helper_hpke_config.id,
            encapsulated_context: helper_encapped_key.to_bytes().to_vec(),
            payload: helper_payload,
        },
    ];

    let upload_status = http_client
        .post(ppm_parameters.upload_endpoint()?)
        .json(&report)
        .send()
        .await?
        .status();

    info!(?upload_status, "upload complete");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let http_client = Client::builder().user_agent(CLIENT_USER_AGENT).build()?;

    let ppm_parameters = Parameters::from_config_file()?;

    let leader_hpke_config = ppm_parameters
        .hpke_config(Role::Leader, &http_client)
        .await?;

    let helper_hpke_config = ppm_parameters
        .hpke_config(Role::Helper, &http_client)
        .await?;

    for count in 0..100 {
        do_upload(
            count,
            &http_client,
            &ppm_parameters,
            &leader_hpke_config,
            &helper_hpke_config,
        )
        .await?;
    }

    Ok(())
}
