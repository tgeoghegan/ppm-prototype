use ::hpke::Serializable;
use color_eyre::eyre::Result;
use ppm_prototype::{
    hpke::Role,
    parameters::Parameters,
    trace,
    upload::{EncryptedInputShare, Report},
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

    let mut hpke_sender =
        leader_hpke_config.report_sender(&ppm_parameters.task_id, Role::Leader)?;

    // TODO(timg): I don't like partially constructing the Report and then
    // filling in `encrypted_input_shares` later. Maybe impl Default on Report.
    let mut report = Report {
        task_id: ppm_parameters.task_id,
        time: 1001,
        nonce: rand::random(),
        extensions: vec![],
        encrypted_input_shares: vec![],
    };

    let plaintext = "plaintext input share".as_bytes();
    let payload = hpke_sender.encrypt_input_share(&report, plaintext)?;
    report.encrypted_input_shares = vec![EncryptedInputShare {
        config_id: leader_hpke_config.id,
        encapsulated_context: hpke_sender.encapped_key.to_bytes().as_slice().to_vec(),
        payload,
    }];

    let upload_endpoint = ppm_parameters.upload_endpoint()?;

    let upload_status = http_client
        .post(upload_endpoint)
        .json(&report)
        .send()
        .await?
        .status();

    info!(?upload_status, "upload complete");

    Ok(())
}
