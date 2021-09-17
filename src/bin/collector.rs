use color_eyre::eyre::{eyre, Result};
use ppm_prototype::{
    collect::{CollectRequest, CollectResponse, ProtocolCollectFields},
    parameters::Parameters,
    trace, Interval,
};
use reqwest::Client;
use tracing::info;

static COLLECTOR_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "collector"
);

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let http_client = Client::builder().user_agent(COLLECTOR_USER_AGENT).build()?;

    let ppm_parameters = Parameters::from_config_file()?;

    let collect_request = CollectRequest {
        task_id: ppm_parameters.task_id,
        batch_interval: Interval { start: 10, end: 20 },
        protocol_parameters: ProtocolCollectFields::Prio {},
    };

    let collect_response = http_client
        .post(ppm_parameters.collect_endpoint()?)
        .json(&collect_request)
        .send()
        .await?;

    let status = collect_response.status();
    if !status.is_success() {
        return Err(eyre!("upload failed"));
    }

    let collect_response_body: CollectResponse = collect_response.json().await?;
    info!(?collect_response_body, "got collect response");

    Ok(())
}
