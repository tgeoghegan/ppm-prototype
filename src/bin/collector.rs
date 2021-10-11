use color_eyre::eyre::{eyre, Result};
use ppm_prototype::{
    collect::{CollectRequest, CollectResponse, OutputShare, ProtocolCollectFields},
    hpke::{self, Role},
    parameters::Parameters,
    trace, Interval,
};
use prio::field::{merge_vector, Field64, FieldElement};
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
    let hpke_config = hpke::Config::from_config_file(Role::Collector)?;

    let batch_interval = Interval {
        start: 1631907500,
        end: 1631907500 + 100,
    };

    let collect_request = CollectRequest {
        task_id: ppm_parameters.task_id,
        batch_interval,
        protocol_parameters: ProtocolCollectFields::Prio {},
    };

    let collect_response = http_client
        .post(ppm_parameters.collect_endpoint()?)
        .json(&collect_request)
        .send()
        .await?;

    let status = collect_response.status();
    info!(http_status = ?status, "collect request HTTP status");
    if !status.is_success() {
        return Err(eyre!("collect request failed"));
    }

    let collect_response_body: CollectResponse = collect_response.json().await?;
    let leader_recipient = hpke_config.output_share_recipient(
        &ppm_parameters.task_id,
        Role::Leader,
        &collect_response_body.encrypted_output_shares[Role::Leader.index()].encapsulated_context,
    )?;
    let decrypted_leader_share: OutputShare =
        serde_json::from_slice(&leader_recipient.decrypt_output_share(
            &collect_response_body.encrypted_output_shares[Role::Leader.index()],
            batch_interval,
        )?)?;

    let helper_recipient = hpke_config.output_share_recipient(
        &ppm_parameters.task_id,
        Role::Helper,
        &collect_response_body.encrypted_output_shares[Role::Helper.index()].encapsulated_context,
    )?;
    let decrypted_helper_share: OutputShare =
        serde_json::from_slice(&helper_recipient.decrypt_output_share(
            &collect_response_body.encrypted_output_shares[Role::Helper.index()],
            batch_interval,
        )?)?;

    if decrypted_leader_share.contributions != decrypted_helper_share.contributions {
        return Err(eyre!(format!(
            "mismatched contribution counts between helper and leader: {} / {}",
            decrypted_leader_share.contributions, decrypted_helper_share.contributions
        )));
    }

    let mut leader_share = Field64::byte_slice_into_vec(&decrypted_leader_share.sum)?;
    let helper_share = Field64::byte_slice_into_vec(&decrypted_helper_share.sum)?;

    merge_vector(&mut leader_share, &helper_share)?;

    info!(aggregate = ?leader_share, "reassembled aggregate");

    Ok(())
}
