use color_eyre::eyre::{Context, Result};
use ppm_prototype::{client::PpmClient, parameters::Parameters, trace};
use prio::vdaf::{prio3::Prio3Sum64, suite::Suite};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;
    let vdaf = Prio3Sum64::new(Suite::Blake3, 2, 63).unwrap();

    let client = PpmClient::new(&ppm_parameters, &vdaf, ()).await?;

    for count in 0..100 {
        client.do_upload(1631907500 + count, &1).await?;
    }

    info!("completed uploads");

    Ok(())
}
