use color_eyre::eyre::{Context, Result};
use ppm_prototype::{client::PpmClient, parameters::Parameters, trace};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;

    let client = PpmClient::new(&ppm_parameters).await?;

    for count in 0..100 {
        client.do_upload(1631907500 + count, 1).await?;
    }

    info!("completed uploads");

    Ok(())
}
