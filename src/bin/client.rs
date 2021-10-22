use color_eyre::eyre::{Context, Result};
use ppm_prototype::{client::Client, parameters::Parameters, trace};
use prio::{field::Field64, pcp::types::Boolean};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;

    let client = Client::new(&ppm_parameters).await?;

    for count in 0..100 {
        client
            .do_upload(1631907500 + count, Boolean::<Field64>::new(true))
            .await?;
    }

    info!("completed uploads");

    Ok(())
}
