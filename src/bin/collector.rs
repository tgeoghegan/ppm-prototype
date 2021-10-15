use color_eyre::eyre::Result;
use ppm_prototype::{
    collect::run_collect,
    hpke::{self, Role},
    parameters::Parameters,
    trace,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file()?;
    let hpke_config = hpke::Config::from_config_file(Role::Collector)?;

    run_collect(&ppm_parameters, &hpke_config).await
}
