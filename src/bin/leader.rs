use color_eyre::eyre::{Context, Result};
use ppm_prototype::{
    hpke::{self, Role},
    leader::run_leader,
    parameters::Parameters,
    trace,
};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;
    let hpke_config =
        hpke::Config::from_config_file(Role::Leader).wrap_err("loading hpke config")?;

    run_leader(ppm_parameters, hpke_config).await
}
