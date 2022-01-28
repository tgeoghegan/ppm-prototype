use color_eyre::eyre::{Context, Result};
use ppm_prototype::{helper::run_helper, hpke, parameters::Parameters, trace, Role};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;
    let hpke_config =
        hpke::Config::from_config_file(Role::Helper).wrap_err("loading HPKE config")?;

    run_helper(ppm_parameters, hpke_config).await
}
