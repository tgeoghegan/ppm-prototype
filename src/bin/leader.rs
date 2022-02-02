use color_eyre::eyre::{Context, Result};
use ppm_prototype::{
    aggregate::DefaultVerifyParam, hpke, leader::run_leader, parameters::Parameters, trace, Role,
};
use prio::{
    field::Field96,
    vdaf::{
        prio3::{Prio3Sum64, Prio3VerifyParam},
        suite::Suite,
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;
    let hpke_config =
        hpke::Config::from_config_file(Role::Leader).wrap_err("loading hpke config")?;
    let vdaf = Prio3Sum64::new(Suite::Blake3, 2, 63).unwrap();
    let pcp_type: prio::pcp::types::Sum<Field96> = prio::pcp::types::Sum::new(63).unwrap();

    run_leader(
        &ppm_parameters,
        &vdaf,
        &Prio3VerifyParam::default(Role::Leader, &pcp_type),
        &(),
        &hpke_config,
    )
    .await
}
