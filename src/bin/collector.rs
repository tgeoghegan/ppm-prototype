use color_eyre::eyre::Result;
use ppm_prototype::{
    collect::run_collect, hpke, parameters::Parameters, trace, Duration, Interval, Role, Time,
};
use prio::vdaf::{prio3::Prio3Sum64, suite::Suite};

#[tokio::main]
async fn main() -> Result<()> {
    // Pretty-print errors
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file()?;
    let hpke_config = hpke::Config::from_config_file(Role::Collector)?;
    let vdaf = Prio3Sum64::new(Suite::Blake3, 2, 63).unwrap();

    let sum = run_collect(
        &ppm_parameters,
        &hpke_config,
        Interval {
            start: Time(1631907500),
            duration: Duration(100),
        },
        vdaf,
        &(),
    )
    .await?;

    println!("Sum: {:?}", sum);

    Ok(())
}
