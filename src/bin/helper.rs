use color_eyre::eyre::Result;
use ppm_prototype::{
    hpke::{self, Role},
    parameters::Parameters,
    trace,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;
use warp::Filter;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file()?;
    let port = ppm_parameters.aggregator_urls[Role::Helper.index()]
        .port()
        .unwrap_or(80);

    let hpke_config = hpke::Config::from_config_file()?;
    let hpke_config_endpoint = hpke_config.warp_endpoint();

    info!("helper serving on 0.0.0.0:{}", port);

    warp::serve(hpke_config_endpoint.with(warp::trace::request()))
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
