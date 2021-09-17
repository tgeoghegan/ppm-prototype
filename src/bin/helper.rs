use color_eyre::eyre::Result;
use http::StatusCode;
use ppm_prototype::{
    aggregate::{AggregateRequest, AggregateResponse},
    hpke::{self, Role},
    parameters::Parameters,
    trace,
};
use prio::field::Field64;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;
use warp::{reply, Filter};

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

    let aggregate = warp::post()
        .and(warp::path("aggregate"))
        .and(warp::body::json())
        .map(move |aggregate_request: AggregateRequest<Field64>| {
            info!(
                sub_request_count = aggregate_request.sub_requests.len(),
                "got aggregate request"
            );
            let response: AggregateResponse<Field64> = AggregateResponse {
                helper_state: vec![],
                sub_responses: vec![],
            };
            reply::with_status(reply::json(&response), StatusCode::OK)
        })
        .with(warp::trace::named("aggregate"));

    let routes = hpke_config_endpoint
        .or(aggregate)
        .with(warp::trace::request());

    info!("helper serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
