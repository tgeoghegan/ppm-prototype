use color_eyre::eyre::Result;
use http::StatusCode;
use ppm_prototype::{
    aggregate::AggregateRequest,
    helper::Helper,
    hpke::{self, Role},
    parameters::Parameters,
    trace,
};
use prio::field::Field64;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::{error, info};
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
            // We intentionally create a new instance of Helper every time we
            // handle a request to prove that we can successfully execute the
            // protocol without maintaining local state
            let mut helper_aggregator = match Helper::new(
                &ppm_parameters,
                &hpke_config,
                &aggregate_request.helper_state,
            ) {
                Ok(helper) => helper,
                Err(e) => {
                    error!(error = ?e, "failed to create helper aggregator with state");
                    return reply::with_status(reply::json(&()), StatusCode::BAD_REQUEST);
                }
            };

            match helper_aggregator.handle_aggregate(&aggregate_request) {
                Ok(response) => reply::with_status(reply::json(&response), StatusCode::OK),
                Err(e) => {
                    error!(error = ?e, "failed to handle aggregate request");
                    reply::with_status(reply::json(&()), StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
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
