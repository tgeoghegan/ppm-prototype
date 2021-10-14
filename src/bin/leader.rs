use color_eyre::eyre::{Context, Result};
use http::StatusCode;
use ppm_prototype::{
    collect::CollectRequest,
    hpke::{self, Role},
    leader::Leader,
    parameters::Parameters,
    trace,
    upload::Report,
    with_shared_value,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{error, info};
use warp::{reply, Filter};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file().wrap_err("loading task parameters")?;
    let port = ppm_parameters.aggregator_urls[Role::Leader.index()]
        .port()
        .unwrap_or(80);
    let hpke_config =
        hpke::Config::from_config_file(Role::Leader).wrap_err("loading hpke config")?;
    let hpke_config_endpoint = hpke_config.warp_endpoint();

    let leader_aggregator = Arc::new(Mutex::new(Leader::new(&ppm_parameters, &hpke_config)?));

    let upload = warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(|report: Report, leader: Arc<Mutex<Leader>>| async move {
            match leader.lock().await.handle_upload(&report).await {
                Ok(()) => Ok(reply::with_status(reply(), StatusCode::OK)),
                Err(e) => {
                    error!(error = ?e, "failed to handle upload");
                    // TODO wire up a type that implements Reject and attach
                    // a warp reject handler that constructs appropriate responses
                    Err(warp::reject::not_found())
                }
            }
        })
        .with(warp::trace::named("upload"));

    let collect = warp::post()
        .and(warp::path("collect"))
        .and(warp::body::json())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(
            |collect_request: CollectRequest, leader: Arc<Mutex<Leader>>| async move {
                match leader.lock().await.handle_collect(&collect_request).await {
                    Ok(response) => Ok(reply::with_status(reply::json(&response), StatusCode::OK)),
                    Err(_) => Err(warp::reject::not_found()),
                }
            },
        )
        .with(warp::trace::named("collect"));

    let routes = hpke_config_endpoint
        .or(upload)
        .or(collect)
        .with(warp::trace::request());

    info!("leader serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
