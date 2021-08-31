use color_eyre::eyre::Result;
use http::StatusCode;
use ppm_prototype::{
    hpke::{self, Role},
    parameters::Parameters,
    trace,
    upload::Report,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;
use warp::{reply, Filter};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file()?;

    let hpke_config = hpke::Config::from_config_file()?;

    let hpke_config_without_private_key = hpke_config.without_private_key();
    let hpke_config_endpoint = warp::get()
        .and(warp::path("hpke_config"))
        .map(move || {
            reply::with_status(
                reply::json(&hpke_config_without_private_key),
                StatusCode::OK,
            )
        })
        .with(warp::trace::named("hpke_config"));

    let upload = warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .map(move |report: Report| {
            if report.task_id != ppm_parameters.task_id {
                // TODO(timg) construct problem document with type=unrecognizedTask
                // per section 3.1
                return reply::with_status(reply(), StatusCode::BAD_REQUEST);
            }

            for share in &report.encrypted_input_shares {
                if share.config_id != hpke_config.id {
                    // TODO(timg) construct problem document with type=outdatedConfig
                    // per section 3.1
                    return reply::with_status(reply(), StatusCode::BAD_REQUEST);
                }
            }

            // Decrypt leader share
            let mut hpke_recipient =
                match hpke_config.report_recipient(&report.task_id, Role::Leader, &report) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("error constructing recipient: {:?}", e);
                        return reply::with_status(reply(), StatusCode::INTERNAL_SERVER_ERROR);
                    }
                };

            let decrypted_input_share = match hpke_recipient.decrypt_input_share(&report) {
                Ok(share) => share,
                Err(e) => {
                    // TODO(timg) construct problem document with type=unrecognizedMessage
                    println!("error decrypting shares: {:?}", e);
                    return reply::with_status(reply(), StatusCode::BAD_REQUEST);
                }
            };

            let decrypted_input = std::str::from_utf8(&decrypted_input_share).unwrap();

            info!(?report, decrypted_input, "obtained report");
            println!(
                "obtained report {:?}\ndecrypted input {}",
                report,
                std::str::from_utf8(&decrypted_input_share).unwrap(),
            );

            reply::with_status(reply(), StatusCode::OK)
        })
        .with(warp::trace::named("upload"));

    info!("serving hpke config on 0.0.0.0:8080");
    warp::serve(hpke_config_endpoint.or(upload).with(warp::trace::request()))
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080))
        .await;

    unreachable!()
}
