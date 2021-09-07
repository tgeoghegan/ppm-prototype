use color_eyre::eyre::Result;
use http::StatusCode;
use ppm_prototype::{
    hpke::{self, Role},
    parameters::Parameters,
    trace,
    upload::Report,
};
use prio::{
    field::{Field64, FieldElement},
    pcp::{query, types::Boolean, Proof, Value},
};
use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tracing::{error, info};
use warp::{reply, Filter};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    trace::install_subscriber();

    let ppm_parameters = Parameters::from_config_file()?;
    let port = ppm_parameters.aggregator_urls[Role::Leader.index()]
        .port()
        .unwrap_or(80);
    let hpke_config = hpke::Config::from_config_file()?;
    let hpke_config_endpoint = hpke_config.warp_endpoint();

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
                        error!("error constructing recipient: {:?}", e);
                        return reply::with_status(reply(), StatusCode::INTERNAL_SERVER_ERROR);
                    }
                };

            let decrypted_input_share = match hpke_recipient.decrypt_input_share(&report) {
                Ok(share) => share,
                Err(e) => {
                    // TODO(timg) construct problem document with type=unrecognizedMessage
                    error!("error decrypting shares: {:?}", e);
                    return reply::with_status(reply(), StatusCode::BAD_REQUEST);
                }
            };

            let deserialized_data: Vec<Field64> =
                match Field64::byte_slice_into_vec(&decrypted_input_share) {
                    Ok(data) => data,
                    Err(e) => {
                        error!("error deserializing shares: {:?}", e);
                        return reply::with_status(reply(), StatusCode::BAD_REQUEST);
                    }
                };

            // Boolean::try_from is infallible
            // TODO(timg): we need the "Param" to deserialize the value, but we
            // need an instance of the param to do that.
            let _input_share: Boolean<Field64> =
                Boolean::try_from(((), &deserialized_data[..1])).unwrap();

            info!(?report, "obtained report");

            reply::with_status(reply(), StatusCode::OK)
        })
        .with(warp::trace::named("upload"));

    info!("leader serving on 0.0.0.0:{}", port);

    warp::serve(hpke_config_endpoint.or(upload).with(warp::trace::request()))
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
