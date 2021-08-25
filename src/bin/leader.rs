use http::StatusCode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::{reply, Filter};

use ppm_prototype::{
    hpke::{
        AuthenticatedEncryptionWithAssociatedData, Config, KeyDerivationFunction,
        KeyEncapsulationMechanism, Role,
    },
    parameters::Parameters,
    upload::Report,
};

#[tokio::main]
async fn main() {
    println!("Hello, leader");

    let ppm_parameters = Parameters::fixed_parameters();

    let config = Config::new_recipient(
        KeyEncapsulationMechanism::X25519HkdfSha256,
        KeyDerivationFunction::HkdfSha256,
        AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
    );

    let config_clone = config.clone();
    let hpke_config = warp::get().and(warp::path("hpke_config")).map(move || {
        println!("handling request to hpke_config");
        reply::with_status(
            reply::json(&config_clone.without_private_key()),
            StatusCode::OK,
        )
    });

    let upload = warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .map(move |report: Report| {
            println!("handling upload request");

            if report.task_id != ppm_parameters.task_id() {
                // TODO(timg) construct problem document with type=unrecognizedTask
                // per section 3.1
                return reply::with_status(reply(), StatusCode::BAD_REQUEST);
            }

            for share in &report.encrypted_input_shares {
                if share.config_id != config.id {
                    // TODO(timg) construct problem document with type=outdatedConfig
                    // per section 3.1
                    return reply::with_status(reply(), StatusCode::BAD_REQUEST);
                }
            }

            // Decrypt leader share
            let mut hpke_recipient =
                match config.report_recipient(&report.task_id, Role::Leader, &report) {
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

            println!(
                "obtained report {:?}\ndecrypted input {}",
                report,
                std::str::from_utf8(&decrypted_input_share).unwrap(),
            );

            reply::with_status(reply(), StatusCode::OK)
        });

    println!("serving hpke config on 0.0.0.0:8080");
    warp::serve(hpke_config.or(upload))
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080))
        .await;
}
