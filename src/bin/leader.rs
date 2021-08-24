use http::Response;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use warp::Filter;

#[tokio::main]
async fn main() {
    println!("Hello, leader");

    let hello = warp::get().and(warp::path("hello")).map(|| {
        println!("handling request to hello");
        Response::builder().status(200).body("PPM leader\n")
    });

    let hpke_config = warp::get().and(warp::path("hpke_config")).map(|| {
        println!("handling request to hpke_config");
        Response::builder().status(200).body("hpke config\n")
    });

    println!("serving hello on 0.0.0.0:8080");
    warp::serve(hello.or(hpke_config))
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080))
        .await;
}
