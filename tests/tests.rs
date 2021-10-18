use ppm_prototype::{
    client::Client, collect::run_collect, helper::run_helper, hpke, leader::run_leader,
    parameters::Parameters, trace,
};
use prio::{field::Field64, pcp::types::Boolean};
use std::io::Cursor;

#[tokio::test]
async fn test() {
    trace::install_subscriber();

    let parameters = Parameters::from_json_reader(Cursor::new(include_bytes!(
        "../sample-config/parameters.json"
    )))
    .unwrap();
    let hpke_config = hpke::ConfigFile::from_json_reader(Cursor::new(include_bytes!(
        "../sample-config/hpke.json"
    )))
    .unwrap();

    // Spawn leader and helper tasks
    let leader_handle = tokio::spawn(run_leader(parameters.clone(), hpke_config.leader));
    let helper_handle = tokio::spawn(run_helper(parameters.clone(), hpke_config.helper));

    // Generate and upload 100 reports
    let client = Client::new(&parameters).await.unwrap();
    for count in 0..100 {
        client
            .do_upload(count, Boolean::<Field64>::new(true))
            .await
            .unwrap();
    }

    // Collect
    run_collect(&parameters, &hpke_config.collector)
        .await
        .unwrap();

    // Kill leader and helper tasks
    leader_handle.abort();
    helper_handle.abort();

    assert!(leader_handle.await.unwrap_err().is_cancelled());
    assert!(helper_handle.await.unwrap_err().is_cancelled());
}
