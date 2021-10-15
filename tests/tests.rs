use ppm_prototype::{
    client::Client,
    collect::run_collect,
    helper::run_helper,
    hpke::{self, Role},
    leader::run_leader,
    parameters::Parameters,
    trace,
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
    let leader_hpke_config = hpke::Config::from_config_file(Role::Leader).unwrap();
    let helper_hpke_config = hpke::Config::from_config_file(Role::Helper).unwrap();
    let collector_hpke_config = hpke::Config::from_config_file(Role::Collector).unwrap();

    // Spawn leader and helper tasks
    let leader_handle = tokio::spawn(run_leader(parameters.clone(), leader_hpke_config));
    let helper_handle = tokio::spawn(run_helper(parameters.clone(), helper_hpke_config));

    // Generate and upload 100 reports
    let client = Client::new(&parameters).await.unwrap();
    for count in 0..100 {
        client
            .do_upload(count, Boolean::<Field64>::new(true))
            .await
            .unwrap();
    }

    // Collect
    run_collect(&parameters, &collector_hpke_config)
        .await
        .unwrap();

    // Kill leader and helper tasks
    leader_handle.abort();
    helper_handle.abort();

    assert!(leader_handle.await.unwrap_err().is_cancelled());
    assert!(helper_handle.await.unwrap_err().is_cancelled());
}
