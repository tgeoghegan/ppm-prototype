use assert_matches::assert_matches;
use color_eyre::Result;
use http::StatusCode;
use ppm_prototype::{
    client::Client,
    collect::{self, run_collect},
    helper::run_helper,
    hpke,
    leader::run_leader,
    parameters::Parameters,
    trace, Interval, Time,
};
use prio::{field::Field64, pcp::types::Boolean};
use serial_test::serial;
use std::io::Cursor;
use std::sync::Once;
use tokio::task::JoinHandle;

const INTERVAL_START: u64 = 1631907500;

// Install a trace subscriber once for all tests
static INSTALL_TRACE_SUBSCRIBER: Once = Once::new();

async fn setup_test() -> (
    Parameters,
    hpke::ConfigFile,
    JoinHandle<Result<()>>,
    JoinHandle<Result<()>>,
) {
    INSTALL_TRACE_SUBSCRIBER.call_once(trace::install_subscriber);

    let parameters = Parameters::from_json_reader(Cursor::new(include_bytes!(
        "../sample-config/parameters.json"
    )))
    .unwrap();
    let hpke_config = hpke::ConfigFile::from_json_reader(Cursor::new(include_bytes!(
        "../sample-config/hpke.json"
    )))
    .unwrap();

    // Spawn leader and helper tasks
    let leader_handle = tokio::spawn(run_leader(parameters.clone(), hpke_config.leader.clone()));
    let helper_handle = tokio::spawn(run_helper(parameters.clone(), hpke_config.helper.clone()));

    // Generate and upload 100 reports, with timestamps one second apart
    let client = Client::new(&parameters).await.unwrap();
    for count in 0..100 {
        client
            .do_upload(INTERVAL_START + count, Boolean::<Field64>::new(true))
            .await
            .unwrap();
    }

    (parameters, hpke_config, leader_handle, helper_handle)
}

async fn teardown_test(
    leader_handle: JoinHandle<Result<()>>,
    helper_handle: JoinHandle<Result<()>>,
) {
    // Kill leader and helper tasks
    leader_handle.abort();
    helper_handle.abort();

    assert!(leader_handle.await.unwrap_err().is_cancelled());
    assert!(helper_handle.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[serial]
async fn insufficient_batch_size() {
    let (parameters, hpke_config, leader_handle, helper_handle) = setup_test().await;

    // Not enough inputs in the interval to meet min batch size
    let error_document = run_collect(
        &parameters,
        &hpke_config.collector,
        Interval {
            start: Time(INTERVAL_START),
            end: Time(INTERVAL_START + 50),
        },
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:insufficientBatchSize".to_string()));
    });

    teardown_test(leader_handle, helper_handle).await;
}

#[tokio::test]
#[serial]
async fn exceed_privacy_budget() {
    let (parameters, hpke_config, leader_handle, helper_handle) = setup_test().await;

    // The interval should capture all inputs send by client
    let collect_interval = Interval {
        start: Time(INTERVAL_START),
        end: Time(INTERVAL_START + 100),
    };

    // Successful collect
    let sum = run_collect(&parameters, &hpke_config.collector, collect_interval)
        .await
        .unwrap();

    assert_eq!(sum.first().unwrap(), &Field64::from(100));

    // Collect again over same interval. Should fail because privacy budget is
    // exceeded.
    let error_document = run_collect(&parameters, &hpke_config.collector, collect_interval)
        .await
        .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:privacyBudgetExceeded".to_string()));
    });

    teardown_test(leader_handle, helper_handle).await;
}
