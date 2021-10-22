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

struct TestCase {
    parameters: Parameters,
    hpke_config: hpke::ConfigFile,
    leader_handle: JoinHandle<Result<()>>,
    helper_handle: JoinHandle<Result<()>>,
}

impl TestCase {
    async fn new_tamper(tamper_leader_proof: bool, tamper_helper_proof: bool) -> Self {
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
        let leader_handle =
            tokio::spawn(run_leader(parameters.clone(), hpke_config.leader.clone()));
        let helper_handle =
            tokio::spawn(run_helper(parameters.clone(), hpke_config.helper.clone()));

        // Generate and upload 100 reports, with timestamps one second apart
        let mut client = Client::new(&parameters).await.unwrap();
        if tamper_leader_proof {
            client.tamper_with_leader_proof = true;
        }
        if tamper_helper_proof {
            client.tamper_with_helper_proof = true;
        }
        for count in 0..100 {
            client
                .do_upload(INTERVAL_START + count, Boolean::<Field64>::new(true))
                .await
                .unwrap();
        }

        Self {
            parameters,
            hpke_config,
            leader_handle,
            helper_handle,
        }
    }

    async fn new() -> Self {
        Self::new_tamper(false, false).await
    }

    async fn teardown(self) {
        // Kill leader and helper tasks
        self.leader_handle.abort();
        self.helper_handle.abort();

        assert!(self.leader_handle.await.unwrap_err().is_cancelled());
        assert!(self.helper_handle.await.unwrap_err().is_cancelled());
    }
}

#[tokio::test]
#[serial]
async fn successful_aggregate() {
    let test_case = TestCase::new().await;

    // The interval should capture all inputs send by client
    let collect_interval = Interval {
        start: Time(INTERVAL_START),
        end: Time(INTERVAL_START + 100),
    };

    // Successful collect
    let sum = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        collect_interval,
    )
    .await
    .unwrap();

    assert_eq!(sum.first().unwrap(), &Field64::from(100));

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn insufficient_batch_size() {
    let test_case = TestCase::new().await;
    // Not enough inputs in the interval to meet min batch size
    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
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

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn exceed_privacy_budget() {
    let test_case = TestCase::new().await;
    // The interval should capture all inputs send by client
    let collect_interval = Interval {
        start: Time(INTERVAL_START),
        end: Time(INTERVAL_START + 100),
    };

    // Successful collect
    let sum = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        collect_interval,
    )
    .await
    .unwrap();

    assert_eq!(sum.first().unwrap(), &Field64::from(100));

    // Collect again over same interval. Should fail because privacy budget is
    // exceeded.
    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        collect_interval,
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:privacyBudgetExceeded".to_string()));
    });

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn unaligned_batch_interval() {
    let test_case = TestCase::new().await;
    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        Interval {
            start: Time(INTERVAL_START),
            end: Time(INTERVAL_START + 99),
        },
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:invalidBatchInterval".to_string()));
    });

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn batch_interval_too_short() {
    let test_case = TestCase::new().await;

    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        Interval {
            start: Time(INTERVAL_START),
            end: Time(INTERVAL_START + 25),
        },
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:invalidBatchInterval".to_string()));
    });

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn invalid_helper_proof() {
    let test_case = TestCase::new_tamper(false, true).await;

    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        Interval {
            start: Time(INTERVAL_START),
            end: Time(INTERVAL_START + 100),
        },
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        // There's no explicit error from proof rejection. Rather, those inputs
        // whose proofs were bad will simply be not have been aggregated, so
        // the collect request fails with insufficient batch size.
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:insufficientBatchSize".to_string()));
    });

    test_case.teardown().await;
}

#[tokio::test]
#[serial]
async fn invalid_leader_proof() {
    let test_case = TestCase::new_tamper(true, false).await;

    let error_document = run_collect(
        &test_case.parameters,
        &test_case.hpke_config.collector,
        Interval {
            start: Time(INTERVAL_START),
            end: Time(INTERVAL_START + 100),
        },
    )
    .await
    .unwrap_err();

    assert_matches!(error_document, collect::Error::ProblemDocument(problem_document) => {
        assert_eq!(problem_document.instance, Some("collect".to_string()));
        assert_eq!(problem_document.status, Some(StatusCode::BAD_REQUEST));
        // There's no explicit error from proof rejection. Rather, those inputs
        // whose proofs were bad will simply be not have been aggregated, so
        // the collect request fails with insufficient batch size.
        assert_eq!(problem_document.type_url, Some("urn:ietf:params:ppm:error:insufficientBatchSize".to_string()));
    });

    test_case.teardown().await;
}
