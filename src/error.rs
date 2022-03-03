use crate::parameters::Parameters;
use http::StatusCode;
use http_api_problem::HttpApiProblem;
use std::{convert::Infallible, error::Error};
use warp::reject::Rejection;

/// Represents the possible URNs in PPM HTTP problem documents
pub(crate) enum ProblemDocumentType {
    UnrecognizedMessage,
    UnrecognizedTask,
    OutdatedConfig,
    InvalidBatchInterval,
    InsufficientBatchSize,
    PrivacyBudgetExceeded,
    HelperError,
    UnknownError,
    StaleReport,
}

impl From<ProblemDocumentType> for String {
    fn from(type_urn: ProblemDocumentType) -> Self {
        let problem_type = match type_urn {
            ProblemDocumentType::UnrecognizedMessage => "unrecognizedMessage",
            ProblemDocumentType::UnrecognizedTask => "unrecognizedTask",
            ProblemDocumentType::OutdatedConfig => "outdatedConfig",
            ProblemDocumentType::InvalidBatchInterval => "invalidBatchInterval",
            ProblemDocumentType::InsufficientBatchSize => "insufficientBatchSize",
            ProblemDocumentType::PrivacyBudgetExceeded => "privacyBudgetExceeded",
            ProblemDocumentType::HelperError => "helperError",
            ProblemDocumentType::UnknownError => "unknownError",
            ProblemDocumentType::StaleReport => "staleReport",
        };

        format!("urn:ietf:params:ppm:error:{}", problem_type)
    }
}

/// Allows conversion into an `HttpApiProblem`. Intended for implementation by
/// the crate's various error types.
pub(crate) trait IntoHttpApiProblem: Error {
    /// Constructs an `HttpApiProblem` annotated with the PPM task ID and
    /// endpoint
    fn problem_document(
        &self,
        ppm_parameters: Option<&Parameters>,
        endpoint: &'static str,
    ) -> HttpApiProblem {
        if let Some(source_document) = self.source_problem_document() {
            return source_document.clone().instance(endpoint);
        }

        let task_id = match ppm_parameters {
            Some(ppm_parameters) => ppm_parameters.task_id.to_string(),
            None => "unknown".to_string(),
        };

        match self.problem_document_type() {
            Some(problem_document_type) => {
                HttpApiProblem::new(StatusCode::BAD_REQUEST).type_url(problem_document_type)
            }
            None => HttpApiProblem::new(StatusCode::INTERNAL_SERVER_ERROR)
                .type_url(ProblemDocumentType::UnknownError),
        }
        .detail(self.to_string())
        .value("taskid", &task_id)
        .instance(endpoint)
    }

    /// Get problem document type for the error, or None for errors not captured
    /// by any of the PPM protocol's error types, in which case a problem
    /// document with HTTP status code 500 is constructed.
    fn problem_document_type(&self) -> Option<ProblemDocumentType>;

    /// Implementations may provide an HttpApiProblem representing the cause of
    /// this problem, which will be returned from [`problem_document`] instead
    /// of constructing a new problem document, though with the `instance`
    /// field set.
    fn source_problem_document(&self) -> Option<&HttpApiProblem> {
        None
    }
}

impl IntoHttpApiProblem for http::Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        None
    }
}

impl IntoHttpApiProblem for prio::codec::CodecError {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        Some(ProblemDocumentType::UnrecognizedMessage)
    }
}

/// warp rejection handler that can be tacked on to routes to construct a
/// warp::Reply with appropriate status code and JSON body for an HTTP problem
/// document.
pub(crate) async fn handle_rejection(rejection: Rejection) -> Result<impl warp::Reply, Infallible> {
    // All our warp rejections should wrap a problem document, so crash if we
    // can't find one.
    let problem_document = rejection.find::<HttpApiProblem>().unwrap();

    Ok(warp::reply::with_header(
        warp::reply::with_status(
            warp::reply::json(problem_document),
            problem_document
                .status
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        ),
        http::header::CONTENT_TYPE,
        "application/problem+json",
    ))
}

/// Returns the problem document encoded into the response's body, if any. If
/// the body could not be loaded and parsed as a problem document, it is
/// returned as Err(body).
pub(crate) async fn response_to_api_problem(
    response: reqwest::Response,
) -> Result<HttpApiProblem, String> {
    // Get the whole response body so that we can put it into the problem
    // document should parsing it as a JSON problem document fail
    let response_body = match response.text().await {
        Ok(text) => text,
        Err(e) => return Err(format!("could not load response body: {:?}", e)),
    };

    let problem_document: HttpApiProblem = match serde_json::from_str(&response_body) {
        Ok(problem_document) => problem_document,
        Err(_) => {
            return Err(format!(
                "response body is not a problem document\n\n{}",
                response_body
            ))
        }
    };

    Ok(problem_document)
}
