use thiserror::Error;
use warp::reject::Reject;

#[derive(Error, Debug)]
pub enum WASPError {
    #[error("Network error: {0}")]
    NetworkError(#[from] std::io::Error),
    #[error("Route selection error: {0}")]
    RouteSelectionError(String),
    #[error("Circuit error: {0}")]
    CircuitError(String),
    #[error("Lsassy error: {0}")]
    LsassyError(String),
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Authentication error: {0}")]
    AuthError(String),
    #[error("Validation error: {0}")]
    ValidationError(#[from] validator::ValidationErrors),
    #[error("Internal server error")]
    InternalServerError,
}

impl Reject for WASPError {}

pub async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(e) = err.find::<WASPError>() {
        match e {
            WASPError::AuthError(_) => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "UNAUTHORIZED";
            }
            WASPError::ValidationError(_) => {
                code = warp::http::StatusCode::BAD_REQUEST;
                message = "BAD_REQUEST";
            }
            _ => {
                eprintln!("unhandled error: {:?}", err);
                code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                message = "INTERNAL_SERVER_ERROR";
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = warp::http::StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD_NOT_ALLOWED";
    } else {
        eprintln!("unhandled error: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "INTERNAL_SERVER_ERROR";
    }

    let json = warp::reply::json(&ErrorResponse {
        code: code.as_u16(),
        message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
}