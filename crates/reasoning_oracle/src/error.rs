use std::fmt;

#[derive(Debug)]
pub enum OracleError {
    /// This backend never attempts this query shape/domain at all — try a
    /// different backend, or treat the question as genuinely open.
    Unsupported,
    /// The backend exists in principle but isn't usable right now (no
    /// `lean` toolchain on `PATH`, no API key configured, ...).
    BackendUnavailable(String),
    Timeout,
    Other(String),
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::Unsupported => write!(f, "this oracle does not support the requested query"),
            OracleError::BackendUnavailable(reason) => write!(f, "oracle backend unavailable: {reason}"),
            OracleError::Timeout => write!(f, "oracle query timed out"),
            OracleError::Other(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for OracleError {}

pub type OracleResult<T> = Result<T, OracleError>;
