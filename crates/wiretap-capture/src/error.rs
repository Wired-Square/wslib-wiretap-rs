/// What a capture store read or write fails with.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error(transparent)]
    Sqlite(rusqlite::Error),
    /// Nothing of the migration was applied.
    #[error("Migration {version} ({name}) failed: {source}")]
    Migration {
        version: i64,
        name: &'static str,
        source: rusqlite::Error,
    },
    #[error("Query cancelled")]
    Cancelled,
    #[error("Unknown protocol '{0}'")]
    UnknownProtocol(String),
    #[error("Event not found")]
    EventNotFound,
}

impl From<rusqlite::Error> for CaptureError {
    fn from(e: rusqlite::Error) -> Self {
        match e.sqlite_error_code() {
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Cancelled,
            _ => Self::Sqlite(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, CaptureError>;
