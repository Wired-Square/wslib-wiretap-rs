//! What `/v1/health` and `/v1/databases` answer, and the body of every error.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub db_ok: bool,
    pub schema: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub name: String,
    pub size_bytes: i64,
    pub schema_state: String,
    pub schema_version: Option<i32>,
    pub busy_secs: Option<u64>,
    pub schema_error: Option<String>,
    pub rollup_state: Option<String>,
    pub rollup_lag_secs: Option<i64>,
    pub rollup_busy_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseList {
    pub databases: Vec<DatabaseInfo>,
    /// The version every database is headed for.
    pub schema_version: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}
