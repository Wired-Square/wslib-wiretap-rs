//! A database's connections from `pg_stat_activity`, and the answer to
//! cancelling or terminating one.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseActivity {
    pub pid: i32,
    pub database: Option<String>,
    pub username: Option<String>,
    pub application_name: Option<String>,
    pub client_addr: Option<String>,
    pub state: Option<String>,
    pub query: Option<String>,
    /// PostgreSQL's `timestamptz::text`, not RFC 3339.
    pub query_start: Option<String>,
    pub duration_secs: Option<f64>,
    pub is_cancellable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseActivityResult {
    pub queries: Vec<DatabaseActivity>,
    pub sessions: Vec<DatabaseActivity>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalResponse {
    pub ok: bool,
}
