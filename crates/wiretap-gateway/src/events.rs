//! A database's annotations: a moment or a span, with a note. Microseconds
//! since the epoch throughout.

use serde::{Deserialize, Serialize};

/// `id` must not be the last field: WireTAP-Server's smoke test greps `"id":N,`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub ts_us: i64,
    pub duration_us: i64,
    pub note: String,
    pub created_at_us: i64,
    pub updated_at_us: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewEvent {
    pub ts_us: i64,
    #[serde(default)]
    pub duration_us: i64,
    #[serde(default)]
    pub note: String,
}

/// An absent field is left as it was.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventPatch {
    pub ts_us: Option<i64>,
    pub duration_us: Option<i64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
}
