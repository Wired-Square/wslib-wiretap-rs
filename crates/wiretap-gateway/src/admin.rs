//! The admin endpoints: `/v1/admin/daemons`, `/v1/admin/assignments` and
//! `/v1/admin/catalogs/{sha}`. A SHA is the catalogue's git blob SHA-1, as 40
//! lowercase hex characters.

use serde::{Deserialize, Serialize};

/// `GET /v1/admin/daemons`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonList {
    pub daemons: Vec<Daemon>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Daemon {
    pub daemon_id: String,
    pub devices: Vec<DaemonDevice>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonDevice {
    pub interface: String,
    /// `None`: assigned, but never seen in a `HELLO`.
    pub bus: Option<u8>,
    pub database: Option<String>,
    pub last_seen_us: Option<i64>,
    pub assignment: Option<Assignment>,
    /// `None`: no `CATALOG_STATUS` yet.
    pub active: Option<ActiveCatalog>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assignment {
    pub blob_sha: String,
    /// The catalogue's `meta.name`.
    pub name: Option<String>,
    pub assigned_at_us: i64,
    pub assigned_by: Option<String>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveCatalog {
    /// `assigned`, `local` or `none`.
    pub source: String,
    pub blob_sha: Option<String>,
    pub name: Option<String>,
    pub since_us: i64,
    pub refused: Option<RefusedCatalog>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefusedCatalog {
    pub blob_sha: String,
    /// `hash_mismatch`, `did_not_parse`, `fetch_failed` or `other`.
    pub reason: String,
}

/// Where a catalogue came from; every field is left out when absent.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_sha: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub based_on: Option<ProvenanceBase>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceBase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_sha: Option<String>,
}

/// `PUT /v1/admin/assignments`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignCatalog {
    pub daemon_id: String,
    pub interface: String,
    /// The catalogue's exact bytes, never normalised.
    pub content: String,
    pub provenance: Provenance,
    /// The SHA assigned now, `""` for "only if unassigned", or absent for no guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
}

/// The `PUT`'s 200.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignedCatalog {
    pub daemon_id: String,
    pub interface: String,
    pub assignment: Assignment,
    pub warnings: Vec<CatalogFinding>,
}

/// The `PUT`'s 400: the catalogue did not validate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogRejected {
    pub error: String,
    pub findings: Vec<CatalogFinding>,
}

/// The 409 of a `PUT` or `DELETE` whose `expected` did not match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentConflict {
    pub error: String,
    /// The SHA assigned now.
    pub current: Option<String>,
}

/// `DELETE /v1/admin/assignments`'s query string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnassignParams {
    pub daemon_id: String,
    pub interface: String,
    /// The SHA assigned now, `""` for "only if unassigned", or absent for no guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
}

/// `GET /v1/admin/catalogs/{sha}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredCatalog {
    pub blob_sha: String,
    pub content: String,
    pub provenance: Provenance,
    pub created_at_us: i64,
}

/// The JSON of `wiretap_catalog::ValidationError`, mirrored so this crate
/// stays serde-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogFinding {
    pub field: String,
    pub message: String,
}
