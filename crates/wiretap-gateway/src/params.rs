//! What a client sends: the `/query/*` and `/payloads` bodies, and the query
//! strings of the `GET` endpoints.
//!
//! `protocol` absent means CAN on every endpoint, so a CAN request leaves it out
//! and reads the same as one from a client that predates the field.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "ArchiveProtocol"))]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Can,
    Modbus,
    Serial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameFilter {
    pub frame_id: u32,
    pub is_extended: Option<bool>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteChangesParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub byte_index: u8,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameChangesParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirrorValidationParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub mirror_frame_id: u32,
    pub source_frame_id: u32,
    pub is_extended: Option<bool>,
    pub tolerance_ms: u32,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MuxStatisticsParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub mux_selector_byte: u8,
    pub include_16bit: bool,
    pub payload_length: u8,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirstLastParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrequencyParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub bucket_size_ms: u32,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistributionParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub byte_index: u8,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapAnalysisParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub gap_threshold_ms: f64,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternSearchParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub pattern: Vec<u8>,
    pub pattern_mask: Vec<u8>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: Option<u32>,
    pub query_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadsParams {
    #[serde(flatten)]
    pub filter: FrameFilter,
    pub limit: Option<u32>,
}

/// `/time-bounds`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

/// `/inventory`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeRangeQuery {
    pub start: Option<String>,
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

/// `/frames`; `after` is the previous batch's `next_cursor`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FramesQuery {
    pub start: Option<String>,
    pub end: Option<String>,
    pub after: Option<String>,
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

/// `/events`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventsQuery {
    pub start: Option<String>,
    pub end: Option<String>,
    pub limit: Option<u32>,
}
