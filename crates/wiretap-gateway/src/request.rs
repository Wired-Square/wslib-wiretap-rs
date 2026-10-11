//! A [`QuerySpec`] as the gateway request that answers it: its path and body,
//! with RFC 3339 bounds.
//!
//! Paths are relative to the database, `/v1/db/{db}`. A CAN request leaves
//! `protocol` out, so it reads the same as one from a client older than the field.

use std::fmt;

use serde::Serialize;

use crate::{
    ByteChangesParams, DistributionParams, FirstLastParams, FrameChangesParams, FrameFilter,
    FrequencyParams, GapAnalysisParams, MirrorValidationParams, MuxStatisticsParams,
    PatternSearchParams, Protocol, QuerySpec, TimeRangeQuery,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    BoundOutOfRange(i64),
    OtherProtocol,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoundOutOfRange(us) => write!(f, "time bound {us} µs is out of range"),
            Self::OtherProtocol => {
                f.write_str("a WireTAP backend profile reads only its own protocol")
            }
        }
    }
}

impl std::error::Error for RequestError {}

/// The body of a `POST /query/*`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum QueryBody {
    ByteChanges(ByteChangesParams),
    FrameChanges(FrameChangesParams),
    MirrorValidation(MirrorValidationParams),
    MuxStatistics(MuxStatisticsParams),
    FirstLast(FirstLastParams),
    Frequency(FrequencyParams),
    Distribution(DistributionParams),
    GapAnalysis(GapAnalysisParams),
    PatternSearch(PatternSearchParams),
}

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayRequest {
    Inventory(TimeRangeQuery),
    Post(&'static str, QueryBody),
}

impl GatewayRequest {
    /// The path, with its query string, relative to `/v1/db/{db}`.
    pub fn path(&self) -> String {
        match self {
            Self::Inventory(query) => query.inventory_path(),
            Self::Post(path, _) => (*path).to_string(),
        }
    }
}

impl QuerySpec {
    /// The request for a client reading `protocol`; `narrowed` drops a mirror
    /// validation's limit, for a caller that narrows the mismatches itself.
    pub fn request(
        &self,
        protocol: Protocol,
        query_id: Option<&str>,
        narrowed: bool,
    ) -> Result<GatewayRequest, RequestError> {
        let window = self.window();
        if window.protocol.is_some_and(|p| p != protocol) {
            return Err(RequestError::OtherProtocol);
        }
        let start = window.start_us.map(rfc3339).transpose()?;
        let end = window.end_us.map(rfc3339).transpose()?;
        let protocol = wire(protocol);
        let query_id = query_id.map(str::to_string);
        let filter = |frame_id: &u32, is_extended: &Option<bool>| FrameFilter {
            frame_id: *frame_id,
            is_extended: *is_extended,
            start_time: start.clone(),
            end_time: end.clone(),
            protocol,
        };
        let (path, body) = match self {
            Self::ByteChanges {
                frame_id,
                is_extended,
                byte_index,
                limit,
                ..
            } => (
                "/query/byte-changes",
                QueryBody::ByteChanges(ByteChangesParams {
                    filter: filter(frame_id, is_extended),
                    byte_index: *byte_index,
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::FrameChanges {
                frame_id,
                is_extended,
                limit,
                ..
            } => (
                "/query/frame-changes",
                QueryBody::FrameChanges(FrameChangesParams {
                    filter: filter(frame_id, is_extended),
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::MirrorValidation {
                mirror_frame_id,
                source_frame_id,
                is_extended,
                tolerance_ms,
                limit,
                ..
            } => (
                "/query/mirror-validation",
                QueryBody::MirrorValidation(MirrorValidationParams {
                    protocol,
                    mirror_frame_id: *mirror_frame_id,
                    source_frame_id: *source_frame_id,
                    is_extended: *is_extended,
                    tolerance_ms: *tolerance_ms,
                    start_time: start,
                    end_time: end,
                    limit: if narrowed { None } else { *limit },
                    query_id,
                }),
            ),
            Self::MuxStatistics {
                frame_id,
                is_extended,
                mux_selector_byte,
                include_16bit,
                payload_length,
                limit,
                ..
            } => (
                "/query/mux-statistics",
                QueryBody::MuxStatistics(MuxStatisticsParams {
                    filter: filter(frame_id, is_extended),
                    mux_selector_byte: *mux_selector_byte,
                    include_16bit: *include_16bit,
                    payload_length: *payload_length,
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::FirstLast {
                frame_id,
                is_extended,
                ..
            } => (
                "/query/first-last",
                QueryBody::FirstLast(FirstLastParams {
                    filter: filter(frame_id, is_extended),
                    query_id,
                }),
            ),
            Self::Frequency {
                frame_id,
                is_extended,
                bucket_size_ms,
                limit,
                ..
            } => (
                "/query/frequency",
                QueryBody::Frequency(FrequencyParams {
                    filter: filter(frame_id, is_extended),
                    bucket_size_ms: *bucket_size_ms,
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::Distribution {
                frame_id,
                is_extended,
                byte_index,
                ..
            } => (
                "/query/distribution",
                QueryBody::Distribution(DistributionParams {
                    filter: filter(frame_id, is_extended),
                    byte_index: *byte_index,
                    query_id,
                }),
            ),
            Self::GapAnalysis {
                frame_id,
                is_extended,
                gap_threshold_ms,
                limit,
                ..
            } => (
                "/query/gap-analysis",
                QueryBody::GapAnalysis(GapAnalysisParams {
                    filter: filter(frame_id, is_extended),
                    gap_threshold_ms: *gap_threshold_ms,
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::PatternSearch {
                pattern,
                pattern_mask,
                limit,
                ..
            } => (
                "/query/pattern-search",
                QueryBody::PatternSearch(PatternSearchParams {
                    protocol,
                    pattern: pattern.clone(),
                    pattern_mask: pattern_mask.clone(),
                    start_time: start,
                    end_time: end,
                    limit: *limit,
                    query_id,
                }),
            ),
            Self::FrameInventory { limit, .. } => {
                return Ok(GatewayRequest::Inventory(TimeRangeQuery {
                    start,
                    end,
                    protocol,
                    limit: *limit,
                }))
            }
        };
        Ok(GatewayRequest::Post(path, body))
    }
}

impl TimeRangeQuery {
    pub(crate) fn inventory_path(&self) -> String {
        let Self {
            start,
            end,
            protocol,
            limit,
        } = self;
        format!(
            "/inventory{}",
            query_string(&[
                ("start", start.clone()),
                ("end", end.clone()),
                ("protocol", protocol.map(|p| p.as_str().into())),
                ("limit", limit.map(|n| n.to_string())),
            ])
        )
    }
}

impl Protocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Can => "can",
            Self::Modbus => "modbus",
            Self::Serial => "serial",
        }
    }
}

/// The `protocol` a request carries: none for CAN, the gateway's default.
pub(crate) fn wire(protocol: Protocol) -> Option<Protocol> {
    (protocol != Protocol::Can).then_some(protocol)
}

/// `?k=v&…` over the present pairs, percent-encoded; empty when none is.
pub(crate) fn query_string(pairs: &[(&str, Option<String>)]) -> String {
    let pairs: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_deref().map(|v| format!("{k}={}", percent_encode(v))))
        .collect();
    if pairs.is_empty() {
        String::new()
    } else {
        format!("?{}", pairs.join("&"))
    }
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A µs bound as the gateway takes it: UTC with `Z`, and a fraction only as
/// long as it needs, milliseconds or microseconds.
pub fn rfc3339(us: i64) -> Result<String, RequestError> {
    let secs = us.div_euclid(1_000_000);
    let micros = us.rem_euclid(1_000_000);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    // chrono's date range, which the desktop's bounds were checked against.
    if !(-262_143..=262_142).contains(&year) {
        return Err(RequestError::BoundOutOfRange(us));
    }
    let of_day = secs.rem_euclid(86_400);
    let year = if (0..10_000).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    };
    let fraction = match micros {
        0 => String::new(),
        _ if micros % 1_000 == 0 => format!(".{:03}", micros / 1_000),
        _ => format!(".{micros:06}"),
    };
    Ok(format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}{fraction}Z",
        of_day / 3_600,
        of_day / 60 % 60,
        of_day % 60,
    ))
}

/// Howard Hinnant's `civil_from_days`, proleptic Gregorian.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
