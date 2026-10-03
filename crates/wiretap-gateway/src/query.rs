//! What the `/query/*` endpoints answer: each result set with its [`QueryStats`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryStats {
    pub rows_scanned: u64,
    pub results_count: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteChangeResult {
    pub timestamp_us: i64,
    pub old_value: u8,
    pub new_value: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteChangeQueryResult {
    pub results: Vec<ByteChangeResult>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameChangeResult {
    pub timestamp_us: i64,
    pub old_payload: Vec<u8>,
    pub new_payload: Vec<u8>,
    pub changed_indices: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameChangeQueryResult {
    pub results: Vec<FrameChangeResult>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirrorValidationResult {
    pub mirror_timestamp_us: i64,
    pub source_timestamp_us: i64,
    pub mirror_payload: Vec<u8>,
    pub source_payload: Vec<u8>,
    pub mismatch_indices: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirrorValidationQueryResult {
    pub results: Vec<MirrorValidationResult>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BytePositionStats {
    pub byte_index: u8,
    pub min: u8,
    pub max: u8,
    pub avg: f64,
    pub distinct_count: u32,
    pub sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Word16Stats {
    pub start_byte: u8,
    pub endianness: String,
    pub min: u16,
    pub max: u16,
    pub avg: f64,
    pub distinct_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MuxCaseStats {
    pub mux_value: u16,
    pub frame_count: u64,
    pub byte_stats: Vec<BytePositionStats>,
    pub word16_stats: Vec<Word16Stats>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MuxStatisticsResult {
    pub mux_byte: u8,
    pub total_frames: u64,
    pub cases: Vec<MuxCaseStats>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MuxStatisticsQueryResult {
    pub results: MuxStatisticsResult,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirstLastResult {
    pub first_timestamp_us: i64,
    pub first_payload: Vec<u8>,
    pub last_timestamp_us: i64,
    pub last_payload: Vec<u8>,
    pub total_count: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FirstLastQueryResult {
    pub results: FirstLastResult,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrequencyBucket {
    pub bucket_start_us: i64,
    pub frame_count: i64,
    pub min_interval_us: f64,
    pub max_interval_us: f64,
    pub avg_interval_us: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrequencyQueryResult {
    pub results: Vec<FrequencyBucket>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistributionResult {
    pub value: u8,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistributionQueryResult {
    pub results: Vec<DistributionResult>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapResult {
    pub gap_start_us: i64,
    pub gap_end_us: i64,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GapAnalysisQueryResult {
    pub results: Vec<GapResult>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternSearchResult {
    pub timestamp_us: i64,
    pub frame_id: u32,
    pub is_extended: bool,
    pub payload: Vec<u8>,
    pub match_positions: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternSearchQueryResult {
    pub results: Vec<PatternSearchResult>,
    pub stats: QueryStats,
}
