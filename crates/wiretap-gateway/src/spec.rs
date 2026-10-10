//! A query as one value: which of the ten it is, the rows it reads and its own
//! fields.
//!
//! Bounds are unix µs, durations ms, and `limit` counts the results returned,
//! never the rows read. Turning a spec into the gateway's params, with their
//! RFC3339 bounds, is the client's.

use serde::{Deserialize, Serialize};

use crate::{CaptureProtocol, FrameRowFilter, Protocol};

/// The rows a query reads besides its frame: `start_us` inclusive, `end_us` exclusive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct RowWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    pub start_us: Option<i64>,
    pub end_us: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QuerySpec {
    ByteChanges {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        byte_index: u8,
        limit: Option<u32>,
    },
    FrameChanges {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        limit: Option<u32>,
    },
    MirrorValidation {
        mirror_frame_id: u32,
        source_frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        tolerance_ms: u32,
        limit: Option<u32>,
    },
    MuxStatistics {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        mux_selector_byte: u8,
        include_16bit: bool,
        payload_length: u8,
        limit: Option<u32>,
    },
    FirstLast {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
    },
    Frequency {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        bucket_size_ms: u32,
        limit: Option<u32>,
    },
    Distribution {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        byte_index: u8,
    },
    GapAnalysis {
        frame_id: u32,
        is_extended: Option<bool>,
        #[serde(flatten)]
        window: RowWindow,
        gap_threshold_ms: f64,
        limit: Option<u32>,
    },
    PatternSearch {
        #[serde(flatten)]
        window: RowWindow,
        pattern: Vec<u8>,
        pattern_mask: Vec<u8>,
        limit: Option<u32>,
    },
    FrameInventory {
        #[serde(flatten)]
        window: RowWindow,
        limit: Option<u32>,
    },
}

impl RowWindow {
    fn filter(&self, frame_id: Option<u32>, is_extended: Option<bool>) -> FrameRowFilter {
        FrameRowFilter {
            frame_id,
            is_extended,
            protocols: self
                .protocol
                .map(CaptureProtocol::of)
                .unwrap_or_default()
                .to_vec(),
            start_us: self.start_us,
            end_us: self.end_us,
        }
    }
}

impl QuerySpec {
    /// The protocol and time bounds every variant carries.
    pub fn window(&self) -> &RowWindow {
        match self {
            Self::ByteChanges { window, .. }
            | Self::FrameChanges { window, .. }
            | Self::MirrorValidation { window, .. }
            | Self::MuxStatistics { window, .. }
            | Self::FirstLast { window, .. }
            | Self::Frequency { window, .. }
            | Self::Distribution { window, .. }
            | Self::GapAnalysis { window, .. }
            | Self::PatternSearch { window, .. }
            | Self::FrameInventory { window, .. } => window,
        }
    }

    /// The row sets the query reads, in order: the mirror's then the source's for a
    /// mirror validation, otherwise one.
    pub fn row_filters(&self) -> Vec<FrameRowFilter> {
        let window = self.window();
        match self {
            Self::ByteChanges {
                frame_id,
                is_extended,
                ..
            }
            | Self::FrameChanges {
                frame_id,
                is_extended,
                ..
            }
            | Self::MuxStatistics {
                frame_id,
                is_extended,
                ..
            }
            | Self::FirstLast {
                frame_id,
                is_extended,
                ..
            }
            | Self::Frequency {
                frame_id,
                is_extended,
                ..
            }
            | Self::Distribution {
                frame_id,
                is_extended,
                ..
            }
            | Self::GapAnalysis {
                frame_id,
                is_extended,
                ..
            } => {
                vec![window.filter(Some(*frame_id), *is_extended)]
            }
            Self::MirrorValidation {
                mirror_frame_id,
                source_frame_id,
                is_extended,
                ..
            } => vec![
                window.filter(Some(*mirror_frame_id), *is_extended),
                window.filter(Some(*source_frame_id), *is_extended),
            ],
            Self::PatternSearch { .. } | Self::FrameInventory { .. } => {
                vec![window.filter(None, None)]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_spec_is_flat_json_tagged_by_type() {
        let spec = QuerySpec::GapAnalysis {
            frame_id: 256,
            is_extended: Some(true),
            window: RowWindow {
                protocol: Some(Protocol::Can),
                start_us: Some(1_000_000),
                end_us: None,
            },
            gap_threshold_ms: 100.5,
            limit: Some(10),
        };
        let served = json!({
            "type": "gap_analysis", "frame_id": 256, "is_extended": true, "protocol": "can",
            "start_us": 1_000_000, "end_us": null, "gap_threshold_ms": 100.5, "limit": 10,
        });
        assert_eq!(serde_json::to_value(&spec).unwrap(), served);
        assert_eq!(serde_json::from_value::<QuerySpec>(served).unwrap(), spec);
    }

    #[test]
    fn absent_options_read_as_none() {
        let spec: QuerySpec = serde_json::from_value(json!({ "type": "frame_inventory" })).unwrap();
        assert_eq!(
            spec,
            QuerySpec::FrameInventory {
                window: RowWindow::default(),
                limit: None,
            }
        );
    }

    #[test]
    fn a_mirror_reads_the_mirror_then_the_source() {
        let spec: QuerySpec = serde_json::from_value(json!({
            "type": "mirror_validation", "mirror_frame_id": 257, "source_frame_id": 256,
            "is_extended": false, "tolerance_ms": 50, "end_us": 9,
        }))
        .unwrap();
        let ids: Vec<_> = spec.row_filters().iter().map(|f| f.frame_id).collect();
        assert_eq!(ids, [Some(257), Some(256)]);
        assert!(spec
            .row_filters()
            .iter()
            .all(|f| f.is_extended == Some(false) && f.end_us == Some(9)));
    }

    #[test]
    fn an_inventory_takes_a_limit() {
        let spec: QuerySpec =
            serde_json::from_value(json!({ "type": "frame_inventory", "limit": 20 })).unwrap();
        assert!(matches!(
            spec,
            QuerySpec::FrameInventory {
                limit: Some(20),
                ..
            }
        ));
    }

    #[test]
    fn a_pattern_search_reads_every_frame() {
        let spec = QuerySpec::PatternSearch {
            window: RowWindow::default(),
            pattern: vec![0xAA],
            pattern_mask: vec![0xFF],
            limit: None,
        };
        assert_eq!(spec.row_filters(), [FrameRowFilter::default()]);
    }

    #[test]
    fn every_variant_answers_its_window() {
        let window = RowWindow {
            protocol: Some(Protocol::Modbus),
            start_us: Some(1),
            end_us: Some(9),
        };
        let specs = [
            QuerySpec::Distribution {
                frame_id: 1,
                is_extended: None,
                window: window.clone(),
                byte_index: 0,
            },
            QuerySpec::MirrorValidation {
                mirror_frame_id: 2,
                source_frame_id: 1,
                is_extended: None,
                window: window.clone(),
                tolerance_ms: 50,
                limit: None,
            },
            QuerySpec::FrameInventory {
                window: window.clone(),
                limit: None,
            },
        ];
        for spec in specs {
            assert_eq!(spec.window(), &window);
        }
    }

    #[test]
    fn a_can_spec_reads_can_fd_rows_too() {
        let spec: QuerySpec = serde_json::from_value(
            json!({ "type": "first_last", "frame_id": 1, "protocol": "can" }),
        )
        .unwrap();
        assert_eq!(
            spec.row_filters()[0].protocols,
            [CaptureProtocol::Can, CaptureProtocol::CanFd]
        );
    }
}
