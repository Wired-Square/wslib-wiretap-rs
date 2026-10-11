//! Every `QuerySpec`'s row filters, as `FrameRowFilter::sql_where` writes them, run
//! against a migrated capture and select exactly the rows the filter describes.

use std::sync::Arc;

use wiretap_capture::rusqlite::Connection;
use wiretap_capture::{insert_frames, migrate, read_rows, StoredFrame};
use wiretap_gateway::{FrameRowFilter, Protocol, QuerySpec, RowWindow, Sql};

const CAPTURE: &str = "c1";

fn seeded() -> (Connection, Vec<StoredFrame>) {
    let mut conn = Connection::open_in_memory().unwrap();
    migrate(&mut conn).unwrap();
    let mut frames = Vec::new();
    for (i, protocol) in ["can", "canfd", "modbus", "modbus_rtu", "serial"]
        .into_iter()
        .enumerate()
    {
        for frame_id in [0x100, 0x101, 0x200] {
            for extended in [false, true] {
                for timestamp_us in [999_999, 1_000_000, 1_500_000, 2_000_000] {
                    frames.push(StoredFrame {
                        protocol: protocol.into(),
                        timestamp_us: timestamp_us + i as u64,
                        frame_id,
                        extended,
                        len: 1,
                        payload: vec![0xAA],
                        ..Default::default()
                    });
                }
            }
        }
    }
    insert_frames(&mut conn, CAPTURE, &frames).unwrap();
    insert_frames(&mut conn, "decoy", &frames).unwrap();
    (conn, frames)
}

fn selects(filter: &FrameRowFilter, f: &StoredFrame) -> bool {
    let ts = f.timestamp_us as i64;
    filter.frame_id.is_none_or(|id| id == f.frame_id)
        && filter.is_extended.is_none_or(|e| e == f.extended)
        && (filter.protocols.is_empty()
            || f.capture_protocol()
                .is_some_and(|p| filter.protocols.contains(&p)))
        && filter.start_us.is_none_or(|s| ts >= s)
        && filter.end_us.is_none_or(|e| ts < e)
}

fn specs(window: RowWindow, is_extended: Option<bool>) -> Vec<QuerySpec> {
    let (frame_id, limit) = (0x100, Some(10));
    let window = || window.clone();
    vec![
        QuerySpec::ByteChanges {
            frame_id,
            is_extended,
            window: window(),
            byte_index: 0,
            limit,
        },
        QuerySpec::FrameChanges {
            frame_id,
            is_extended,
            window: window(),
            limit,
        },
        QuerySpec::MirrorValidation {
            mirror_frame_id: 0x101,
            source_frame_id: 0x100,
            is_extended,
            window: window(),
            tolerance_ms: 50,
            limit,
        },
        QuerySpec::MuxStatistics {
            frame_id,
            is_extended,
            window: window(),
            mux_selector_byte: 0,
            include_16bit: false,
            payload_length: 1,
            limit,
        },
        QuerySpec::FirstLast {
            frame_id,
            is_extended,
            window: window(),
        },
        QuerySpec::Frequency {
            frame_id,
            is_extended,
            window: window(),
            bucket_size_ms: 1000,
            limit,
        },
        QuerySpec::Distribution {
            frame_id,
            is_extended,
            window: window(),
            byte_index: 0,
        },
        QuerySpec::GapAnalysis {
            frame_id,
            is_extended,
            window: window(),
            gap_threshold_ms: 1.0,
            limit,
        },
        QuerySpec::PatternSearch {
            window: window(),
            pattern: vec![0xAA],
            pattern_mask: vec![0xFF],
            limit,
        },
        QuerySpec::FrameInventory {
            window: window(),
            limit: None,
        },
    ]
}

#[test]
fn every_row_filter_selects_exactly_its_rows() {
    let (conn, frames) = seeded();
    let mut checked = 0;
    for protocol in [
        None,
        Some(Protocol::Can),
        Some(Protocol::Modbus),
        Some(Protocol::Serial),
    ] {
        for (start_us, end_us) in [(None, None), (Some(1_000_000), Some(2_000_000))] {
            for is_extended in [None, Some(true)] {
                for spec in specs(
                    RowWindow {
                        protocol,
                        start_us,
                        end_us,
                    },
                    is_extended,
                ) {
                    for filter in spec.row_filters() {
                        let condition = filter.sql_where(CAPTURE);
                        let statement = Sql {
                            sql: format!(
                                "SELECT rowid FROM frames WHERE {} ORDER BY rowid",
                                condition.sql
                            ),
                            values: condition.values,
                        };
                        let got =
                            read_rows(&conn, &statement, &Arc::default(), |r| r.get::<_, i64>(0))
                                .unwrap();
                        let expected: Vec<i64> = frames
                            .iter()
                            .zip(1..)
                            .filter(|(f, _)| selects(&filter, f))
                            .map(|(_, rowid)| rowid)
                            .collect();
                        assert!(!expected.is_empty(), "{spec:?} selects nothing to compare");
                        assert_eq!(got, expected, "{spec:?}\n{}", statement.sql);
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 4 * 2 * 2 * 11);
}
