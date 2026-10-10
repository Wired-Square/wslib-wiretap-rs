//! Each [`QuerySpec`]'s row filters against the statements the desktop's capture
//! queries ran, in `fixtures/desktop/querySql.capture.json` (WireTAP `ebab8d9d`):
//! the queries the desktop's test issued, as specs, select the same rows.

use std::path::PathBuf;

use serde_json::Value;
use wiretap_gateway::{QuerySpec, RowWindow};

const CAPTURE: &str = "d1-sql-golden";

fn golden() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop/querySql.capture.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The desktop test's arguments: frame 0x100 (mirror 0x101), limit 5000; bounded
/// is `is_extended` true over 1 000 000..2 000 000 µs.
fn spec(query: &str, bounded: bool) -> QuerySpec {
    let is_extended = bounded.then_some(true);
    let window = RowWindow {
        protocol: None,
        start_us: bounded.then_some(1_000_000),
        end_us: bounded.then_some(2_000_000),
    };
    let (frame_id, limit) = (0x100, Some(5000));
    match query {
        "byte_changes" => QuerySpec::ByteChanges {
            frame_id,
            is_extended,
            window,
            byte_index: 2,
            limit,
        },
        "frame_changes" => QuerySpec::FrameChanges {
            frame_id,
            is_extended,
            window,
            limit,
        },
        "mirror_validation" => QuerySpec::MirrorValidation {
            mirror_frame_id: 0x101,
            source_frame_id: 0x100,
            is_extended,
            window,
            tolerance_ms: 50,
            limit,
        },
        "mux_statistics" => QuerySpec::MuxStatistics {
            frame_id,
            is_extended,
            window,
            mux_selector_byte: 0,
            include_16bit: true,
            payload_length: 8,
            limit,
        },
        "first_last" => QuerySpec::FirstLast {
            frame_id,
            is_extended,
            window,
        },
        "frequency" => QuerySpec::Frequency {
            frame_id,
            is_extended,
            window,
            bucket_size_ms: 1000,
            limit,
        },
        "distribution" => QuerySpec::Distribution {
            frame_id,
            is_extended,
            window,
            byte_index: 2,
        },
        "gap_analysis" => QuerySpec::GapAnalysis {
            frame_id,
            is_extended,
            window,
            gap_threshold_ms: 100.0,
            limit,
        },
        "pattern_search" => QuerySpec::PatternSearch {
            window,
            pattern: vec![0xAA, 0xBB],
            pattern_mask: vec![0xFF, 0x00],
            limit,
        },
        "frame_inventory" => QuerySpec::FrameInventory {
            window,
            limit: None,
        },
        other => panic!("unknown query {other}"),
    }
}

#[test]
fn every_golden_statement_selects_its_specs_rows() {
    let golden = golden();
    let cases = golden["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let (query, bounds) = name.split_once(' ').unwrap();
        let spec = spec(query, bounds == "bounded");
        assert_eq!(serde_json::to_value(&spec).unwrap()["type"], query);

        let filters = spec.row_filters();
        for (i, statement) in case["sql"].as_array().unwrap().iter().enumerate() {
            let statement = statement.as_str().unwrap();
            let filter = &filters[i.min(filters.len() - 1)];
            let condition = format!("WHERE {} ", filter.sql_where(CAPTURE).inlined());
            let rest = format!("{statement} ")
                .split_once(&condition)
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_else(|| panic!("{name}: {statement}\nlacks {condition}"));
            assert!(!rest.starts_with("AND"), "{name}: {statement}");
        }
    }
}
