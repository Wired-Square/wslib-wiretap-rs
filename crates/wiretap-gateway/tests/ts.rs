#![cfg(feature = "ts")]
//! Each declaration against the JSON its type serialises to, under the desktop's
//! `Config` (`large_int` as `number`).

use serde_json::json;
use ts_rs::{Config, TS};
use wiretap_gateway::*;

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
}

#[test]
fn a_protocol_is_its_lowercase_name_as_archive_protocol() {
    assert_eq!(
        serde_json::to_value([Protocol::Can, Protocol::Modbus, Protocol::Serial]).unwrap(),
        json!(["can", "modbus", "serial"])
    );
    assert_eq!(
        decl::<Protocol>(),
        r#"type ArchiveProtocol = "can" | "modbus" | "serial";"#
    );
}

#[test]
fn a_spec_is_tagged_by_type_with_its_window_flattened() {
    let spec = QuerySpec::FirstLast {
        frame_id: 256,
        is_extended: None,
        window: RowWindow {
            protocol: Some(Protocol::Can),
            start_us: Some(1),
            end_us: None,
        },
    };
    assert_eq!(
        serde_json::to_value(&spec).unwrap(),
        json!({ "type": "first_last", "frame_id": 256, "is_extended": null, "protocol": "can", "start_us": 1, "end_us": null })
    );
    let window =
        "protocol?: ArchiveProtocol | null, start_us: number | null, end_us: number | null, }";
    let variants = [
        r#""type": "byte_changes", frame_id: number, is_extended: boolean | null, byte_index: number, limit: number | null, "#,
        r#""type": "frame_changes", frame_id: number, is_extended: boolean | null, limit: number | null, "#,
        r#""type": "mirror_validation", mirror_frame_id: number, source_frame_id: number, is_extended: boolean | null, tolerance_ms: number, limit: number | null, "#,
        r#""type": "mux_statistics", frame_id: number, is_extended: boolean | null, mux_selector_byte: number, include_16bit: boolean, payload_length: number, limit: number | null, "#,
        r#""type": "first_last", frame_id: number, is_extended: boolean | null, "#,
        r#""type": "frequency", frame_id: number, is_extended: boolean | null, bucket_size_ms: number, limit: number | null, "#,
        r#""type": "distribution", frame_id: number, is_extended: boolean | null, byte_index: number, "#,
        r#""type": "gap_analysis", frame_id: number, is_extended: boolean | null, gap_threshold_ms: number, limit: number | null, "#,
        r#""type": "pattern_search", pattern: Array<number>, pattern_mask: Array<number>, limit: number | null, "#,
        r#""type": "frame_inventory", limit: number | null, "#,
    ]
    .map(|fields| format!("{{ {fields}{window}"));
    assert_eq!(
        decl::<QuerySpec>(),
        format!("type QuerySpec = {};", variants.join(" | "))
    );
}

#[test]
fn a_result_nests_its_rows_and_stats_by_name() {
    assert_eq!(
        decl::<FirstLastQueryResult>(),
        "type FirstLastQueryResult = { results: FirstLastResult, stats: QueryStats, };"
    );
    assert_eq!(
        decl::<FirstLastResult>(),
        "type FirstLastResult = { first_timestamp_us: number, first_payload: Array<number>, \
         last_timestamp_us: number, last_payload: Array<number>, total_count: number, };"
    );
}
