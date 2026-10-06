use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use wiretap_gateway::*;

fn parse<T: DeserializeOwned>(sample: Value) -> T {
    serde_json::from_value(sample).unwrap()
}

/// Parses a sample, and serialises back to the same JSON value.
fn round_trip<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(sample: Value) -> T {
    let parsed: T = parse(sample.clone());
    assert_eq!(serde_json::to_value(&parsed).unwrap(), sample);
    assert_eq!(parse::<T>(serde_json::to_value(&parsed).unwrap()), parsed);
    parsed
}

fn stats() -> Value {
    json!({ "rows_scanned": 120, "results_count": 2, "execution_time_ms": 7 })
}

fn activity() -> Value {
    json!({
        "pid": 4242, "database": "vehicle_test", "username": "wiretap",
        "application_name": "WireTAP Query", "client_addr": "10.0.0.2/32", "state": "active",
        "query": "SELECT 1", "query_start": "2026-09-29 01:02:03.456789+00",
        "duration_secs": 1.5, "is_cancellable": true,
    })
}

fn frame_row() -> Value {
    json!({
        "ts_us": 1700000000000000i64, "id": 259, "extended": false, "dlc": 8, "len": 8,
        "is_fd": false, "is_rtr": false, "is_brs": false, "is_esi": false, "bus": 2, "dir": "rx",
        "data_hex": "010300000001840a",
    })
}

fn event() -> Value {
    json!({
        "id": 17, "ts_us": 1700000000000000i64, "duration_us": 2500000, "note": "smoke",
        "created_at_us": 1700000001000000i64, "updated_at_us": 1700000001000000i64,
    })
}

#[test]
fn query_results_parse() {
    round_trip::<ByteChangeQueryResult>(json!({
        "results": [{ "timestamp_us": 1, "old_value": 0, "new_value": 255 }],
        "stats": stats(),
    }));
    round_trip::<FrameChangeQueryResult>(json!({
        "results": [{ "timestamp_us": 1, "old_payload": [0, 1], "new_payload": [0, 2], "changed_indices": [1] }],
        "stats": stats(),
    }));
    round_trip::<MirrorValidationQueryResult>(json!({
        "results": [{
            "mirror_timestamp_us": 2, "source_timestamp_us": 1, "mirror_payload": [1, 2],
            "source_payload": [1, 3], "mismatch_indices": [1],
        }],
        "stats": stats(),
    }));
    round_trip::<MuxStatisticsQueryResult>(json!({
        "results": {
            "mux_byte": 0, "total_frames": 40,
            "cases": [{
                "mux_value": 3, "frame_count": 40,
                "byte_stats": [{ "byte_index": 1, "min": 0, "max": 9, "avg": 4.5, "distinct_count": 10, "sample_count": 40 }],
                "word16_stats": [{ "start_byte": 1, "endianness": "little", "min": 0, "max": 900, "avg": 450.0, "distinct_count": 10 }],
            }],
        },
        "stats": stats(),
    }));
    let first_last = round_trip::<FirstLastQueryResult>(json!({
        "results": {
            "first_timestamp_us": 1, "first_payload": [1], "last_timestamp_us": 9,
            "last_payload": [2], "total_count": 250,
        },
        "stats": stats(),
    }));
    assert_eq!(first_last.results.total_count, 250);
    round_trip::<FrequencyQueryResult>(json!({
        "results": [{
            "bucket_start_us": 0, "frame_count": 10, "min_interval_us": 90.0,
            "max_interval_us": 110.0, "avg_interval_us": 100.0,
        }],
        "stats": stats(),
    }));
    round_trip::<DistributionQueryResult>(json!({
        "results": [{ "value": 0, "count": 40, "percentage": 100.0 }],
        "stats": stats(),
    }));
    round_trip::<GapAnalysisQueryResult>(json!({
        "results": [{ "gap_start_us": 1000, "gap_end_us": 5000, "duration_ms": 4.0 }],
        "stats": stats(),
    }));
    round_trip::<PatternSearchQueryResult>(json!({
        "results": [{ "timestamp_us": 1, "frame_id": 2016, "is_extended": false, "payload": [0, 7], "match_positions": [0] }],
        "stats": stats(),
    }));
}

#[test]
fn archive_responses_parse() {
    let inventory = round_trip::<InventoryResponse>(json!({
        "entries": [{
            "frame_id": 2032, "is_extended": false, "count": 1, "first_us": 1, "last_us": 1,
            "max_dlc": 9, "max_len": 12,
        }],
    }));
    assert_eq!(inventory.entries[0].max_len, Some(12));
    round_trip::<TimeBounds>(json!({ "min_ts_us": 1, "max_ts_us": 9 }));
    round_trip::<TimeBounds>(json!({ "min_ts_us": null, "max_ts_us": null }));
    round_trip::<FrameBatch>(json!({ "frames": [frame_row()], "next_cursor": "MTo1" }));
    round_trip::<FrameBatch>(json!({ "frames": [], "next_cursor": null }));
    round_trip::<PayloadsResponse>(json!({ "payloads": [[1, 2, 3], []] }));
    round_trip::<ImportResult>(json!({ "imported": 1000, "elapsed_ms": 42 }));
}

#[test]
fn max_len_absent_is_none() {
    let entry: InventoryEntry = parse(json!({
        "frame_id": 0, "is_extended": false, "count": 1, "first_us": 0, "last_us": 0, "max_dlc": 9,
    }));
    assert_eq!(entry.max_len, None);
}

#[test]
fn a_frame_row_from_a_gateway_without_len_parses() {
    let mut row = frame_row();
    row.as_object_mut().unwrap().remove("len");
    assert_eq!(parse::<FrameBatchRow>(row).len, None);
}

#[test]
fn a_frame_row_from_a_gateway_without_the_can_flags_has_none() {
    let mut row = frame_row();
    let fields = row.as_object_mut().unwrap();
    for flag in ["is_rtr", "is_brs", "is_esi"] {
        fields.remove(flag);
    }
    let row = parse::<FrameBatchRow>(row);
    assert!(!row.is_rtr && !row.is_brs && !row.is_esi);
}

#[test]
fn a_frame_rows_can_flags_round_trip() {
    let mut row = frame_row();
    for flag in ["is_rtr", "is_brs", "is_esi"] {
        row[flag] = json!(true);
    }
    let row = round_trip::<FrameBatchRow>(row);
    assert!(row.is_rtr && row.is_brs && row.is_esi);
}

#[test]
fn events_parse() {
    round_trip::<Event>(event());
    round_trip::<EventsResponse>(json!({ "events": [event()] }));
    round_trip::<NewEvent>(
        json!({ "ts_us": 1700000000000000i64, "duration_us": 2500000, "note": "smoke" }),
    );
    round_trip::<EventPatch>(json!({ "ts_us": null, "duration_us": null, "note": "smoke edited" }));
    let bare: NewEvent = parse(json!({ "ts_us": 1 }));
    assert_eq!((bare.duration_us, bare.note.as_str()), (0, ""));
    let patch: EventPatch = parse(json!({ "note": "smoke edited" }));
    assert_eq!((patch.ts_us, patch.duration_us), (None, None));
}

#[test]
fn activity_parses() {
    round_trip::<DatabaseActivityResult>(
        json!({ "queries": [activity()], "sessions": [activity()] }),
    );
    round_trip::<SignalResponse>(json!({ "ok": true }));
}

#[test]
fn server_responses_parse() {
    round_trip::<Health>(
        json!({ "status": "ok", "version": "0.1.4", "db_ok": true, "schema": "v3" }),
    );
    round_trip::<DatabaseList>(json!({
        "databases": [
            {
                "name": "vehicle_test", "size_bytes": 8912896, "schema_state": "current",
                "schema_version": 3, "busy_secs": null, "schema_error": null,
                "rollup_state": "covered", "rollup_lag_secs": 12, "rollup_busy_secs": null,
            },
            {
                "name": "bench", "size_bytes": 1024, "schema_state": "migrating",
                "schema_version": null, "busy_secs": 4, "schema_error": null,
                "rollup_state": null, "rollup_lag_secs": null, "rollup_busy_secs": 30,
            },
        ],
        "schema_version": 3,
    }));
    round_trip::<ErrorBody>(json!({ "error": "database 'x' is not at the current schema" }));
}

#[test]
fn event_id_is_followed_by_a_field() {
    let wire = serde_json::to_string(&parse::<Event>(event())).unwrap();
    assert!(wire.contains(r#""id":17,"#), "{wire}");
}

#[test]
fn frame_row_keeps_dlc_directly_before_len() {
    let wire = serde_json::to_string(&parse::<FrameBatchRow>(frame_row())).unwrap();
    assert!(wire.contains(r#""dlc":8,"len":8"#), "{wire}");
}

#[test]
fn protocol_is_spelt_lowercase() {
    for (protocol, word) in [
        (Protocol::Can, "can"),
        (Protocol::Modbus, "modbus"),
        (Protocol::Serial, "serial"),
    ] {
        assert_eq!(serde_json::to_value(protocol).unwrap(), json!(word));
    }
    assert!(serde_json::from_value::<Protocol>(json!("modbsu")).is_err());
}

#[test]
fn a_can_request_leaves_protocol_out() {
    let params = FirstLastParams {
        filter: FrameFilter {
            frame_id: 2016,
            is_extended: None,
            start_time: None,
            end_time: None,
            protocol: None,
        },
        query_id: None,
    };
    let wire = serde_json::to_value(&params).unwrap();
    assert!(wire.get("protocol").is_none(), "{wire}");
    assert_eq!(wire.get("frame_id"), Some(&json!(2016)));
}

fn filter(extra: Value) -> Value {
    let mut body = json!({
        "frame_id": 2016, "is_extended": false,
        "start_time": "2023-11-14T00:00:00Z", "end_time": null, "protocol": "modbus",
    });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    body
}

#[test]
fn params_round_trip() {
    let p = round_trip::<ByteChangesParams>(filter(
        json!({ "byte_index": 0, "limit": 5, "query_id": "q1" }),
    ));
    assert_eq!(p.filter.protocol, Some(Protocol::Modbus));
    round_trip::<FrameChangesParams>(filter(json!({ "limit": null, "query_id": "q2" })));
    round_trip::<MuxStatisticsParams>(filter(json!({
        "mux_selector_byte": 0, "include_16bit": true, "payload_length": 8, "limit": null, "query_id": null,
    })));
    round_trip::<FirstLastParams>(filter(json!({ "query_id": null })));
    round_trip::<FrequencyParams>(filter(
        json!({ "bucket_size_ms": 1000, "limit": 10, "query_id": null }),
    ));
    round_trip::<DistributionParams>(filter(json!({ "byte_index": 0, "query_id": null })));
    round_trip::<GapAnalysisParams>(filter(
        json!({ "gap_threshold_ms": 1.5, "limit": null, "query_id": null }),
    ));
    round_trip::<PayloadsParams>(filter(json!({ "limit": 5 })));
    round_trip::<MirrorValidationParams>(json!({
        "protocol": "serial", "mirror_frame_id": 2016, "source_frame_id": 2017, "is_extended": null,
        "tolerance_ms": 100, "start_time": null, "end_time": null, "limit": null, "query_id": "q3",
    }));
    round_trip::<PatternSearchParams>(json!({
        "pattern": [0], "pattern_mask": [0], "start_time": null, "end_time": null, "limit": 10, "query_id": null,
    }));
    round_trip::<ProtocolQuery>(json!({ "protocol": "modbus" }));
    round_trip::<TimeRangeQuery>(json!({ "start": "2023-11-14T00:00:00Z", "end": null }));
    round_trip::<FramesQuery>(
        json!({ "start": null, "end": null, "after": "MTo1", "limit": 30, "protocol": "can" }),
    );
    round_trip::<EventsQuery>(
        json!({ "start": null, "end": "2023-11-14T00:00:00Z", "limit": 1000000 }),
    );
}

/// The server's smoke test sends these, leaving every optional field out, and
/// the gap threshold as an integer through the flattened filter.
#[test]
fn smoke_test_bodies_parse() {
    let gap: GapAnalysisParams = parse(json!({ "frame_id": 2016, "gap_threshold_ms": 1 }));
    assert_eq!(gap.gap_threshold_ms, 1.0);
    assert_eq!(gap.filter.protocol, None);
    parse::<PayloadsParams>(json!({ "frame_id": 2016, "limit": 5 }));
    parse::<MuxStatisticsParams>(
        json!({ "frame_id": 2016, "mux_selector_byte": 0, "include_16bit": true, "payload_length": 8 }),
    );
    parse::<PatternSearchParams>(json!({ "pattern": [0], "pattern_mask": [0] }));
    parse::<MirrorValidationParams>(
        json!({ "mirror_frame_id": 2016, "source_frame_id": 2017, "tolerance_ms": 100 }),
    );
    parse::<EventPatch>(json!({}));
}

fn provenance() -> Value {
    json!({
        "repo": "Wired-Square/catalogs", "path": "ess/bms.toml", "blob_sha": "ab".repeat(20),
        "ref": "main", "commit": "cd".repeat(20),
        "based_on": { "repo": "Wired-Square/catalogs", "path": "ess/bms-v1.toml" },
    })
}

fn assignment() -> Value {
    json!({
        "blob_sha": "ab".repeat(20), "name": "BMS", "assigned_at_us": 1700000000000000i64,
        "assigned_by": "alex", "provenance": provenance(),
    })
}

fn finding() -> Value {
    json!({ "field": "frame.0x100.signal.soc", "message": "runs past the frame" })
}

#[test]
fn admin_responses_parse() {
    let list = round_trip::<DaemonList>(json!({
        "daemons": [{
            "daemon_id": "bench-1",
            "devices": [
                {
                    "interface": "can0", "bus": 0, "database": "ess", "last_seen_us": 1700000001000000i64,
                    "assignment": assignment(),
                    "active": {
                        "source": "assigned", "blob_sha": "ab".repeat(20), "name": "BMS",
                        "since_us": 1700000001000000i64,
                        "refused": { "blob_sha": "ef".repeat(20), "reason": "hash_mismatch" },
                    },
                },
                {
                    "interface": "can1", "bus": null, "database": null, "last_seen_us": null,
                    "assignment": assignment(), "active": null,
                },
            ],
        }],
    }));
    assert_eq!(
        list.daemons[0].devices[0]
            .assignment
            .as_ref()
            .unwrap()
            .provenance
            .git_ref
            .as_deref(),
        Some("main")
    );
    round_trip::<AssignedCatalog>(json!({
        "daemon_id": "bench-1", "interface": "can0", "assignment": assignment(), "warnings": [finding()],
    }));
    round_trip::<CatalogRejected>(
        json!({ "error": "the catalogue did not validate", "findings": [finding()] }),
    );
    round_trip::<AssignmentConflict>(
        json!({ "error": "assignment changed", "current": "ab".repeat(20) }),
    );
    round_trip::<AssignmentConflict>(json!({ "error": "assignment changed", "current": null }));
    round_trip::<StoredCatalog>(json!({
        "blob_sha": "ab".repeat(20), "content": "[meta]\nname = \"BMS\"\n", "provenance": provenance(),
        "created_at_us": 1700000000000000i64,
    }));
}

#[test]
fn admin_requests_round_trip() {
    round_trip::<AssignCatalog>(json!({
        "daemon_id": "bench-1", "interface": "can0", "content": "[meta]\r\n", "provenance": {},
        "expected": "",
    }));
    let unguarded =
        round_trip::<UnassignParams>(json!({ "daemon_id": "bench-1", "interface": "can0" }));
    assert_eq!(unguarded.expected, None);
    let guarded = round_trip::<UnassignParams>(
        json!({ "daemon_id": "bench-1", "interface": "can0", "expected": "ab".repeat(20) }),
    );
    assert_eq!(guarded.expected, Some("ab".repeat(20)));
}

#[test]
fn an_empty_provenance_is_an_empty_object() {
    assert_eq!(
        serde_json::to_value(Provenance::default()).unwrap(),
        json!({})
    );
}
