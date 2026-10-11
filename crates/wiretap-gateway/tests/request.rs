use serde_json::{json, Value};
use wiretap_gateway::*;

fn window(protocol: Option<Protocol>, start_us: Option<i64>) -> RowWindow {
    RowWindow {
        protocol,
        start_us,
        end_us: None,
    }
}

fn body(request: GatewayRequest) -> (String, Value) {
    match request {
        GatewayRequest::Post(path, body) => (path.into(), serde_json::to_value(body).unwrap()),
        GatewayRequest::Inventory(_) => panic!("an inventory is not a POST"),
    }
}

#[test]
fn a_bound_is_utc_with_only_the_fraction_it_needs() {
    for (us, text) in [
        (0, "1970-01-01T00:00:00Z"),
        (1_767_225_600_000_000, "2026-01-01T00:00:00Z"),
        (1_700_000_000_123_000, "2023-11-14T22:13:20.123Z"),
        (1_700_000_000_123_456, "2023-11-14T22:13:20.123456Z"),
        (951_782_400_000_000, "2000-02-29T00:00:00Z"),
        (-1, "1969-12-31T23:59:59.999999Z"),
        (-62_135_596_800_000_001, "0000-12-31T23:59:59.999999Z"),
        (-62_167_219_200_000_001, "-0001-12-31T23:59:59.999999Z"),
        (253_402_300_800_000_000, "+10000-01-01T00:00:00Z"),
    ] {
        assert_eq!(rfc3339(us).unwrap(), text, "{us}");
    }
}

#[test]
fn a_bound_past_the_calendar_is_refused_by_name() {
    let err = rfc3339(i64::MAX).unwrap_err();
    assert_eq!(err, RequestError::BoundOutOfRange(i64::MAX));
    assert_eq!(
        err.to_string(),
        format!("time bound {} µs is out of range", i64::MAX)
    );
}

#[test]
fn a_query_body_names_the_protocol_only_when_it_is_not_can() {
    let spec = QuerySpec::ByteChanges {
        frame_id: 613,
        is_extended: Some(false),
        window: window(None, Some(1_767_225_600_000_000)),
        byte_index: 2,
        limit: Some(10),
    };
    let can = json!({
        "frame_id": 613, "is_extended": false, "start_time": "2026-01-01T00:00:00Z",
        "end_time": null, "byte_index": 2, "limit": 10, "query_id": "q",
    });
    let request = |protocol| body(spec.request(protocol, Some("q"), false).unwrap());
    assert_eq!(
        request(Protocol::Can),
        ("/query/byte-changes".into(), can.clone())
    );
    let mut modbus = can;
    modbus["protocol"] = json!("modbus");
    assert_eq!(request(Protocol::Modbus).1, modbus);

    let pattern = QuerySpec::PatternSearch {
        window: RowWindow::default(),
        pattern: vec![1],
        pattern_mask: vec![0xff],
        limit: None,
    };
    let pattern = |protocol| body(pattern.request(protocol, None, false).unwrap()).1;
    assert!(pattern(Protocol::Can).get("protocol").is_none());
    assert_eq!(pattern(Protocol::Modbus)["protocol"], "modbus");
}

#[test]
fn every_post_goes_to_its_own_path() {
    let w = RowWindow::default;
    let specs = [
        (
            QuerySpec::FrameChanges {
                frame_id: 1,
                is_extended: None,
                window: w(),
                limit: None,
            },
            "/query/frame-changes",
        ),
        (
            QuerySpec::MuxStatistics {
                frame_id: 1,
                is_extended: None,
                window: w(),
                mux_selector_byte: 0,
                include_16bit: true,
                payload_length: 8,
                limit: None,
            },
            "/query/mux-statistics",
        ),
        (
            QuerySpec::FirstLast {
                frame_id: 1,
                is_extended: None,
                window: w(),
            },
            "/query/first-last",
        ),
        (
            QuerySpec::Frequency {
                frame_id: 1,
                is_extended: None,
                window: w(),
                bucket_size_ms: 100,
                limit: None,
            },
            "/query/frequency",
        ),
        (
            QuerySpec::Distribution {
                frame_id: 1,
                is_extended: None,
                window: w(),
                byte_index: 0,
            },
            "/query/distribution",
        ),
        (
            QuerySpec::GapAnalysis {
                frame_id: 1,
                is_extended: None,
                window: w(),
                gap_threshold_ms: 10.0,
                limit: None,
            },
            "/query/gap-analysis",
        ),
    ];
    for (spec, path) in specs {
        let request = spec.request(Protocol::Can, None, false).unwrap();
        assert_eq!(request.path(), path);
        assert_eq!(body(request).1["frame_id"], 1, "{path}");
    }
}

#[test]
fn a_narrowed_mirror_asks_for_every_mismatch() {
    let spec = QuerySpec::MirrorValidation {
        mirror_frame_id: 257,
        source_frame_id: 256,
        is_extended: None,
        window: RowWindow::default(),
        tolerance_ms: 50,
        limit: Some(5),
    };
    let limit =
        |narrowed| body(spec.request(Protocol::Can, None, narrowed).unwrap()).1["limit"].clone();
    assert_eq!(limit(false), 5);
    assert_eq!(limit(true), Value::Null);
}

#[test]
fn a_backend_reader_refuses_another_protocols_window() {
    let spec = |protocol| QuerySpec::FrameInventory {
        window: window(protocol, None),
        limit: Some(5),
    };
    assert_eq!(
        spec(Some(Protocol::Can)).request(Protocol::Modbus, None, false),
        Err(RequestError::OtherProtocol)
    );
    for protocol in [None, Some(Protocol::Modbus)] {
        let request = spec(protocol)
            .request(Protocol::Modbus, None, false)
            .unwrap();
        assert_eq!(request.path(), "/inventory?protocol=modbus&limit=5");
    }
}

#[test]
fn an_inventory_request_carries_its_bounds_protocol_and_limit() {
    let path = |protocol, limit| {
        GatewayRequest::Inventory(TimeRangeQuery {
            start: Some("2026-01-01T00:00:00Z".into()),
            end: None,
            protocol,
            limit,
        })
        .path()
    };
    assert_eq!(
        path(None, None),
        "/inventory?start=2026-01-01T00%3A00%3A00Z"
    );
    assert_eq!(
        path(Some(Protocol::Modbus), Some(50)),
        "/inventory?start=2026-01-01T00%3A00%3A00Z&protocol=modbus&limit=50"
    );
    let bare = TimeRangeQuery {
        start: None,
        end: None,
        protocol: None,
        limit: None,
    };
    assert_eq!(GatewayRequest::Inventory(bare).path(), "/inventory");
}
