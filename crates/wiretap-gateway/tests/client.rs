#![cfg(feature = "client")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use wiretap_gateway::client::{
    ArchiveFrame, AssignOutcome, ClientError, ClientOptions, GatewayClient,
};
use wiretap_gateway::*;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn line(&self) -> String {
        format!("{} {}", self.method, self.path)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// A gateway on 127.0.0.1 answering each request with `answer`'s status and
/// body, one thread per connection, recording what it was asked.
fn gateway(answer: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> (String, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let log = Log::default();
    let seen = log.clone();
    let answer = Arc::new(answer);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (seen, answer) = (seen.clone(), answer.clone());
            std::thread::spawn(move || {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split(' ');
                let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
                let mut headers = Vec::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let Some((k, v)) = header.trim_end().split_once(':') else {
                        break;
                    };
                    headers.push((k.to_ascii_lowercase(), v.trim().to_string()));
                }
                let length = headers
                    .iter()
                    .find(|(k, _)| k == "content-length")
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let request = Seen {
                    method: method.into(),
                    path: path.into(),
                    headers,
                    body,
                };
                seen.lock().unwrap().push(request.clone());
                let (status, body) = answer(&request);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            });
        }
    });
    (base_url, log)
}

fn ok(body: Value) -> (u16, String) {
    (200, body.to_string())
}

fn client(base_url: &str, api_key: &str) -> GatewayClient {
    GatewayClient::new(base_url, api_key, ClientOptions::default()).unwrap()
}

fn lines(log: &Log) -> Vec<String> {
    log.lock().unwrap().iter().map(Seen::line).collect()
}

fn database_list() -> Value {
    json!({ "databases": [{
        "name": "site", "size_bytes": 1, "schema_state": "ready", "schema_version": 4,
        "busy_secs": null, "schema_error": null, "rollup_state": null,
        "rollup_lag_secs": null, "rollup_busy_secs": null,
    }], "schema_version": 4 })
}

#[tokio::test]
async fn a_key_goes_as_a_bearer_and_an_empty_one_not_at_all() {
    let (base_url, log) = gateway(|_| ok(database_list()));
    client(&format!("{base_url}/"), "k")
        .databases()
        .await
        .unwrap();
    client(&base_url, "").databases().await.unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "GET /v1/databases");
    assert_eq!(log[0].header("authorization"), Some("Bearer k"));
    assert_eq!(log[1].header("authorization"), None);
}

#[tokio::test]
async fn health_is_asked_without_the_key() {
    let (base_url, log) = gateway(|_| {
        ok(json!({ "status": "ok", "version": "0.4.0", "db_ok": true, "schema": "v4" }))
    });
    let health = client(&base_url, "k").health().await.unwrap();
    assert_eq!(health.version, "0.4.0");
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "GET /v1/health");
    assert_eq!(log[0].header("authorization"), None);
}

#[tokio::test]
async fn a_refusal_reads_as_the_gateways_error_text() {
    let (base_url, _) = gateway(|seen| match seen.path.as_str() {
        "/v1/databases" => (
            404,
            json!({ "error": "invalid database name 'X'" }).to_string(),
        ),
        _ => (500, "not json".into()),
    });
    let gateway = client(&base_url, "k");
    let refused = gateway.databases().await.unwrap_err();
    assert_eq!(
        refused,
        ClientError::Status {
            code: 404,
            error: Some("invalid database name 'X'".into())
        }
    );
    assert_eq!(refused.to_string(), "invalid database name 'X'");
    let failed = gateway.health().await.unwrap_err();
    assert_eq!(failed.to_string(), "HTTP 500 Internal Server Error");
}

#[tokio::test]
async fn an_unanswered_request_names_its_cause() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let err = client(&base_url, "").health().await.unwrap_err();
    assert!(matches!(err, ClientError::Transport(_)));
    let text = err.to_string();
    assert!(
        text.starts_with("API request failed: error sending request")
            && text.matches(": ").count() > 1,
        "{text}"
    );
}

#[tokio::test]
async fn a_malformed_answer_is_a_decode_error() {
    let (base_url, _) = gateway(|_| ok(json!({})));
    let err = client(&base_url, "").databases().await.unwrap_err();
    assert!(matches!(err, ClientError::Decode(_)));
    assert!(
        err.to_string().starts_with("API response decode failed: "),
        "{err}"
    );
}

#[tokio::test]
async fn a_database_is_created_by_name() {
    let (base_url, log) = gateway(|_| ok(json!({ "created": "fresh" })));
    client(&base_url, "admin")
        .create_database("fresh")
        .await
        .unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "POST /v1/databases");
    assert_eq!(log[0].json(), json!({ "name": "fresh" }));
}

/// A gateway whose queries answer only once a `DELETE /v1/queries/*` has arrived.
fn held_queries() -> (String, Log) {
    let released = Arc::new((Mutex::new(false), Condvar::new()));
    gateway(move |seen| {
        let (lock, signal) = &*released;
        if seen.method == "DELETE" {
            *lock.lock().unwrap() = true;
            signal.notify_all();
            return ok(json!({ "cancelled": true }));
        }
        drop(
            signal
                .wait_while(lock.lock().unwrap(), |released| !*released)
                .unwrap(),
        );
        ok(
            json!({ "results": [], "stats": { "rows_scanned": 0, "results_count": 0, "execution_time_ms": 0 } }),
        )
    })
}

async fn until_running(client: &GatewayClient) {
    while client.running().is_empty() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn a_running_query_is_cancelled_on_the_gateway_that_runs_it() {
    let (base_url, log) = held_queries();
    let elsewhere = client("http://127.0.0.1:1", "other").with_label("status");
    let running = elsewhere
        .with_endpoint(&base_url, "k")
        .with_label("profile-1");
    let spec = QuerySpec::FrameChanges {
        frame_id: 1,
        is_extended: None,
        window: RowWindow::default(),
        limit: None,
    };
    let GatewayRequest::Post(path, body) = spec.request(Protocol::Can, Some("q1"), false).unwrap()
    else {
        unreachable!()
    };
    let query = tokio::spawn(async move {
        running
            .db("site", Protocol::Can)
            .query::<FrameChangeQueryResult>(path, &body, "q1")
            .await
    });

    until_running(&elsewhere).await;
    let listed = elsewhere.running();
    assert_eq!(listed[0].0, "q1");
    assert_eq!(listed[0].1.path, "/v1/db/site/query/frame-changes");
    assert_eq!(listed[0].1.label, "profile-1");

    assert!(elsewhere.cancel("q1").await);
    assert!(!elsewhere.cancel("q1").await);
    query.await.unwrap().unwrap();
    assert!(elsewhere.running().is_empty());
    let log = log.lock().unwrap();
    assert_eq!(log[1].line(), "DELETE /v1/queries/q1");
    assert_eq!(log[1].header("authorization"), Some("Bearer k"));
    assert_eq!(log[0].json()["query_id"], "q1");
}

#[tokio::test]
async fn a_dropped_query_is_no_longer_running() {
    let (base_url, _) = held_queries();
    let gateway = client(&base_url, "");
    let running = gateway.clone();
    let query = tokio::spawn(async move {
        running
            .query::<Value>("/v1/db/site/query/first-last", &json!({}), "q2")
            .await
    });
    until_running(&gateway).await;
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());
    assert!(gateway.running().is_empty());
}

fn entries(ids: &[u32], truncated: bool) -> Value {
    let entries: Vec<Value> = ids
        .iter()
        .map(|id| json!({ "frame_id": id, "is_extended": false, "count": 1, "first_us": 0, "last_us": 0, "max_dlc": 8 }))
        .collect();
    json!({ "entries": entries, "truncated": truncated })
}

#[tokio::test]
async fn an_inventory_is_cut_by_the_gateway_or_here() {
    let (base_url, log) = gateway(|seen| {
        ok(match seen.path.contains("limit=2") {
            true => entries(&[1, 2, 3], false),
            false => entries(&[1, 2], true),
        })
    });
    let gateway = client(&base_url, "");
    let db = gateway.db("site", Protocol::Modbus);
    let query = |limit| TimeRangeQuery {
        start: Some("2026-01-01T00:00:00Z".into()),
        end: None,
        protocol: None,
        limit,
    };
    let ids = |(entries, truncated): (Vec<InventoryEntry>, bool)| {
        (
            entries.iter().map(|e| e.frame_id).collect::<Vec<_>>(),
            truncated,
        )
    };
    assert_eq!(
        ids(db.inventory(query(Some(2))).await.unwrap()),
        (vec![1, 2], true)
    );
    assert_eq!(
        ids(db.inventory(query(None)).await.unwrap()),
        (vec![1, 2], true)
    );
    assert_eq!(
        lines(&log)[0],
        "GET /v1/db/site/inventory?start=2026-01-01T00%3A00%3A00Z&protocol=modbus&limit=2"
    );
}

#[tokio::test]
async fn payloads_arrive_newest_first_and_are_read_oldest_first() {
    let (base_url, log) = gateway(|_| ok(json!({ "payloads": [[3], [2], [1]] })));
    let gateway = client(&base_url, "");
    let filter = FrameFilter {
        frame_id: 613,
        is_extended: Some(false),
        start_time: None,
        end_time: None,
        protocol: Some(Protocol::Modbus),
    };
    let can = gateway.db("site", Protocol::Can);
    assert_eq!(
        can.payloads(filter.clone(), 10).await.unwrap(),
        [[1], [2], [3]]
    );
    gateway
        .db("site", Protocol::Modbus)
        .payloads(filter, 10)
        .await
        .unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "POST /v1/db/site/payloads");
    assert_eq!(
        log[0].json(),
        json!({ "frame_id": 613, "is_extended": false, "start_time": null, "end_time": null, "limit": 10 })
    );
    assert_eq!(log[1].json()["protocol"], "modbus");
}

#[tokio::test]
async fn time_bounds_name_the_protocol_only_when_it_is_not_can() {
    let (base_url, log) = gateway(|_| ok(json!({ "min_ts_us": 1, "max_ts_us": 2 })));
    let gateway = client(&base_url, "");
    let bounds = gateway
        .db("site", Protocol::Can)
        .time_bounds()
        .await
        .unwrap();
    assert_eq!(bounds.max_ts_us, Some(2));
    gateway
        .db("site", Protocol::Modbus)
        .time_bounds()
        .await
        .unwrap();
    assert_eq!(
        lines(&log),
        [
            "GET /v1/db/site/time-bounds",
            "GET /v1/db/site/time-bounds?protocol=modbus"
        ]
    );
}

fn event() -> Value {
    json!({
        "id": 17, "ts_us": 5, "duration_us": 0, "note": "n", "created_at_us": 1, "updated_at_us": 1,
    })
}

#[tokio::test]
async fn events_are_listed_whole_added_patched_and_deleted() {
    let (base_url, log) = gateway(|seen| match seen.method.as_str() {
        "DELETE" => (204, String::new()),
        "GET" => ok(json!({ "events": [event()] })),
        _ => ok(event()),
    });
    let gateway = client(&base_url, "");
    let db = gateway.db("site", Protocol::Can);
    assert_eq!(db.events_list().await.unwrap()[0].id, 17);
    let new = NewEvent {
        ts_us: 5,
        duration_us: 0,
        note: "n".into(),
    };
    assert_eq!(db.events_add(&new).await.unwrap().id, 17);
    let patch = EventPatch {
        ts_us: Some(5),
        duration_us: None,
        note: Some("m".into()),
    };
    db.events_update(17, &patch).await.unwrap();
    db.events_delete(17).await.unwrap();
    assert_eq!(
        lines(&log),
        [
            "GET /v1/db/site/events?limit=1000000",
            "POST /v1/db/site/events",
            "PATCH /v1/db/site/events/17",
            "DELETE /v1/db/site/events/17",
        ]
    );
    let log = log.lock().unwrap();
    assert_eq!(
        log[1].json(),
        json!({ "ts_us": 5, "duration_us": 0, "note": "n" })
    );
    assert_eq!(
        log[2].json(),
        json!({ "ts_us": 5, "duration_us": null, "note": "m" })
    );
}

#[tokio::test]
async fn an_import_posts_the_frames_format_and_may_create() {
    let (base_url, log) = gateway(|_| ok(json!({ "imported": 2, "elapsed_ms": 0 })));
    let gateway = client(&base_url, "");
    let imported = gateway
        .db("fresh", Protocol::Can)
        .import(vec![1, 2, 3], true)
        .await;
    assert_eq!(imported.unwrap().imported, 2);
    gateway
        .db("fresh", Protocol::Can)
        .import(vec![4], false)
        .await
        .unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "POST /v1/db/fresh/import?create=true");
    assert_eq!(
        log[0].header("content-type"),
        Some("application/x-wiretap-frames")
    );
    assert_eq!(log[0].body, [1, 2, 3]);
    assert_eq!(log[1].line(), "POST /v1/db/fresh/import");
}

#[tokio::test]
async fn a_backend_is_cancelled_by_post_and_terminated_by_delete() {
    let (base_url, log) = gateway(|seen| match seen.method.as_str() {
        "GET" => ok(json!({ "queries": [], "sessions": [] })),
        _ => ok(json!({ "ok": true })),
    });
    let gateway = client(&base_url, "");
    let db = gateway.db("site", Protocol::Can);
    assert!(db.activity().await.unwrap().queries.is_empty());
    assert!(db.signal(42, false).await.unwrap());
    assert!(db.signal(42, true).await.unwrap());
    assert_eq!(
        lines(&log),
        [
            "GET /v1/db/site/activity",
            "POST /v1/db/site/activity/42/cancel",
            "DELETE /v1/db/site/activity/42",
        ]
    );
}

fn rows(ids: std::ops::Range<u32>) -> Vec<Value> {
    ids.map(|id| {
        json!({
            "ts_us": 1_000 + id as i64, "id": id, "extended": false, "dlc": 1,
            "is_fd": false, "bus": 0, "dir": "rx", "data_hex": "ab",
        })
    })
    .collect()
}

fn paged_gateway() -> (String, Log) {
    gateway(|seen| {
        ok(match seen.path.contains("after=p2") {
            false => json!({ "frames": rows(0..40), "next_cursor": "p2" }),
            true => json!({ "frames": rows(40..60), "next_cursor": null }),
        })
    })
}

fn page(limit: u32) -> FramesQuery {
    FramesQuery {
        start: None,
        end: None,
        after: None,
        limit: Some(limit),
        protocol: None,
    }
}

#[tokio::test]
async fn a_frame_cursor_follows_the_gateways_cursor_to_the_end() {
    let (base_url, log) = paged_gateway();
    let gateway = client(&base_url, "");
    let mut cursor = gateway.db("site", Protocol::Can).frames(page(40));
    let mut ids = Vec::new();
    while !cursor.is_done() {
        ids.extend(cursor.next_page().await.unwrap().iter().map(|f| f.id));
    }
    assert_eq!(ids, (0..60).collect::<Vec<_>>());
    assert_eq!(
        lines(&log),
        [
            "GET /v1/db/site/frames?limit=40",
            "GET /v1/db/site/frames?limit=40&after=p2"
        ]
    );
}

#[tokio::test]
async fn a_frame_cursor_stops_at_its_total_and_names_its_protocol_and_bounds() {
    let (base_url, log) = paged_gateway();
    let gateway = client(&base_url, "");
    let query = FramesQuery {
        start: Some("2026-01-01T00:00:00Z".into()),
        end: Some("2026-01-02T00:00:00Z".into()),
        ..page(40)
    };
    let mut cursor = gateway
        .db("site", Protocol::Modbus)
        .frames(query)
        .at_most(45);
    assert_eq!(cursor.next_page().await.unwrap().len(), 40);
    assert!(!cursor.is_done());
    assert_eq!(cursor.next_page().await.unwrap().len(), 5);
    assert!(cursor.is_done());
    assert!(cursor.next_page().await.unwrap().is_empty());
    assert_eq!(
        lines(&log),
        [
            "GET /v1/db/site/frames?limit=40&protocol=modbus&start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z",
            "GET /v1/db/site/frames?limit=40&protocol=modbus&start=2026-01-01T00%3A00%3A00Z&end=2026-01-02T00%3A00%3A00Z&after=p2",
        ]
    );
}

fn frame(extra: Value) -> Result<ArchiveFrame, ClientError> {
    let mut row = json!({
        "ts_us": 1, "id": 0x123, "extended": false, "dlc": 0, "is_fd": false,
        "bus": 0, "dir": "rx", "data_hex": "",
    });
    row.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    ArchiveFrame::try_from(serde_json::from_value::<FrameBatchRow>(row).unwrap())
}

#[test]
fn an_fd_row_takes_its_length_from_the_payload_not_the_length_code() {
    let frame = frame(json!({ "dlc": 15, "is_fd": true, "data_hex": "ab".repeat(64) })).unwrap();
    assert_eq!((frame.len, frame.data.len()), (64, 64));
}

#[test]
fn a_remote_row_asks_for_its_length_code_with_no_payload() {
    let frame = frame(json!({ "dlc": 4, "is_rtr": true })).unwrap();
    assert!(frame.is_rtr && frame.data.is_empty());
    assert_eq!(frame.len, 4);
}

#[test]
fn an_fd_row_keeps_its_brs_and_esi() {
    let frame = frame(json!({
        "dlc": 9, "is_fd": true, "is_brs": true, "is_esi": true, "data_hex": "00".repeat(12),
    }))
    .unwrap();
    assert!(frame.is_brs && frame.is_esi && !frame.is_rtr);
    assert_eq!(frame.len, 12);
}

#[test]
fn a_row_from_an_older_gateway_has_no_flags() {
    let frame = frame(json!({ "dlc": 2, "data_hex": "abcd" })).unwrap();
    assert!(!frame.is_rtr && !frame.is_brs && !frame.is_esi);
    assert_eq!((frame.len, frame.data), (2, vec![0xab, 0xcd]));
}

#[test]
fn a_rows_crc_verdict_and_its_absence_reach_the_frame() {
    assert_eq!(frame(json!({})).unwrap().crc_valid, None);
    for valid in [false, true] {
        assert_eq!(
            frame(json!({ "crc_valid": valid })).unwrap().crc_valid,
            Some(valid)
        );
    }
}

#[test]
fn a_modbus_message_over_255_bytes_counts_every_byte() {
    let frame = frame(json!({ "id": 0x0103, "dlc": 256, "data_hex": "00".repeat(256) })).unwrap();
    assert_eq!(frame.len, 256);
}

#[test]
fn a_row_that_is_not_hex_is_refused_by_its_text() {
    let err = frame(json!({ "data_hex": "zz" })).unwrap_err();
    assert_eq!(err, ClientError::BadHex("zz".into()));
    assert_eq!(err.to_string(), "bad data_hex 'zz'");
}

fn entry(max_dlc: u16, max_len: Option<u16>) -> InventoryEntry {
    InventoryEntry {
        frame_id: 0,
        is_extended: false,
        count: 1,
        first_us: 0,
        last_us: 0,
        max_dlc,
        max_len,
    }
}

#[test]
fn an_inventory_length_code_becomes_a_length_for_can_only() {
    for (code, len) in [(8, 8), (9, 12), (15, 64)] {
        assert_eq!(entry(code, None).max_len_for(Protocol::Can), len);
    }
    assert_eq!(entry(15, None).max_len_for(Protocol::Modbus), 15);
    assert_eq!(entry(256, None).max_len_for(Protocol::Modbus), 256);
}

#[test]
fn the_gateways_max_len_is_taken_over_the_code_when_served() {
    assert_eq!(entry(9, Some(20)).max_len_for(Protocol::Can), 20);
    assert_eq!(entry(9, None).max_len_for(Protocol::Can), 12);
}

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn finding() -> CatalogFinding {
    CatalogFinding {
        field: "meta.name".into(),
        message: "missing".into(),
    }
}

fn assign() -> AssignCatalog {
    AssignCatalog {
        daemon_id: "debian".into(),
        interface: "/dev/ttyUSB0".into(),
        content: "[meta]\r\nname = \"Site\"\r\n".into(),
        provenance: Provenance::default(),
        expected: Some(String::new()),
    }
}

fn unassign(expected: Option<&str>) -> UnassignParams {
    UnassignParams {
        daemon_id: "debian".into(),
        interface: "/dev/ttyUSB0".into(),
        expected: expected.map(String::from),
    }
}

#[tokio::test]
async fn the_daemons_and_a_stored_catalogue_are_read_with_the_key() {
    let (base_url, log) = gateway(|seen| match seen.path.as_str() {
        "/v1/admin/daemons" => ok(json!({ "daemons": [{ "daemon_id": "debian", "devices": [] }] })),
        _ => ok(json!({
            "blob_sha": A, "content": "x = 1\r\n", "provenance": { "path": "cats/site.toml" },
            "created_at_us": 1,
        })),
    });
    let gateway = client(&base_url, "admin-key");
    assert_eq!(
        gateway.daemons().await.unwrap().daemons[0].daemon_id,
        "debian"
    );
    let stored = gateway.stored_catalogue(A).await.unwrap();
    assert_eq!(stored.content, "x = 1\r\n");
    assert_eq!(stored.provenance.path.as_deref(), Some("cats/site.toml"));
    assert_eq!(
        lines(&log),
        [
            "GET /v1/admin/daemons".to_string(),
            format!("GET /v1/admin/catalogs/{A}")
        ]
    );
    assert_eq!(
        log.lock().unwrap()[0].header("authorization"),
        Some("Bearer admin-key")
    );
}

#[tokio::test]
async fn an_assignment_puts_the_body_and_is_done_with_its_warnings() {
    let (base_url, log) = gateway(|_| {
        ok(json!({
            "daemon_id": "debian", "interface": "/dev/ttyUSB0",
            "assignment": { "blob_sha": A, "name": "Site", "assigned_at_us": 1, "assigned_by": null, "provenance": {} },
            "warnings": [{ "field": "meta.name", "message": "missing" }],
        }))
    });
    let outcome = client(&base_url, "").assign_catalogue(&assign()).await;
    assert_eq!(
        outcome.unwrap(),
        AssignOutcome::Done {
            warnings: vec![finding()]
        }
    );
    let log = log.lock().unwrap();
    assert_eq!(log[0].line(), "PUT /v1/admin/assignments");
    assert_eq!(log[0].json(), serde_json::to_value(assign()).unwrap());
}

#[tokio::test]
async fn an_empty_success_is_done_without_warnings() {
    let (base_url, _) = gateway(|_| (204, String::new()));
    let gateway = client(&base_url, "");
    let done = AssignOutcome::Done { warnings: vec![] };
    assert_eq!(gateway.assign_catalogue(&assign()).await.unwrap(), done);
    assert_eq!(
        gateway.unassign_catalogue(&unassign(None)).await.unwrap(),
        done
    );
}

#[tokio::test]
async fn a_rejected_catalogue_carries_its_findings() {
    let (base_url, _) = gateway(|_| {
        (
            400,
            json!({ "error": "meta.name: missing", "findings": [{ "field": "meta.name", "message": "missing" }] })
                .to_string(),
        )
    });
    let outcome = client(&base_url, "").assign_catalogue(&assign()).await;
    assert_eq!(
        outcome.unwrap(),
        AssignOutcome::Rejected(CatalogRejected {
            error: "meta.name: missing".into(),
            findings: vec![finding()],
        })
    );
}

#[tokio::test]
async fn an_unassignment_names_its_guard_only_when_set_and_reports_a_conflict() {
    let (base_url, log) = gateway(|seen| match seen.path.contains("expected") {
        true => (
            409,
            json!({ "error": "the assignment changed since it was read", "current": B })
                .to_string(),
        ),
        false => (204, String::new()),
    });
    let gateway = client(&base_url, "");
    assert_eq!(
        gateway
            .unassign_catalogue(&unassign(Some(A)))
            .await
            .unwrap(),
        AssignOutcome::Conflict(AssignmentConflict {
            error: "the assignment changed since it was read".into(),
            current: Some(B.into()),
        })
    );
    gateway.unassign_catalogue(&unassign(None)).await.unwrap();
    assert_eq!(
        lines(&log),
        [
            format!("DELETE /v1/admin/assignments?daemon_id=debian&interface=%2Fdev%2FttyUSB0&expected={A}"),
            "DELETE /v1/admin/assignments?daemon_id=debian&interface=%2Fdev%2FttyUSB0".to_string(),
        ]
    );
}

#[tokio::test]
async fn an_unassignment_of_nothing_on_an_older_gateway_is_done() {
    let (base_url, _) = gateway(|_| {
        (
            404,
            json!({ "error": "nothing is assigned there" }).to_string(),
        )
    });
    let outcome = client(&base_url, "")
        .unassign_catalogue(&unassign(None))
        .await;
    assert_eq!(outcome.unwrap(), AssignOutcome::Done { warnings: vec![] });
}

#[tokio::test]
async fn any_other_admin_answer_is_the_gateways_error() {
    let (base_url, _) = gateway(|_| (500, json!({ "error": "database unavailable" }).to_string()));
    let gateway = client(&base_url, "");
    let refused = ClientError::Status {
        code: 500,
        error: Some("database unavailable".into()),
    };
    assert_eq!(
        gateway.assign_catalogue(&assign()).await.unwrap_err(),
        refused
    );
    assert_eq!(
        gateway
            .unassign_catalogue(&unassign(None))
            .await
            .unwrap_err(),
        refused
    );
    assert_eq!(gateway.daemons().await.unwrap_err(), refused);
}
