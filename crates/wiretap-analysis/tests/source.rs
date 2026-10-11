//! The levers over a source, driven on the in-memory one without a runtime.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use serde_json::json;
use wiretap_analysis::source::{
    byte_profile, byte_profiles, catalog_coverage, checksum_scan, message_order, timed_by_protocol,
    FrameSelection, FrameSource, InventoryRow, MemorySource, OrderStart, PayloadQuery,
    PayloadSource, ProtocolFrames, Sampling, ScanFilter,
};
use wiretap_analysis::{analyse_order, ByteRole, Direction, FrameKey};
use wiretap_catalog::Catalog;

/// Every future here is ready on its first poll, or polled until it is.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
}

fn counter_source(frames: u8) -> MemorySource {
    let mut source = MemorySource::default();
    for i in 0..frames {
        source.push("can", 0x100, false, vec![0xC0, i]);
    }
    source
}

#[test]
fn byte_profiles_read_each_frames_most_recent_run() {
    let source = counter_source(50);

    let profiles = block_on(byte_profiles(
        &source,
        &ScanFilter::Ids(vec![]),
        10,
        usize::MAX,
    ))
    .unwrap();

    let profile = &profiles.frames[0].profile;
    assert_eq!(profile.sample_count, 10);
    assert_eq!(
        profile.columns[1].stats.min, 40,
        "the newest ten, not the first"
    );
    assert!(matches!(
        profile.columns[1].role,
        ByteRole::Counter {
            direction: Direction::Up,
            step: 1,
            ..
        }
    ));
}

#[test]
fn a_checksum_scan_samples_across_the_recording() {
    let source = counter_source(50);

    block_on(checksum_scan(
        &source,
        &ScanFilter::Ids(vec![]),
        10,
        Default::default(),
    ))
    .unwrap();

    assert_eq!(source.asked(), vec![(0x100, None, Sampling::Spread)]);
}

#[test]
fn a_checksum_scan_over_more_ids_than_a_chunk_counts_every_one() {
    let mut source = MemorySource::default();
    for id in 0..40 {
        for i in 0..20u8 {
            source.push("can", id, false, vec![i, i ^ 0x5A]);
        }
    }

    let result = block_on(checksum_scan(
        &source,
        &ScanFilter::Ids(vec![]),
        20,
        Default::default(),
    ))
    .unwrap();

    assert_eq!(result.unique_frame_ids, 40);
    assert_eq!(result.frame_count, 800);
}

#[test]
fn only_an_id_seen_both_standard_and_extended_is_fetched_by_its_width() {
    let mut source = MemorySource::default();
    source.push("can", 0x100, false, vec![1]);
    source.push("can", 0x100, true, vec![2]);
    source.push("can", 0x200, false, vec![3]);

    let profiles = block_on(byte_profiles(
        &source,
        &ScanFilter::Ids(vec![]),
        10,
        usize::MAX,
    ))
    .unwrap();

    assert_eq!(profiles.frames.len(), 3);
    let asked: Vec<_> = source.asked().iter().map(|a| (a.0, a.1)).collect();
    assert_eq!(
        asked,
        vec![(0x100, Some(false)), (0x100, Some(true)), (0x200, None)]
    );
}

#[test]
fn frames_past_max_frames_are_counted_not_profiled() {
    let mut source = MemorySource::default();
    for id in 0..5 {
        source.push("can", id, false, vec![0]);
    }

    let profiles = block_on(byte_profiles(&source, &ScanFilter::Ids(vec![]), 10, 2)).unwrap();

    assert_eq!(profiles.frames.len(), 2);
    assert_eq!(profiles.skipped_frames, 3);
}

#[test]
fn a_selection_scans_only_its_protocols_ids() {
    let mut source = MemorySource::default();
    source.push("can", 0x100, false, vec![1]);
    source.push("modbus", 0x100, false, vec![2]);
    let selection = FrameSelection::from_groups(vec![ProtocolFrames::ids("can", vec![0x100])]);

    let profiles = block_on(byte_profiles(
        &source,
        &ScanFilter::Selection(selection),
        10,
        usize::MAX,
    ))
    .unwrap();

    assert_eq!(profiles.frames.len(), 1);
    assert_eq!(profiles.frames[0].protocol.as_deref(), Some("can"));
}

/// Two ids carrying one counter together, and a third sent in bursts of two.
fn mirrored_and_bursty() -> MemorySource {
    let mut source = MemorySource::default();
    for i in 0..20u8 {
        let t = i as u64 * 100_000;
        source.push_at("can", 0, 0x100, false, t, vec![i, 0xA0]);
        source.push_at("can", 0, 0x200, false, t + 1_000, vec![i, 0xA0]);
        source.push_at("can", 1, 0x300, false, t + 2_000, vec![0x80 + i, 0x55]);
        source.push_at("can", 1, 0x300, false, t + 4_000, vec![0x80 + i, 0x66]);
    }
    source
}

#[test]
fn frame_order_is_the_libs_answer_per_protocol() {
    let mut source = mirrored_and_bursty();
    source.push_at("modbus", 0, 0x100, false, 5_000_000, vec![1]);
    let start = OrderStart {
        protocol: Some("can".into()),
        frame_id: 0x200,
        is_extended: false,
    };

    let orders = block_on(message_order(
        &source,
        &FrameSelection::default(),
        None,
        Some(&start),
    ))
    .unwrap();

    let protocols: Vec<&str> = orders.iter().map(|o| o.protocol.as_str()).collect();
    assert_eq!(protocols, vec!["can", "modbus"]);
    let frames =
        timed_by_protocol(block_on(source.frames(&FrameSelection::default(), None)).unwrap());
    assert_eq!(
        orders[0].order,
        analyse_order(&frames["can"], Some(FrameKey::new(0x200, false)))
    );
    assert_eq!(orders[1].order, analyse_order(&frames["modbus"], None));
    assert_eq!(orders[0].order.buses.len(), 2, "each bus its own schedule");
}

#[test]
fn a_live_window_reads_only_the_newest_frames() {
    let source = mirrored_and_bursty();

    let orders = block_on(message_order(
        &source,
        &FrameSelection::default(),
        Some(10),
        None,
    ))
    .unwrap();

    assert_eq!(orders[0].order.total_frames, 10);
}

fn groups(entries: &[(&str, &[u32])]) -> Vec<ProtocolFrames> {
    entries
        .iter()
        .map(|(protocol, ids)| ProtocolFrames::ids(*protocol, ids.to_vec()))
        .collect()
}

/// Empty means "select everything" at every call site, so a group carrying no ids must
/// not leave the selection looking non-empty — that would invert "select nothing".
#[test]
fn groups_with_no_ids_normalise_to_an_empty_selection() {
    assert!(FrameSelection::from_groups(groups(&[("can", &[])])).is_empty());
    assert!(FrameSelection::from_groups(Vec::new()).is_empty());
    assert!(!FrameSelection::from_groups(groups(&[("can", &[256])])).is_empty());
}

#[test]
fn repeated_groups_merge_and_deduplicate() {
    let selection = FrameSelection::from_groups(groups(&[("can", &[256, 256]), ("can", &[257])]));
    assert_eq!(selection.pairs(), vec![(256, "can"), (257, "can")]);
}

/// Keyed on the bare id, a CAN-only selection wrongly "covered" a capture holding
/// Modbus too, and the tail silently returned unfiltered rows.
#[test]
fn covers_is_protocol_aware() {
    let seen: &[(&str, &[u32])] = &[("can", &[256]), ("modbus", &[256])];
    let covers = |selection: FrameSelection| selection.covers(seen.iter().copied());

    assert!(!covers(FrameSelection::from_groups(groups(&[(
        "can",
        &[256, 257]
    )]))));
    assert!(covers(FrameSelection::from_groups(groups(seen))));
}

/// A protocol tab selects its protocol whole: not empty (which would select
/// everything), covering every id of that protocol including ones not yet seen,
/// and contributing no pairs — the predicate matches it by name.
#[test]
fn a_protocol_selected_whole_covers_ids_it_has_not_seen() {
    let selection = FrameSelection::from_groups(vec![ProtocolFrames::whole("modbus_rtu")]);
    assert!(!selection.is_empty());
    assert!(selection.contains("modbus_rtu", 0x0265));
    assert!(!selection.contains("can", 0x0265));
    let modbus: &[(&str, &[u32])] = &[("modbus_rtu", &[288, 613])];
    assert!(selection.covers(modbus.iter().copied()));
    let mixed_seen: &[(&str, &[u32])] = &[("modbus_rtu", &[288]), ("can", &[256])];
    assert!(!selection.covers(mixed_seen.iter().copied()));
    assert!(selection.pairs().is_empty());
    assert_eq!(selection.protocols(), vec!["modbus_rtu"]);

    let mut mixed = groups(&[("can", &[256]), ("modbus_rtu", &[288])]);
    mixed.push(ProtocolFrames::whole("modbus_rtu"));
    let mixed = FrameSelection::from_groups(mixed);
    assert_eq!(mixed.pairs(), vec![(256, "can")]);
    assert_eq!(mixed.protocols(), vec!["modbus_rtu"]);
}

#[test]
fn pairs_are_sorted_regardless_of_insertion_order() {
    let a = FrameSelection::from_groups(groups(&[("modbus", &[257, 256]), ("can", &[256])]));
    let b = FrameSelection::from_groups(groups(&[("can", &[256]), ("modbus", &[256, 257])]));
    assert_eq!(a.pairs(), b.pairs());
    assert_eq!(
        a.pairs(),
        vec![(256, "can"), (256, "modbus"), (257, "modbus")]
    );
}

const COVERED: &str = r#"
[meta]
name = "covered"

[frame.can.0x100]
length = 2

[[frame.can.0x100.signals]]
name = "high"
start_bit = 0
bit_length = 8
confidence = "high"

[[frame.can.0x100.signals]]
name = "said_none"
start_bit = 8
bit_length = 4
confidence = "none"

[[frame.can.0x100.signals]]
name = "said_nothing"
start_bit = 12
bit_length = 4

[frame.can.0x200]
length = 1
"#;

/// Inventory from memory, and payloads that never read.
struct UnreadablePayloads(MemorySource);

impl PayloadSource for UnreadablePayloads {
    type Error = String;

    async fn inventory(
        &self,
        start_us: Option<i64>,
        end_us: Option<i64>,
    ) -> Result<Vec<InventoryRow>, String> {
        Ok(self.0.inventory(start_us, end_us).await.unwrap())
    }

    async fn payloads(&self, _: PayloadQuery<'_>) -> Result<Vec<Vec<u8>>, String> {
        Err("unreadable".into())
    }
}

#[test]
fn coverage_is_snake_case_and_says_unset_for_none_and_absent_alike() {
    let catalog = Catalog::parse(COVERED).unwrap();
    let mut source = MemorySource::default();
    source.push("can", 0x100, false, vec![1, 2]);
    source.push("can", 0x300, false, vec![3]);

    let report = block_on(catalog_coverage(
        &source, "covered", &catalog, false, 10, None, None,
    ))
    .unwrap();

    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        json!({
            "catalog": "covered",
            "catalog_frames": 2,
            "data_frames": 2,
            "present": [{
                "frame_id": 0x100,
                "frame_id_hex": "0x100",
                "name": null,
                "count": 1,
                "first_us": 0,
                "last_us": 0,
                "signals": [
                    { "name": "high", "confidence": "high" },
                    { "name": "said_none", "confidence": "unset" },
                    { "name": "said_nothing", "confidence": "unset" },
                ],
            }],
            "missing": [{ "frame_id": 0x200, "frame_id_hex": "0x200", "name": null }],
            "uncatalogued": [{
                "frame_id": 0x300,
                "frame_id_hex": "0x300",
                "is_extended": false,
                "count": 1,
            }],
            "confidence": { "high": 1, "medium": 0, "low": 0, "unset": 2 },
        })
    );
}

#[test]
fn a_payload_read_failure_costs_coverage_its_byte_roles_not_the_report() {
    let catalog = Catalog::parse(COVERED).unwrap();
    let mut memory = MemorySource::default();
    memory.push("can", 0x100, false, vec![1, 2]);

    let report = block_on(catalog_coverage(
        &UnreadablePayloads(memory),
        "covered",
        &catalog,
        true,
        10,
        None,
        None,
    ))
    .unwrap();

    let roles = report.present[0].byte_roles.as_ref().unwrap();
    assert_eq!(roles.sample_count, 0);
}

#[test]
fn the_mcp_shapes_keep_their_casing() {
    let mut source = MemorySource::default();
    source.push("can", 0x100, false, vec![1]);

    let profile = serde_json::to_value(
        block_on(byte_profile(&source, Some("can"), 0x100, None, 10)).unwrap(),
    )
    .unwrap();
    assert_eq!(profile["frameId"], 0x100);
    assert_eq!(profile["isExtended"], false);
    assert_eq!(profile["frameIdHex"], "0x100");
    assert_eq!(profile["protocol"], "can");
    assert_eq!(profile["sampleCount"], 1, "the profile flattened in");

    let orders = block_on(message_order(
        &source,
        &FrameSelection::default(),
        None,
        None,
    ))
    .unwrap();
    let order = serde_json::to_value(&orders[0]).unwrap();
    assert_eq!(order["protocol"], "can");
    assert_eq!(order["order"]["totalFrames"], 1);

    let start: OrderStart =
        serde_json::from_value(json!({ "frameId": 1, "isExtended": true })).unwrap();
    assert_eq!(start.protocol, None);
    assert_eq!(
        serde_json::to_value(&start).unwrap(),
        json!({ "protocol": null, "frameId": 1, "isExtended": true })
    );

    let rows = block_on(source.inventory(None, None)).unwrap();
    assert_eq!(
        serde_json::to_value(&rows[0]).unwrap(),
        json!({
            "protocol": "can",
            "frame_id": 0x100,
            "frame_id_hex": "0x100",
            "is_extended": false,
            "count": 1,
            "first_us": 0,
            "last_us": 0,
            "max_dlc": 1,
        })
    );
}
