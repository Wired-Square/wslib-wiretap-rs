use super::*;
use serde_json::json;

/// Build an `EditOp` from a JSON object the way the WS layer does.
fn op(v: Json) -> EditOp {
    serde_json::from_value(v).expect("valid EditOp")
}

fn edit(text: &str, v: Json) -> String {
    apply_edit(text, op(v)).expect("edit ok")
}

const SIGNAL_SORT: [&str; 3] = ["start_bit", "bit_length", "name"];

// ── headline: add one signal, lose nothing ───────────────────────────────────

#[test]
fn add_signal_preserves_comments_and_only_adds_entry() {
    let toml = r#"# catalogue header comment
[meta]
name = "demo"
version = 1

# the temperature frame
[frame.can.0x100]
length = 8  # full frame

[[frame.can.0x100.signals]]
name = "temp"          # degrees C
start_bit = 0
bit_length = 16

# a second, untouched frame
[frame.can.0x200]
length = 8
"#;

    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x100", "signals"],
            "value": { "name": "soc", "start_bit": 16, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );

    // Every comment survives.
    assert!(out.contains("# catalogue header comment"));
    assert!(out.contains("# the temperature frame"));
    assert!(out.contains("# full frame"));
    assert!(out.contains("# degrees C"));
    assert!(out.contains("# a second, untouched frame"));
    // The new signal landed.
    assert!(out.contains(r#"name = "soc""#));
    // The untouched sibling frame is byte-for-byte intact.
    assert!(out.contains("# a second, untouched frame\n[frame.can.0x200]\nlength = 8\n"));
    // It parses and now has two signals on 0x100.
    let cat = crate::Catalog::parse(&out).expect("parses");
    let f = cat.frames.iter().find(|f| f.frame_id == 0x100).unwrap();
    assert_eq!(f.signals.len(), 2);
}

#[test]
fn signal_inserts_in_sorted_position() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
[[frame.can.0x10.signals]]
name = "a"
start_bit = 0
bit_length = 8
[[frame.can.0x10.signals]]
name = "c"
start_bit = 16
bit_length = 8
"#;
    // start_bit 8 sorts between a(0) and c(16).
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "b", "start_bit": 8, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let a = out.find(r#"name = "a""#).unwrap();
    let b = out.find(r#"name = "b""#).unwrap();
    let c = out.find(r#"name = "c""#).unwrap();
    assert!(a < b && b < c, "expected a<b<c order, got:\n{out}");
}

#[test]
fn signal_replace_in_place_keeps_other_signals_comment() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
[[frame.can.0x10.signals]]
name = "keep"   # important note
start_bit = 0
bit_length = 8
[[frame.can.0x10.signals]]
name = "edit_me"
start_bit = 8
bit_length = 8
"#;
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "edited", "start_bit": 8, "bit_length": 8, "unit": "V" },
            "index": 1,
            "sort_keys": SIGNAL_SORT,
        }),
    );
    assert!(out.contains("# important note"));
    assert!(out.contains(r#"name = "edited""#));
    assert!(out.contains(r#"unit = "V""#));
    assert!(!out.contains("edit_me"));
}

#[test]
fn add_signal_with_enum_subtable_round_trips() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n[frame.can.0x10]\nlength = 8\n";
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": {
                "name": "mode",
                "start_bit": 0,
                "bit_length": 8,
                "enum": { "0": "off", "2": "on" }
            },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let cat = crate::Catalog::parse(&out).expect("parses");
    let f = cat.frames.iter().find(|f| f.frame_id == 0x10).unwrap();
    let sig = f
        .signals
        .iter()
        .find(|s| s.name.as_deref() == Some("mode"))
        .unwrap();
    let enum_map = sig.enum_map.as_ref().expect("enum map present");
    assert_eq!(enum_map.get(&0).map(String::as_str), Some("off"));
    assert_eq!(enum_map.get(&2).map(String::as_str), Some("on"));
}

// ── hex rendering of masks ────────────────────────────────────────────────────

#[test]
fn frame_id_mask_renders_as_hex() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n";
    for (mask, expect) in [
        (0xFFu64, "0xFF"),
        (0xFF00, "0xFF00"),
        (0x1FFF_FF00, "0x1FFFFF00"),
    ] {
        let out = edit(
            toml,
            json!({
                "op": "SetTable",
                "path": ["meta", "can"],
                "value": { "default_byte_order": "little", "frame_id_mask": mask },
                "replace_contents": true,
            }),
        );
        assert!(
            out.contains(&format!("frame_id_mask = {expect}")),
            "mask {mask:#x} -> {out}"
        );
    }
}

#[test]
fn header_field_mask_renders_as_hex() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n";
    let out = edit(
        toml,
        json!({
            "op": "SetTable",
            "path": ["meta", "can"],
            "value": {
                "default_byte_order": "big",
                "fields": { "priority": { "mask": 0xFF00_0000u64, "shift": 24 } }
            },
            "replace_contents": true,
        }),
    );
    assert!(out.contains("mask = 0xFF000000"), "{out}");
    assert!(out.contains("shift = 24"));
}

// ── meta update preserves protocol configs ───────────────────────────────────

#[test]
fn update_meta_preserves_protocol_config() {
    let toml = r#"[meta]
name = "old"
version = 1

[meta.can]
default_byte_order = "little"  # keep me
"#;
    let out = edit(
        toml,
        json!({
            "op": "SetTable",
            "path": ["meta"],
            "value": { "name": "new", "version": 2 },
            "managed_keys": ["name", "version"],
        }),
    );
    assert!(out.contains(r#"name = "new""#));
    assert!(out.contains("version = 2"));
    assert!(out.contains("[meta.can]"));
    assert!(out.contains("# keep me"));
}

// ── CAN frame upsert: rename + numeric sort + sub-table preservation ─────────

#[test]
fn can_frame_rename_carries_signals_and_sorts() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x200]
length = 8
[[frame.can.0x200.signals]]
name = "s"
start_bit = 0
bit_length = 8
[frame.can.0x050]
length = 8
"#;
    // Rename 0x200 -> 0x010; result should sort before 0x050 and keep its signal.
    let out = edit(
        toml,
        json!({
            "op": "UpsertFrame",
            "protocol": "can",
            "key": "0x010",
            "rename_from": "0x200",
            "value": { "length": 8 },
            "managed_keys": ["length", "notes", "transmitter", "tx"],
        }),
    );
    let p010 = out.find("[frame.can.0x010]").expect("renamed");
    let p050 = out.find("[frame.can.0x050]").expect("present");
    assert!(p010 < p050, "0x010 should sort before 0x050:\n{out}");
    let cat = crate::Catalog::parse(&out).unwrap();
    let f = cat.frames.iter().find(|f| f.frame_id == 0x010).unwrap();
    assert_eq!(f.signals.len(), 1);
}

#[test]
fn can_frame_inherited_field_is_removed() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x100]
length = 8
transmitter = "ECU"
"#;
    // transmitter omitted from value + managed -> dropped (now inherited).
    let out = edit(
        toml,
        json!({
            "op": "UpsertFrame",
            "protocol": "can",
            "key": "0x100",
            "value": { "length": 8 },
            "managed_keys": ["length", "notes", "transmitter", "tx"],
        }),
    );
    assert!(!out.contains("transmitter"), "{out}");
}

// ── nodes: rename rewrites transmitter references ─────────────────────────────

#[test]
fn node_rename_updates_transmitter_refs() {
    let toml = r#"[meta]
name = "d"
version = 1
[node.ecu_a]
notes = "the ECU"
[frame.can.0x100]
length = 8
transmitter = "ecu_a"
"#;
    let out = edit(
        toml,
        json!({
            "op": "RenameKey",
            "parent_path": ["node"],
            "old": "ecu_a",
            "new": "ecu_b",
            "set_value": { "notes": "the ECU" },
            "managed_keys": ["notes"],
            "sort_numeric": true,
            "update_transmitter_refs": true,
            "error_if_exists": true,
        }),
    );
    assert!(out.contains("[node.ecu_b]"));
    assert!(out.contains(r#"transmitter = "ecu_b""#));
    assert!(out.contains(r#"notes = "the ECU""#));
}

#[test]
fn mux_case_collision_is_error() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x100]
length = 8
[frame.can.0x100.mux]
name = "m"
start_bit = 0
bit_length = 8
[frame.can.0x100.mux.0]
[frame.can.0x100.mux.1]
"#;
    let res = apply_edit(
        toml,
        op(json!({
            "op": "RenameKey",
            "parent_path": ["frame", "can", "0x100", "mux"],
            "old": "0",
            "new": "1",
            "error_if_exists": true,
        })),
    );
    assert!(res.is_err());
}

// ── checksum array empty-cleanup ──────────────────────────────────────────────

#[test]
fn remove_last_checksum_drops_the_array() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.serial.0x01]
length = 4
[[frame.serial.0x01.checksum]]
name = "crc"
algorithm = "crc16"
start_byte = 2
"#;
    let out = edit(
        toml,
        json!({
            "op": "RemoveArrayItem",
            "array_path": ["frame", "serial", "0x01", "checksum"],
            "index": 0,
            "remove_if_empty": true,
        }),
    );
    assert!(!out.contains("checksum"), "{out}");
}

// ── inline signals array fallback ─────────────────────────────────────────────

#[test]
fn inline_signal_array_is_supported() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
signals = [ { name = "a", start_bit = 0, bit_length = 8 } ]
"#;
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "b", "start_bit": 8, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let cat = crate::Catalog::parse(&out).unwrap();
    let f = cat.frames.iter().find(|f| f.frame_id == 0x10).unwrap();
    assert_eq!(f.signals.len(), 2);
}

// ── serde: a stray `content` key in the params is ignored ─────────────────────

#[test]
fn editop_ignores_extra_content_key() {
    let parsed: EditOp = serde_json::from_value(json!({
        "op": "DeleteAtPath",
        "path": ["frame", "can", "0x100"],
        "content": "[meta]\nname=\"x\"\n",
    }))
    .expect("deserialises with extra content key");
    assert!(matches!(parsed, EditOp::DeleteAtPath { .. }));
}

#[test]
fn invalid_toml_errors() {
    let res = apply_edit(
        "this is = = not toml",
        op(json!({ "op": "DeleteAtPath", "path": ["x"] })),
    );
    assert!(res.is_err());
}

// ── bump_meta_version ────────────────────────────────────────────────────────
//
// These assert **whole documents**, not `contains`. The bump exists on the publish
// path, which hashes exact bytes, so "the version changed and nothing else did" is
// the entire contract — and `contains` is precisely what would let a decor or
// line-ending regression through.

/// The test the `EditOp::SetTable` approach fails. A `DocumentMut` round-trip deletes
/// the comment block above `version` (the parser folds it into that key's decor, and
/// `Table::insert` re-formats the key) and the trailing note (value suffix decor).
#[test]
fn bump_preserves_every_other_byte() {
    let text = "\
# Sungrow SHx inverter, reverse-engineered from a live SH10RT.
[meta]
name = \"Sungrow SHx\"

# Bumped when the mux map was corrected.
version = 3  # keep in step with the wiki page

[meta.can]
bitrate = 500000

[frame.can.0x100]
name = \"Status\"
";
    let bumped = bump_meta_version(text).expect("bumps");
    assert_eq!(bumped.from, 3);
    assert_eq!(bumped.to, 4);
    assert_eq!(bumped.text, text.replace("version = 3", "version = 4"));
}

/// Fails loudly if anyone "simplifies" this back to a `DocumentMut` round-trip, whose
/// encoder re-emits every key-value with a bare `\n`.
#[test]
fn bump_preserves_crlf() {
    let text = "[meta]\r\nname = \"X\"\r\nversion = 9\r\n\r\n[meta.can]\r\nbitrate = 250000\r\n";
    let bumped = bump_meta_version(text).expect("bumps");
    assert_eq!(bumped.text, text.replace("version = 9", "version = 10"));
    assert!(bumped.text.contains("\r\n"), "line endings survive");
}

/// Absent and `= 1` are the same claim, so the honest increment is 2. Asserts the
/// placement as well as the value — it must land inside `[meta]`, after `name`, and
/// before the sub-tables.
#[test]
fn bump_writes_version_two_when_the_key_is_absent() {
    let text = "[meta]\nname = \"X\"\n\n[meta.can]\nbitrate = 500000\n";
    let bumped = bump_meta_version(text).expect("bumps");
    assert_eq!((bumped.from, bumped.to), (1, 2));
    assert_eq!(
        bumped.text,
        "[meta]\nname = \"X\"\nversion = 2\n\n[meta.can]\nbitrate = 500000\n"
    );
}

#[test]
fn bump_inserts_with_the_documents_own_line_ending() {
    let text = "[meta]\r\nname = \"X\"\r\n";
    let bumped = bump_meta_version(text).expect("bumps");
    assert_eq!(bumped.text, "[meta]\r\nname = \"X\"\r\nversion = 2\r\n");
}

#[test]
fn bump_refuses_a_non_integer_version() {
    assert!(bump_meta_version("[meta]\nname = \"X\"\nversion = \"3\"\n").is_err());
}

#[test]
fn bump_refuses_at_the_maximum() {
    let text = format!("[meta]\nname = \"X\"\nversion = {}\n", u32::MAX);
    assert!(bump_meta_version(&text).is_err());
}

#[test]
fn bump_refuses_without_a_meta_section() {
    assert!(bump_meta_version("[frame.can.0x100]\nname = \"X\"\n").is_err());
}

/// The bumped text must still parse, and to the number we claimed.
#[test]
fn bump_round_trips_through_the_parser() {
    let text = "[meta]\nname = \"X\"\nversion = 7\n";
    let bumped = bump_meta_version(text).expect("bumps");
    let catalog = crate::model::Catalog::parse(&bumped.text).expect("parses");
    assert_eq!(catalog.meta.version, bumped.to);
}
