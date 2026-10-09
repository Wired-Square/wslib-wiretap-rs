use super::*;
use crate::edit::{apply_edit, apply_edits, EditOp};
use crate::validate::validate;
use crate::Catalog;
use serde_json::json;

fn path(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|s| s.to_string()).collect()
}

fn build(ops: &[EditOp]) -> String {
    apply_edits("", ops).expect("ops apply")
}

fn edit(text: &str, op: EditOp) -> String {
    apply_edit(text, op).expect("op applies")
}

fn assert_clean(text: &str) -> Catalog {
    assert_eq!(validate(text), vec![], "{text}");
    Catalog::parse(text).expect("parses")
}

fn meta(name: &str, protocol: Protocol) -> EditOp {
    EditOp::SetMeta {
        meta: MetaFields {
            name: name.into(),
            version: 1,
            default_frame: Some(protocol),
        },
    }
}

fn frame(protocol: Protocol, key: &str, frame: FrameFields) -> EditOp {
    EditOp::SetFrame {
        protocol,
        key: key.into(),
        rename_from: None,
        frame,
    }
}

fn can_frame(key: &str, length: u32) -> EditOp {
    frame(
        Protocol::Can,
        key,
        FrameFields {
            length: Some(length),
            ..Default::default()
        },
    )
}

fn sig(name: &str, start_bit: u32, bit_length: u32) -> SignalFields {
    SignalFields {
        name: name.into(),
        start_bit,
        bit_length,
        ..Default::default()
    }
}

fn hex_fill(name: &str, start_bit: u32, bit_length: u32) -> SignalFields {
    SignalFields {
        format: Some("hex".into()),
        ..sig(name, start_bit, bit_length)
    }
}

fn put(owner: &[&str], signal: SignalFields) -> EditOp {
    EditOp::UpsertSignal {
        owner_path: path(owner),
        index: None,
        signal,
    }
}

fn update(owner: &[&str], index: usize, signal: SignalFields) -> EditOp {
    EditOp::UpsertSignal {
        owner_path: path(owner),
        index: Some(index),
        signal,
    }
}

fn mux(owner: &[&str], name: &str, start_bit: u32, bit_length: u32) -> EditOp {
    EditOp::SetMux {
        owner_path: path(owner),
        mux: MuxFields {
            name: name.into(),
            start_bit,
            bit_length,
            notes: vec![],
        },
    }
}

/// The signal written by one op on a fresh frame, as its TOML table body.
fn signal_text(signal: SignalFields) -> String {
    let text = build(&[
        meta("d", Protocol::Can),
        can_frame("0x100", 8),
        put(&["frame", "can", "0x100"], signal),
    ]);
    text.split("[[frame.can.0x100.signals]]")
        .nth(1)
        .expect("a signal")
        .to_string()
}

fn frame_text(protocol: Protocol, fields: FrameFields) -> String {
    let text = build(&[frame(protocol, "10", fields)]);
    text.split_once(']').expect("a frame header").1.to_string()
}

const ONE_SIGNAL: &str = r#"[meta]
name = "d"
version = 1

[frame.can.0x100]
length = 8

[[frame.can.0x100.signals]]
name = "temp"
start_bit = 0
bit_length = 16
"#;

// ── the three desktop exports, built from empty text ──────────────────────────

#[test]
fn a_discovery_export_with_notes_and_muxes_is_clean() {
    let text = build(&[
        meta("export", Protocol::Can),
        EditOp::SetCanConfig {
            config: CanConfigFields {
                default_byte_order: Some(Endianness::Big),
                default_interval: Some(100),
                ..Default::default()
            },
        },
        frame(
            Protocol::Can,
            "0x100",
            FrameFields {
                length: Some(8),
                notes: vec!["seen at 10 Hz".into(), "line one\nline \"two\" \\".into()],
                interval_ms: Some(50),
                ..Default::default()
            },
        ),
        put(
            &["frame", "can", "0x100"],
            SignalFields {
                byte_order: Some(Endianness::Little),
                confidence: Some(Confidence::High),
                ..sig("counter_0_1", 0, 16)
            },
        ),
        put(&["frame", "can", "0x100"], hex_fill("hex_2_7", 16, 48)),
        can_frame("0x200", 8),
        mux(&["frame", "can", "0x200"], "selector", 16, 8),
        put(
            &["frame", "can", "0x200", "mux", "1"],
            hex_fill("hex_0_1", 0, 16),
        ),
        put(
            &["frame", "can", "0x200", "mux", "2"],
            hex_fill("hex_0_1", 0, 16),
        ),
        can_frame("0x300", 8),
        mux(&["frame", "can", "0x300"], "outer", 0, 8),
        mux(&["frame", "can", "0x300", "mux", "1"], "inner", 8, 8),
        put(
            &["frame", "can", "0x300", "mux", "1", "mux", "2"],
            hex_fill("data_2_7", 16, 48),
        ),
    ]);
    let cat = assert_clean(&text);

    let f100 = cat.frames.iter().find(|f| f.frame_id == 0x100).unwrap();
    assert_eq!(
        f100.notes,
        ["seen at 10 Hz", "line one\nline \"two\" \\"],
        "{text}"
    );
    assert_eq!(f100.interval, Some(50));
    assert_eq!(f100.signals[0].confidence, Some(Confidence::High));
    let f300 = cat.frames.iter().find(|f| f.frame_id == 0x300).unwrap();
    let inner = f300.mux.as_ref().unwrap().cases["1"].mux.as_ref().unwrap();
    assert_eq!((inner.start_bit, inner.cases["2"].signals.len()), (8, 1));
}

#[test]
fn a_serial_discovery_export_is_clean() {
    let text = build(&[
        meta("serial export", Protocol::Serial),
        EditOp::SetSerialConfig {
            config: SerialConfigFields {
                encoding: Some("slip".into()),
                byte_order: Some(Endianness::Big),
                fields: BTreeMap::from([
                    (
                        "id".to_string(),
                        HeaderFieldFields {
                            mask: Mask::Value(0xFFFF00),
                            byte_order: Some(Endianness::Little),
                            ..Default::default()
                        },
                    ),
                    (
                        "source_address".to_string(),
                        HeaderFieldFields {
                            mask: Mask::Value(0xFF),
                            ..Default::default()
                        },
                    ),
                ]),
                checksum: Some(SerialChecksumFields {
                    algorithm: "xor".into(),
                    start_byte: -1,
                    byte_length: 1,
                    calc_start_byte: 0,
                    calc_end_byte: Some(-1),
                    big_endian: false,
                }),
                ..Default::default()
            },
        },
        frame(
            Protocol::Serial,
            "0x10",
            FrameFields {
                length: Some(8),
                ..Default::default()
            },
        ),
        put(&["frame", "serial", "0x10"], hex_fill("hex_3_6", 24, 32)),
    ]);
    let cat = assert_clean(&text);

    let serial = cat.serial.unwrap();
    assert_eq!(
        (serial.frame_id_start_byte, serial.frame_id_bytes),
        (Some(1), Some(2))
    );
    assert_eq!(serial.frame_id_byte_order, Some(Endianness::Little));
    assert_eq!(serial.checksum.unwrap().calc_end_byte, Some(-1));
}

#[test]
fn a_plain_frames_export_is_clean() {
    let text = build(&[
        meta("export", Protocol::Can),
        EditOp::SetCanConfig {
            config: CanConfigFields {
                default_byte_order: Some(Endianness::Big),
                default_interval: Some(100),
                ..Default::default()
            },
        },
        can_frame("0x100", 8),
        can_frame("0x7FF", 2),
    ]);
    let cat = assert_clean(&text);

    assert_eq!(cat.frames.len(), 2);
    assert_eq!(cat.can.unwrap().default_interval, Some(100));
}

#[test]
fn a_modbus_discovery_export_is_clean() {
    let modbus = |register: u16, register_type, length| {
        frame(
            Protocol::Modbus,
            &register.to_string(),
            FrameFields {
                register_number: Some(register),
                register_type: Some(register_type),
                length: Some(length),
                ..Default::default()
            },
        )
    };
    let text = build(&[
        meta(r#"Sungrow "SH10RT""#, Protocol::Modbus),
        EditOp::SetModbusConfig {
            config: ModbusConfigFields {
                device_address: Some(1),
                register_base: Some(0),
                default_interval: Some(1000),
                ..Default::default()
            },
        },
        modbus(5000, RegisterType::Input, 2),
        modbus(5002, RegisterType::Input, 1),
        modbus(13000, RegisterType::Holding, 1),
    ]);
    let cat = assert_clean(&text);

    assert_eq!(cat.meta.name, r#"Sungrow "SH10RT""#);
    let mut types: Vec<_> = cat
        .frames
        .iter()
        .map(|f| (f.frame_id, f.modbus_register_type, f.modbus_register_count))
        .collect();
    types.sort_by_key(|t| t.0);
    assert_eq!(
        types,
        [
            (5000, Some(RegisterType::Input), Some(2)),
            (5002, Some(RegisterType::Input), Some(1)),
            (13000, Some(RegisterType::Holding), Some(1)),
        ]
    );
}

// ── elision rules, one per rule ───────────────────────────────────────────────

#[test]
fn a_factor_of_one_is_not_written() {
    let written = |factor| {
        signal_text(SignalFields {
            factor: Some(factor),
            ..sig("s", 0, 8)
        })
    };
    assert!(!written(1.0).contains("factor"));
    assert!(written(0.1).contains("factor = 0.1"));
}

#[test]
fn an_offset_of_zero_is_not_written() {
    let written = |offset| {
        signal_text(SignalFields {
            offset: Some(offset),
            ..sig("s", 0, 8)
        })
    };
    assert!(!written(0.0).contains("offset"));
    assert!(written(-40.0).contains("offset = -40.0"));
}

#[test]
fn empty_text_is_not_written() {
    let text = signal_text(SignalFields {
        unit: Some(String::new()),
        format: Some(String::new()),
        ..sig("s", 0, 8)
    });
    assert!(!text.contains("unit") && !text.contains("format"), "{text}");
}

#[test]
fn byte_order_is_written_as_byte_order_and_replaces_endianness() {
    let legacy = ONE_SIGNAL.replace(
        "bit_length = 16\n",
        "bit_length = 16\nendianness = \"big\"\n",
    );
    let text = edit(
        &legacy,
        update(
            &["frame", "can", "0x100"],
            0,
            SignalFields {
                byte_order: Some(Endianness::Little),
                ..sig("temp", 0, 16)
            },
        ),
    );
    assert!(text.contains(r#"byte_order = "little""#), "{text}");
    assert!(!text.contains("endianness"), "{text}");
}

#[test]
fn one_note_is_a_string_and_more_are_an_array() {
    let written = |notes: &[&str]| {
        signal_text(SignalFields {
            notes: notes.iter().map(|n| n.to_string()).collect(),
            ..sig("s", 0, 8)
        })
    };
    assert!(!written(&[]).contains("notes"));
    assert!(!written(&[" ", ""]).contains("notes"));
    assert!(written(&[" one ", " "]).contains(r#"notes = "one""#));
    assert!(written(&["one", "two"]).contains(r#"notes = ["one", "two"]"#));
}

#[test]
fn signed_false_is_not_written() {
    let written = |signed| {
        signal_text(SignalFields {
            signed: Some(signed),
            ..sig("s", 0, 8)
        })
    };
    assert!(!written(false).contains("signed"));
    assert!(written(true).contains("signed = true"));
}

#[test]
fn a_frame_interval_is_interval_ms_and_replaces_the_legacy_keys() {
    let legacy = ONE_SIGNAL.replace(
        "length = 8\n",
        "length = 8\ninterval = 20\ntx = { interval_ms = 10 }\n",
    );
    let text = edit(
        &legacy,
        frame(
            Protocol::Can,
            "0x100",
            FrameFields {
                length: Some(8),
                interval_ms: Some(50),
                ..Default::default()
            },
        ),
    );
    assert!(text.contains("interval_ms = 50"), "{text}");
    assert!(
        !text.contains("interval =") && !text.contains("tx"),
        "{text}"
    );
}

#[test]
fn a_holding_register_type_is_not_written() {
    let written = |register_type| {
        frame_text(
            Protocol::Modbus,
            FrameFields {
                register_type: Some(register_type),
                ..Default::default()
            },
        )
    };
    assert!(!written(RegisterType::Holding).contains("register_type"));
    assert!(written(RegisterType::Coil).contains(r#"register_type = "coil""#));
}

#[test]
fn a_modbus_length_of_one_is_not_written() {
    let written = |length| {
        frame_text(
            Protocol::Modbus,
            FrameFields {
                length: Some(length),
                ..Default::default()
            },
        )
    };
    assert!(!written(1).contains("length"));
    assert!(written(2).contains("length = 2"));
}

#[test]
fn a_serial_length_of_zero_and_an_empty_delimiter_are_not_written() {
    let text = frame_text(
        Protocol::Serial,
        FrameFields {
            length: Some(0),
            ..Default::default()
        },
    );
    assert!(
        !text.contains("length") && !text.contains("delimiter"),
        "{text}"
    );
}

#[test]
fn keys_of_another_protocol_are_not_written() {
    let text = frame_text(
        Protocol::Can,
        FrameFields {
            register_number: Some(5000),
            delimiter: vec![0x0D],
            extended: Some(true),
            ..Default::default()
        },
    );
    assert_eq!(text.trim(), "extended = true");
}

#[test]
fn header_field_defaults_are_not_written_and_masks_are_hex() {
    let text = build(&[EditOp::SetCanConfig {
        config: CanConfigFields {
            frame_id_mask: Some(Mask::Text(" 1fffff00 ".into())),
            fields: BTreeMap::from([(
                " source ".to_string(),
                HeaderFieldFields {
                    mask: Mask::Text("0xFF".into()),
                    shift: Some(0),
                    format: Some("hex".into()),
                    byte_order: Some(Endianness::Big),
                },
            )]),
            ..Default::default()
        },
    }]);
    assert_eq!(
        text,
        "[meta.can]\nframe_id_mask = 0x1FFFFF00\n\n[meta.can.fields.source]\nmask = 0xFF\n"
    );
}

#[test]
fn a_checksum_writes_big_endian_only_when_true() {
    let written = |big_endian| {
        build(&[EditOp::SetSerialConfig {
            config: SerialConfigFields {
                checksum: Some(SerialChecksumFields {
                    algorithm: "sum8".into(),
                    start_byte: -1,
                    byte_length: 1,
                    calc_start_byte: 0,
                    calc_end_byte: None,
                    big_endian,
                }),
                ..Default::default()
            },
        }])
    };
    assert!(!written(false).contains("big_endian"));
    assert!(written(true).contains("big_endian = true"));
}

#[test]
fn config_byte_order_replaces_its_legacy_key() {
    let legacy =
        "[meta.can]\ndefault_endianness = \"big\"\n\n[meta.modbus]\nbyte_order = \"big\"\n";
    let text = apply_edits(
        legacy,
        &[
            EditOp::SetCanConfig {
                config: CanConfigFields {
                    default_byte_order: Some(Endianness::Little),
                    ..Default::default()
                },
            },
            EditOp::SetModbusConfig {
                config: ModbusConfigFields {
                    default_byte_order: Some(Endianness::Little),
                    ..Default::default()
                },
            },
        ],
    )
    .unwrap();
    assert_eq!(
        text,
        "[meta.can]\ndefault_byte_order = \"little\"\n\n[meta.modbus]\ndefault_byte_order = \"little\"\n"
    );
}

#[test]
fn can_config_byte_order_at_decode_default_is_written_only_where_the_file_states_one() {
    let little = || EditOp::SetCanConfig {
        config: CanConfigFields {
            default_byte_order: Some(Endianness::Little),
            default_interval: Some(100),
            ..Default::default()
        },
    };
    assert_eq!(build(&[little()]), "[meta.can]\ndefault_interval = 100\n");
    let stated = edit("[meta.can]\ndefault_byte_order = \"big\"\n", little());
    assert!(
        stated.contains("default_byte_order = \"little\""),
        "{stated}"
    );
}

#[test]
fn an_unparseable_mask_refuses_the_op() {
    let op = |mask: &str| EditOp::SetSerialConfig {
        config: SerialConfigFields {
            frame_id_mask: Some(Mask::Text(mask.into())),
            ..Default::default()
        },
    };
    assert_eq!(
        apply_edit("", op("0xZZ")),
        Err("mask '0xZZ' is not hexadecimal".to_string())
    );
    assert!(!build(&[op(" ")]).contains("frame_id_mask"));
}

#[test]
fn a_serial_checksum_is_snake_case_and_keeps_an_absent_calc_end_byte_absent() {
    let ops: Vec<EditOp> = serde_json::from_value(json!([
        { "op": "SetSerialConfig", "config": { "checksum": { "algorithm": "sum8", "start_byte": -1 } } },
        { "op": "SetSerialConfig", "config": { "checksum": { "algorithm": "sum8", "startByte": -2 } } },
    ]))
    .unwrap();
    let text = build(&ops[..1]);
    assert!(!text.contains("calc_end_byte"), "{text}");
    assert!(build(&ops).contains("start_byte = -2"));
}

// ── frames ────────────────────────────────────────────────────────────────────

const COPIED: &str = r#"[meta]
name = "d"
version = 1

[meta.can]
default_extended = false
default_interval = 100

[frame.can.0x100]
length = 4
transmitter = "BMS"

[[frame.can.0x100.signals]]
name = "temp"
start_bit = 0
bit_length = 16

[frame.can.0x100.mux]
name = "m"
start_bit = 16
bit_length = 8
"#;

#[test]
fn a_frame_does_not_write_what_its_source_or_the_defaults_give() {
    let resolved = FrameFields {
        length: Some(4),
        transmitter: Some("BMS".into()),
        interval_ms: Some(100),
        extended: Some(false),
        fd: Some(false),
        mirror_of: Some("0x100".into()),
        ..Default::default()
    };
    let text = edit(COPIED, frame(Protocol::Can, "0x200", resolved.clone()));
    let mirror = text.split_once("[frame.can.0x200]").unwrap().1;
    assert_eq!(mirror.trim(), r#"mirror_of = "0x100""#);

    let overridden = FrameFields {
        transmitter: Some("VCU".into()),
        interval_ms: Some(50),
        extended: Some(true),
        ..resolved
    };
    let text = edit(COPIED, frame(Protocol::Can, "0x200", overridden));
    let f = assert_clean(&text).frames[1].clone();
    assert_eq!(
        (
            f.transmitter.as_deref(),
            f.interval,
            f.is_extended,
            f.length
        ),
        (Some("VCU"), Some(50), Some(true), 4)
    );
}

#[test]
fn a_frame_key_is_trimmed_and_a_blank_one_refused() {
    let text = build(&[can_frame(" 0x100 ", 8)]);
    assert!(text.contains("[frame.can.0x100]"), "{text}");
    assert_eq!(
        apply_edit("", can_frame(" ", 8)),
        Err("a frame key is required".to_string())
    );
}

#[test]
fn add_frame_refuses_an_existing_key_and_seeds_only_modbus() {
    let add = |protocol, key: &str| EditOp::AddFrame {
        protocol,
        key: key.into(),
        frame: FrameFields::default(),
    };
    assert_eq!(
        apply_edit(ONE_SIGNAL, add(Protocol::Can, "0x100")),
        Err("frame '0x100' already exists".to_string())
    );
    assert!(!build(&[add(Protocol::Can, "0x200")]).contains("signals"));
    let text = build(&[add(Protocol::Modbus, "level")]);
    assert!(
        text.contains("name = \"level\"\nstart_bit = 0\nbit_length = 16"),
        "{text}"
    );
}

// ── muxes ─────────────────────────────────────────────────────────────────────

#[test]
fn a_mux_needs_its_frame_and_parent_mux_but_not_its_case() {
    let on = |owner: &[&str]| apply_edit(ONE_SIGNAL, mux(owner, "", 0, 8));
    assert_eq!(
        on(&["frame", "serial", "0x100"]),
        Err("'frame.serial.0x100' does not exist".to_string())
    );
    assert_eq!(
        on(&["frame", "can", "0x100", "mux", "1"]),
        Err("'frame.can.0x100.mux' does not exist".to_string())
    );
    let text = apply_edits(
        ONE_SIGNAL,
        &[
            mux(&["frame", "can", "0x100"], "", 16, 8),
            mux(&["frame", "can", "0x100", "mux", "1, 2"], "", 24, 0),
        ],
    )
    .unwrap();
    assert!(text.contains("name = \"mux_256_16_8\""), "{text}");
    assert!(
        text.contains("name = \"mux_256_1_2_24_0\"\nstart_bit = 24\nbit_length = 0"),
        "{text}"
    );
}

// ── updates ───────────────────────────────────────────────────────────────────

#[test]
fn updating_a_signal_writes_its_display_and_keeps_keys_it_does_not_model() {
    let authored = ONE_SIGNAL.replace(
        "bit_length = 16\n",
        "bit_length = 16\nword_order = \"little\"\nvendor_tag = 7\ndisplay = { widget = \"gauge\", max = 100 }\n",
    );
    let hint = DisplayHint {
        widget: "gauge".into(),
        options: BTreeMap::from([("max".to_string(), json!(100))]),
    };
    let text = edit(
        &authored,
        update(
            &["frame", "can", "0x100"],
            0,
            SignalFields {
                unit: Some("°C".into()),
                display: Some(hint.clone()),
                ..sig("temp", 0, 16)
            },
        ),
    );

    assert!(text.contains(r#"word_order = "little""#), "{text}");
    assert!(text.contains("vendor_tag = 7"), "{text}");
    let signal = &assert_clean(&text).frames[0].signals[0];
    assert_eq!(signal.display, Some(hint));
    assert_eq!(signal.unit.as_deref(), Some("°C"));
}

#[test]
fn a_modelled_key_left_unset_is_removed() {
    let authored = ONE_SIGNAL.replace("bit_length = 16\n", "bit_length = 16\nunit = \"V\"\n");
    let text = edit(
        &authored,
        update(&["frame", "can", "0x100"], 0, sig("temp", 0, 16)),
    );
    assert!(!text.contains("unit"), "{text}");
}

#[test]
fn an_unchanged_value_keeps_its_comment_and_a_changed_one_its_trailing_comment() {
    let authored = ONE_SIGNAL
        .replace("name = \"temp\"\n", "name = \"temp\"  # the coolant\n")
        .replace("bit_length = 16\n", "bit_length = 16  # two bytes\n");
    let text = edit(
        &authored,
        update(&["frame", "can", "0x100"], 0, sig("temp", 0, 12)),
    );
    assert!(text.contains("name = \"temp\"  # the coolant\n"), "{text}");
    assert!(text.contains("bit_length = 12  # two bytes\n"), "{text}");
}

#[test]
fn enum_labels_are_replaced_in_numeric_order() {
    let authored = format!(
        "{ONE_SIGNAL}\n[frame.can.0x100.signals.enum]\n0 = \"off\"  # idle\n1 = \"on\"\n5 = \"fault\"\n"
    );
    let signal = SignalFields {
        enum_map: BTreeMap::from([
            ("10".to_string(), "boost".to_string()),
            ("0".to_string(), "off".to_string()),
            ("2".to_string(), "standby".to_string()),
        ]),
        ..sig("temp", 0, 16)
    };
    let text = edit(&authored, update(&["frame", "can", "0x100"], 0, signal));
    assert!(
        text.contains("0 = \"off\"  # idle\n2 = \"standby\"\n10 = \"boost\"\n"),
        "{text}"
    );
    let labels = &assert_clean(&text).frames[0].signals[0].enum_map;
    assert_eq!(labels.as_ref().unwrap().len(), 3);
}

#[test]
fn a_signal_is_inserted_in_start_bit_order() {
    let text = apply_edits(
        ONE_SIGNAL,
        &[
            put(&["frame", "can", "0x100"], sig("late", 32, 8)),
            put(&["frame", "can", "0x100"], sig("early", 16, 8)),
        ],
    )
    .unwrap();
    let names: Vec<_> = assert_clean(&text).frames[0]
        .signals
        .iter()
        .map(|s| s.name.clone().unwrap())
        .collect();
    assert_eq!(names, ["temp", "early", "late"]);
}

#[test]
fn an_inline_signal_array_is_updated_in_place() {
    let authored = "[frame.can.0x100]\nsignals = [{ name = \"a\", start_bit = 0, bit_length = 8, vendor_tag = 1 }]\n";
    let text = edit(
        authored,
        update(&["frame", "can", "0x100"], 0, sig("a", 0, 4)),
    );
    assert_eq!(
        text,
        "[frame.can.0x100]\nsignals = [{ name = \"a\", start_bit = 0, bit_length = 4, vendor_tag = 1 }]\n"
    );
}

#[test]
fn set_mux_keeps_its_cases() {
    let authored = "[frame.can.0x100.mux]\nname = \"m\"\nstart_bit = 0\nbit_length = 8\n\n[frame.can.0x100.mux.1]\nnotes = \"one\"\n";
    let text = edit(authored, mux(&["frame", "can", "0x100"], "m", 8, 8));
    assert!(text.contains("start_bit = 8"), "{text}");
    assert!(
        text.contains("[frame.can.0x100.mux.1]\nnotes = \"one\""),
        "{text}"
    );
}

#[test]
fn set_frame_renames_and_keeps_its_signals() {
    let text = edit(
        ONE_SIGNAL,
        EditOp::SetFrame {
            protocol: Protocol::Can,
            key: "0x080".into(),
            rename_from: Some("0x100".into()),
            frame: FrameFields {
                length: Some(4),
                ..Default::default()
            },
        },
    );
    let f = &assert_clean(&text).frames[0];
    assert_eq!((f.frame_id, f.length, f.signals.len()), (0x80, 4, 1));
}

// ── the WS shape ──────────────────────────────────────────────────────────────

#[test]
fn typed_ops_deserialise_from_ws_params() {
    let ops: Vec<EditOp> = serde_json::from_value(json!([
        { "op": "SetFrame", "protocol": "can", "key": "0x100", "frame": { "length": 8 } },
        {
            "op": "UpsertSignal",
            "owner_path": ["frame", "can", "0x100"],
            "signal": {
                "name": "state", "start_bit": 0, "bit_length": 8, "factor": 1,
                "endianness": "little", "confidence": "low",
                "enum": { "0": "off", "1": "on" },
                "display": { "widget": "level-bar", "orientation": "vertical" }
            }
        },
        { "op": "SetMeta", "meta": { "name": "d", "version": 2 } }
    ]))
    .expect("typed ops deserialise");
    let text = apply_edits("", &ops).unwrap();

    let cat = Catalog::parse(&text).unwrap();
    let signal = &cat.frames[0].signals[0];
    assert_eq!(signal.endianness, Some(Endianness::Little));
    assert_eq!(signal.confidence, Some(Confidence::Low));
    assert_eq!(signal.enum_map.as_ref().unwrap()[&1], "on");
    assert_eq!(signal.display.as_ref().unwrap().widget, "level-bar");
    assert_eq!(cat.meta.version, 2);
}

// ── batches ───────────────────────────────────────────────────────────────────

#[test]
fn a_batch_matches_its_ops_applied_one_at_a_time() {
    let ops = || {
        [
            meta("d", Protocol::Can),
            can_frame("0x100", 8),
            put(&["frame", "can", "0x100"], sig("a", 0, 8)),
        ]
    };
    let one_at_a_time = ops().into_iter().fold(String::new(), |t, op| edit(&t, op));
    assert_eq!(apply_edits("", &ops()).unwrap(), one_at_a_time);
}

#[test]
fn a_batch_is_all_or_nothing() {
    let result = apply_edits(
        ONE_SIGNAL,
        &[
            can_frame("0x200", 8),
            EditOp::RenameKey {
                parent_path: path(&["node"]),
                old: "missing".into(),
                new: "other".into(),
                set_value: None,
                managed_keys: vec![],
                sort_numeric: false,
                update_transmitter_refs: false,
                error_if_exists: false,
            },
        ],
    );
    assert_eq!(result, Err("'missing' not found".to_string()));
}

// ── line endings ──────────────────────────────────────────────────────────────

const CRLF_CATALOGUE: &str = "# header\r\n[meta]\r\nname = \"old\"\r\nversion = 1\r\n\r\n[frame.can.0x100]\r\nlength = 8\r\nnotes = \"\"\"\r\nfirst\r\nsecond\r\n\"\"\"\r\n";

#[test]
fn a_typed_edit_keeps_a_crlf_file_crlf() {
    let out = edit(CRLF_CATALOGUE, meta("new", Protocol::Can));
    assert!(out.contains("name = \"new\""), "{out:?}");
    assert!(!out.replace("\r\n", "").contains('\n'), "bare LF: {out:?}");
    assert!(!out.contains("\r\r"), "doubled CR: {out:?}");
}

#[test]
fn a_typed_edit_keeps_an_lf_file_lf() {
    let out = edit(
        &CRLF_CATALOGUE.replace("\r\n", "\n"),
        meta("new", Protocol::Can),
    );
    assert!(!out.contains('\r'), "{out:?}");
    assert!(!build(&[meta("new", Protocol::Can)]).contains('\r'));
}
