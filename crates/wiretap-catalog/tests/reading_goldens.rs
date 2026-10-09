//! Reading a catalogue against the desktop's adapter and walker goldens in
//! `fixtures/desktop/`: `tree.*`, `resolved.*`, `treeConfigs.json`,
//! `walkers.json` and `bitPreviewRanges.json`. Those are TypeScript shapes, so
//! each test maps what the lib provides onto the fields it can answer and skips
//! what is presentation (display keys, node types, snake-case form objects).
//! Every field where the lib differs is pinned below with the TypeScript value,
//! the lib's value and the reason, by the plan's decision (D#) or the facts
//! note's item (facts #).

use std::path::PathBuf;

use serde_json::{json, Map, Value};
use wiretap_catalog::{
    compare_mux_case_keys, frame_layout, parse::parse_id, Catalog, EffectiveDefaults, Frame,
    FrameLayout, Protocol, RangeKind,
};

fn read(name: &str) -> String {
    let name = name.trim_start_matches("catalog/");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn fixture(name: &str) -> Value {
    serde_json::from_str(&read(name)).unwrap()
}

fn cases(name: &str) -> Vec<Value> {
    fixture(name)["cases"].as_array().unwrap().clone()
}

fn catalogue(toml: &str) -> Catalog {
    Catalog::parse(&read(toml)).unwrap()
}

fn protocol(name: &str) -> Protocol {
    serde_json::from_value(json!(name)).unwrap()
}

/// One field where the lib and the TypeScript differ.
type Found = (String, String, Value, Value);

/// (case, field, TypeScript value, the lib's value, why).
type Pinned = (&'static str, &'static str, Value, Value, &'static str);

#[derive(Default)]
struct Differences(Vec<Found>);

impl Differences {
    fn compare(&mut self, case: &str, field: impl Into<String>, ts: &Value, lib: Value) {
        if *ts != lib {
            self.0
                .push((case.to_string(), field.into(), ts.clone(), lib));
        }
    }

    fn assert_pinned(self, pinned: Vec<Pinned>) {
        let pinned: Vec<Found> = pinned
            .into_iter()
            .map(|(case, field, ts, lib, _)| (case.into(), field.into(), ts, lib))
            .collect();
        let unpinned: Vec<&Found> = self.0.iter().filter(|d| !pinned.contains(d)).collect();
        let stale: Vec<&Found> = pinned.iter().filter(|p| !self.0.contains(p)).collect();
        assert!(
            unpinned.is_empty() && stale.is_empty(),
            "unpinned differences: {unpinned:#?}\npinned but not found: {stale:#?}"
        );
    }
}

// ---------- the served model ----------

/// The model the desktop is served, with this release's additions taken out,
/// is the one its adapters' goldens were built from: everything here is
/// additive (D2).
#[test]
fn the_served_models_change_only_by_addition() {
    for name in ["sbrxxx", "modbus", "serial"] {
        let catalog = catalogue(&format!("{name}.toml"));
        let mut served = serde_json::to_value(&catalog).unwrap();
        let defaults = served.as_object_mut().unwrap().remove("effectiveDefaults");
        assert_eq!(
            defaults,
            Some(serde_json::to_value(catalog.derived_defaults()).unwrap())
        );

        let mut added = Vec::new();
        let frames = served["frames"].as_array_mut().unwrap();
        frames.retain(|f| {
            let by_name = f["frameId"] == json!(wiretap_catalog::NAME_KEYED_FRAME_ID);
            if by_name {
                added.push(format!("frame {}", f["key"].as_str().unwrap()));
            }
            !by_name
        });
        for frame in frames.iter_mut() {
            let frame = frame.as_object_mut().unwrap();
            let key = frame["key"].as_str().unwrap().to_string();
            let Some(Value::Array(fields)) = frame.get_mut("inheritedFields") else {
                continue;
            };
            fields.retain(|f| match f.as_str().unwrap() {
                "signals" => {
                    added.push("inherits signals".into());
                    false
                }
                "mux" => {
                    added.push(format!("{key} inherits mux"));
                    false
                }
                _ => true,
            });
            if fields.is_empty() {
                frame.remove("inheritedFields");
            }
        }
        added.sort();
        added.dedup();

        assert_eq!(served, fixture(&format!("{name}.catalog.json")), "{name}");
        let expected: &[&str] = match name {
            "sbrxxx" => &[
                "0x008 inherits mux",
                "0x00a inherits mux",
                "inherits signals",
            ],
            "serial" => &["frame heartbeat"],
            _ => &[],
        };
        assert_eq!(added, expected, "{name}");
    }
}

/// D4: a mirror's inherited signals and mux are named in `inheritedFields`.
#[test]
fn a_mirror_names_what_it_inherits() {
    let toml = r#"
[meta]
name = "m"
[frame.can.0x100]
[frame.can.0x100.mux]
start_bit = 0
bit_length = 8
[[frame.can.0x100.mux."1".signals]]
name = "a"
start_bit = 8
bit_length = 8
[[frame.can.0x100.signals]]
name = "b"
start_bit = 56
bit_length = 8
[frame.can.0x101]
mirror_of = "0x100"
[frame.can.0x102]
mirror_of = "0x100"
[frame.can.0x102.mux]
start_bit = 0
bit_length = 4
[[frame.can.0x102.signals]]
name = "own"
start_bit = 56
bit_length = 8
"#;
    let catalog = Catalog::parse(toml).unwrap();
    let inherited = |key: &str| {
        catalog
            .frame_by_key(Protocol::Can, key)
            .unwrap()
            .inherited_fields
            .clone()
    };
    assert!(inherited("0x101").contains(&"signals".into()));
    assert!(inherited("0x101").contains(&"mux".into()));
    assert!(!inherited("0x102").contains(&"signals".into()));
    assert!(!inherited("0x102").contains(&"mux".into()));
    assert!(!inherited("0x100")
        .iter()
        .any(|f| f == "signals" || f == "mux"));
}

/// D1, D3: a frame is found by protocol and key, and a serial frame keyed by a
/// name is in the model but has no numeric id to be found by.
#[test]
fn frames_are_found_by_protocol_and_key() {
    let serial = catalogue("serial.toml");
    let heartbeat = serial.frame_by_key(Protocol::Serial, "heartbeat").unwrap();
    assert!(heartbeat.is_keyed_by_name());
    assert_eq!(heartbeat.name.as_deref(), Some("heartbeat"));
    assert_eq!(heartbeat.length, 4);
    assert_eq!(heartbeat.notes, ["Keyed by a name, not an id"]);
    assert!(serial.frame(wiretap_catalog::NAME_KEYED_FRAME_ID).is_none());
    assert_eq!(serial.frame(0x10).unwrap().key, "0x10");
    assert!(serial.frame_by_key(Protocol::Can, "0x10").is_none());

    let sbrxxx = catalogue("sbrxxx.toml");
    let tunnels = ["tunnel_4de2_input", "tunnel_4de2_holding"]
        .map(|key| sbrxxx.frame_by_key(Protocol::Modbus, key).unwrap().frame_id);
    assert_eq!(tunnels, [0x4DE2, 0x4DE2]);
}

/// D5: decode's defaults are in the model, and an unset serial calculation end
/// stays unset.
#[test]
fn the_effective_defaults_are_decodes() {
    let bare =
        Catalog::parse("[meta]\nname = \"d\"\n[meta.can]\ndefault_extended = true\n").unwrap();
    assert_eq!(bare.effective_defaults, EffectiveDefaults::default());
    let json = serde_json::to_value(bare.effective_defaults).unwrap();
    assert_eq!(
        json,
        json!({
            "canByteOrder": "little",
            "serialByteOrder": "little",
            "modbusByteOrder": "big",
            "modbusWordOrder": "big",
            "modbusRegisterBase": 0,
        })
    );
    let modbus = catalogue("modbus.toml").effective_defaults;
    assert_eq!(
        serde_json::to_value(modbus).unwrap()["modbusWordOrder"],
        "little"
    );
    assert_eq!(modbus.modbus_register_base, 1);
}

// ---------- the tree ----------

fn nodes<'a>(node: &'a Value, out: &mut Vec<&'a Value>) {
    out.push(node);
    for child in node["children"].as_array().into_iter().flatten() {
        nodes(child, out);
    }
}

fn opt<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

/// The frame node fields the lib answers, under the tree's names. Skipped as
/// presentation: `frameType`, `isId`, `idValue`, `isCopy`, `isMirror`,
/// `nodeAddress`, `signals` (the form objects) and `muxSignalCount`.
fn frame_metadata(catalog: &Catalog, f: &Frame) -> Map<String, Value> {
    let inherited = |field: &str| json!(f.inherited_fields.iter().any(|i| i == field));
    let mut m = Map::new();
    m.insert("length".into(), json!(f.length));
    m.insert("lengthInherited".into(), inherited("length"));
    m.insert("transmitter".into(), opt(&f.transmitter));
    m.insert("transmitterInherited".into(), inherited("transmitter"));
    m.insert("interval".into(), opt(f.interval));
    m.insert("intervalInherited".into(), inherited("interval"));
    m.insert(
        "notes".into(),
        if f.notes.is_empty() {
            Value::Null
        } else {
            opt(&f.notes)
        },
    );
    m.insert("hasMux".into(), json!(f.mux.is_some()));
    match f.protocol {
        Protocol::Can => {
            m.insert("copyFrom".into(), opt(&f.copy_from));
            m.insert("mirrorOf".into(), opt(&f.mirror_of));
            m.insert("extended".into(), opt(f.is_extended));
            m.insert("extendedInherited".into(), inherited("extended"));
            m.insert("fd".into(), opt(f.is_fd));
            m.insert("fdInherited".into(), inherited("fd"));
            m.insert("bus".into(), opt(f.bus));
        }
        Protocol::Modbus => {
            m.insert("registerNumber".into(), json!(f.frame_id));
            m.insert("node".into(), opt(&f.modbus_node));
            m.insert("deviceAddress".into(), opt(f.modbus_device_address));
            m.insert("deviceAddressInherited".into(), inherited("deviceAddress"));
            m.insert("registerType".into(), opt(f.modbus_register_type));
            m.insert(
                "registerBase".into(),
                json!(catalog.effective_defaults.modbus_register_base),
            );
            m.insert("registerBaseInherited".into(), inherited("registerBase"));
        }
        Protocol::Serial => {
            m.insert(
                "encoding".into(),
                opt(catalog.serial.as_ref().and_then(|s| s.encoding.clone())),
            );
            m.insert("frameId".into(), json!(f.key));
            m.insert("delimiter".into(), opt(&f.delimiter));
        }
    }
    m
}

fn edited(layout: &FrameLayout) -> Vec<Value> {
    layout
        .ranges
        .iter()
        .filter(|r| r.edited)
        .map(|r| json!([r.name, r.start_bit, r.bit_length, opt(r.kind)]))
        .collect()
}

/// What the lib holds at each tree node. Frames by protocol and key; each
/// signal, mux, case and checksum by its path through [`frame_layout`]; mux
/// cases in the lib's order.
#[test]
fn the_tree_goldens() {
    let mut differences = Differences::default();
    for name in ["sbrxxx", "modbus", "serial"] {
        let case = &cases(&format!("tree.{name}.json"))[0];
        let catalog = catalogue(&format!("{name}.toml"));
        let label = format!("tree.{name}");
        let mut all = Vec::new();
        for root in case["expected"]["tree"].as_array().unwrap() {
            nodes(root, &mut all);
        }

        for p in ["can", "modbus", "serial"] {
            let ts: Vec<&str> = all
                .iter()
                .filter(|n| {
                    n["path"].as_array().unwrap().len() == 3
                        && n["path"][1] == p
                        && n["path"][0] == "frame"
                })
                .map(|n| n["key"].as_str().unwrap())
                .collect();
            let lib: Vec<&str> = catalog
                .frames
                .iter()
                .filter(|f| f.protocol == protocol(p))
                .map(|f| f.key.as_str())
                .collect();
            differences.compare(&label, format!("frame keys ({p})"), &json!(ts), json!(lib));
        }

        for node in &all {
            let path: Vec<&str> = node["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            if path[0] != "frame" || path.len() < 3 {
                continue;
            }
            let (p, key, rest) = (protocol(path[1]), path[2], &path[3..]);
            let at = path.join(".");
            let meta = &node["metadata"];
            match node["type"].as_str().unwrap() {
                "can-frame" | "modbus-frame" | "serial-frame" => {
                    let frame = catalog.frame_by_key(p, key).unwrap();
                    for (field, lib) in frame_metadata(&catalog, frame) {
                        let ts = meta.get(&field).cloned().unwrap_or(Value::Null);
                        differences.compare(&label, format!("{at} {field}"), &ts, lib);
                    }
                }
                "signal" => {
                    let layout = frame_layout(&catalog, p, key, rest).unwrap();
                    let ts = json!([[
                        meta["properties"]["name"],
                        meta["signalStartBit"],
                        meta["signalBitLength"],
                        "signal"
                    ]]);
                    differences.compare(&label, at, &ts, json!(edited(&layout)));
                }
                "checksum" => {
                    let layout = frame_layout(&catalog, p, key, rest).unwrap();
                    let start = meta["checksumStartByte"].as_i64().unwrap();
                    let start = if start < 0 {
                        layout.byte_length as i64 + start
                    } else {
                        start
                    };
                    let ts = json!([[
                        node["key"],
                        start * 8,
                        meta["checksumByteLength"].as_u64().unwrap() * 8,
                        "checksum"
                    ]]);
                    differences.compare(&label, at, &ts, json!(edited(&layout)));
                }
                "mux" => {
                    let layout = frame_layout(&catalog, p, key, rest).unwrap();
                    let ts = json!([[
                        meta["muxName"],
                        meta["muxStartBit"],
                        meta["muxBitLength"],
                        "selector"
                    ]]);
                    differences.compare(&label, at.clone(), &ts, json!(edited(&layout)));

                    let ts: Vec<&str> = node["children"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|c| c["metadata"]["caseValue"].as_str().unwrap())
                        .collect();
                    let mut lib = ts.clone();
                    lib.sort_by(|a, b| compare_mux_case_keys(a, b));
                    differences.compare(&label, format!("{at} case order"), &json!(ts), json!(lib));
                }
                "mux-case" => {
                    let layout = frame_layout(&catalog, p, key, rest).unwrap();
                    differences.compare(&label, at, &json!([]), json!(edited(&layout)));
                }
                other => panic!("{other} at {at}"),
            }
        }
    }
    let unset_base =
        "the crate reads an unset register_base as 0; effectiveDefaults.modbusRegisterBase says so";
    differences.assert_pinned(vec![
        (
            "tree.sbrxxx",
            "frame.modbus.tunnel_4de2_holding registerBase",
            Value::Null,
            json!(0),
            unset_base,
        ),
        (
            "tree.sbrxxx",
            "frame.modbus.tunnel_4de2_input registerBase",
            Value::Null,
            json!(0),
            unset_base,
        ),
        (
            "tree.serial",
            "frame keys (serial)",
            json!(["0x10", "0x20"]),
            json!(["0x10", "0x20", "heartbeat"]),
            "D3, facts 8: a serial frame keyed by a name is in the model",
        ),
    ]);
}

// ---------- the resolved catalogue ----------

/// The resolved catalogue's frames, keyed by bare id, against the lib's frames
/// with that id; and its configs against the model's. `pollGroups` is not this
/// item's (it is the poll schedule), and the frames' signal and mux details are
/// the served model's, already pinned whole above.
#[test]
fn the_resolved_goldens() {
    let mut differences = Differences::default();
    for name in ["sbrxxx", "modbus", "serial"] {
        let case = &cases(&format!("resolved.{name}.json"))[0];
        let expected = &case["expected"];
        let catalog = catalogue(&format!("{name}.toml"));
        let label = format!("resolved.{name}");

        let ts_ids: Vec<u64> = expected["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e[0].as_u64().unwrap())
            .collect();
        let mut lib_ids: Vec<u64> = catalog
            .frames
            .iter()
            .map(|f| u64::from(f.frame_id))
            .collect();
        lib_ids.sort();
        lib_ids.dedup();
        let mut ts_sorted = ts_ids.clone();
        ts_sorted.sort();
        differences.compare(&label, "frame ids", &json!(ts_sorted), json!(lib_ids));

        for entry in expected["frames"].as_array().unwrap() {
            let id = entry[0].as_u64().unwrap() as u32;
            let ts = &entry[1];
            let lib: Vec<&Frame> = catalog.frames.iter().filter(|f| f.frame_id == id).collect();
            if lib.len() > 1 {
                let keys: Vec<String> = lib
                    .iter()
                    .map(|f| format!("{}:{}", opt(f.protocol).as_str().unwrap(), f.key))
                    .collect();
                differences.compare(&label, format!("frames[{id}]"), &json!(1), json!(keys));
            }
            let f = lib.last().unwrap();
            let lib_frame = json!({
                "protocol": f.protocol, "length": f.length, "transmitter": f.transmitter,
                "interval": f.interval, "isExtended": f.is_extended, "isFd": f.is_fd,
                "mirrorOf": f.mirror_of, "copyFrom": f.copy_from,
                "signals": f.signals.iter().map(|s| json!([s.name, s.start_bit, s.bit_length, s.inherited])).collect::<Vec<_>>(),
                "cases": f.mux.as_ref().map(|m| m.cases.keys().collect::<Vec<_>>()),
            });
            let ts_frame = json!({
                "protocol": ts["protocol"], "length": ts["length"], "transmitter": ts["transmitter"],
                "interval": ts["interval"], "isExtended": ts["isExtended"], "isFd": ts["isFd"],
                "mirrorOf": ts["mirrorOf"], "copyFrom": ts["copyFrom"],
                "signals": ts["signals"].as_array().unwrap().iter()
                    .map(|s| json!([s["name"], s["start_bit"], s["bit_length"], s["_inherited"] == true]))
                    .collect::<Vec<_>>(),
                "cases": ts["mux"]["cases"].as_object().map(|c| c.keys().collect::<Vec<_>>()),
            });
            differences.compare(&label, format!("frames[{id}]"), &ts_frame, lib_frame);
        }

        let mut metadata = json!({ "name": catalog.meta.name, "version": catalog.meta.version });
        if let Some(p) = catalog.meta.default_frame {
            metadata["default_frame"] = opt(p);
        }
        differences.compare(&label, "metadata", &expected["metadata"], metadata);
        compare_configs(
            &mut differences,
            &label,
            &catalog,
            &expected["canConfig"],
            &expected["serialConfig"],
            &expected["modbusConfig"],
        );
    }
    differences.assert_pinned(vec![
        (
            "resolved.sbrxxx",
            "frames[19938]",
            json!(1),
            json!(["modbus:tunnel_4de2_holding", "modbus:tunnel_4de2_input"]),
            "D1, facts 9: two frames share 0x4DE2; the lib keeps both, found by (protocol, key)",
        ),
        (
            "resolved.serial",
            "frame ids",
            json!([16, 32]),
            json!([16, 32, 4294967295u32]),
            "D3, facts 8: heartbeat is in the model, frameId NAME_KEYED_FRAME_ID (u32::MAX); find it by (serial, \"heartbeat\")",
        ),
    ]);
}

fn snake(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn snake_keys(value: Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (snake(&k), snake_keys(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.into_iter().map(snake_keys).collect()),
        other => other,
    }
}

/// Each key the adapter copies, from the model's config. The adapter also
/// copies serial `byte_order` to `default_byte_order`, which is the model's
/// effective serial byte order.
fn compare_configs(
    differences: &mut Differences,
    label: &str,
    catalog: &Catalog,
    can: &Value,
    serial: &Value,
    modbus: &Value,
) {
    let configs = [
        ("canConfig", can, opt(&catalog.can)),
        ("serialConfig", serial, opt(&catalog.serial)),
        ("modbusConfig", modbus, opt(&catalog.modbus)),
    ];
    for (field, ts, lib) in configs {
        let lib = snake_keys(lib);
        let Some(ts) = ts.as_object() else {
            differences.compare(label, field, ts, lib);
            continue;
        };
        for (key, ts_value) in ts {
            let lib_value = if field == "serialConfig" && key == "default_byte_order" {
                opt(catalog.derived_defaults().serial_byte_order)
            } else {
                lib.get(key).cloned().unwrap_or(Value::Null)
            };
            differences.compare(label, format!("{field}.{key}"), ts_value, lib_value);
        }
    }
}

/// The configs the editor's forms are seeded with (`tree`) and the resolved
/// catalogue's (`resolved`). The input is a served model, so it is read as one.
#[test]
fn the_tree_config_goldens() {
    let mut differences = Differences::default();
    for case in cases("treeConfigs.json") {
        let label = case["name"].as_str().unwrap();
        let catalog: Catalog = serde_json::from_value(case["input"].clone()).unwrap();
        let resolved = &case["expected"]["resolved"];
        compare_configs(
            &mut differences,
            label,
            &catalog,
            &resolved["can"],
            &resolved["serial"],
            &resolved["modbus"],
        );

        let tree = &case["expected"]["tree"];
        let defaults = catalog.derived_defaults();
        if let Some(can) = tree.get("canConfig") {
            differences.compare(
                label,
                "tree.canConfig.default_endianness",
                &can["default_endianness"],
                opt(defaults.can_byte_order),
            );
            differences.compare(
                label,
                "tree.canConfig.default_extended",
                &can["default_extended"],
                opt(catalog.can.as_ref().unwrap().default_extended),
            );
        }
        if let Some(serial) = tree.get("serialConfig") {
            let checksum = catalog.serial.as_ref().unwrap().checksum.as_ref().unwrap();
            differences.compare(
                label,
                "tree.serialConfig.checksum.calc_end_byte",
                &serial["checksum"]["calc_end_byte"],
                opt(checksum.calc_end_byte),
            );
        }
        if let Some(modbus) = tree.get("modbusConfig") {
            differences.compare(
                label,
                "tree.modbusConfig.register_base",
                &modbus["register_base"],
                json!(defaults.modbus_register_base),
            );
            differences.compare(
                label,
                "tree.modbusConfig.default_interval",
                &modbus["default_interval"],
                opt(catalog.modbus.as_ref().unwrap().default_interval),
            );
        }
    }
    // Skipped: the serial form's `encoding: "raw"`, which the lib does not default.
    differences.assert_pinned(vec![
        (
            "a CAN section with no byte order",
            "tree.canConfig.default_endianness",
            json!("big"),
            json!("little"),
            "D5, facts 3: decode reads an unset CAN byte order as little; the model's effectiveDefaults.canByteOrder says so",
        ),
        (
            "a serial checksum with no calculation end and no encoding",
            "tree.serialConfig.checksum.calc_end_byte",
            json!(0),
            Value::Null,
            "D5, facts 4: an unset calculation end stays absent rather than 0",
        ),
    ]);
}

// ---------- walkers and previews ----------

/// `(protocol, key, path below the frame)`, or `None` for a path outside a frame.
fn split(path: &[&str]) -> Option<(Protocol, String, Vec<String>)> {
    match path {
        ["frame", p, key, rest @ ..] => Some((
            protocol(p),
            key.to_string(),
            rest.iter().map(|s| s.to_string()).collect(),
        )),
        _ => None,
    }
}

fn layout_at(catalog: &Catalog, path: &[&str]) -> Option<FrameLayout> {
    let (p, key, rest) = split(path)?;
    frame_layout(catalog, p, &key, &rest)
}

/// Ranges in the walkers' shape, ordered by position, the checksums left out
/// (no walker reads them; see the checksum test below).
fn ts_ranges(layout: &FrameLayout, kind: RangeKind, with_edited: bool) -> Value {
    let (ts_kind, default_name) = match kind {
        RangeKind::Selector => ("mux", "Mux"),
        _ => ("signal", "Signal"),
    };
    let mut ranges: Vec<&wiretap_catalog::LayoutRange> = layout
        .ranges
        .iter()
        .filter(|r| r.kind == kind && (with_edited || !r.edited))
        .collect();
    ranges.sort_by_key(|r| (r.start_bit, r.bit_length));
    Value::Array(
        ranges
            .into_iter()
            .map(|r| {
                json!({
                    "name": r.name.as_deref().unwrap_or(default_name),
                    "start_bit": r.start_bit,
                    "bit_length": r.bit_length,
                    "type": ts_kind,
                })
            })
            .collect(),
    )
}

fn sorted(ranges: &Value) -> Value {
    let mut ranges = ranges.as_array().unwrap().clone();
    ranges.sort_by_key(|r| (r["start_bit"].as_u64(), r["bit_length"].as_u64()));
    Value::Array(ranges)
}

fn strs(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect()
}

/// `walkers.json`: the path walkers against [`frame_layout`]. Selectors are the
/// walker's mux ranges; signals the layout's, less the edited one (the walker
/// leaves out an edited case signal). The case-key order is in `rule_tables.rs`,
/// and the editor's id formatting is presentation, so only its parse is here.
#[test]
fn the_walker_goldens() {
    let mut differences = Differences::default();
    for case in cases("walkers.json") {
        let label = case["name"].as_str().unwrap();
        let (input, expected) = (&case["input"], &case["expected"]);
        if let Some(path) = input.get("path") {
            let catalog = catalogue(input["catalogue"].as_str().unwrap());
            let layout = layout_at(&catalog, &strs(path));
            let lib =
                |f: &dyn Fn(&FrameLayout) -> Value| layout.as_ref().map(f).unwrap_or(json!([]));
            differences.compare(
                label,
                "muxRanges",
                &sorted(&expected["muxRanges"]),
                lib(&|l| ts_ranges(l, RangeKind::Selector, true)),
            );
            differences.compare(
                label,
                "signalRanges",
                &sorted(&expected["signalRanges"]),
                lib(&|l| ts_ranges(l, RangeKind::Signal, false)),
            );
            differences.compare(
                label,
                "frameByteLength",
                &expected["frameByteLength"],
                opt(layout.map(|l| l.byte_length)),
            );
        } else if label == "frame keys per protocol" {
            for (name, ts) in strs(input).into_iter().zip(expected.as_array().unwrap()) {
                let catalog = catalogue(&format!("{name}.toml"));
                let keys = |p: Protocol| -> Vec<&str> {
                    let mut keys: Vec<&str> = catalog
                        .frames
                        .iter()
                        .filter(|f| f.protocol == p)
                        .map(|f| f.key.as_str())
                        .collect();
                    keys.sort();
                    keys
                };
                let mut ts_modbus = strs(&ts["modbus"]);
                ts_modbus.sort();
                let mut ts_serial = strs(&ts["serial"]);
                ts_serial.sort();
                differences.compare(
                    label,
                    format!("{name} can"),
                    &ts["can"],
                    json!(keys(Protocol::Can).len()),
                );
                differences.compare(
                    label,
                    format!("{name} modbus"),
                    &json!(ts_modbus),
                    json!(keys(Protocol::Modbus)),
                );
                differences.compare(
                    label,
                    format!("{name} serial"),
                    &json!(ts_serial),
                    json!(keys(Protocol::Serial)),
                );
            }
        } else if label.starts_with("id parsing") {
            for (id, ts) in strs(input).into_iter().zip(expected.as_array().unwrap()) {
                differences.compare(
                    label,
                    format!("{id:?} number"),
                    &ts["number"],
                    opt(parse_id(id)),
                );
            }
        }
    }
    differences.assert_pinned(walker_deviations());
}

fn range(name: &str, start_bit: u32, bit_length: u32, kind: &str) -> Value {
    json!({ "name": name, "start_bit": start_bit, "bit_length": bit_length, "type": kind })
}

fn walker_deviations() -> Vec<Pinned> {
    let mirror_0x005 = [
        range("Info_Battery_Operation", 0, 8, "signal"),
        range("Status_Battery_End_Stop", 8, 8, "signal"),
        range("705_Always_1", 16, 8, "signal"),
        range("Info_Battery_Type", 24, 16, "signal"),
        range("Status_Battery_Voltage_Alt_705", 40, 16, "signal"),
        range("705_Padding", 56, 8, "signal"),
    ];
    let edited_frame_signal = "D6, facts 11: the edited signal is flagged, not listed with the rest; the walker drops an edited case signal but keeps an edited frame signal";
    vec![
        (
            "walk sbrxxx frame.can.0x70F",
            "muxRanges",
            json!([]),
            json!([range("mux_1807_0_8", 0, 8, "mux")]),
            "D6: a frame's own selector is on the path to the frame (CANFrameView already shows it)",
        ),
        (
            "walk sbrxxx frame.can.0x005",
            "signalRanges",
            json!([range("Status_Battery_End_Stop", 8, 8, "signal")]),
            json!(mirror_0x005),
            "D4, D6: 0x005 mirrors 0x705; the walker reads the raw TOML, which holds only the override",
        ),
        (
            "walk sbrxxx frame.can.0x005.signals.0",
            "signalRanges",
            json!([range("Status_Battery_End_Stop", 8, 8, "signal")]),
            json!(mirror_0x005[1..]),
            "D4, D6: as above, and signals.0 is the model's signal 0 (the tree's index), Info_Battery_Operation, flagged edited",
        ),
        (
            "walk sbrxxx frame.can.0x999",
            "frameByteLength",
            json!(8),
            Value::Null,
            "D6: no such frame is no layout, not 8 bytes",
        ),
        (
            "walk sbrxxx node.BMS",
            "frameByteLength",
            json!(8),
            Value::Null,
            "D6: a path outside a frame is no layout, not 8 bytes",
        ),
        (
            "walk modbus frame.modbus.5000.signals.0",
            "signalRanges",
            json!([range("Daily_Yield", 0, 32, "signal")]),
            json!([]),
            edited_frame_signal,
        ),
        (
            "walk modbus frame.modbus.100.signals.0",
            "signalRanges",
            json!([range("Relays", 0, 4, "signal")]),
            json!([]),
            edited_frame_signal,
        ),
        (
            "walk modbus frame.modbus.100.signals.0",
            "frameByteLength",
            json!(8),
            json!(1),
            "D6, facts 10: four coils are one byte; the walker doubles every Modbus length",
        ),
        (
            "walk serial frame.serial.0x10.signals.1",
            "signalRanges",
            json!([range("Voltage", 24, 16, "signal"), range("Flags", 40, 8, "signal")]),
            json!([range("Voltage", 24, 16, "signal")]),
            edited_frame_signal,
        ),
        (
            "id parsing and the editor's id formatting",
            "\"0X10\" number",
            Value::Null,
            json!(16),
            "facts 20: the crate's parse_id takes 0X as catalogParser.ts does; utils.ts parseCanIdToNumber does not",
        ),
    ]
}

/// `bitPreviewRanges.json`: the range each preview site shows against
/// [`frame_layout`] at the site's path. A site hands the edited item over
/// separately (`current…`), so the layout's edited range is compared there for
/// the views and left out for the dialogs, whose current range is the form's.
#[test]
fn the_bit_preview_goldens() {
    let mut differences = Differences::default();
    for case in cases("bitPreviewRanges.json") {
        let label = case["name"].as_str().unwrap();
        let catalog = catalogue(case["input"]["catalogue"].as_str().unwrap());
        let site = label.split(' ').next().unwrap();
        // The mux dialog's path is the owner it adds under, which the golden
        // records in the case name.
        let mut path: Vec<&str> = if site == "MuxEditDialog" {
            label.split(' ').nth(2).unwrap().split('.').collect()
        } else {
            strs(&case["input"]["path"])
        };
        let editing = label
            .rsplit(' ')
            .next()
            .filter(|i| i.parse::<usize>().is_ok());
        if let Some(i) = editing.filter(|_| !path.contains(&"signals")) {
            path.extend(["signals", i]);
        }
        let Some(layout) = layout_at(&catalog, &path) else {
            differences.compare(label, "preview", &case["expected"], Value::Null);
            continue;
        };
        let with_edited = !site.starts_with("Signal");
        let mut ranges = ts_ranges(&layout, RangeKind::Selector, with_edited)
            .as_array()
            .unwrap()
            .clone();
        ranges.extend(
            ts_ranges(&layout, RangeKind::Signal, with_edited)
                .as_array()
                .unwrap()
                .clone(),
        );
        let Some(ts) = case["expected"].as_array().unwrap().first() else {
            let lib =
                json!({ "numBytes": layout.byte_length, "ranges": sorted(&Value::Array(ranges)) });
            differences.compare(label, "preview", &case["expected"], lib);
            continue;
        };
        differences.compare(
            label,
            "numBytes",
            &ts["numBytes"],
            json!(layout.byte_length),
        );
        differences.compare(
            label,
            "ranges",
            &sorted(&ts["ranges"]),
            sorted(&Value::Array(ranges)),
        );
        if site == "SignalView" {
            let current = layout.ranges.iter().find(|r| r.edited).unwrap();
            differences.compare(
                label,
                "current",
                &json!([ts["currentStartBit"], ts["currentBitLength"]]),
                json!([current.start_bit, current.bit_length]),
            );
        }
    }
    differences.assert_pinned(preview_deviations());
}

fn preview_deviations() -> Vec<Pinned> {
    vec![
        (
            "SerialFrameView 0x20",
            "preview",
            json!([]),
            json!({ "numBytes": 16, "ranges": [range("Page", 24, 8, "mux")] }),
            "D6, facts 11: a frame with only a mux has a layout; the view shows none",
        ),
        (
            "MuxView frame.can.0x71F.mux.8.mux",
            "ranges",
            json!([range("mux_1823_0_8", 0, 8, "mux")]),
            json!([range("mux_1823_0_8", 0, 8, "mux"), range("mux_1823_8_8_8", 8, 8, "mux")]),
            "D6, facts 11: a nested mux's own selector (flagged edited) is shown with the selectors above it",
        ),
        (
            "SignalView sbrxxx frame.can.0x70F.mux.4.signals.1",
            "ranges",
            json!([range("mux_1807_0_8", 0, 8, "mux")]),
            json!([
                range("mux_1807_0_8", 0, 8, "mux"),
                range("70F_Mux4_Padding_0", 8, 8, "signal"),
                range("70F_Mux4_Padding_1", 32, 24, "signal"),
                range("Status_Charge_State", 56, 8, "signal"),
            ]),
            "D6, facts 11: a signal's view shows its siblings, as the edit dialog does",
        ),
        (
            "SignalView modbus frame.modbus.100.signals.0",
            "numBytes",
            json!(8),
            json!(1),
            "D6, facts 10: four coils are one byte",
        ),
        (
            "SignalView serial frame.serial.0x10.signals.1",
            "ranges",
            json!([]),
            json!([range("Voltage", 24, 16, "signal")]),
            "D6, facts 11: a signal's view shows its siblings",
        ),
        (
            "SignalEditDialog sbrxxx frame.can.0x70F editing null",
            "ranges",
            json!([]),
            json!([range("mux_1807_0_8", 0, 8, "mux")]),
            "D6, facts 11: adding a frame signal on a mux frame keeps the selector in view",
        ),
        (
            "MuxEditDialog sbrxxx frame.can.0x71F.mux.8",
            "ranges",
            json!([range("mux_1823_0_8", 0, 8, "mux")]),
            json!([range("mux_1823_0_8", 0, 8, "mux"), range("mux_1823_8_8_8", 8, 8, "mux")]),
            "D6, facts 11: adding under case 8 shows the case's layout, here its existing nested selector",
        ),
    ]
}

/// No walker or preview shows a checksum; the layout does (D6).
#[test]
fn the_layout_shows_checksums() {
    let serial = catalogue("serial.toml");
    let layout = frame_layout(&serial, Protocol::Serial, "0x10", &["signals", "1"]).unwrap();
    let checksums: Vec<Value> = layout
        .ranges
        .iter()
        .filter(|r| r.kind == RangeKind::Checksum)
        .map(|r| json!([r.name, r.start_bit, r.bit_length, r.edited]))
        .collect();
    assert_eq!(checksums, [json!(["Frame CRC", 80, 16, false])]);
    let layout = frame_layout(&serial, Protocol::Serial, "0x10", &["checksum", "0"]).unwrap();
    assert!(layout
        .ranges
        .iter()
        .any(|r| r.kind == RangeKind::Checksum && r.edited));
}

#[test]
fn a_path_to_nothing_has_no_layout() {
    let sbrxxx = catalogue("sbrxxx.toml");
    let at = |path: &[&str]| frame_layout(&sbrxxx, Protocol::Can, "0x71F", path);
    assert!(at(&["mux", "8", "mux"]).is_some());
    for path in [
        &["mux", "99"][..],
        &["signals", "0"],
        &["mux", "8", "checksum", "0"],
        &["mux", "8", "mux", "3", "mux"],
        &["mux", "8", "signals", "x"],
        &["notes"],
    ] {
        assert_eq!(at(path), None, "{path:?}");
    }
    assert_eq!(
        frame_layout(&sbrxxx, Protocol::Serial, "0x71F", &[] as &[&str]),
        None
    );
}

#[test]
fn a_zero_bit_length_stays_zero() {
    let toml = "[meta]\nname = \"z\"\n[[frame.can.0x100.signals]]\nname = \"empty\"\nstart_bit = 8\nbit_length = 0\n";
    let catalog = Catalog::parse(toml).unwrap();
    let layout = frame_layout(&catalog, Protocol::Can, "0x100", &["signals", "0"]).unwrap();
    assert_eq!(
        (
            layout.ranges[0].start_bit,
            layout.ranges[0].bit_length,
            layout.ranges[0].edited
        ),
        (8, 0, true)
    );
}

/// A model deserialised without `effectiveDefaults` still decodes by its configs.
#[test]
fn decode_derives_its_defaults_from_the_configs() {
    let toml = "[meta]\nname = \"d\"\n[meta.can]\ndefault_byte_order = \"big\"\n[[frame.can.0x100.signals]]\nname = \"w\"\nstart_bit = 0\nbit_length = 16\n";
    let mut served = serde_json::to_value(Catalog::parse(toml).unwrap()).unwrap();
    served.as_object_mut().unwrap().remove("effectiveDefaults");
    let catalog: Catalog = serde_json::from_value(served).unwrap();
    assert_eq!(catalog.effective_defaults, EffectiveDefaults::default());
    let decoded = wiretap_catalog::decode::decode_by_id(&catalog, 0x100, &[0x01, 0x02]).unwrap();
    assert_eq!(decoded.signals[0].value, f64::from(0x0102));
}
