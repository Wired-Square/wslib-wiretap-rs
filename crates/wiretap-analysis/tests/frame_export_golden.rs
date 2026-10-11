//! Discovery's catalogue export against the desktop's TypeScript
//! `frameExport.ts`, every case of `fixtures/desktop/frame_export_golden.json`.
//! The golden's ops are what the desktop hands `apply_edits`, so they are read
//! as [`EditOp`]s and compared with ours. The cases D7 overrides, and the one a
//! `u32` start byte cannot carry, are listed below with their new answers.

use std::path::PathBuf;

use serde_json::{json, Map, Value};
use wiretap_analysis::draft::{
    frames_ops, head_ops, modbus_ops, ByteSpan, ExportFinding, ExportFrame, ExportMeta,
    ModbusExportConfig, ModbusRegister,
};
use wiretap_catalog::edit::EditOp;
use wiretap_catalog::model::{Protocol, SerialConfig};

/// A field's name, start byte and bytes.
type Unwritten = &'static [(&'static str, u32, u32)];

/// D7: a header field ending past byte 4 is not written, and comes back as a
/// finding. Each serial config here is a `headOps` case under both metas.
const OUT_OF_RANGE: &[(&str, Unwritten)] = &[
    (
        "id 2/2 big, source 4/2 little, crc16 at -2 big",
        &[("source_address", 4, 2)],
    ),
    (
        "id 3/3, source 6/1",
        &[("id", 3, 3), ("source_address", 6, 1)],
    ),
    ("id 4/4 (mask past 2^53)", &[("id", 4, 4)]),
    ("id 0/7 (mask past 2^53)", &[("id", 0, 7)]),
    ("id 0/8 (mask past 2^53)", &[("id", 0, 8)]),
    ("id 6/2", &[("id", 6, 2)]),
];

/// `SerialConfig`'s id start is a `u32`, so the TypeScript's `-2` cannot cross
/// and no span is reserved for it.
const NEGATIVE_START_SPANS: &str = "serialReservedSpans negative id start is no field";

fn cases() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop/frame_export_golden.json");
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden["cases"].as_array().unwrap().clone()
}

fn from<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap()
}

fn camel(key: &str) -> String {
    let mut words = key.split('_');
    let first = words.next().unwrap().to_string();
    words.fold(first, |mut out, w| {
        out.push_str(&w[..1].to_uppercase());
        out.push_str(&w[1..]);
        out
    })
}

/// The TypeScript `SerialFrameConfig` as the lib's `SerialConfig`, a negative
/// start byte dropped.
fn serial_config(ts: &Value) -> SerialConfig {
    fn walk(v: &Value) -> Value {
        let Some(object) = v.as_object() else {
            return v.clone();
        };
        let fields: Map<String, Value> = object
            .iter()
            .filter(|(k, v)| !(k.ends_with("_start_byte") && v.as_i64().is_some_and(|n| n < 0)))
            .map(|(k, v)| match k.as_str() {
                "default_byte_order" => ("byteOrder".into(), v.clone()),
                _ => (camel(k), walk(v)),
            })
            .collect();
        Value::Object(fields)
    }
    from(&walk(ts))
}

fn ops_text(ops: &[EditOp]) -> String {
    format!("{ops:#?}")
}

fn golden_ops(expected: &Value) -> String {
    ops_text(&from::<Vec<EditOp>>(expected))
}

/// The fields a `headOps serial` case leaves out, by the config its name ends with.
fn out_of_range(name: &str) -> Option<Unwritten> {
    let config = name.strip_prefix("headOps serial ")?;
    OUT_OF_RANGE
        .iter()
        .find(|(c, _)| config.ends_with(&format!(" {c}")))
        .map(|(_, fields)| *fields)
}

fn check_head(name: &str, input: &Value, expected: &Value) {
    let protocol: Protocol = from(&input["protocol"]);
    let serial = input
        .get("serialConfig")
        .map(serial_config)
        .unwrap_or_default();
    let (ops, findings) = head_ops(protocol, &from(&input["meta"]), &serial);
    let mut expected = expected.clone();
    let mut wanted = Vec::new();
    if let Some(fields) = out_of_range(name) {
        let written = expected[1]["config"]["fields"].as_object_mut().unwrap();
        for &(field, start_byte, bytes) in fields {
            assert!(
                written.remove(field).is_some(),
                "{name}: golden has no {field}"
            );
            wanted.push(ExportFinding::HeaderFieldOutOfRange {
                field: field.into(),
                start_byte,
                bytes,
            });
        }
    }
    assert_eq!(findings, wanted, "{name}");
    assert_eq!(ops_text(&ops), golden_ops(&expected), "{name}");
}

fn check_frames(name: &str, input: &Value, expected: &Value) {
    let frames: Vec<ExportFrame> = from(&input["frames"]);
    let decimal_ids = input["formatId"].as_str().unwrap().contains("\"decimal\"");
    match frames_ops(&frames, &from(&input["meta"]), decimal_ids) {
        Ok((ops, findings)) => {
            assert!(findings.is_empty(), "{name}");
            assert_eq!(ops_text(&ops), golden_ops(expected), "{name}");
        }
        Err(e) => assert_eq!(
            json!({ "error": format!("Error: {e}") }),
            *expected,
            "{name}"
        ),
    }
}

fn check_modbus(name: &str, input: &Value, expected: &Value) {
    let registers: Vec<ModbusRegister> = from(&input["registers"]);
    let meta: ExportMeta = from(&input["meta"]);
    let config: ModbusExportConfig = from(&input["config"]);
    let ops = modbus_ops(&registers, &meta, &config);
    assert_eq!(ops_text(&ops), golden_ops(expected), "{name}");
}

fn check_spans(name: &str, input: &Value, expected: &Value) {
    let got = serde_json::to_value(ByteSpan::serial(&serial_config(input))).unwrap();
    if name == NEGATIVE_START_SPANS {
        assert_eq!(*expected, json!([{ "start": -2, "len": 2 }]), "{name}");
        assert_eq!(got, json!([]), "{name}");
    } else {
        assert_eq!(got, *expected, "{name}");
    }
}

#[test]
fn every_case_matches_the_golden_but_the_listed_overrides() {
    let cases = cases();
    assert_eq!(cases.len(), 65);
    let mut overridden = 0;
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let (input, expected) = (&case["input"], &case["expected"]);
        match name.split(' ').next().unwrap() {
            "headOps" => {
                overridden += usize::from(out_of_range(name).is_some());
                check_head(name, input, expected);
            }
            "framesCatalogOps" => check_frames(name, input, expected),
            "modbusCatalogOps" => check_modbus(name, input, expected),
            "serialReservedSpans" => check_spans(name, input, expected),
            other => panic!("{name}: no function {other}"),
        }
    }
    assert_eq!(overridden, 2 * OUT_OF_RANGE.len());
}
