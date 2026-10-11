//! Modbus register readings against the desktop's TypeScript `modbusValues.ts`,
//! every case of `fixtures/modbus_values_golden.json`. The golden writes an f32
//! as its exact number, or as `"NaN"`, `"Infinity"`, `"-Infinity"` or `"-0"`;
//! NaN payloads don't survive it, so a NaN matches any NaN.

use std::path::PathBuf;

use serde_json::Value;
use wiretap_decode::register::{interpret_pair, interpret_register};
use wiretap_decode::Endianness;

fn cases() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/modbus_values_golden.json");
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden["cases"].as_array().unwrap().clone()
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::from_value(v.clone()).unwrap()
}

fn f32_matches(got: f32, expected: &Value) -> bool {
    match expected.as_str() {
        Some("NaN") => got.is_nan(),
        Some("Infinity") => got == f32::INFINITY,
        Some("-Infinity") => got == f32::NEG_INFINITY,
        Some("-0") => got.to_bits() == (-0.0f32).to_bits(),
        Some(other) => panic!("no f32 spelt {other}"),
        None => got.to_bits() == (expected.as_f64().unwrap() as f32).to_bits(),
    }
}

#[test]
fn every_case_matches_the_golden() {
    let cases = cases();
    assert_eq!(cases.len(), 60);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let (input, expected) = (&case["input"], &case["expected"]);
        if name.starts_with("interpretRegister") {
            let got = serde_json::to_value(interpret_register(&bytes(input))).unwrap();
            assert_eq!(&got, expected, "{name}");
            continue;
        }
        let order = match input.get("order") {
            Some(order) => serde_json::from_value(order.clone()).unwrap(),
            None => Endianness::Big,
        };
        let got = interpret_pair(&bytes(&input["first"]), &bytes(&input["second"]), order);
        assert_eq!(Some(u64::from(got.u32)), expected["u32"].as_u64(), "{name}");
        assert_eq!(Some(i64::from(got.s32)), expected["s32"].as_i64(), "{name}");
        assert!(
            f32_matches(got.f32, &expected["f32"]),
            "{name}: {} against {}",
            got.f32,
            expected["f32"]
        );
    }
}
