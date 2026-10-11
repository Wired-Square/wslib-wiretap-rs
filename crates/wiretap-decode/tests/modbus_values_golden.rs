//! Modbus register readings against the desktop's TypeScript `modbusValues.ts`,
//! every case of `fixtures/modbus_values_golden.json`. The golden spells a
//! non-finite f32 as the pair serialises it, and writes `-0` as `"-0"`, where
//! the pair writes a number.

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
        let json = serde_json::to_value(got).unwrap();
        assert_eq!(json["u32"], expected["u32"], "{name}");
        assert_eq!(json["s32"], expected["s32"], "{name}");
        match &expected["f32"] {
            Value::String(s) if s == "-0" => {
                assert_eq!(got.f32.to_bits(), (-0.0f32).to_bits(), "{name}")
            }
            Value::String(_) => assert_eq!(json["f32"], expected["f32"], "{name}"),
            number => assert_eq!(
                got.f32.to_bits(),
                (number.as_f64().unwrap() as f32).to_bits(),
                "{name}"
            ),
        }
    }
}
