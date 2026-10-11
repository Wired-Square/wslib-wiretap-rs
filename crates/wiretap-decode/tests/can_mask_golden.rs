//! CAN mask ranges against the desktop's TypeScript `canMask.ts`, every case of
//! `fixtures/can_mask_golden.json`. Its widths are 11 and 29, so no count reaches
//! the `u64::MAX` saturation, and none is overridden.

use std::path::PathBuf;

use serde_json::{json, Value};
use wiretap_decode::frame_id::{matched_id_count, matched_range};

fn cases() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/can_mask_golden.json");
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden["cases"].as_array().unwrap().clone()
}

fn u32_of(v: &Value) -> u32 {
    v.as_u64().unwrap().try_into().unwrap()
}

#[test]
fn every_case_matches_the_golden() {
    let cases = cases();
    assert_eq!(cases.len(), 133);
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let got = match name.split(' ').next().unwrap() {
            "matchedIdCount" => json!(matched_id_count(
                u32_of(&input["mask"]),
                u32_of(&input["bitWidth"])
            )),
            "matchedRange" => serde_json::to_value(matched_range(
                u32_of(&input["id"]),
                u32_of(&input["mask"]),
                u32_of(&input["bitWidth"]),
            ))
            .unwrap(),
            // TS `value >>> 0`, then the set bits: `u32::count_ones`.
            "popcount" => json!((input.as_i64().unwrap() as u32).count_ones()),
            other => panic!("{name}: no function {other}"),
        };
        assert_eq!(got, case["expected"], "{name}");
    }
}
