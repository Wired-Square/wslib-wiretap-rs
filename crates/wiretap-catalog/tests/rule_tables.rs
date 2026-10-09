//! The desktop's rule tables, `fixtures/desktop/muxCaseKeys.json` and
//! `checksumAlgorithms.json`, with the case-key order from `walkers.json`. The
//! lib's values are asserted, and every row where the TypeScript differs is
//! named with its reason (facts #).

use std::path::PathBuf;

use serde_json::Value;
use wiretap_catalog::{compare_mux_case_keys, is_mux_case_key, Catalog};
use wiretap_checksum::{algorithm_widths, all_algorithm_ids};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn parses_as_a_case(key: &str) -> bool {
    let toml = format!(
        "[meta]\nname = \"m\"\n[frame.can.0x100.mux.{}]\nnotes = \"case\"\n",
        serde_json::to_string(key).unwrap()
    );
    Catalog::parse(&toml).unwrap().frames[0]
        .mux
        .as_ref()
        .is_some_and(|m| m.cases.contains_key(key))
}

#[test]
fn mux_case_keys_match_the_rule_table() {
    let table = fixture("muxCaseKeys.json");
    let mut ts_differs = Vec::new();
    for row in table["keys"].as_array().unwrap() {
        let key = row["key"].as_str().unwrap();
        let rust = is_mux_case_key(key);
        assert_eq!(rust, row["rust"].as_bool().unwrap(), "{key:?}");
        assert_eq!(parses_as_a_case(key), rust, "{key:?} through parse");
        if row["ts"].as_bool().unwrap() != rust {
            ts_differs.push(key);
        }
    }
    // Facts 18: the TypeScript accepts anything not reserved.
    assert_eq!(
        ts_differs,
        [
            "0x10", "-1", "1-", "-3", "1,,2", "2-3-4", "1.5", "٣", "", "abc", "notes", "signals",
            "mux"
        ]
    );
}

#[test]
fn mux_case_keys_have_a_total_order() {
    let walkers = fixture("walkers.json");
    let case = walkers["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "mux case key order")
        .unwrap();
    let mut keys: Vec<&str> = case["input"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    keys.sort_by(|a, b| compare_mux_case_keys(a, b));
    // Facts 19: the TypeScript reads `0x10` and `-1` as numbers and compares the
    // rest with localeCompare.
    assert_eq!(
        case["expected"],
        serde_json::json!(["-1", "0-3", "0x10", "1,2", "2", "2-5", "10", "a", "abc", "B"])
    );
    assert_eq!(
        keys,
        ["0-3", "1,2", "2", "2-5", "10", "-1", "0x10", "B", "a", "abc"]
    );

    for a in &keys {
        for b in &keys {
            assert_eq!(
                compare_mux_case_keys(a, b),
                compare_mux_case_keys(b, a).reverse(),
                "{a} {b}"
            );
            assert_eq!(compare_mux_case_keys(a, b).is_eq(), a == b, "{a} {b}");
        }
    }
}

#[test]
fn algorithm_widths_match_the_rule_table() {
    let table = fixture("checksumAlgorithms.json");
    let rows = table["algorithms"].as_array().unwrap();
    let widths = algorithm_widths();
    assert_eq!(
        widths.iter().map(|w| w.id).collect::<Vec<_>>(),
        all_algorithm_ids()
    );

    let mut ts_differs = Vec::new();
    for (width, row) in widths.iter().zip(rows) {
        assert_eq!(width.id, row["id"].as_str().unwrap());
        let rust = width.output_bytes.map(|b| b as u64);
        assert_eq!(rust, row["rustBytes"].as_u64(), "{}", width.id);
        if row["tsBytes"].as_u64() != rust || !row["tsListed"].as_bool().unwrap() {
            ts_differs.push(width.id);
        }
    }
    // Facts §7: the TypeScript does not list the two parameterised ids, and
    // falls back to 1 byte for each.
    assert_eq!(ts_differs, ["crc_custom", "sum8_negated"]);
}
