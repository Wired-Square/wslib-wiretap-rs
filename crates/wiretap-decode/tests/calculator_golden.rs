//! The Frame Calculator against the desktop's TypeScript `decodeGroups`, every
//! case of `fixtures/calculator_golden.json`. The cases the plan's D6 fixes are
//! listed below, or for case 2 named by rule; each is checked against the rule
//! it now keeps, and every other case must equal the golden.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{json, Value};
use wiretap_decode::groups::{decode_groups, parse_sizes, GroupMode, GroupOrder};

/// D6 case 1: a 1B mid-* group names the byte its value came from.
const ONE_BYTE_MID: &[&str] = &[
    "1B mid-big 12 mixed",
    "1B mid-big 123456789abcdef0",
    "1B mid-big 16 ascii+control",
    "1B mid-big 7fff",
    "1B mid-big 800000",
    "1B mid-big 80017f",
    "1B mid-big 8x 00",
    "1B mid-big 8x ff",
    "1B mid-big e808",
    "1B mid-big Hello",
    "1B mid-little 12 mixed",
    "1B mid-little 123456789abcdef0",
    "1B mid-little 16 ascii+control",
    "1B mid-little 800000",
    "1B mid-little 80017f",
    "1B mid-little 8x 00",
    "1B mid-little 8x ff",
    "1B mid-little Hello",
];

/// D6 case 4: a big custom group's display bytes and text cover every byte its
/// bits touch. The mid-big cases are case 2's.
const BIG_CUSTOM_SPAN: &[&str] = &[
    "custom-bits [1,7,12] big 12 mixed",
    "custom-bits [1,7,12] big 123456789abcdef0",
    "custom-bits [1,7,12] big 16 ascii+control",
    "custom-bits [1,7,12] big Hello",
    "custom-bits [3,8] big 12 mixed",
    "custom-bits [3,8] big 123456789abcdef0",
    "custom-bits [3,8] big 16 ascii+control",
    "custom-bits [3,8] big 80017f",
    "custom-bits [3,8] big e808",
    "custom-bits [3,8] big Hello",
    "custom-bits [3] big 123456789abcdef0",
    "custom-bits [3] big 80017f",
    "custom-bits [3] big e808",
    "custom-bits [3] big Hello",
];

/// D6 case 2: every custom mid-* case. A mid order swaps each word's bytes,
/// then walks as big or little; 206 of the 278 differ from the golden.
fn is_mid_custom(case: &Case) -> bool {
    case.sizes.is_some() && case.name.contains(" mid-")
}

const MID_CUSTOM_CHANGED: usize = 206;

struct Case {
    name: String,
    bytes: Vec<u8>,
    sizes: Option<Vec<u32>>,
    expected: Vec<Value>,
    got: Vec<Value>,
}

fn cases() -> Vec<Case> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/calculator_golden.json");
    let golden: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    golden
        .into_iter()
        .map(|c| {
            let bytes: Vec<u8> = serde_json::from_value(c["bytes"].clone()).unwrap();
            let sizes = c["customInput"].as_str().unwrap();
            let sizes = match c["mode"].as_str().unwrap() {
                "custom-bits" => Some(parse_sizes(sizes, 1)),
                "custom-bytes" => Some(parse_sizes(sizes, 8)),
                _ => None,
            };
            let mode = match &sizes {
                Some(sizes) => GroupMode::Custom(sizes.clone()),
                None => serde_json::from_value(c["mode"].clone()).unwrap(),
            };
            let order: GroupOrder = serde_json::from_value(c["endianness"].clone()).unwrap();
            let got = decode_groups(&bytes, &mode, order)
                .iter()
                .map(|g| serde_json::to_value(g).unwrap())
                .collect();
            Case {
                name: c["name"].as_str().unwrap().to_string(),
                bytes,
                sizes,
                expected: serde_json::from_value(c["groups"].clone()).unwrap(),
                got,
            }
        })
        .collect()
}

fn field(group: &Value, key: &str) -> usize {
    group[key].as_u64().unwrap() as usize
}

fn hex(bytes: &[u8]) -> String {
    let digits: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{digits}")
}

fn ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// The fields a fix may change differ from the golden, and nothing else does.
fn differs_only_in(case: &Case, allowed: &[&str]) {
    assert_eq!(case.got.len(), case.expected.len(), "{}", case.name);
    let mut changed = BTreeSet::new();
    for (got, expected) in case.got.iter().zip(&case.expected) {
        for (key, value) in got.as_object().unwrap() {
            if expected[key] != *value {
                changed.insert(key.as_str());
            }
        }
    }
    assert!(
        !changed.is_empty(),
        "{} no longer differs from the golden",
        case.name
    );
    assert!(
        changed.iter().all(|k| allowed.contains(k)),
        "{} changes {changed:?}",
        case.name
    );
}

fn names_the_source_byte(case: &Case) {
    differs_only_in(
        case,
        &[
            "displayHex",
            "startByteIndex",
            "usedBitStart",
            "usedBitEnd",
            "bitOffset",
        ],
    );
    let mut starts = BTreeSet::new();
    for g in &case.got {
        let start = field(g, "startByteIndex");
        assert_eq!(g["displayHex"], g["hex"], "{}", case.name);
        assert_eq!(
            g["unsigned"],
            json!(case.bytes[start].to_string()),
            "{}",
            case.name
        );
        assert_eq!(field(g, "usedBitStart"), start * 8, "{}", case.name);
        assert_eq!(field(g, "usedBitEnd"), start * 8 + 7, "{}", case.name);
        assert_eq!(field(g, "bitOffset"), start * 8 + 7, "{}", case.name);
        starts.insert(start);
    }
    assert_eq!(starts, (0..case.bytes.len()).collect(), "{}", case.name);
}

fn spans_every_touched_byte(case: &Case) {
    differs_only_in(case, &["displayHex", "text"]);
    for g in &case.got {
        let touched = &case.bytes[field(g, "usedBitStart") / 8..=field(g, "usedBitEnd") / 8];
        assert_eq!(g["displayHex"], json!(hex(touched)), "{}", case.name);
        assert_eq!(g["text"], json!(ascii(touched)), "{}", case.name);
    }
}

/// Each group read straight off the word-swapped walk: its original bit
/// positions, its value bits and the bytes from its lowest to highest bit.
fn reads_the_word_swapped_walk(case: &Case) {
    let mid_big = case.name.contains(" mid-big ");
    let len = case.bytes.len();
    let positions: Vec<usize> = (0..len * 8)
        .map(|k| {
            let byte = Some((k / 8) ^ 1).filter(|&b| b < len).unwrap_or(k / 8);
            byte * 8 + if mid_big { 7 - k % 8 } else { k % 8 }
        })
        .collect();
    let sizes = case.sizes.as_ref().unwrap();
    let mut rest = &positions[..];
    for (i, g) in case.got.iter().enumerate() {
        let size = sizes[i % sizes.len()] as usize;
        let (run, after) = rest.split_at(size.min(rest.len()));
        rest = after;
        let mut bits: Vec<u8> = run
            .iter()
            .map(|p| case.bytes[p / 8] >> (p % 8) & 1)
            .collect();
        if !mid_big {
            bits.reverse();
        }
        let (low, high) = (*run.iter().min().unwrap(), *run.iter().max().unwrap());
        let binary: String = bits.iter().map(|b| b.to_string()).collect();
        let unsigned = bits.iter().fold(0u128, |v, &b| v << 1 | u128::from(b));
        let span = &case.bytes[low / 8..=high / 8];
        let at = format!("{} group {}", case.name, i + 1);
        assert_eq!(
            g["binary"].as_str().unwrap().replace(' ', ""),
            binary,
            "{at}"
        );
        assert_eq!(g["unsigned"], json!(unsigned.to_string()), "{at}");
        assert_eq!(field(g, "usedBitStart"), low, "{at}");
        assert_eq!(field(g, "usedBitEnd"), high, "{at}");
        assert_eq!(
            field(g, "bitOffset"),
            if mid_big { high } else { low },
            "{at}"
        );
        assert_eq!(field(g, "startByteIndex"), low / 8, "{at}");
        assert_eq!(g["displayHex"], json!(hex(span)), "{at}");
        assert_eq!(g["text"], json!(ascii(span)), "{at}");
    }
    assert!(rest.is_empty(), "{}", case.name);
}

#[test]
fn every_case_matches_the_golden_but_the_d6_fixes() {
    let cases = cases();
    assert_eq!(cases.len(), 820);
    for name in ONE_BYTE_MID.iter().chain(BIG_CUSTOM_SPAN) {
        assert!(cases.iter().any(|c| c.name == *name), "no case {name}");
    }
    for case in &cases {
        if ONE_BYTE_MID.contains(&case.name.as_str()) {
            names_the_source_byte(case);
        } else if BIG_CUSTOM_SPAN.contains(&case.name.as_str()) {
            spans_every_touched_byte(case);
        } else if is_mid_custom(case) {
            reads_the_word_swapped_walk(case);
        } else {
            assert_eq!(case.got, case.expected, "{}", case.name);
        }
    }
    let mid_custom: Vec<_> = cases.iter().filter(|c| is_mid_custom(c)).collect();
    assert_eq!(mid_custom.len(), 278);
    let changed = mid_custom.iter().filter(|c| c.got != c.expected).count();
    assert_eq!(changed, MID_CUSTOM_CHANGED);
}

#[test]
fn the_named_d6_cases_give_their_new_answers() {
    let cases = cases();
    let case = |name: &str| cases.iter().find(|c| c.name == name).unwrap();
    let labels = |name: &str| -> Vec<(String, String, usize)> {
        case(name)
            .got
            .iter()
            .map(|g| {
                let text = |k: &str| g[k].as_str().unwrap().to_string();
                (text("hex"), text("displayHex"), field(g, "startByteIndex"))
            })
            .collect()
    };
    let label = |hex: &str, start| (hex.to_string(), hex.to_string(), start);
    assert_eq!(
        labels("1B mid-big 80017f"),
        [label("0x01", 1), label("0x80", 0), label("0x7f", 2)]
    );
    assert_eq!(
        labels("1B mid-little 80017f"),
        [label("0x7f", 2), label("0x80", 0), label("0x01", 1)]
    );
    let hexes = |name: &str| -> Vec<String> {
        case(name)
            .got
            .iter()
            .map(|g| g["hex"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(
        hexes("custom-bytes [4,4] mid-big 123456789abcdef0"),
        ["0x34127856", "0xbc9af0de"]
    );
    assert_eq!(
        hexes("custom-bytes [4,4] mid-little 123456789abcdef0"),
        ["0x56781234", "0xdef09abc"]
    );
    assert_eq!(
        hexes("custom-bytes [4,4] mid-big 123456789abcdef0"),
        hexes("4B mid-big 123456789abcdef0")
    );
    assert_eq!(
        hexes("custom-bytes [4,4] mid-little 123456789abcdef0"),
        hexes("4B mid-little 123456789abcdef0")
    );
    let third = &case("custom-bits [3] big e808").got[2];
    assert_eq!(third["displayHex"], "0xe808");
    assert_eq!(third["text"], "..");
    assert_eq!(third["bitOffset"], 15);
}
