//! Notes cross the boundary as a code plus interpolation values, so the prose
//! stays translatable at the edge instead of shipping English from Rust.
//!
//! WireTAP renders these as ``t(`serial.checksumNote.${code}`, values)``. A code
//! with no translation reaches the user as a raw key, so [`ALL_NOTES`] publishes
//! the surface for a consumer to pin its locale file against — adding a note
//! here means adding the translation there.

use serde::Serialize;

/// A translatable note: the frontend renders `t(code, values)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumNote {
    pub code: String,
    pub values: serde_json::Map<String, serde_json::Value>,
}

impl ChecksumNote {
    pub fn new(code: &str, values: &[(&str, serde_json::Value)]) -> Self {
        Self {
            code: code.to_string(),
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        }
    }
}

/// One note the engine can emit: its code and the variables it interpolates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteSpec {
    pub code: &'static str,
    pub values: &'static [&'static str],
}

/// Every note the engine can emit.
///
/// The prose lives in a consumer's locale file, in another repository, so no
/// type can join the two halves — a code with no translation renders as the raw
/// key, and a renamed variable silently drops a value. Publishing the surface as
/// data lets a consumer pin its locale against it in both directions.
///
/// Hand-written, and kept honest by `manifest_covers_every_emitted_note` below.
pub const ALL_NOTES: &[NoteSpec] = &[
    NoteSpec {
        code: "analysed",
        values: &["frames", "minLength", "maxLength"],
    },
    NoteSpec {
        code: "columnNearlyConstant",
        values: &["distinct"],
    },
    NoteSpec {
        code: "columnVaries",
        values: &["distinct", "samples"],
    },
    NoteSpec {
        code: "configurationsTested",
        values: &["specs", "algorithms"],
    },
    NoteSpec {
        code: "constantExcluded",
        values: &["value"],
    },
    NoteSpec {
        code: "constantPadding",
        values: &["position", "value"],
    },
    NoteSpec {
        code: "constantPaddingRun",
        values: &["from", "to", "value"],
    },
    NoteSpec {
        code: "fewSamples",
        values: &["count"],
    },
    NoteSpec {
        code: "highByteConstant",
        values: &[],
    },
    NoteSpec {
        code: "matchesAll",
        values: &["count"],
    },
    NoteSpec {
        code: "matchesSome",
        values: &["matched", "total"],
    },
    NoteSpec {
        code: "noFrames",
        values: &[],
    },
    NoteSpec {
        code: "noneButLastByteVaries",
        values: &["distinct", "frames"],
    },
    NoteSpec {
        code: "noneLastByteConstant",
        values: &["value", "frames"],
    },
    NoteSpec {
        code: "shortRange",
        values: &[],
    },
    NoteSpec {
        code: "startsAfterHeader",
        values: &["byte"],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// The call's arguments, found by balancing parentheses rather than by
    /// searching for a closing delimiter. A note with no values ends `&[])`, so
    /// scanning for `"],"` runs past the call and swallows whatever follows.
    fn call_arguments(after_open_paren: &str) -> Option<&str> {
        let mut depth = 1usize;
        let mut in_string = false;
        let mut escaped = false;

        for (i, c) in after_open_paren.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if in_string => escaped = true,
                '"' => in_string = !in_string,
                _ if in_string => {}
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&after_open_paren[..i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Every `ChecksumNote::new("code", &[("var", …)])` in the engine, parsed out
    /// of the source. The same technique the consumer used to use directly —
    /// kept here, next to what it describes, now the consumer is another repo.
    fn emitted() -> BTreeMap<String, BTreeSet<String>> {
        const CALL: &str = "ChecksumNote::new(";
        let source = include_str!("detect.rs");
        let mut found = BTreeMap::new();
        let mut rest = source;

        while let Some(start) = rest.find(CALL) {
            rest = &rest[start + CALL.len()..];
            let Some(call) = call_arguments(rest) else {
                break;
            };

            // A tuple key is a bare identifier; `format!("0x{value:02X}")` and
            // friends are string *values* and must not read as variable names.
            let quoted = call
                .split('"')
                .skip(1)
                .step_by(2)
                .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric()));

            let mut quoted = quoted.map(str::to_string);
            let Some(code) = quoted.next() else { continue };
            found.insert(code, quoted.collect());
        }

        found
    }

    #[test]
    fn manifest_covers_every_emitted_note() {
        let emitted = emitted();

        // Guards the parser: a refactor of how notes are built must not make
        // this test silently vacuous.
        assert!(emitted.len() > 10, "parsed only {} notes", emitted.len());
        assert_eq!(
            emitted.get("matchesAll"),
            Some(&BTreeSet::from(["count".to_string()]))
        );

        let declared: BTreeMap<String, BTreeSet<String>> = ALL_NOTES
            .iter()
            .map(|n| {
                (
                    n.code.to_string(),
                    n.values.iter().map(|v| (*v).to_string()).collect(),
                )
            })
            .collect();

        assert_eq!(declared, emitted);
    }
}
