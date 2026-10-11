//! Text over a catalogue's source and its filename, without parsing the
//! catalogue: a line diff for the editor, `[meta].name` from a file that may not
//! validate, and the rules that turn outside input into a bare filename.

use serde::{Deserialize, Serialize};

/// What a diff row says happened to its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum DiffKind {
    Context,
    Add,
    Remove,
}

/// One row of a unified diff, with 1-based line numbers for the gutter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "DiffLine"))]
pub struct DiffRow {
    pub kind: DiffKind,
    pub text: String,
    pub old_line: Option<usize>,
    pub new_line: Option<usize>,
}

impl DiffRow {
    fn new(kind: DiffKind, text: &str, old_line: Option<usize>, new_line: Option<usize>) -> Self {
        Self {
            kind,
            text: text.to_string(),
            old_line,
            new_line,
        }
    }
}

/// A full-context line diff, baseline to current: every line comes back as
/// context, add or remove. Lines split on `\n`, so a CRLF line keeps its `\r`.
pub fn diff_lines(baseline: &str, current: &str) -> Vec<DiffRow> {
    let a: Vec<&str> = baseline.split('\n').collect();
    let b: Vec<&str> = current.split('\n').collect();
    lcs_diff(&a, &b)
}

/// Above this many `n * m` cells the LCS table costs more than the diff is worth
/// (4 bytes per cell, so 25M cells ≈ 100 MB). Catalogues are a few thousand lines
/// at most; anything past this is pathological or hostile — an imported file, an
/// MCP write, or a paste into text mode — so degrade instead of allocating.
const MAX_LCS_CELLS: usize = 25_000_000;

/// Longest-common-subsequence line diff. O(n·m) in time and memory, so bounded
/// by [`MAX_LCS_CELLS`]; beyond that it falls back to remove-all/add-all, which
/// is a truthful (if coarse) diff rather than an out-of-memory abort.
fn lcs_diff(a: &[&str], b: &[&str]) -> Vec<DiffRow> {
    let (n, m) = (a.len(), b.len());
    if n.saturating_mul(m) > MAX_LCS_CELLS {
        let mut rows = Vec::with_capacity(n + m);
        rows.extend(
            a.iter()
                .enumerate()
                .map(|(i, line)| DiffRow::new(DiffKind::Remove, line, Some(i + 1), None)),
        );
        rows.extend(
            b.iter()
                .enumerate()
                .map(|(j, line)| DiffRow::new(DiffKind::Add, line, None, Some(j + 1))),
        );
        return rows;
    }
    // One flat allocation rather than `vec![vec![]; n + 1]`: the nested form is n+1
    // separate heap blocks for the same bytes, and a contiguous row keeps the inner
    // loop's reads adjacent.
    let stride = m + 1;
    let mut dp = vec![0u32; (n + 1) * stride];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i * stride + j] = if a[i] == b[j] {
                dp[(i + 1) * stride + j + 1] + 1
            } else {
                dp[(i + 1) * stride + j].max(dp[i * stride + j + 1])
            };
        }
    }
    let mut rows = Vec::new();
    let (mut i, mut j, mut oln, mut nln) = (0, 0, 1usize, 1usize);
    while i < n && j < m {
        if a[i] == b[j] {
            rows.push(DiffRow::new(DiffKind::Context, a[i], Some(oln), Some(nln)));
            i += 1;
            j += 1;
            oln += 1;
            nln += 1;
        } else if dp[(i + 1) * stride + j] >= dp[i * stride + j + 1] {
            rows.push(DiffRow::new(DiffKind::Remove, a[i], Some(oln), None));
            i += 1;
            oln += 1;
        } else {
            rows.push(DiffRow::new(DiffKind::Add, b[j], None, Some(nln)));
            j += 1;
            nln += 1;
        }
    }
    while i < n {
        rows.push(DiffRow::new(DiffKind::Remove, a[i], Some(oln), None));
        i += 1;
        oln += 1;
    }
    while j < m {
        rows.push(DiffRow::new(DiffKind::Add, b[j], None, Some(nln)));
        j += 1;
        nln += 1;
    }
    rows
}

/// `[meta].name` alone, from any TOML, so a catalogue that fails to parse as one
/// still shows its name. `None` when it is missing or blank.
pub fn meta_name(text: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Head {
        meta: Option<Meta>,
    }
    #[derive(Deserialize)]
    struct Meta {
        name: Option<String>,
    }
    toml::from_str::<Head>(text)
        .ok()?
        .meta?
        .name
        .filter(|n| !n.trim().is_empty())
}

/// Why a filename is not a bare, visible name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnsafeFilename {
    #[error("Filename is empty")]
    Empty,
    #[error("Invalid filename '{0}' — must be a bare name with no path separators")]
    NotBare(String),
    /// It would hide the file from a directory scan.
    #[error("Invalid filename '{0}' — must not start with a dot")]
    Hidden(String),
}

/// `filename` trimmed, when it is a bare, visible name: no separator, no `..`,
/// no leading dot.
pub fn reject_unsafe_filename(filename: &str) -> Result<&str, UnsafeFilename> {
    let name = filename.trim();
    if name.is_empty() {
        return Err(UnsafeFilename::Empty);
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(UnsafeFilename::NotBare(name.to_string()));
    }
    if name.starts_with('.') {
        return Err(UnsafeFilename::Hidden(name.to_string()));
    }
    Ok(name)
}

/// An untrusted name as a bare `*.toml` filename.
pub fn sanitise_filename(filename: &str) -> Result<String, UnsafeFilename> {
    let name = reject_unsafe_filename(filename)?;
    if name.to_lowercase().ends_with(".toml") {
        Ok(name.to_string())
    } else {
        Ok(format!("{name}.toml"))
    }
}

/// The filename a new catalogue named `name` is first offered: a numeric name
/// in the save format's id style, anything else slugged, and `decoder.toml` when
/// neither is safe.
pub fn suggested_filename(name: &str, hex_ids: bool) -> String {
    let name = name.trim();
    let numeric = name.bytes().all(|b| b.is_ascii_digit());
    let stem = match name.parse::<u64>() {
        Ok(id) if numeric && hex_ids => format!("{id:#x}"),
        Ok(id) if numeric => id.to_string(),
        _ => name
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-"),
    };
    sanitise_filename(&stem).unwrap_or_else(|_| "decoder.toml".to_string())
}

/// The first `name-N.toml` (N from 2 to 999) beside `desired` that `taken`
/// says is free; `None` when every one is taken.
pub fn next_free_filename(desired: &str, taken: impl Fn(&str) -> bool) -> Option<String> {
    let stem = desired.strip_suffix(".toml").unwrap_or(desired);
    (2..1000)
        .map(|n| format!("{stem}-{n}.toml"))
        .find(|candidate| !taken(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use DiffKind::{Add, Context, Remove};

    fn row(kind: DiffKind, text: &str, old: Option<usize>, new: Option<usize>) -> DiffRow {
        DiffRow::new(kind, text, old, new)
    }

    #[test]
    fn rows_number_their_lines_from_one_on_each_side() {
        assert_eq!(
            diff_lines("a\nb\nc", "a\nx\nc"),
            [
                row(Context, "a", Some(1), Some(1)),
                row(Remove, "b", Some(2), None),
                row(Add, "x", None, Some(2)),
                row(Context, "c", Some(3), Some(3)),
            ]
        );
    }

    #[test]
    fn a_crlf_text_diffs_by_line_and_keeps_its_carriage_returns() {
        assert_eq!(
            diff_lines("a\r\nb\r\n", "a\r\nc\r\n"),
            [
                row(Context, "a\r", Some(1), Some(1)),
                row(Remove, "b\r", Some(2), None),
                row(Add, "c\r", None, Some(2)),
                row(Context, "", Some(3), Some(3)),
            ]
        );
    }

    #[test]
    fn past_the_lcs_cap_every_line_is_removed_then_added() {
        let side = 5_001;
        assert!(side * side > MAX_LCS_CELLS);
        let text = vec!["same"; side].join("\n");

        let rows = diff_lines(&text, &text);

        assert_eq!(rows.len(), 2 * side);
        assert_eq!(rows[0], row(Remove, "same", Some(1), None));
        assert_eq!(rows[side - 1], row(Remove, "same", Some(side), None));
        assert_eq!(rows[side], row(Add, "same", None, Some(1)));
        assert_eq!(rows[2 * side - 1], row(Add, "same", None, Some(side)));
    }

    #[test]
    fn a_row_serialises_in_the_editors_camel_case() {
        let json = serde_json::to_string(&row(Add, "x", None, Some(2))).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"add","text":"x","oldLine":null,"newLine":2}"#
        );
    }

    #[test]
    fn catalogue_name_is_read_from_meta_only() {
        let below_a_signal =
            "[[frame.can.0x100.signals]]\nname = \"Voltage\"\n\n[meta]\nname = \"Pack\"\n";
        assert_eq!(meta_name(below_a_signal).as_deref(), Some("Pack"));

        let commented = "[meta]\nname = \"Pack = BMS\" # the display name\n";
        assert_eq!(meta_name(commented).as_deref(), Some("Pack = BMS"));

        let prefix_first = "name_prefix = \"hyp_\"\n[meta]\nname = \"Pack\"\n";
        assert_eq!(meta_name(prefix_first).as_deref(), Some("Pack"));

        assert_eq!(meta_name("[meta]\nversion = 1\n"), None);
    }

    #[test]
    fn an_unsafe_filename_is_refused_in_the_desktops_words() {
        let refusal = |name| reject_unsafe_filename(name).unwrap_err().to_string();
        assert_eq!(refusal("  "), "Filename is empty");
        assert_eq!(
            refusal("a/b"),
            "Invalid filename 'a/b' — must be a bare name with no path separators"
        );
        assert_eq!(
            refusal("a..b"),
            "Invalid filename 'a..b' — must be a bare name with no path separators"
        );
        assert_eq!(
            refusal(" .hidden "),
            "Invalid filename '.hidden' — must not start with a dot"
        );
        assert_eq!(reject_unsafe_filename(" pack.toml "), Ok("pack.toml"));
    }

    #[test]
    fn a_new_catalogue_is_offered_a_bare_toml_filename() {
        assert_eq!(suggested_filename("  My  Pack ", false), "my-pack.toml");
        assert_eq!(suggested_filename("256", true), "0x100.toml");
        assert_eq!(suggested_filename("0256", false), "256.toml");
        assert_eq!(suggested_filename("pack.TOML", false), "pack.toml");
        assert_eq!(suggested_filename("", false), "decoder.toml");
        assert_eq!(suggested_filename("a/b", false), "decoder.toml");
        assert_eq!(suggested_filename(".hidden", false), "decoder.toml");
    }

    #[test]
    fn the_next_free_filename_counts_up_from_two() {
        let taken = ["pack.toml", "pack-2.toml"];
        assert_eq!(
            next_free_filename("pack.toml", |c| taken.contains(&c)).as_deref(),
            Some("pack-3.toml")
        );
        assert_eq!(next_free_filename("pack", |_| true), None);
    }
}
