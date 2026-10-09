//! Mux case keys: which table keys under a `mux` are cases, and the order they
//! are shown in.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Whether a mux table key denotes a case (numeric, range `0-3`, or list
/// `1,2,5`, parts trimmed) rather than a reserved key.
pub fn is_mux_case_key(key: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    key.split(',')
        .all(|part| match part.trim().split_once('-') {
            Some((a, b)) => digits(a) && digits(b),
            None => digits(part.trim()),
        })
}

/// An inclusive run of selector values a case matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRange {
    pub first: u64,
    pub last: u64,
}

/// The values a case key matches, one range per part in authored order (a
/// reversed range `3-1` as `1..=3`), or `None` when the key is not a case or a
/// value is wider than 64 bits.
pub fn mux_case_values(key: &str) -> Option<Vec<CaseRange>> {
    if !is_mux_case_key(key) {
        return None;
    }
    key.split(',')
        .map(|part| {
            let part = part.trim();
            let (a, b) = part.split_once('-').unwrap_or((part, part));
            let (a, b) = (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?);
            Some(CaseRange {
                first: a.min(b),
                last: a.max(b),
            })
        })
        .collect()
}

/// A total order over mux table keys: case keys by their first value (a range
/// or list by its first part), then every other key; ties by the key's text.
pub fn compare_mux_case_keys(a: &str, b: &str) -> Ordering {
    sort_key(a).cmp(&sort_key(b))
}

/// The first value's digits lose their leading zeros, so length then text
/// compares them numerically at any width.
fn sort_key(key: &str) -> (bool, usize, &str, &str) {
    if !is_mux_case_key(key) {
        return (true, 0, "", key);
    }
    let first = key.split([',', '-']).next().unwrap_or_default();
    let digits = first.trim().trim_start_matches('0');
    (false, digits.len(), digits, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_keys_are_not_cases() {
        for key in ["name", "start_bit", "bit_length", "default", "notes", "mux"] {
            assert!(!is_mux_case_key(key), "{key}");
        }
    }

    #[test]
    fn case_keys_sort_by_first_value_then_text_and_the_rest_after() {
        let mut keys = ["10", "abc", "2-5", "007", "1,2", "7", "0-3", "B", "2", "1"];
        keys.sort_by(|a, b| compare_mux_case_keys(a, b));
        assert_eq!(
            keys,
            ["0-3", "1", "1,2", "2", "2-5", "007", "7", "10", "B", "abc"]
        );
    }

    #[test]
    fn case_values_are_parsed_not_read_as_their_first_number() {
        let range = |first, last| CaseRange { first, last };
        assert_eq!(mux_case_values("0-3"), Some(vec![range(0, 3)]));
        assert_eq!(
            mux_case_values("10, 12"),
            Some(vec![range(10, 10), range(12, 12)])
        );
        assert_eq!(
            mux_case_values("3-1,007"),
            Some(vec![range(1, 3), range(7, 7)])
        );
        assert_eq!(mux_case_values("notes"), None);
        assert_eq!(mux_case_values("123456789012345678901234567890"), None);
    }

    #[test]
    fn values_wider_than_any_integer_still_order() {
        let wide = "123456789012345678901234567890";
        assert_eq!(compare_mux_case_keys("9", wide), Ordering::Less);
        assert_eq!(compare_mux_case_keys(wide, "9"), Ordering::Greater);
    }
}
