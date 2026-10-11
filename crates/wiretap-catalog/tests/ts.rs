#![cfg(feature = "ts")]
//! Each declaration as the desktop's generated file declares it, under its
//! `Config` (`large_int` as `number`), doc comments aside.

use ts_rs::{Config, TS};
use wiretap_catalog::{DiffKind, DiffRow};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn a_diff_row_is_the_editors_diff_line() {
    assert_eq!(
        decl::<DiffKind>(),
        r#"type DiffKind = "context" | "add" | "remove";"#
    );
    assert_eq!(
        decl::<DiffRow>(),
        "type DiffLine = { kind: DiffKind, text: string, oldLine: number | null, newLine: number | null, };"
    );
}
