#![cfg(feature = "ts")]
//! Each declaration under the desktop's `Config` (`large_int` as `number`),
//! doc comments aside. `Group` keeps the desktop's `GroupedValue` name.

use ts_rs::{Config, TS};
use wiretap_decode::frame_id::MatchedRange;
use wiretap_decode::groups::{Group, GroupMode, GroupOrder};
use wiretap_decode::register::{RegisterPairView, RegisterView};
use wiretap_decode::Endianness;

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn an_endianness_is_its_lower_case_name() {
    assert_eq!(
        decl::<Endianness>(),
        r#"type Endianness = "big" | "little";"#
    );
}

#[test]
fn a_group_is_the_desktops_grouped_value() {
    assert_eq!(
        decl::<Group>(),
        "type GroupedValue = { index: number, bits: number, hex: string, unsigned: string, \
         signedTwos: string, signedOnes: string, signedMag: string, text: string, \
         binary: string, displayHex: string, bitOffset: number, startByteIndex: number, \
         usedBitStart: number, usedBitEnd: number, };"
    );
    assert_eq!(
        decl::<GroupMode>(),
        r#"type GroupMode = "1B" | "2B" | "4B" | "8B" | { "custom": Array<number> };"#
    );
    assert_eq!(
        decl::<GroupOrder>(),
        r#"type GroupOrder = "big" | "little" | "mid-big" | "mid-little";"#
    );
}

#[test]
fn register_views_are_numbers_and_strings() {
    assert_eq!(
        decl::<RegisterView>(),
        "type RegisterView = { hex: string, u16: number, s16: number, ascii: string, };"
    );
    assert_eq!(
        decl::<RegisterPairView>(),
        r#"type RegisterPairView = { u32: number, s32: number, f32: number | "NaN" | "Infinity" | "-Infinity", };"#
    );
}

#[test]
fn a_matched_range_is_two_numbers() {
    assert_eq!(
        decl::<MatchedRange>(),
        "type MatchedRange = { lo: number, hi: number, };"
    );
}
