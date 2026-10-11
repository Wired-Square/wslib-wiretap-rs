#![cfg(feature = "ts")]
//! The serial framing declarations as the desktop's generated `FramingMode.ts`
//! and `FrameIdConfig.ts` declare them, doc comments aside.

use ts_rs::{Config, TS};
use wiretap_catalog::{FrameIdConfig, FramingMode};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn a_framing_mode_is_its_snake_case_name() {
    assert_eq!(
        decl::<FramingMode>(),
        r#"type FramingMode = "raw" | "slip" | "delimiter" | "modbus_rtu";"#
    );
}

#[test]
fn a_frame_id_config_is_three_snake_case_fields() {
    assert_eq!(
        decl::<FrameIdConfig>(),
        "type FrameIdConfig = { start_byte: number, num_bytes: number, big_endian: boolean, };"
    );
}
