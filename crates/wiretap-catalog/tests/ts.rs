#![cfg(feature = "ts")]
//! Each declaration as the desktop's generated file declares it, under its
//! `Config` (`large_int` as `number`), doc comments aside.

use ts_rs::{Config, TS};
use wiretap_catalog::{DiffKind, DiffRow, RtuSettings};

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

/// The desktop's `ModbusRtuOptions.ts`, from its `export type` line on.
#[test]
fn rtu_settings_are_the_desktops_modbus_rtu_options() {
    let full = RtuSettings::decl(&Config::new().with_large_int("number"));
    assert_eq!(
        full,
        r#"type ModbusRtuOptions = { 
/**
 * Device address filter (1-247). `None` syncs on any valid address.
 */
device_address?: number, 
/**
 * Whether a message has to pass its CRC to be framed. `false` is a lenient
 * mode, not "no framing" — see `CrcPolicy::Lenient`.
 */
validate_crc?: boolean, 
/**
 * Function codes the RTU length rules do not model but this line carries.
 * Framed by CRC search instead; empty leaves stock Modbus untouched.
 */
vendor_functions?: Array<number>, 
/**
 * Whether address 0 may start a message, for a master that broadcasts.
 */
allow_broadcast?: boolean, 
/**
 * Frame every function code, declared or not. What a tap on an unknown
 * line wants, at the cost of a fabricated message about once in 260
 * resyncs — see `ModbusRtuStream::frame_any_function`.
 */
any_function?: boolean, };"#
    );
}
