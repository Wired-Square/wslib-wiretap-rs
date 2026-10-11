#![cfg(feature = "ts")]
//! Each declaration as the desktop's generated file declares it, under its
//! `Config` (`large_int` as `number`), doc comments aside.

use ts_rs::{Config, TS};
use wiretap_catalog::model::{
    ChecksumConfig, HeaderField, HeaderFieldPosition, RegisterType, SerialConfig,
};
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

#[test]
fn a_register_type_is_its_lower_case_name() {
    assert_eq!(
        decl::<RegisterType>(),
        r#"type RegisterType = "input" | "holding" | "coil" | "discrete";"#
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

/// Served camelCase; a field serde skips when empty is optional.
#[test]
fn a_serial_config_keeps_its_served_camel_case_shape() {
    assert_eq!(
        decl::<SerialConfig>(),
        "type SerialConfig = { encoding?: string | null, byteOrder?: Endianness | null, \
         frameIdMask?: number | null, headerLength?: number | null, \
         minFrameLength?: number | null, checksum?: ChecksumConfig | null, \
         fields?: { [key in string]: HeaderField }, frameIdStartByte?: number | null, \
         frameIdBytes?: number | null, frameIdByteOrder?: Endianness | null, \
         sourceAddressStartByte?: number | null, sourceAddressBytes?: number | null, \
         sourceAddressByteOrder?: Endianness | null, \
         headerFields?: Array<HeaderFieldPosition>, };"
    );
    assert_eq!(
        decl::<ChecksumConfig>(),
        "type ChecksumConfig = { algorithm: string, startByte: number, byteLength: number, \
         calcStartByte: number, calcEndByte?: number | null, bigEndian: boolean, };"
    );
    assert_eq!(
        decl::<HeaderField>(),
        "type HeaderField = { mask?: number | null, shift?: number | null, \
         format?: string | null, endianness?: Endianness | null, startByte?: number | null, \
         bytes?: number | null, };"
    );
    assert_eq!(
        decl::<HeaderFieldPosition>(),
        "type HeaderFieldPosition = { name: string, mask?: number | null, \
         byteOrder: Endianness, format: string, startByte: number, bytes: number, };"
    );
}
