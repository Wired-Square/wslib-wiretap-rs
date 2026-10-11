#![cfg(all(feature = "profile", feature = "ts"))]
//! The profile's wire types as the desktop's generated `SerialOverrides.ts`,
//! `ProfileValidationError.ts` and `ValidationCode.ts` declare them, doc
//! comments aside.

use ts_rs::{Config, TS};
use wiretap_io::profile::{ProfileValidationError, SerialOverrides, ValidationCode};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn serial_overrides_are_every_field_optional_and_nullable() {
    assert_eq!(
        decl::<SerialOverrides>(),
        "type SerialOverrides = { framing_encoding?: FramingMode | null, delimiter?: Array<number> | null, \
max_frame_length?: number | null, min_frame_length?: number | null, emit_raw_bytes?: boolean | null, \
modbus_validate_crc?: boolean | null, modbus_device_address?: number | null, \
modbus_vendor_functions?: Array<number> | null, modbus_allow_broadcast?: boolean | null, \
modbus_any_function?: boolean | null, frame_id_start_byte?: number | null, frame_id_bytes?: number | null, \
frame_id_big_endian?: boolean | null, source_address_start_byte?: number | null, \
source_address_bytes?: number | null, source_address_big_endian?: boolean | null, };"
    );
}

#[test]
fn a_rejection_is_a_camel_case_code_and_a_field() {
    assert_eq!(
        decl::<ValidationCode>(),
        r#"type ValidationCode = "nameRequired" | "nameDuplicate" | "portRequired" | "hostRequired" | "fieldRequired" | "fieldInvalid";"#
    );
    assert_eq!(
        decl::<ProfileValidationError>(),
        "type ProfileValidationError = { code: ValidationCode, field: string | null, };"
    );
}
