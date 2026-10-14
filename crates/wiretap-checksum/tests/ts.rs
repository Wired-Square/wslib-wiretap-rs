#![cfg(feature = "ts")]
//! Each declaration under the desktop's `Config` (`large_int` as `number`),
//! doc comments aside.

use ts_rs::{Config, TS};
use wiretap_checksum::{
    ChecksumAlgorithm, ChecksumDetectionOptions, ChecksumNote, ChecksumSpecification,
    CrcParameters, SolvedChecksum,
};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn an_algorithm_is_its_snake_case_id() {
    assert_eq!(
        decl::<ChecksumAlgorithm>(),
        r#"type ChecksumAlgorithm = "xor" | "sum8" | "crc8" | "crc8_sae_j1850" | "crc8_autosar" | "crc8_maxim" | "crc8_cdma2000" | "crc8_dvb_s2" | "crc8_nissan" | "crc16_modbus" | "crc16_ccitt";"#
    );
}

#[test]
fn every_detection_option_may_be_left_out() {
    assert_eq!(
        decl::<ChecksumDetectionOptions>(),
        "type ChecksumDetectionOptions = { positions?: Array<number>, lengths?: Array<number>, \
         headerBoundaries?: Array<number>, minMatchRate?: number, minConfidence?: number, };"
    );
}

#[test]
fn a_note_is_a_code_and_its_values() {
    assert_eq!(
        decl::<ChecksumNote>(),
        "type ChecksumNote = { code: string, values: { [key in string]: unknown }, };"
    );
}

#[test]
fn a_specification_is_tagged_by_kind_and_flattened_into_a_solution() {
    let specification = r#"{ "kind": "named", algorithm: ChecksumAlgorithm, } | { "kind": "additive", op: AdditiveOp, offset: number, } | { "kind": "crc" } & CrcParameters"#;
    assert_eq!(
        decl::<ChecksumSpecification>(),
        format!("type ChecksumSpecification = {specification};")
    );
    assert_eq!(
        decl::<CrcParameters>(),
        "type CrcParameters = { width: number, polynomial: number, reflectIn: boolean, \
         reflectOut: boolean, init: number, xorOut: number, wellKnown: boolean, \
         alternatives: Array<CrcAlternative>, };"
    );
    assert_eq!(
        decl::<SolvedChecksum>(),
        format!(
            "type SolvedChecksum = {{ target: SolveTarget, sampleCount: number, \
             excludedCount: number, equivalentRanges: Array<CalcRange>, }} & ({specification});"
        )
    );
}
