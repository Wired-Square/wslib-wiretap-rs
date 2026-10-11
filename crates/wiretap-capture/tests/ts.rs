#![cfg(feature = "ts")]
//! The model types as the desktop's generated `CaptureKind.ts`, `TimestampedByte.ts`,
//! `CaptureMetadata.ts` and `CaptureFrameInfo.ts` declare them, doc comments aside.

use ts_rs::{Config, TS};
use wiretap_capture::{CaptureFrameInfo, CaptureKind, CaptureMetadata, TimestampedByte};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn a_capture_kind_is_snake_case() {
    assert_eq!(
        decl::<CaptureKind>(),
        r#"type CaptureKind = "frames" | "bytes";"#
    );
}

#[test]
fn a_timestamped_byte_is_snake_case() {
    assert_eq!(
        decl::<TimestampedByte>(),
        "type TimestampedByte = { byte: number, timestamp_us: number, bus: number, };"
    );
}

#[test]
fn capture_metadata_keeps_is_streaming() {
    assert_eq!(
        decl::<CaptureMetadata>(),
        "type CaptureMetadata = { id: string, kind: CaptureKind, name: string, count: number, \
         start_time_us: number | null, end_time_us: number | null, created_at: number, \
         is_streaming: boolean, owning_session_id: string | null, persistent: boolean, \
         buses: Array<number>, };"
    );
}

#[test]
fn capture_frame_info_is_snake_case() {
    assert_eq!(
        decl::<CaptureFrameInfo>(),
        "type CaptureFrameInfo = { protocol: string, frame_id: number, max_dlc: number, bus: number, \
         is_extended: boolean, has_dlc_mismatch: boolean, };"
    );
}
