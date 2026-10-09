//! Decode raw frame bytes into signal values against a [`Catalog`].
//!
//! Faithful Rust port of WireTAP's `src/utils/bits.ts`,
//! `src/utils/signalDecode.ts` and `src/utils/muxCaseMatch.ts`, plus the
//! plain/mux signal orchestration from `decoderStore.ts`. This is the single
//! decode implementation: the `modbus` module's decoders share
//! [`wiretap_decode::extract_field`] with it.
//!
//! The path forks by bank. A Modbus coil or discrete frame's block is packed
//! bits, so the catalogue's byte and word order do not apply to it and neither
//! does a signal's override of them; `frame_bit_order` settles that once per
//! frame so nothing downstream can reintroduce it.

use crate::model::{Catalog, Endianness, Frame, Mux, Protocol, Signal, SignalFormat};
use rust_decimal::prelude::ToPrimitive;
use wiretap_decode::{
    decode_text, extract_field, format_decimal, format_hex, format_unix_time, scale, BitOrder,
};

/// A decoded signal value. Mirrors the TS `DecodedValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    pub name: String,
    /// Raw integer value (pre-scale), as `f64` (lossless to 53 bits).
    pub value: f64,
    /// Scaled numeric value (`raw * factor + offset`), or the raw value for
    /// formats where scaling doesn't apply (enum/text).
    pub scaled: f64,
    /// Human display string (hex digits, enum label, decoded text, timestamp,
    /// or the scaled number).
    pub display: String,
    pub unit: Option<String>,
    /// For a signal from a mux case, the selector value of its mux (so consumers
    /// can track each mux case's signals separately). `None` for plain signals.
    pub mux_value: Option<i64>,
    /// The signal's declared format (enum/hex/ascii/…), carried through for the
    /// UI's per-format rendering. `None` for a plain numeric signal.
    pub format: Option<SignalFormat>,
}

/// A mux selector reading + the case it matched.
#[derive(Debug, Clone, PartialEq)]
pub struct MuxSelector {
    pub name: Option<String>,
    pub value: i64,
    pub matched_case: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
}

/// A header field extracted from the CAN id (mask + shift) or serial header
/// bytes (mask → byte range). Mirrors the TS `HeaderFieldValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderFieldValue {
    pub name: String,
    pub value: u64,
    pub display: String,
    /// `hex` or `decimal`.
    pub format: String,
}

/// The full decode of one frame: its signals, mux selector readings, and the
/// header fields extracted from the id/header bytes.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FrameDecode {
    pub signals: Vec<Decoded>,
    pub selectors: Vec<MuxSelector>,
    pub header_fields: Vec<HeaderFieldValue>,
    /// Source address resolved from a CAN header field (source_address / sender
    /// / source / src / sa), when present.
    pub source_address: Option<u64>,
}

// ---------- single-signal decode (port of signalDecode.ts) ----------

/// Decode one signal from `bytes`, in the ordering its frame's bank imposes.
pub fn decode_signal(bytes: &[u8], sig: &Signal, fallback_name: &str, order: BitOrder) -> Decoded {
    let name = sig
        .name
        .clone()
        .unwrap_or_else(|| fallback_name.to_string());
    let start = sig.start_bit.unwrap_or(0);
    let len = sig.bit_length.unwrap_or(0);
    let order = order.with_overrides(sig.endianness, sig.word_order);
    let raw = extract_field(bytes, start, len, order, sig.signed.unwrap_or(false));

    // Scale in exact Decimal (raw is integer-valued; from_f64 rounds the factor
    // cleanly) so the display string carries no binary-float artifacts. `scaled`
    // (f64) is kept for the numeric consumers (charts).
    let scaled_dec = scale(raw, sig.factor, sig.offset);
    let scaled = scaled_dec.and_then(|d| d.to_f64()).unwrap_or(f64::NAN);
    let out_of_range = || "(out of range)".to_string();
    let unit = sig.unit.clone();

    // Per-format display + the scaled/unit that actually apply (enum/text don't
    // scale and carry no unit).
    let (display, scaled, unit) = match sig.format {
        Some(SignalFormat::Hex) => (format_hex(raw, len, order.endianness()), scaled, unit),
        Some(SignalFormat::Enum) => {
            let label = sig
                .enum_map
                .as_ref()
                .and_then(|m| m.get(&(raw as i64)).cloned());
            (
                label.unwrap_or_else(|| format!("Unknown ({})", raw as i64)),
                raw,
                None,
            )
        }
        Some(SignalFormat::Utf8) | Some(SignalFormat::Ascii) => {
            let text = decode_text(bytes, start, len);
            let display = if text.is_empty() {
                "(empty)".to_string()
            } else {
                text
            };
            (display, raw, None)
        }
        Some(SignalFormat::UnixTime) => (
            scaled_dec.map_or_else(out_of_range, |_| format_unix_time(scaled)),
            scaled,
            None,
        ),
        Some(SignalFormat::Other) | None => (
            scaled_dec.map_or_else(out_of_range, format_decimal),
            scaled,
            unit,
        ),
    };

    Decoded {
        name,
        value: raw,
        scaled,
        display,
        unit,
        mux_value: None,
        format: sig.format,
    }
}

// ---------- mux matching (port of muxCaseMatch.ts) ----------

/// Expand a mux case key (`"0"`, `"0-3"`, `"1,2,5"`, `"0-3,7"`) to the set of
/// values it matches. `None` if the key has no numeric parts.
fn parse_mux_case_values(key: &str) -> Option<Vec<i64>> {
    if matches!(key, "name" | "start_bit" | "bit_length" | "default") {
        return None;
    }
    let mut values = Vec::new();
    for part in key.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Range a-b (allowing a leading '-' on each bound).
        if let Some((a, b)) = split_range(part) {
            let (min, max) = (a.min(b), a.max(b));
            let capped = if max - min > 1000 { min + 1000 } else { max };
            for v in min..=capped {
                values.push(v);
            }
        } else if let Ok(n) = part.parse::<i64>() {
            values.push(n);
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// Split `"a-b"` into signed integer bounds, matching the TS regex
/// `^(-?\d+)-(-?\d+)$`.
fn split_range(part: &str) -> Option<(i64, i64)> {
    let body = part.strip_prefix('-');
    let (neg_a, rest) = match body {
        Some(r) => (true, r),
        None => (false, part),
    };
    let dash = rest.find('-')?;
    let a_digits = &rest[..dash];
    let b_str = &rest[dash + 1..];
    if a_digits.is_empty() || !a_digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let a: i64 = a_digits.parse().ok()?;
    let a = if neg_a { -a } else { a };
    let b: i64 = b_str.parse().ok()?;
    Some((a, b))
}

/// True if `selector` matches the case key pattern.
pub fn mux_case_matches(selector: i64, case_key: &str) -> bool {
    parse_mux_case_values(case_key)
        .map(|vs| vs.contains(&selector))
        .unwrap_or(false)
}

/// First case key matching `selector`, in iteration order.
pub fn find_matching_mux_case<'a>(
    selector: i64,
    keys: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    keys.into_iter().find(|k| mux_case_matches(selector, k))
}

// ---------- frame decode orchestration (port of decoderStore) ----------

/// Decode every signal (and resolve any mux) in `frame` from `bytes`, choosing
/// the per-protocol default byte/word order from `catalog`.
pub fn decode_frame(catalog: &Catalog, frame: &Frame, bytes: &[u8]) -> FrameDecode {
    let order = frame_bit_order(catalog, frame);
    let mut out = FrameDecode::default();

    for (idx, sig) in frame.signals.iter().enumerate() {
        out.signals.push(decode_signal(
            bytes,
            sig,
            &format!("Signal {}", idx + 1),
            order,
        ));
    }

    if let Some(mux) = &frame.mux {
        decode_mux(bytes, mux, order, &mut out);
    }

    out
}

fn decode_mux(bytes: &[u8], mux: &Mux, order: BitOrder, out: &mut FrameDecode) {
    let selector = extract_field(bytes, mux.start_bit, mux.bit_length, order, false) as i64;
    let matched =
        find_matching_mux_case(selector, mux.cases.keys().map(String::as_str)).map(str::to_string);

    out.selectors.push(MuxSelector {
        name: mux.name.clone(),
        value: selector,
        matched_case: matched.clone(),
        start_bit: mux.start_bit,
        bit_length: mux.bit_length,
    });

    if let Some(case) = matched.as_deref().and_then(|k| mux.cases.get(k)) {
        for (idx, sig) in case.signals.iter().enumerate() {
            let mut decoded = decode_signal(bytes, sig, &format!("Mux Signal {}", idx + 1), order);
            // Tag with this mux's selector value so consumers can track each
            // mux case's signals separately.
            decoded.mux_value = Some(selector);
            out.signals.push(decoded);
        }
        if let Some(nested) = &case.mux {
            decode_mux(bytes, nested, order, out);
        }
    }
}

/// Decode a frame from its raw id + bytes: apply the protocol's `frame_id_mask`
/// to look up the catalogue frame, decode its signals/mux, and extract header
/// fields (CAN: from the raw id; serial: from the header bytes). Returns `None`
/// when no catalogue frame matches. This is the entry point the live stream uses.
pub fn decode_by_id(catalog: &Catalog, raw_frame_id: u32, bytes: &[u8]) -> Option<FrameDecode> {
    let masked = masked_frame_id(catalog, raw_frame_id);
    let frame = catalog.frame(masked)?;
    let mut out = decode_frame(catalog, frame, bytes);
    extract_header_fields(catalog, raw_frame_id, bytes, &mut out);
    Some(out)
}

/// Apply the protocol's `frame_id_mask` (if any) before catalogue lookup, so a
/// catalogue keyed by message-type-only (e.g. J1939 PGN) matches frames that
/// carry extra id bits. Mirrors `decoderStore`'s `maskedFrameId`.
fn masked_frame_id(catalog: &Catalog, raw: u32) -> u32 {
    frame_id_mask(catalog).map(|m| raw & m).unwrap_or(raw)
}

/// The protocol's `frame_id_mask`, if it declares one. Exposed so a caller that
/// masks ids repeatedly can read it once rather than re-deriving per frame.
pub fn frame_id_mask(catalog: &Catalog) -> Option<u32> {
    match catalog.protocol {
        Protocol::Can => catalog.can.as_ref().and_then(|c| c.frame_id_mask),
        Protocol::Serial => catalog.serial.as_ref().and_then(|c| c.frame_id_mask),
        Protocol::Modbus => None,
    }
}

/// Extract header fields into `out` — CAN from the raw id (mask + shift), serial
/// from the header bytes (mask → byte range). Port of `decoderStore`.
fn extract_header_fields(catalog: &Catalog, raw_id: u32, bytes: &[u8], out: &mut FrameDecode) {
    match catalog.protocol {
        Protocol::Can => {
            let Some(can) = &catalog.can else { return };
            for (name, field) in &can.fields {
                // Shift defaults to the mask's trailing-zero count.
                let shift = field.shift.unwrap_or_else(|| {
                    if field.mask > 0 {
                        field.mask.trailing_zeros()
                    } else {
                        0
                    }
                });
                let value = ((raw_id & field.mask) >> shift) as u64;
                let format = field.format.clone().unwrap_or_else(|| "hex".to_string());
                out.header_fields.push(HeaderFieldValue {
                    name: name.clone(),
                    value,
                    display: format_header_value(value, &format),
                    format,
                });
                if matches!(
                    name.to_lowercase().as_str(),
                    "source_address" | "sender" | "source" | "src" | "sa"
                ) {
                    out.source_address = Some(value);
                }
            }
        }
        Protocol::Serial => {
            let Some(serial) = &catalog.serial else {
                return;
            };
            for (name, field) in &serial.fields {
                if name == "id" {
                    continue;
                }
                let Some((start_byte, nbytes)) = mask_to_byte_position(field.mask) else {
                    continue;
                };
                if start_byte >= bytes.len() {
                    continue;
                }
                let end = (start_byte + nbytes).min(bytes.len());
                let mut value: u64 = 0;
                if field.endianness == Some(Endianness::Little) {
                    for (i, b) in bytes[start_byte..end].iter().enumerate() {
                        value |= (*b as u64) << (i * 8);
                    }
                } else {
                    for b in &bytes[start_byte..end] {
                        value = (value << 8) | *b as u64;
                    }
                }
                // The mask is relative to the header start; shift it down to the field.
                let shifted_mask = (field.mask as u64) >> (start_byte * 8);
                value &= shifted_mask;
                let format = field.format.clone().unwrap_or_else(|| "hex".to_string());
                out.header_fields.push(HeaderFieldValue {
                    name: name.clone(),
                    value,
                    display: format_header_value(value, &format),
                    format,
                });
            }
        }
        Protocol::Modbus => {}
    }
}

fn format_header_value(value: u64, format: &str) -> String {
    if format == "decimal" {
        value.to_string()
    } else {
        format!("0x{value:X}")
    }
}

/// First set bit → byte position + byte span of a header-byte mask. Port of
/// `maskToBytePosition`. Shared with `parse` so the derived serial header
/// positions are computed from the one algorithm.
pub(crate) fn mask_to_byte_position(mask: u32) -> Option<(usize, usize)> {
    if mask == 0 {
        return None;
    }
    let first = mask.trailing_zeros() as usize;
    let last = 31 - mask.leading_zeros() as usize;
    let start_byte = first / 8;
    let end_byte = last / 8;
    Some((start_byte, end_byte - start_byte + 1))
}

/// The bit ordering a frame's block is in. Resolved once per frame, so a coil
/// bank's order cannot be overridden per signal downstream.
fn frame_bit_order(catalog: &Catalog, frame: &Frame) -> BitOrder {
    // A coil or discrete block is packed bits; no default applies to it.
    if frame
        .modbus_register_type
        .is_some_and(|bank| !bank.is_register_bank())
    {
        return BitOrder::Coils;
    }
    let defaults = catalog.derived_defaults();
    let (endianness, word_order) = match frame.protocol {
        Protocol::Modbus => (defaults.modbus_byte_order, Some(defaults.modbus_word_order)),
        Protocol::Can => (defaults.can_byte_order, None),
        Protocol::Serial => (defaults.serial_byte_order, None),
    };
    BitOrder::Registers {
        endianness,
        word_order,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    fn parse(toml: &str) -> Catalog {
        Catalog::parse(toml).unwrap()
    }

    fn decoded<'a>(d: &'a FrameDecode, name: &str) -> &'a Decoded {
        d.signals
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("decoded {name}"))
    }

    #[test]
    fn can_signal_scales_and_picks_default_endianness() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "RPM"
start_bit = 0
bit_length = 16
factor = 0.25
unit = "rpm"
"#,
        );
        let f = c.frame(0x100).unwrap();
        // 0x0190 = 400 ×0.25 = 100 rpm (big-endian).
        let d = decode_frame(&c, f, &[0x01, 0x90, 0, 0, 0, 0, 0, 0]);
        let rpm = decoded(&d, "RPM");
        assert!((rpm.scaled - 100.0).abs() < 1e-9);
        assert_eq!(rpm.display, "100");
        assert_eq!(rpm.unit.as_deref(), Some("rpm"));
    }

    #[test]
    fn float_scale_display_is_clean() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x101]
length = 8
[[frame.can.0x101.signals]]
name = "SoC"
start_bit = 0
bit_length = 16
factor = 0.1
unit = "%"
"#,
        );
        let f = c.frame(0x101).unwrap();
        // 555 ×0.1 = 55.5 — must not render 55.50000000000001.
        let d = decode_frame(&c, f, &[0x02, 0x2B, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoded(&d, "SoC").display, "55.5");
    }

    #[test]
    fn enum_hex_text_formats() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x102]
length = 8
[[frame.can.0x102.signals]]
name = "Mode"
start_bit = 0
bit_length = 8
format = "enum"
enum = { 1 = "run", 2 = "stop" }
[[frame.can.0x102.signals]]
name = "Raw"
start_bit = 8
bit_length = 16
format = "hex"
[[frame.can.0x102.signals]]
name = "Tag"
start_bit = 24
bit_length = 24
format = "ascii"
"#,
        );
        let f = c.frame(0x102).unwrap();
        let bytes = [0x02, 0xAB, 0xCD, b'A', b'B', b'C', 0, 0];
        let d = decode_frame(&c, f, &bytes);
        assert_eq!(decoded(&d, "Mode").display, "stop");
        assert_eq!(decoded(&d, "Raw").display, "AB CD");
        assert_eq!(decoded(&d, "Tag").display, "ABC");
    }

    #[test]
    fn a_scale_past_decimals_range_decodes_as_out_of_range_not_a_panic() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x104]
length = 8
[[frame.can.0x104.signals]]
name = "Huge"
start_bit = 0
bit_length = 64
factor = 1e10
[[frame.can.0x104.signals]]
name = "Mode"
start_bit = 0
bit_length = 8
format = "enum"
factor = 1e29
enum = { 255 = "all" }
"#,
        );
        let d = decode_by_id(&c, 0x104, &[0xFF; 8]).expect("decodes");
        let huge = decoded(&d, "Huge");
        assert!(huge.scaled.is_nan());
        assert_eq!(huge.display, "(out of range)");
        let mode = decoded(&d, "Mode");
        assert_eq!((mode.scaled, mode.display.as_str()), (255.0, "all"));
    }

    #[test]
    fn unknown_enum_value_labelled() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x103]
length = 8
[[frame.can.0x103.signals]]
name = "M"
start_bit = 0
bit_length = 8
format = "enum"
enum = { 1 = "a" }
"#,
        );
        let f = c.frame(0x103).unwrap();
        let d = decode_frame(&c, f, &[9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoded(&d, "M").display, "Unknown (9)");
    }

    #[test]
    fn mux_selects_case_and_decodes_nested() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x200]
length = 8
[frame.can.0x200.mux]
name = "sel"
start_bit = 0
bit_length = 8
[[frame.can.0x200.mux."0-3".signals]]
name = "low"
start_bit = 8
bit_length = 8
[[frame.can.0x200.mux."4,5".signals]]
name = "mid"
start_bit = 8
bit_length = 8
"#,
        );
        let f = c.frame(0x200).unwrap();
        // selector = 2 → matches "0-3".
        let d = decode_frame(&c, f, &[2, 0x37, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.selectors[0].value, 2);
        assert_eq!(d.selectors[0].matched_case.as_deref(), Some("0-3"));
        assert_eq!(decoded(&d, "low").value, 0x37 as f64);
        // Mux-case signals are tagged with their selector value.
        assert_eq!(decoded(&d, "low").mux_value, Some(2));
        // selector = 5 → matches "4,5", not "0-3".
        let d2 = decode_frame(&c, f, &[5, 0x42, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d2.selectors[0].matched_case.as_deref(), Some("4,5"));
        assert!(d2.signals.iter().any(|s| s.name == "mid"));
    }

    #[test]
    fn modbus_word_swapped_signed_32bit_matches_modbus_module() {
        // Parity with modbus::decode_frame for the Sungrow word-swap case.
        let c = parse(
            r#"
[meta]
name = "x"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"
[frame.modbus.13007]
register_type = "input"
length = 2
[[frame.modbus.13007.signals]]
name = "Battery_Power"
start_bit = 0
bit_length = 32
signed = true
unit = "W"
"#,
        );
        let f = c.frame(13007).unwrap();
        // -1000 W: registers [low=0xFC18, high=0xFFFF] → bytes FC 18 FF FF.
        let d = decode_frame(&c, f, &[0xFC, 0x18, 0xFF, 0xFF]);
        assert!((decoded(&d, "Battery_Power").scaled - -1000.0).abs() < 1e-9);
    }

    #[test]
    fn a_coil_frame_decodes_lsb_first_whatever_the_orders_say() {
        // Both orders are set, and one signal overrides them itself. A coil
        // block has neither, so none of it may reach the extraction — resolving
        // the bank in `frame_bit_order` is what stops the override.
        let c = parse(
            r#"
[meta]
name = "x"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"
[frame.modbus.20]
register_type = "coil"
length = 24
[[frame.modbus.20.signals]]
name = "Plain"
start_bit = 0
bit_length = 20
[[frame.modbus.20.signals]]
name = "Overridden"
start_bit = 0
bit_length = 20
byte_order = "big"
word_order = "big"
"#,
        );
        let f = c.frame(20).unwrap();
        // Coils 0, 3, 7, 8, 17 on → bytes 0x89 0x01 0x02.
        let d = decode_frame(&c, f, &[0x89, 0x01, 0x02]);
        assert!((decoded(&d, "Plain").scaled - 131_465.0).abs() < 1e-9);
        // The override changes nothing: there was nothing to override.
        assert_eq!(
            decoded(&d, "Overridden").scaled,
            decoded(&d, "Plain").scaled
        );
    }

    #[test]
    fn unix_time_formats_utc() {
        // 2021-01-01 00:00:00 UTC = 1609459200.
        assert_eq!(format_unix_time(1_609_459_200.0), "2021-01-01 00:00:00");
        // millisecond input auto-detected.
        assert_eq!(format_unix_time(1_609_459_200_000.0), "2021-01-01 00:00:00");
    }

    #[test]
    fn can_header_fields_and_frame_id_mask() {
        // J1939-style: catalogue keyed by PGN (id & mask); source address is the
        // low byte, extracted from the raw id.
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
frame_id_mask = 0x1FFFFF00
[meta.can.fields]
pgn = { mask = 0x1FFFFF00, format = "hex" }
source_address = { mask = 0x000000FF, format = "decimal" }
[frame.can.0x18EF0000]
length = 8
[[frame.can.0x18EF0000.signals]]
name = "A"
start_bit = 0
bit_length = 8
"#,
        );
        // Raw id has source 0x42 in the low byte; masked id matches the frame.
        let d = decode_by_id(&c, 0x18EF0042, &[0x05, 0, 0, 0, 0, 0, 0, 0]).expect("decodes");
        assert_eq!(d.source_address, Some(0x42));
        let sa = d
            .header_fields
            .iter()
            .find(|h| h.name == "source_address")
            .unwrap();
        assert_eq!(sa.value, 0x42);
        assert_eq!(sa.display, "66"); // decimal format
        let pgn = d.header_fields.iter().find(|h| h.name == "pgn").unwrap();
        assert_eq!(pgn.value, 0x18EF00); // (raw & mask) >> 8
        assert_eq!(decoded(&d, "A").value, 5.0);
        // Unmasked lookup would miss; decode_by_id applies the mask.
        assert!(c.frame(0x18EF0042).is_none());
    }

    #[test]
    fn serial_header_fields_from_bytes() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.serial]
[meta.serial.fields]
length = { mask = 0x0000FF00, format = "decimal" }
[frame.serial.0x10]
length = 4
[[frame.serial.0x10.signals]]
name = "V"
start_bit = 16
bit_length = 8
"#,
        );
        // bytes: [id=0x10, length=0x07, payload...]; the length field is byte 1.
        let d = decode_by_id(&c, 0x10, &[0x10, 0x07, 0xAB, 0x00]).expect("decodes");
        let len = d.header_fields.iter().find(|h| h.name == "length").unwrap();
        assert_eq!(len.value, 0x07);
        assert_eq!(len.display, "7");
        assert_eq!(decoded(&d, "V").value, 0xAB as f64);
    }

    #[test]
    fn mask_to_byte_position_spans() {
        assert_eq!(mask_to_byte_position(0x000000FF), Some((0, 1)));
        assert_eq!(mask_to_byte_position(0x0000FF00), Some((1, 1)));
        assert_eq!(mask_to_byte_position(0x0000FFFF), Some((0, 2)));
        assert_eq!(mask_to_byte_position(0), None);
    }

    #[test]
    fn mux_range_matching() {
        assert!(mux_case_matches(3, "0-3"));
        assert!(!mux_case_matches(4, "0-3"));
        assert!(mux_case_matches(5, "1,2,5"));
        assert!(mux_case_matches(11, "0-3,7,10-12"));
        assert_eq!(find_matching_mux_case(7, ["0-3", "7", "8"]), Some("7"));
    }
}
