//! Parse a TOML catalogue into the unified [`Catalog`] model.
//!
//! This is a Rust port of WireTAP's `src/utils/catalogParser.ts`
//! (`parseCatalogText`): it resolves the CAN/Serial frame sections including
//! mirror/copy inheritance and header-field masks, and reuses
//! [`crate::modbus::ModbusManifest`] for the Modbus section so the two Modbus
//! authoring shorthands (register-from-key, signal-less register) stay
//! single-sourced.

use std::collections::BTreeMap;

use toml::Value;

use crate::modbus::{ManifestError, ModbusManifest};
use crate::modbus_rtu_stream::{
    rtu_options_for, LengthRule, ModbusRtuOptions, Selector, VendorLen,
};
use crate::model::*;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalogue is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
}

/// A catalogue's name and Modbus RTU rules, read without the rest of its model.
#[derive(Debug, Clone, PartialEq)]
pub struct RtuRules {
    pub name: String,
    pub options: ModbusRtuOptions,
}

#[derive(Debug, thiserror::Error)]
pub enum RtuRulesError {
    #[error("catalogue is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("{}", .0.iter().map(|f| format!("{}: {}", f.field, f.message)).collect::<Vec<_>>().join("; "))]
    Rules(Vec<ValidationError>),
}

/// What [`Catalog::parse`] then [`Catalog::rtu_options`] would give, refusing a
/// rule the parser would drop rather than leaving its code to the CRC search.
pub fn rtu_rules(text: &str) -> Result<RtuRules, RtuRulesError> {
    let root: Value = toml::from_str(text)?;
    let mut findings = Vec::new();
    if let Some(table) = root.as_table() {
        crate::validate::require_meta_name(table, &mut findings);
    }
    let section = modbus_section(&root);
    if let Some(codes) = section.and_then(|s| get(s, "function_code")) {
        crate::validate::validate_function_codes(codes, &mut findings);
    }
    if !findings.is_empty() {
        return Err(RtuRulesError::Rules(findings));
    }
    Ok(RtuRules {
        name: meta_name(&root),
        options: section
            .map(|s| rtu_options_for(&parse_function_codes(s)))
            .unwrap_or_default(),
    })
}

fn modbus_section(root: &Value) -> Option<&Value> {
    get(root, "meta").and_then(|m| get(m, "modbus"))
}

fn meta_name(root: &Value) -> String {
    get(root, "meta")
        .and_then(|m| as_str(m, "name"))
        .unwrap_or("")
        .to_string()
}

// ---------- small typed accessors over toml::Value ----------

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_table().and_then(|t| t.get(key))
}

fn as_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    get(v, key).and_then(Value::as_str)
}

fn as_i64(v: &Value, key: &str) -> Option<i64> {
    get(v, key).and_then(Value::as_integer)
}

/// A number that may be written as an integer or float in TOML.
fn as_f64(v: &Value, key: &str) -> Option<f64> {
    get(v, key).and_then(|n| n.as_float().or_else(|| n.as_integer().map(|i| i as f64)))
}

fn as_bool(v: &Value, key: &str) -> Option<bool> {
    get(v, key).and_then(Value::as_bool)
}

fn as_u32(v: &Value, key: &str) -> Option<u32> {
    as_i64(v, key).and_then(|i| u32::try_from(i).ok())
}

fn as_u8(v: &Value, key: &str) -> Option<u8> {
    as_i64(v, key).and_then(|i| u8::try_from(i).ok())
}

fn as_u16(v: &Value, key: &str) -> Option<u16> {
    as_i64(v, key).and_then(|i| u16::try_from(i).ok())
}

/// A byte offset, in three states: absent (`Some(None)`), a usable signed
/// integer (`Some(Some(n))`), or present but unusable (`None`).
///
/// The third state is the point. A *present* value that will not fit is an
/// authoring error, not a default — it drops the whole checksum rather than
/// quietly reading as 0, because a checksum calculated over the wrong bytes is
/// worse than one that is missing. That silent `unwrap_or(0)` was the open bug
/// this replaces.
fn byte_offset(v: &Value, key: &str) -> Option<Option<i32>> {
    match get(v, key) {
        None => Some(None),
        Some(raw) => raw
            .as_integer()
            .and_then(|i| i32::try_from(i).ok())
            .map(Some),
    }
}

fn parse_checksum_parameters(c: &Value) -> ChecksumParameters {
    ChecksumParameters {
        polynomial: as_u16(c, "polynomial"),
        init: as_u16(c, "init"),
        xor_out: as_u16(c, "xor_out"),
        reflect_in: as_bool(c, "reflect_in"),
        reflect_out: as_bool(c, "reflect_out"),
        offset: as_u8(c, "offset"),
    }
}

fn parse_endianness(s: &str) -> Option<Endianness> {
    match s {
        "big" => Some(Endianness::Big),
        "little" => Some(Endianness::Little),
        _ => None,
    }
}

fn endianness_at(v: &Value, key: &str) -> Option<Endianness> {
    as_str(v, key).and_then(parse_endianness)
}

fn parse_format(s: &str) -> Option<SignalFormat> {
    match s {
        "enum" => Some(SignalFormat::Enum),
        "ascii" => Some(SignalFormat::Ascii),
        "utf8" => Some(SignalFormat::Utf8),
        "hex" => Some(SignalFormat::Hex),
        "unix_time" => Some(SignalFormat::UnixTime),
        _ => None,
    }
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    match s {
        "none" => Some(Confidence::None),
        "low" => Some(Confidence::Low),
        "medium" => Some(Confidence::Medium),
        "high" => Some(Confidence::High),
        _ => None,
    }
}

/// Parse a CAN/serial/modbus id key (hex `0x..` or decimal) to a number.
/// Mirrors `parseCanId`.
pub fn parse_id(id: &str) -> Option<u32> {
    let t = id.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty() {
        t.parse::<u32>().ok()
    } else {
        None
    }
}

/// Find a frame body in a section by its numeric id value (so `0x123` and `291`
/// match). Mirrors `findFrameByNumericId`.
fn find_frame_by_numeric_id<'a>(target: &str, section: &'a Value) -> Option<&'a Value> {
    let target_num = parse_id(target)?;
    let table = section.as_table()?;
    table
        .iter()
        .find(|(k, _)| parse_id(k) == Some(target_num))
        .map(|(_, v)| v)
}

/// `value` may be a number (`copy = 291`) or a string (`copy = "0x123"`).
fn id_ref_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

// ---------- signals / mux ----------

/// Port of `normaliseSignal`: map `byte_order` → `endianness`, carry fields.
fn normalise_signal(raw: &Value, inherited: bool) -> Signal {
    let endianness = endianness_at(raw, "byte_order").or_else(|| endianness_at(raw, "endianness"));
    Signal {
        name: as_str(raw, "name").map(str::to_string),
        start_bit: as_u32(raw, "start_bit"),
        bit_length: as_u32(raw, "bit_length"),
        signed: as_bool(raw, "signed"),
        endianness,
        word_order: endianness_at(raw, "word_order"),
        factor: as_f64(raw, "factor"),
        offset: as_f64(raw, "offset"),
        unit: as_str(raw, "unit").map(str::to_string),
        min: as_f64(raw, "min"),
        max: as_f64(raw, "max"),
        format: as_str(raw, "format").and_then(parse_format),
        enum_map: parse_enum_map(get(raw, "enum")),
        confidence: as_str(raw, "confidence").and_then(parse_confidence),
        display: get(raw, "display").and_then(DisplayHint::from_toml),
        inherited: inherited || as_bool(raw, "_inherited").unwrap_or(false),
        notes: parse_notes(raw),
        ..Default::default()
    }
}

fn parse_enum_map(v: Option<&Value>) -> Option<BTreeMap<i64, String>> {
    let table = v?.as_table()?;
    let mut out = BTreeMap::new();
    for (k, val) in table {
        if let (Ok(key), Some(label)) = (k.parse::<i64>(), val.as_str()) {
            out.insert(key, label.to_string());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn normalise_signals(arr: Option<&Value>, inherited: bool) -> Vec<Signal> {
    arr.and_then(Value::as_array)
        .map(|a| a.iter().map(|s| normalise_signal(s, inherited)).collect())
        .unwrap_or_default()
}

/// Whether a mux table key denotes a case (numeric, range `0-3`, or list
/// `1,2,5`) rather than a reserved key. Mirrors `isMuxCaseKey`.
fn is_mux_case_key(key: &str) -> bool {
    if matches!(key, "name" | "start_bit" | "bit_length" | "default") {
        return false;
    }
    key.split(',').all(|part| {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => {
                !a.is_empty()
                    && a.chars().all(|c| c.is_ascii_digit())
                    && !b.is_empty()
                    && b.chars().all(|c| c.is_ascii_digit())
            }
            None => !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()),
        }
    })
}

/// Port of `parseMux`.
fn parse_mux(mux: Option<&Value>, inherited: bool) -> Option<Mux> {
    let mux = mux?;
    let table = mux.as_table()?;
    let mut cases = BTreeMap::new();
    for (key, case_data) in table {
        if !is_mux_case_key(key) {
            continue;
        }
        let signals = normalise_signals(get(case_data, "signals"), inherited);
        let nested = parse_mux(get(case_data, "mux"), inherited).map(Box::new);
        cases.insert(
            key.clone(),
            MuxCase {
                signals,
                mux: nested,
                notes: parse_notes(case_data),
            },
        );
    }
    Some(Mux {
        name: as_str(mux, "name").map(str::to_string),
        start_bit: as_u32(mux, "start_bit").unwrap_or(0),
        bit_length: as_u32(mux, "bit_length").unwrap_or(8),
        default: as_str(mux, "default").map(str::to_string),
        notes: parse_notes(mux),
        cases,
    })
}

/// Normalise the `notes` key (a string or an array of strings) to a list.
fn parse_notes(body: &Value) -> Vec<String> {
    match get(body, "notes") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse a serial frame's `delimiter` byte array.
fn parse_delimiter(body: &Value) -> Option<Vec<u8>> {
    let arr = get(body, "delimiter")?.as_array()?;
    let bytes: Vec<u8> = arr
        .iter()
        .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
        .collect();
    (!bytes.is_empty()).then_some(bytes)
}

/// An authored Modbus register number as its protocol (wire) address. Base 0
/// passes through; base 1 strips the traditional type prefix. The unified-model
/// counterpart of [`crate::modbus::ModbusManifest::protocol_address`].
fn protocol_address(register_number: u32, register_type: RegisterType, base_one: bool) -> u32 {
    if !base_one {
        return register_number;
    }
    register_number.saturating_sub(register_type.base_one_prefix())
}

/// Parse a frame's `[…tunnel]` table. An unrecognised `protocol` yields `None`
/// here; [`crate::validate`] reports it rather than the parser failing the file.
fn parse_tunnel(body: &Value) -> Option<FrameTunnel> {
    let t = get(body, "tunnel")?;
    let protocol = match as_str(t, "protocol")? {
        "modbus_rtu" => TunnelProtocol::ModbusRtu,
        _ => return None,
    };
    Some(FrameTunnel {
        protocol,
        device_address: as_u8(t, "device_address"),
        vendor_functions: as_u8_array(t, "vendor_functions"),
        allow_broadcast: as_bool(t, "allow_broadcast").unwrap_or(false),
        notes: parse_notes(t),
    })
}

/// A TOML array of bytes, empty when the key is absent or holds anything else.
fn as_u8_array(body: &Value, key: &str) -> Vec<u8> {
    let Some(arr) = get(body, key).and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
        .collect()
}

/// A `[meta.modbus.function_code.<code>]` key as its code.
pub(crate) fn parse_function_code_key(key: &str) -> Option<u8> {
    parse_id(key).and_then(|code| u8::try_from(code).ok())
}

/// One `lengths` rule, or `None` for one that is malformed.
pub(crate) fn parse_length_rule(rule: &Value) -> Option<LengthRule> {
    let when = match get(rule, "when") {
        None => None,
        Some(w) => Some(Selector {
            offset: as_u8(w, "offset")?,
            value: as_u8(w, "value")?,
        }),
    };
    let len = get(rule, "len")?;
    let len = match (
        as_u16(len, "fixed"),
        as_u8(len, "count_at"),
        as_u16(len, "overhead"),
    ) {
        (Some(fixed), None, None) => VendorLen::Fixed(fixed),
        (None, Some(count_at), Some(overhead)) => VendorLen::Counted { count_at, overhead },
        _ => return None,
    };
    Some(LengthRule { when, len })
}

/// A code with a malformed key is dropped, and a malformed rule from its code,
/// for [`crate::validate`] to report.
fn parse_function_codes(section: &Value) -> BTreeMap<u8, FunctionCode> {
    let Some(codes) = get(section, "function_code").and_then(Value::as_table) else {
        return BTreeMap::new();
    };
    codes
        .iter()
        .filter_map(|(key, body)| {
            let code = FunctionCode {
                name: as_str(body, "name").map(str::to_string),
                lengths: get(body, "lengths")
                    .and_then(Value::as_array)
                    .map(|rules| rules.iter().filter_map(parse_length_rule).collect())
                    .unwrap_or_default(),
                notes: parse_notes(body),
            };
            Some((parse_function_code_key(key)?, code))
        })
        .collect()
}

/// Parse per-frame `[[…checksum]]` (array) or `[…checksum]` (single table).
fn parse_frame_checksums(body: &Value) -> Vec<FrameChecksum> {
    let one_checksum = |c: &Value| -> Option<FrameChecksum> {
        Some(FrameChecksum {
            name: as_str(c, "name").map(str::to_string),
            algorithm: as_str(c, "algorithm")?.to_string(),
            start_byte: byte_offset(c, "start_byte")??,
            byte_length: as_u32(c, "byte_length").unwrap_or(1),
            endianness: endianness_at(c, "byte_order").or_else(|| endianness_at(c, "endianness")),
            calc_start_byte: byte_offset(c, "calc_start_byte")?.unwrap_or(0),
            calc_end_byte: byte_offset(c, "calc_end_byte")?,
            parameters: parse_checksum_parameters(c),
            notes: parse_notes(c),
        })
    };
    match get(body, "checksum") {
        Some(Value::Array(a)) => a.iter().filter_map(one_checksum).collect(),
        Some(t @ Value::Table(_)) => one_checksum(t).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Parse the `[node]` table into ordered peer definitions.
fn parse_nodes(root: &Value) -> Vec<NodeDef> {
    let Some(table) = get(root, "node").and_then(Value::as_table) else {
        return Vec::new();
    };
    table
        .iter()
        .map(|(name, body)| NodeDef {
            name: name.clone(),
            device_address: as_u8(body, "device_address"),
            notes: parse_notes(body),
        })
        .collect()
}

/// Frame poll/tx interval: the canonical top-level `interval_ms` (or `interval`),
/// falling back to the legacy `tx.interval_ms` / `tx.interval`.
fn frame_interval(body: &Value) -> Option<u64> {
    as_i64(body, "interval_ms")
        .or_else(|| as_i64(body, "interval"))
        .or_else(|| {
            let tx = get(body, "tx")?;
            as_i64(tx, "interval_ms").or_else(|| as_i64(tx, "interval"))
        })
        .and_then(|i| u64::try_from(i).ok())
}

// ---------- mirror / copy inheritance ----------

#[derive(Default)]
struct InheritedMeta {
    length: Option<u32>,
    transmitter: Option<String>,
    interval: Option<u64>,
}

struct Resolution {
    signals: Vec<Signal>,
    mux: Option<Mux>,
    mirror_of: Option<String>,
    copy_from: Option<String>,
    inherited: InheritedMeta,
}

fn bit_key(s: &Value) -> String {
    format!(
        "{}:{}",
        as_i64(s, "start_bit").unwrap_or(0),
        as_i64(s, "bit_length").unwrap_or(0)
    )
}

fn raw_signals(body: &Value) -> Vec<Value> {
    get(body, "signals")
        .or_else(|| get(body, "signal"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Port of `resolveMirrorInheritance`.
fn resolve_mirror_inheritance(body: &Value, all_frames: &Value) -> Resolution {
    let copy_from = get(body, "copy").and_then(id_ref_to_string);
    let mirror_of = get(body, "mirror_of").and_then(id_ref_to_string);

    let signals_raw = raw_signals(body);
    let mut mux = get(body, "mux");
    let mut mux_inherited = false;
    let mut inherited = InheritedMeta::default();

    // copy: metadata only.
    if let Some(src) = copy_from
        .as_deref()
        .and_then(|c| find_frame_by_numeric_id(c, all_frames))
    {
        inherit_metadata(body, src, &mut inherited);
    }

    // mirror: signals + metadata.
    let mut result_signals: Vec<Signal>;
    if let Some(src) = mirror_of
        .as_deref()
        .and_then(|m| find_frame_by_numeric_id(m, all_frames))
    {
        let primary = raw_signals(src);
        let mirror_by_pos: BTreeMap<String, &Value> =
            signals_raw.iter().map(|s| (bit_key(s), s)).collect();

        // Start with primary signals, overridden by position; inherited unless
        // overridden.
        result_signals = primary
            .iter()
            .map(|ps| match mirror_by_pos.get(&bit_key(ps)) {
                Some(over) => normalise_signal(over, false),
                None => normalise_signal(ps, true),
            })
            .collect();

        // Add mirror signals at new positions (not inherited).
        let primary_positions: std::collections::BTreeSet<String> =
            primary.iter().map(bit_key).collect();
        for ms in &signals_raw {
            if !primary_positions.contains(&bit_key(ms)) {
                result_signals.push(normalise_signal(ms, false));
            }
        }

        if mux.is_none() {
            mux = get(src, "mux");
            mux_inherited = mux.is_some();
        }

        // Inherit metadata unless this frame is also a copy (copy already did it).
        if copy_from.is_none() {
            inherit_metadata(body, src, &mut inherited);
        }
    } else {
        result_signals = signals_raw
            .iter()
            .map(|s| normalise_signal(s, false))
            .collect();
    }

    Resolution {
        signals: result_signals,
        mux: parse_mux(mux, mux_inherited),
        mirror_of,
        copy_from,
        inherited,
    }
}

fn inherit_metadata(body: &Value, src: &Value, out: &mut InheritedMeta) {
    if as_i64(body, "length").is_none() {
        if let Some(len) = as_u32(src, "length") {
            out.length = Some(len);
        }
    }
    if as_str(body, "transmitter").is_none() {
        if let Some(tx) = as_str(src, "transmitter") {
            out.transmitter = Some(tx.to_string());
        }
    }
    if frame_interval(body).is_none() {
        if let Some(iv) = frame_interval(src) {
            out.interval = Some(iv);
        }
    }
}

// ---------- protocol configs ----------

fn parse_header_fields(section: Option<&Value>, serial: bool) -> BTreeMap<String, HeaderField> {
    let mut out = BTreeMap::new();
    let Some(table) = section.and_then(Value::as_table) else {
        return out;
    };
    for (name, def) in table {
        // mask, or (serial only) legacy start_byte + bytes.
        let mask = if let Some(m) = as_u32(def, "mask") {
            m
        } else if serial {
            match as_u32(def, "start_byte") {
                Some(start_byte) => {
                    let bytes = as_u32(def, "bytes").unwrap_or(1);
                    let num_bits = bytes * 8;
                    let base = if num_bits >= 32 {
                        u32::MAX
                    } else {
                        (1u32 << num_bits) - 1
                    };
                    base.wrapping_shl(start_byte * 8)
                }
                None => continue,
            }
        } else {
            continue;
        };

        let endianness =
            endianness_at(def, "endianness").or_else(|| endianness_at(def, "byte_order"));
        let format = as_str(def, "format")
            .filter(|f| *f == "hex" || *f == "decimal")
            .map(str::to_string);
        out.insert(
            name.clone(),
            HeaderField {
                mask,
                shift: as_u32(def, "shift"),
                format,
                endianness,
            },
        );
    }
    out
}

fn parse_can_config(root: &Value) -> Option<CanConfig> {
    let section = get(root, "meta").and_then(|m| get(m, "can")).or_else(|| {
        get(root, "frame")
            .and_then(|f| get(f, "can"))
            .and_then(|c| get(c, "config"))
    })?;

    let cfg = CanConfig {
        default_byte_order: endianness_at(section, "default_byte_order")
            .or_else(|| endianness_at(section, "default_endianness")),
        default_interval: as_i64(section, "default_interval").and_then(|i| u64::try_from(i).ok()),
        default_extended: as_bool(section, "default_extended"),
        default_fd: as_bool(section, "default_fd"),
        frame_id_mask: as_u32(section, "frame_id_mask"),
        fields: parse_header_fields(get(section, "fields"), false),
    };
    if cfg == CanConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

fn parse_serial_config(root: &Value) -> Option<SerialConfig> {
    let section = get(root, "meta").and_then(|m| get(m, "serial"))?;

    let encoding = as_str(section, "encoding")
        .filter(|e| matches!(*e, "slip" | "cobs" | "raw" | "length_prefixed"))
        .map(str::to_string);

    let checksum = get(section, "checksum").and_then(parse_checksum);
    let fields = parse_header_fields(get(section, "fields"), true);

    // Derive byte positions from the field masks once, here, so consumers
    // (WireTAP's adapter, decode) don't each re-derive them.
    let mut cfg = SerialConfig {
        encoding,
        byte_order: endianness_at(section, "byte_order"),
        frame_id_mask: as_u32(section, "frame_id_mask"),
        header_length: as_u32(section, "header_length"),
        min_frame_length: as_u32(section, "min_frame_length"),
        checksum,
        fields,
        ..SerialConfig::default()
    };
    for (name, field) in &cfg.fields {
        let Some((start_byte, bytes)) = crate::decode::mask_to_byte_position(field.mask) else {
            continue;
        };
        let (start_byte, bytes) = (start_byte as u32, bytes as u32);
        let byte_order = field.endianness.unwrap_or(Endianness::Big);
        cfg.header_fields.push(HeaderFieldPosition {
            name: name.clone(),
            mask: field.mask,
            byte_order,
            format: field.format.clone().unwrap_or_else(|| "hex".to_string()),
            start_byte,
            bytes,
        });
        match name.as_str() {
            "id" => {
                cfg.frame_id_start_byte = Some(start_byte);
                cfg.frame_id_bytes = Some(bytes);
                cfg.frame_id_byte_order = Some(byte_order);
            }
            "source_address" => {
                cfg.source_address_start_byte = Some(start_byte);
                cfg.source_address_bytes = Some(bytes);
                cfg.source_address_byte_order = Some(byte_order);
            }
            _ => {}
        }
    }

    if cfg == SerialConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

fn parse_checksum(section: &Value) -> Option<ChecksumConfig> {
    let algorithm = as_str(section, "algorithm")?.to_string();
    Some(ChecksumConfig {
        algorithm,
        start_byte: byte_offset(section, "start_byte")??,
        byte_length: as_u32(section, "byte_length").unwrap_or(1),
        calc_start_byte: byte_offset(section, "calc_start_byte")?.unwrap_or(0),
        calc_end_byte: byte_offset(section, "calc_end_byte")?,
        big_endian: as_bool(section, "big_endian").unwrap_or(false),
    })
}

fn parse_modbus_config(root: &Value) -> Option<ModbusConfig> {
    let section = modbus_section(root)?;
    let register_base = match as_i64(section, "register_base") {
        Some(0) => Some(0),
        Some(1) => Some(1),
        _ => None,
    };
    let cfg = ModbusConfig {
        device_address: as_u8(section, "device_address"),
        register_base,
        default_interval: as_i64(section, "default_interval").and_then(|i| u64::try_from(i).ok()),
        default_byte_order: endianness_at(section, "default_byte_order")
            .or_else(|| endianness_at(section, "byte_order")),
        default_word_order: endianness_at(section, "default_word_order"),
        function_codes: parse_function_codes(section),
    };
    if cfg == ModbusConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

// ---------- modbus frame mapping (reuse ModbusManifest) ----------

fn map_modbus_signal(
    s: &crate::modbus::ModbusSignal,
    base_register: u32,
    register_type: RegisterType,
) -> Signal {
    let enum_map = s.enum_map.as_ref().map(|m| {
        m.iter()
            .filter_map(|(k, v)| k.parse::<i64>().ok().map(|n| (n, v.clone())))
            .collect::<BTreeMap<i64, String>>()
    });
    Signal {
        name: Some(s.name.clone()),
        start_bit: Some(s.start_bit),
        bit_length: Some(s.bit_length),
        signed: Some(s.signed),
        endianness: s.byte_order,
        word_order: s.word_order,
        factor: s.factor,
        offset: s.offset,
        unit: s.unit.clone(),
        format: s.format,
        enum_map: enum_map.filter(|m| !m.is_empty()),
        display: s.display.clone(),
        // The signal's own address and span, from its bit offset within the
        // frame's block.
        modbus_register: Some(base_register + register_type.address_offset(s.start_bit)),
        modbus_register_count: Some(register_type.address_span(s.bit_length)),
        ..Default::default()
    }
}

fn modbus_frames(text: &str) -> Vec<Frame> {
    let manifest = match ModbusManifest::parse(text) {
        Ok(m) => m,
        Err(ManifestError::NoFrames) => return Vec::new(),
        // A parse error here means the modbus section is malformed; CAN/serial
        // frames still parse independently, so we just skip modbus frames.
        Err(_) => return Vec::new(),
    };
    manifest
        .frames
        .iter()
        .map(|f| {
            Frame {
                key: f.name.clone(),
                frame_id: f.register_number as u32,
                protocol: Protocol::Modbus,
                name: Some(f.name.clone()),
                length: f.register_type.data_bytes(f.length) as u32,
                transmitter: None,
                // ModbusFrame.interval_ms is already resolved (frame tx → meta
                // default → built-in default).
                interval: Some(f.interval_ms),
                bus: None,
                is_extended: None,
                is_fd: None,
                signals: f
                    .signals
                    .iter()
                    .map(|s| map_modbus_signal(s, f.register_number as u32, f.register_type))
                    .collect(),
                mux: None,
                tunnel: None,
                mirror_of: None,
                copy_from: None,
                modbus_register_type: Some(f.register_type),
                modbus_register_count: Some(f.length),
                modbus_node: f.node.clone(),
                modbus_device_address: Some(f.device_address),
                delimiter: None,
                // notes + inherited_fields are filled by a post-pass in
                // `parse()` (the manifest doesn't carry the raw frame body).
                notes: Vec::new(),
                checksums: Vec::new(),
                inherited_fields: Vec::new(),
            }
        })
        .collect()
}

// ---------- top-level ----------

impl Catalog {
    /// Parse a TOML catalogue into the resolved model. Mirrors
    /// `parseCatalogText`.
    pub fn parse(text: &str) -> Result<Catalog, CatalogError> {
        let root: Value = toml::from_str(text)?;

        let meta = Meta {
            name: meta_name(&root),
            version: get(&root, "meta")
                .and_then(|m| as_u32(m, "version"))
                .unwrap_or(1),
            default_frame: get(&root, "meta")
                .and_then(|m| as_str(m, "default_frame"))
                .and_then(|p| match p {
                    "can" => Some(Protocol::Can),
                    "serial" => Some(Protocol::Serial),
                    "modbus" => Some(Protocol::Modbus),
                    _ => None,
                }),
        };

        let can = parse_can_config(&root);
        let serial = parse_serial_config(&root);
        let modbus = parse_modbus_config(&root);

        let empty = Value::Table(Default::default());
        let can_frames = get(&root, "frame")
            .and_then(|f| get(f, "can"))
            .unwrap_or(&empty);
        let serial_frames = get(&root, "frame")
            .and_then(|f| get(f, "serial"))
            .unwrap_or(&empty);
        let modbus_frames_section = get(&root, "frame")
            .and_then(|f| get(f, "modbus"))
            .unwrap_or(&empty);

        let mut frames: Vec<Frame> = Vec::new();

        // CAN frames.
        if let Some(table) = can_frames.as_table() {
            for (id_key, body) in table {
                if id_key == "config" {
                    continue;
                }
                let Some(num_id) = parse_id(id_key) else {
                    continue;
                };
                let resolved = resolve_mirror_inheritance(body, can_frames);
                let length = as_u32(body, "length")
                    .or(resolved.inherited.length)
                    .unwrap_or(8);
                let is_extended = as_bool(body, "extended")
                    .or(can.as_ref().and_then(|c| c.default_extended))
                    .unwrap_or(num_id > 0x7ff);
                let is_fd = as_bool(body, "fd")
                    .or(can.as_ref().and_then(|c| c.default_fd))
                    .unwrap_or(false);
                // Interval: explicit → copy/mirror source → catalogue default.
                let default_interval = can.as_ref().and_then(|c| c.default_interval);
                let interval = frame_interval(body)
                    .or(resolved.inherited.interval)
                    .or(default_interval);

                // Track which fields were inherited rather than set explicitly
                // (mirrors the per-protocol handlers in the TS catalog parser).
                let mut inherited_fields = Vec::new();
                if as_i64(body, "length").is_none() && resolved.inherited.length.is_some() {
                    inherited_fields.push("length".to_string());
                }
                if as_str(body, "transmitter").is_none() && resolved.inherited.transmitter.is_some()
                {
                    inherited_fields.push("transmitter".to_string());
                }
                if frame_interval(body).is_none() && interval.is_some() {
                    inherited_fields.push("interval".to_string());
                }
                // `extended` is inherited whenever not set explicitly (whether
                // from the catalogue default or auto-detected from the id).
                if as_bool(body, "extended").is_none() {
                    inherited_fields.push("extended".to_string());
                }
                if as_bool(body, "fd").is_none()
                    && can.as_ref().and_then(|c| c.default_fd).is_some()
                {
                    inherited_fields.push("fd".to_string());
                }

                frames.push(Frame {
                    key: id_key.clone(),
                    frame_id: num_id,
                    protocol: Protocol::Can,
                    name: None,
                    length,
                    transmitter: as_str(body, "transmitter")
                        .map(str::to_string)
                        .or(resolved.inherited.transmitter),
                    interval,
                    bus: as_u32(body, "bus"),
                    is_extended: Some(is_extended),
                    is_fd: Some(is_fd),
                    signals: resolved.signals,
                    mux: resolved.mux,
                    tunnel: parse_tunnel(body),
                    mirror_of: resolved.mirror_of,
                    copy_from: resolved.copy_from,
                    modbus_register_type: None,
                    modbus_register_count: None,
                    modbus_node: None,
                    modbus_device_address: None,
                    delimiter: None,
                    notes: parse_notes(body),
                    checksums: parse_frame_checksums(body),
                    inherited_fields,
                });
            }
        }

        // Serial frames (no inheritance).
        if let Some(table) = serial_frames.as_table() {
            for (id_key, body) in table {
                if id_key == "config" {
                    continue;
                }
                let Some(num_id) = parse_id(id_key) else {
                    continue;
                };
                frames.push(Frame {
                    key: id_key.clone(),
                    frame_id: num_id,
                    protocol: Protocol::Serial,
                    name: None,
                    length: as_u32(body, "length").unwrap_or(0),
                    transmitter: as_str(body, "transmitter").map(str::to_string),
                    interval: frame_interval(body),
                    bus: as_u32(body, "bus"),
                    is_extended: None,
                    is_fd: None,
                    signals: normalise_signals(get(body, "signals"), false),
                    mux: parse_mux(get(body, "mux"), false),
                    // Tunnels are CAN-only: a serial source is already a byte
                    // stream, and `FramingEncoding::ModbusRtu` frames it there.
                    tunnel: None,
                    mirror_of: None,
                    copy_from: None,
                    modbus_register_type: None,
                    modbus_register_count: None,
                    modbus_node: None,
                    modbus_device_address: None,
                    delimiter: parse_delimiter(body),
                    notes: parse_notes(body),
                    checksums: parse_frame_checksums(body),
                    inherited_fields: Vec::new(),
                });
            }
        }

        // Modbus frames (reuse ModbusManifest for shorthands). The manifest
        // drops the raw frame body, so backfill notes + inheritance flags from
        // the `[frame.modbus]` table here (device address / register base come
        // from `[meta.modbus]`, so they're always inherited when present).
        let modbus_base = frames.len();
        frames.extend(modbus_frames(text));
        let modbus_default_interval = modbus.as_ref().and_then(|m| m.default_interval);
        for frame in &mut frames[modbus_base..] {
            let body = get(modbus_frames_section, &frame.key);
            frame.notes = body.map(parse_notes).unwrap_or_default();
            let mut inherited = Vec::new();
            // The device address is never set on the register itself — it's
            // resolved from the assigned node (or the legacy `[meta.modbus]`
            // default), so it's always inherited.
            if frame.modbus_device_address.is_some() {
                inherited.push("deviceAddress".to_string());
            }
            if modbus.as_ref().and_then(|m| m.register_base).is_some() {
                inherited.push("registerBase".to_string());
            }
            let explicit_interval = body.and_then(frame_interval);
            if explicit_interval.is_none() && modbus_default_interval.is_some() {
                inherited.push("interval".to_string());
            }
            frame.inherited_fields = inherited;
        }

        // Protocol determination (mirror TS).
        let has = |section: &Value| {
            section
                .as_table()
                .map(|t| t.keys().any(|k| k != "config"))
                .unwrap_or(false)
        };
        let has_can = has(can_frames);
        let has_serial = has(serial_frames);
        let has_modbus = has(modbus_frames_section);
        let protocol = match meta.default_frame {
            Some(p) => p,
            None if has_modbus && !has_can && !has_serial => Protocol::Modbus,
            None if has_serial && !has_can => Protocol::Serial,
            None => Protocol::Can,
        };

        // Migration: a legacy modbus catalogue carries its slave address on
        // `[meta.modbus].device_address` with no `[node]` tables. Synthesise a
        // slave node and attach the orphaned registers to it so the editor shows
        // them grouped (display-only until the catalogue is re-saved).
        let mut nodes = parse_nodes(&root);
        if has_modbus && nodes.is_empty() {
            if let Some(addr) = frames[modbus_base..]
                .iter()
                .find_map(|f| f.modbus_device_address)
            {
                let name = crate::migrate::slave_node_name(addr);
                for frame in &mut frames[modbus_base..] {
                    if frame.modbus_node.is_none() {
                        frame.modbus_node = Some(name.clone());
                    }
                }
                nodes.push(NodeDef {
                    name,
                    device_address: Some(addr),
                    notes: Vec::new(),
                });
            }
        }

        Ok(Catalog {
            meta,
            protocol,
            can,
            serial,
            modbus,
            frames,
            nodes,
        })
    }

    /// Find a parsed frame by its numeric id.
    pub fn frame(&self, id: u32) -> Option<&Frame> {
        self.frames.iter().find(|f| f.frame_id == id)
    }

    /// Find the Modbus register frame at protocol (wire) address `register`,
    /// for `register_type` and (when the frame names one) `device_address`.
    ///
    /// Protocol-filtered on purpose: [`Self::frame`] matches on `frame_id`
    /// alone, so in a catalogue holding both — a CAN tunnel and the registers
    /// it carries — CAN id `0x1E0` and Modbus register 480 are the same lookup.
    ///
    /// `register` is always the address as it appeared on the wire; a catalogue
    /// authored in the traditional 1-based `3xxxx`/`4xxxx` form is converted to
    /// match, so callers never have to know which form was used.
    pub fn modbus_register_frame(
        &self,
        register: u16,
        register_type: RegisterType,
        device_address: u8,
    ) -> Option<&Frame> {
        self.modbus_frames_by_address(register_type, device_address)
            .find(|&(address, _)| address == u32::from(register))
            .map(|(_, f)| f)
    }

    /// Every Modbus frame a read of `quantity` from `start` holds whole, matched
    /// as [`Self::modbus_register_frame`] matches, with its offset in addresses
    /// from `start`, in offset order.
    ///
    /// A frame the window cuts is left out: decoding it from a short slice
    /// would read its missing registers as zero.
    pub fn modbus_register_frames_within(
        &self,
        start: u16,
        quantity: u16,
        register_type: RegisterType,
        device_address: u8,
    ) -> Vec<(u16, &Frame)> {
        let window = u32::from(start)..u32::from(start) + u32::from(quantity);
        let mut within: Vec<(u16, &Frame)> = self
            .modbus_frames_by_address(register_type, device_address)
            .filter(|&(address, f)| {
                let end = address + u32::from(f.modbus_register_count.unwrap_or_default());
                window.contains(&address) && end <= window.end
            })
            .map(|(address, f)| ((address - window.start) as u16, f))
            .collect();
        within.sort_by_key(|&(offset, _)| offset);
        within
    }

    fn modbus_frames_by_address(
        &self,
        register_type: RegisterType,
        device_address: u8,
    ) -> impl Iterator<Item = (u32, &Frame)> {
        let base_one = self.modbus.as_ref().and_then(|m| m.register_base) == Some(1);
        self.frames
            .iter()
            .filter(move |f| {
                f.protocol == Protocol::Modbus
                    && f.modbus_register_type == Some(register_type)
                    && f.modbus_device_address.is_none_or(|a| a == device_address)
            })
            .map(move |f| (protocol_address(f.frame_id, register_type, base_one), f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig<'a>(f: &'a Frame, name: &str) -> &'a Signal {
        f.signals
            .iter()
            .find(|s| s.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("signal {name} present"))
    }

    #[test]
    fn preserves_authored_key_and_tracks_inheritance() {
        let toml = r#"
[meta]
name = "x"
[meta.can]
default_interval = 500
default_fd = true
[frame.can.0x100]
length = 8
transmitter = "ECU1"
[frame.can.0x101]
copy = "0x100"
"#;
        let c = Catalog::parse(toml).unwrap();
        let base = c.frame(0x100).unwrap();
        assert_eq!(base.key, "0x100"); // authored key preserved (frame_id is numeric)
                                       // 0x100: extended auto-detected, fd from default, interval from default.
        assert!(base.inherited_fields.contains(&"extended".to_string()));
        assert!(base.inherited_fields.contains(&"fd".to_string()));
        assert!(base.inherited_fields.contains(&"interval".to_string()));
        assert!(!base.inherited_fields.contains(&"length".to_string()));
        // 0x101 copies 0x100: length + transmitter inherited from the copy source.
        let cp = c.frame(0x101).unwrap();
        assert_eq!(cp.length, 8);
        assert_eq!(cp.transmitter.as_deref(), Some("ECU1"));
        assert!(cp.inherited_fields.contains(&"length".to_string()));
        assert!(cp.inherited_fields.contains(&"transmitter".to_string()));
    }

    #[test]
    fn modbus_register_resolves_address_from_its_node() {
        let toml = r#"
[meta]
name = "x"
default_frame = "modbus"
[meta.modbus]
register_base = 0
[node."Slave 1"]
device_address = 1
[node.Battery]
device_address = 3
[frame.modbus.grid_power]
register_number = 5083
node_address = 1
[frame.modbus.battery_soc]
register_number = 13022
node_address = 3
"#;
        let c = Catalog::parse(toml).unwrap();
        let grid = c.frame(5083).unwrap();
        assert_eq!(grid.modbus_node.as_deref(), Some("Slave 1"));
        assert_eq!(grid.modbus_device_address, Some(1));
        let batt = c.frame(13022).unwrap();
        assert_eq!(batt.modbus_node.as_deref(), Some("Battery"));
        assert_eq!(batt.modbus_device_address, Some(3));
        // The device address is resolved (from the node), so it's inherited.
        assert!(batt.inherited_fields.contains(&"deviceAddress".to_string()));
        // Both declared nodes survive, each carrying its address.
        assert_eq!(c.nodes.len(), 2);
        assert_eq!(
            c.nodes
                .iter()
                .find(|n| n.name == "Battery")
                .unwrap()
                .device_address,
            Some(3)
        );
    }

    #[test]
    fn parses_a_can_tunnel_declaration() {
        let toml = r#"
[meta]
name = "x"
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "modbus_rtu"
device_address = 1
notes = "Inverter <-> BMS Modbus RTU"
[frame.can."0x200"]
length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let t = c.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        assert_eq!(t.protocol, TunnelProtocol::ModbusRtu);
        assert_eq!(t.device_address, Some(1));
        assert_eq!(t.notes, vec!["Inverter <-> BMS Modbus RTU".to_string()]);
        // Absent means declaring nothing, not defaulting to something.
        assert!(t.vendor_functions.is_empty());
        assert!(!t.allow_broadcast);
        // A frame without the table is untouched.
        assert!(c.frame(0x200).unwrap().tunnel.is_none());
    }

    #[test]
    fn parses_a_tunnel_declaring_vendor_codes_and_broadcast() {
        let toml = r#"
[meta]
name = "x"
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "modbus_rtu"
device_address = 1
vendor_functions = [0x20, 0x60, 0x65]
allow_broadcast = true
"#;
        let c = Catalog::parse(toml).unwrap();
        let t = c.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        assert_eq!(t.vendor_functions, vec![0x20, 0x60, 0x65]);
        assert!(t.allow_broadcast);
    }

    #[test]
    fn parses_function_codes() {
        let toml = r#"
[meta]
name = "x"
[meta.modbus.function_code.0x60]
name = "Dispatch"
notes = "Broadcast by the logger"
lengths = [{ len = { count_at = 6, overhead = 9 } }]
[meta.modbus.function_code.0x20]
lengths = [
  { when = { offset = 4, value = 0x03 }, len = { fixed = 11 } },
  { len = { fixed = 11, overhead = 7 } },
]
[meta.modbus.function_code.101]
[meta.modbus.function_code.0x160]
"#;
        let c = Catalog::parse(toml).unwrap();
        let codes = &c.modbus.as_ref().unwrap().function_codes;
        // The second 0x20 rule and the 0x160 key are malformed, and dropped for
        // validate() to report.
        let expected = BTreeMap::from([
            (
                0x20,
                FunctionCode {
                    lengths: vec![LengthRule {
                        when: Some(Selector {
                            offset: 4,
                            value: 0x03,
                        }),
                        len: VendorLen::Fixed(11),
                    }],
                    ..FunctionCode::default()
                },
            ),
            (
                0x60,
                FunctionCode {
                    name: Some("Dispatch".into()),
                    lengths: vec![LengthRule {
                        when: None,
                        len: VendorLen::Counted {
                            count_at: 6,
                            overhead: 9,
                        },
                    }],
                    notes: vec!["Broadcast by the logger".into()],
                },
            ),
            (0x65, FunctionCode::default()),
        ]);
        assert_eq!(codes, &expected);

        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(
            json["modbus"]["functionCodes"]["96"],
            serde_json::json!({
                "name": "Dispatch",
                "lengths": [{ "len": { "countAt": 6, "overhead": 9 } }],
                "notes": ["Broadcast by the logger"],
            })
        );
        assert_eq!(serde_json::from_value::<Catalog>(json).unwrap(), c);
    }

    #[test]
    fn an_unknown_tunnel_protocol_parses_as_no_tunnel() {
        // validate() reports it; the parser must not fail the whole file.
        let toml = r#"
[meta]
name = "x"
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "carrier_pigeon"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert!(c.frame(0x1E0).unwrap().tunnel.is_none());
    }

    #[test]
    fn modbus_register_lookup_is_protocol_filtered() {
        // CAN 0x1E0 is 480, and so is the Modbus register — `frame()` matches
        // on the id alone, so only the filtered lookup tells them apart.
        let toml = r#"
[meta]
name = "x"
[frame.can."0x1E0"]
length = 8
[frame.modbus.limits]
register_number = 480
register_type = "input"
length = 1
[[frame.modbus.limits.signals]]
name = "Limit"
start_bit = 0
bit_length = 16
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.frame(480).unwrap().protocol, Protocol::Can);

        let m = c
            .modbus_register_frame(480, RegisterType::Input, 1)
            .unwrap();
        assert_eq!(m.protocol, Protocol::Modbus);
        assert_eq!(m.key, "limits");
        // Wrong register class, and an unknown register, both miss.
        assert!(c
            .modbus_register_frame(480, RegisterType::Holding, 1)
            .is_none());
        assert!(c
            .modbus_register_frame(481, RegisterType::Input, 1)
            .is_none());
    }

    #[test]
    fn modbus_register_lookup_resolves_a_one_based_catalogue() {
        // Authored in the traditional 3xxxx form; the wire address is 480.
        let toml = r#"
[meta]
name = "x"
[meta.modbus]
register_base = 1
[frame.modbus.limits]
register_number = 30481
register_type = "input"
length = 1
[[frame.modbus.limits.signals]]
name = "Limit"
start_bit = 0
bit_length = 16
"#;
        let c = Catalog::parse(toml).unwrap();
        assert!(c
            .modbus_register_frame(480, RegisterType::Input, 1)
            .is_some());
        // The authored number is not the wire address, so it must not match.
        assert!(c
            .modbus_register_frame(30481, RegisterType::Input, 1)
            .is_none());
    }

    const WINDOW_CATALOGUE: &str = r#"
[meta]
name = "x"
[meta.modbus]
register_base = 1
[frame.modbus.before]
register_number = 37813
register_type = "input"
length = 4
[frame.modbus.second]
register_number = 37820
register_type = "input"
length = 2
[frame.modbus.first]
register_number = 37816
register_type = "input"
length = 3
[frame.modbus.after]
register_number = 37830
register_type = "input"
length = 4
[frame.modbus.holding]
register_number = 47816
register_type = "holding"
length = 1
"#;

    fn within(c: &Catalog, start: u16, quantity: u16) -> Vec<(u16, &str)> {
        c.modbus_register_frames_within(start, quantity, RegisterType::Input, 1)
            .into_iter()
            .map(|(offset, f)| (offset, f.key.as_str()))
            .collect()
    }

    #[test]
    fn a_window_resolves_every_frame_it_holds_with_its_offset_in_order() {
        // The Sungrow logger's 7815 × 17, over a 1-based catalogue.
        let c = Catalog::parse(WINDOW_CATALOGUE).unwrap();
        assert_eq!(within(&c, 7815, 17), [(0, "first"), (4, "second")]);
    }

    #[test]
    fn a_frame_the_window_cuts_is_left_out() {
        let c = Catalog::parse(WINDOW_CATALOGUE).unwrap();
        // `before` (7812..7816) sticks out below, `after` (7829..7833) above.
        assert_eq!(within(&c, 7815, 16), [(0, "first"), (4, "second")]);
        assert_eq!(within(&c, 7815, 17), within(&c, 7815, 16));
        assert_eq!(within(&c, 7815, 2), []);
        assert_eq!(within(&c, 7812, 5), [(0, "before")]);
    }

    #[test]
    fn a_frame_that_fills_the_window_exactly_is_held() {
        let c = Catalog::parse(WINDOW_CATALOGUE).unwrap();
        assert_eq!(within(&c, 7815, 3), [(0, "first")]);
    }

    #[test]
    fn a_window_matches_register_type_and_device_address_as_the_exact_lookup_does() {
        let toml = r#"
[meta]
name = "x"
[node.a]
device_address = 1
[node.b]
device_address = 2
[frame.modbus.on_a]
register_number = 100
register_type = "holding"
node_address = 1
[frame.modbus.on_b]
register_number = 101
register_type = "holding"
node_address = 2
"#;
        let c = Catalog::parse(toml).unwrap();
        let keys = |register_type, device_address| -> Vec<&str> {
            c.modbus_register_frames_within(100, 2, register_type, device_address)
                .into_iter()
                .map(|(_, f)| f.key.as_str())
                .collect()
        };
        assert_eq!(keys(RegisterType::Holding, 1), ["on_a"]);
        assert_eq!(keys(RegisterType::Holding, 2), ["on_b"]);
        assert!(keys(RegisterType::Input, 1).is_empty());
    }

    #[test]
    fn legacy_modbus_meta_address_migrates_to_a_slave_node() {
        // No [node] tables, address only on [meta.modbus] — the legacy form.
        let toml = r#"
[meta]
name = "x"
default_frame = "modbus"
[meta.modbus]
device_address = 5
register_base = 0
[frame.modbus.grid_power]
register_number = 5083
"#;
        let c = Catalog::parse(toml).unwrap();
        // A slave node is synthesised from the legacy address...
        assert_eq!(c.nodes.len(), 1);
        let node = &c.nodes[0];
        assert_eq!(node.device_address, Some(5));
        // ...and the orphaned register is attached to it and resolves the address.
        let f = c.frame(5083).unwrap();
        assert_eq!(f.modbus_device_address, Some(5));
        assert_eq!(f.modbus_node.as_deref(), Some(node.name.as_str()));
    }

    #[test]
    fn parses_frame_notes_both_forms_and_checksums() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
notes = "single note"
[[frame.can.0x100.checksum]]
algorithm = "sum8"
start_byte = 7
byte_length = 1
calc_start_byte = 0
calc_end_byte = 7
[frame.can.0x200]
length = 8
notes = ["line one", "line two"]
"#;
        let c = Catalog::parse(toml).unwrap();
        let f1 = c.frame(0x100).unwrap();
        assert_eq!(f1.notes, vec!["single note".to_string()]);
        assert_eq!(f1.checksums.len(), 1);
        assert_eq!(f1.checksums[0].algorithm, "sum8");
        assert_eq!(f1.checksums[0].start_byte, 7);
        assert_eq!(f1.checksums[0].calc_end_byte, Some(7));
        let f2 = c.frame(0x200).unwrap();
        assert_eq!(
            f2.notes,
            vec!["line one".to_string(), "line two".to_string()]
        );
    }

    #[test]
    fn parses_node_table_and_modbus_notes() {
        let toml = r#"
[meta]
name = "x"
[meta.modbus]
device_address = 1
default_interval = 1000
[node.ECU_1]
notes = "the main controller"
[node.Sensor]
[frame.modbus.ems_control]
register_number = 13049
register_type = "holding"
length = 3
notes = "energy management"
"#;
        let c = Catalog::parse(toml).unwrap();
        // Nodes parsed in key order, notes carried.
        let names: Vec<&str> = c.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["ECU_1", "Sensor"]);
        assert_eq!(c.nodes[0].notes, vec!["the main controller".to_string()]);
        // Modbus frame: key, notes, and inherited device address / interval.
        let f = c.frames.iter().find(|f| f.key == "ems_control").unwrap();
        assert_eq!(f.frame_id, 13049);
        assert_eq!(f.modbus_register_type, Some(RegisterType::Holding));
        assert_eq!(f.notes, vec!["energy management".to_string()]);
        assert!(f.inherited_fields.contains(&"deviceAddress".to_string()));
        // explicit frame interval absent → inherited from meta default.
        assert!(f.inherited_fields.contains(&"interval".to_string()));
    }

    #[test]
    fn parses_can_frame_with_signal_and_defaults() {
        let toml = r#"
[meta]
name = "Test"
version = 1

[meta.can]
default_byte_order = "little"

[frame.can.0x123]
length = 8
transmitter = "ECU1"
tx.interval_ms = 100

[[frame.can.0x123.signals]]
name = "RPM"
start_bit = 0
bit_length = 16
factor = 0.25
unit = "rpm"
byte_order = "big"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Can);
        assert_eq!(c.meta.name, "Test");
        assert_eq!(
            c.can.as_ref().unwrap().default_byte_order,
            Some(Endianness::Little)
        );
        let f = c.frame(0x123).unwrap();
        assert_eq!(f.length, 8);
        assert_eq!(f.transmitter.as_deref(), Some("ECU1"));
        assert_eq!(f.interval, Some(100));
        assert_eq!(f.is_extended, Some(false)); // 0x123 <= 0x7ff
        assert_eq!(f.is_fd, Some(false));
        let s = sig(f, "RPM");
        assert_eq!(s.start_bit, Some(0));
        assert_eq!(s.bit_length, Some(16));
        assert_eq!(s.factor, Some(0.25));
        // byte_order key maps onto endianness.
        assert_eq!(s.endianness, Some(Endianness::Big));
    }

    #[test]
    fn extended_auto_detected_and_overridable() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x1ABCDE]
length = 8
[frame.can.0x100]
length = 8
extended = true
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.frame(0x1ABCDE).unwrap().is_extended, Some(true)); // > 0x7ff
        assert_eq!(c.frame(0x100).unwrap().is_extended, Some(true)); // explicit
    }

    #[test]
    fn default_extended_and_fd_from_config() {
        let toml = r#"
[meta]
name = "x"
[meta.can]
default_extended = true
default_fd = true
[frame.can.0x10]
length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x10).unwrap();
        assert_eq!(f.is_extended, Some(true)); // config default beats auto-detect
        assert_eq!(f.is_fd, Some(true));
    }

    #[test]
    fn mirror_inherits_signals_and_marks_inherited() {
        let toml = r#"
[meta]
name = "x"

[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "A"
start_bit = 0
bit_length = 8
[[frame.can.0x100.signals]]
name = "B"
start_bit = 8
bit_length = 8

[frame.can.0x200]
mirror_of = "0x100"
[[frame.can.0x200.signals]]
name = "B_override"
start_bit = 8
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x200).unwrap();
        assert_eq!(f.mirror_of.as_deref(), Some("0x100"));
        // A inherited from primary (same position, no override).
        let a = sig(f, "A");
        assert!(a.inherited);
        // Position 8:8 overridden by the mirror's own signal.
        let b = sig(f, "B_override");
        assert!(!b.inherited);
        // Length inherited from the mirror source.
        assert_eq!(f.length, 8);
    }

    #[test]
    fn copy_inherits_metadata_only() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 6
transmitter = "ECU"
tx.interval_ms = 250
[frame.can.0x200]
copy = "0x100"
[[frame.can.0x200.signals]]
name = "S"
start_bit = 0
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x200).unwrap();
        assert_eq!(f.copy_from.as_deref(), Some("0x100"));
        assert_eq!(f.length, 6);
        assert_eq!(f.transmitter.as_deref(), Some("ECU"));
        assert_eq!(f.interval, Some(250));
        // copy carries metadata only — signals are the frame's own.
        assert_eq!(f.signals.len(), 1);
        assert!(!sig(f, "S").inherited);
    }

    const MUXED_SOURCE: &str = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[frame.can.0x100.mux]
start_bit = 0
bit_length = 8
[[frame.can.0x100.mux."0".signals]]
name = "zero"
start_bit = 8
bit_length = 8
[frame.can.0x100.mux."1".mux]
start_bit = 8
bit_length = 8
[[frame.can.0x100.mux."1".mux."2".signals]]
name = "deep"
start_bit = 16
bit_length = 8
"#;

    fn mux_signals(mux: &Mux) -> Vec<&Signal> {
        mux.cases
            .values()
            .flat_map(|case| {
                let nested = case.mux.as_deref().map(mux_signals).unwrap_or_default();
                case.signals.iter().chain(nested)
            })
            .collect()
    }

    #[test]
    fn a_mux_inherited_through_mirror_of_flags_its_signals_at_every_level() {
        let toml = format!("{MUXED_SOURCE}[frame.can.0x200]\nmirror_of = \"0x100\"\n");
        let c = Catalog::parse(&toml).unwrap();
        let mirror = c.frame(0x200).unwrap();
        let signals = mux_signals(mirror.mux.as_ref().unwrap());
        assert_eq!(signals.len(), 2);
        assert!(signals.iter().all(|s| s.inherited));
        assert!(mux_signals(c.frame(0x100).unwrap().mux.as_ref().unwrap())
            .iter()
            .all(|s| !s.inherited));

        let d = crate::decode::decode_frame(&c, mirror, &[1, 2, 0x37, 0, 0, 0, 0, 0]);
        assert_eq!(d.signals.len(), 1);
        assert_eq!(d.signals[0].name, "deep");
        assert_eq!(d.signals[0].value, 0x37 as f64);
    }

    #[test]
    fn a_mirror_with_its_own_mux_keeps_its_case_signals_as_own() {
        let toml = format!(
            r#"{MUXED_SOURCE}
[frame.can.0x200]
mirror_of = "0x100"
[frame.can.0x200.mux]
start_bit = 0
bit_length = 8
[[frame.can.0x200.mux."0".signals]]
name = "local"
start_bit = 8
bit_length = 8
"#
        );
        let c = Catalog::parse(&toml).unwrap();
        let signals = mux_signals(c.frame(0x200).unwrap().mux.as_ref().unwrap());
        assert_eq!(signals.len(), 1);
        assert!(!signals[0].inherited);
    }

    #[test]
    fn parses_mux_with_ranges_lists_and_nesting() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x300]
length = 8
[frame.can.0x300.mux]
name = "sel"
start_bit = 0
bit_length = 8
[[frame.can.0x300.mux."0-3".signals]]
name = "low"
start_bit = 8
bit_length = 8
[[frame.can.0x300.mux."4,5".signals]]
name = "mid"
start_bit = 8
bit_length = 8
[frame.can.0x300.mux."6".mux]
name = "inner"
start_bit = 16
bit_length = 4
[[frame.can.0x300.mux."6".mux."0".signals]]
name = "deep"
start_bit = 24
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let m = c.frame(0x300).unwrap().mux.as_ref().unwrap();
        assert_eq!(m.name.as_deref(), Some("sel"));
        assert!(m.cases.contains_key("0-3"));
        assert!(m.cases.contains_key("4,5"));
        let nested = m.cases.get("6").unwrap().mux.as_ref().unwrap();
        assert_eq!(nested.name.as_deref(), Some("inner"));
        assert_eq!(
            nested.cases.get("0").unwrap().signals[0].name.as_deref(),
            Some("deep")
        );
    }

    #[test]
    fn parses_mux_and_case_notes() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x300]
length = 8
[frame.can.0x300.mux]
name = "sel"
start_bit = 0
bit_length = 8
notes = "the selector"
[frame.can.0x300.mux."0"]
notes = ["case zero", "second line"]
[[frame.can.0x300.mux."0".signals]]
name = "a"
start_bit = 8
bit_length = 8
"#;
        let m = Catalog::parse(toml)
            .unwrap()
            .frame(0x300)
            .unwrap()
            .mux
            .clone()
            .unwrap();
        assert_eq!(m.notes, vec!["the selector".to_string()]);
        assert_eq!(
            m.cases.get("0").unwrap().notes,
            vec!["case zero".to_string(), "second line".to_string()]
        );
    }

    #[test]
    fn parses_serial_config_and_frames() {
        let toml = r#"
[meta]
name = "ser"
[meta.serial]
encoding = "slip"
byte_order = "big"

[meta.serial.checksum]
algorithm = "crc16"
start_byte = 6
byte_length = 2

[meta.serial.fields]
id = { start_byte = 0, bytes = 2 }
source_address = { start_byte = 2, bytes = 1 }

[frame.serial.0xFDE0]
length = 8
[[frame.serial.0xFDE0.signals]]
name = "V"
start_bit = 0
bit_length = 16
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Serial);
        let s = c.serial.as_ref().unwrap();
        assert_eq!(s.encoding.as_deref(), Some("slip"));
        assert_eq!(s.byte_order, Some(Endianness::Big));
        assert_eq!(s.checksum.as_ref().unwrap().algorithm, "crc16");
        assert_eq!(s.checksum.as_ref().unwrap().byte_length, 2);
        // legacy start_byte/bytes → mask 0xFFFF for the first two bytes.
        assert_eq!(s.fields.get("id").unwrap().mask, 0xFFFF);
        // Byte positions derived from the masks at parse time.
        assert_eq!(s.frame_id_start_byte, Some(0));
        assert_eq!(s.frame_id_bytes, Some(2));
        assert_eq!(s.frame_id_byte_order, Some(Endianness::Big));
        assert_eq!(s.source_address_start_byte, Some(2));
        assert_eq!(s.source_address_bytes, Some(1));
        // One header_fields position entry per field (sorted by name in the map).
        assert_eq!(s.header_fields.len(), 2);
        let id_pos = s.header_fields.iter().find(|h| h.name == "id").unwrap();
        assert_eq!((id_pos.start_byte, id_pos.bytes), (0, 2));
        assert_eq!(id_pos.format, "hex");
        assert_eq!(c.frame(0xFDE0).unwrap().signals.len(), 1);
    }

    #[test]
    fn reuses_modbus_shorthands() {
        let toml = r#"
[meta]
name = "mb"
[meta.modbus]
register_base = 0
default_word_order = "little"

[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "Inverter_Temperature"
factor = 0.1
unit = "C"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Modbus);
        assert_eq!(
            c.modbus.as_ref().unwrap().default_word_order,
            Some(Endianness::Little)
        );
        let f = c.frame(0x138F).unwrap();
        // register-from-key + signal-less shorthands resolved by ModbusManifest.
        assert_eq!(f.modbus_register_type, Some(RegisterType::Input));
        assert_eq!(f.modbus_register_count, Some(1));
        assert_eq!(f.length, 2); // 1 register = 2 bytes
        let s = sig(f, "Inverter_Temperature");
        assert_eq!(s.factor, Some(0.1));
        assert_eq!(s.bit_length, Some(16));
        // Single-register signal sits on the frame's base register.
        assert_eq!(s.modbus_register, Some(0x138F));
        assert_eq!(s.modbus_register_count, Some(1));
    }

    #[test]
    fn synthesises_per_signal_modbus_registers() {
        // A multi-register block: signals carry their own register + span,
        // derived from the frame's base register and each signal's bit offset.
        let toml = r#"
[meta]
name = "mb"
[meta.modbus]
register_base = 0

[frame.modbus.13019]
register_type = "input"
length = 9
name = "Battery_Block"
[[frame.modbus.13019.signals]]
name = "Battery_Voltage"
start_bit = 0
bit_length = 16
[[frame.modbus.13019.signals]]
name = "Battery_Energy"
start_bit = 32
bit_length = 32
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(13019).unwrap();
        let v = sig(f, "Battery_Voltage");
        assert_eq!(v.modbus_register, Some(13019)); // base + 0/16
        assert_eq!(v.modbus_register_count, Some(1)); // 16 bits → 1 register
        let e = sig(f, "Battery_Energy");
        assert_eq!(e.modbus_register, Some(13021)); // base + 32/16
        assert_eq!(e.modbus_register_count, Some(2)); // 32 bits → 2 registers
    }

    #[test]
    fn a_frame_is_as_long_as_its_bank_packs() {
        // A register bank takes two bytes each; a coil bank packs eight to a
        // byte, and a partial byte still costs a whole one.
        let toml = r#"
[meta]
name = "mb"

[frame.modbus.100]
register_type = "holding"
length = 3

[frame.modbus.200]
register_type = "coil"
length = 10

[frame.modbus.300]
register_type = "discrete"
length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.frame(100).unwrap().length, 6);
        assert_eq!(c.frame(200).unwrap().length, 2);
        assert_eq!(c.frame(300).unwrap().length, 1);
    }

    #[test]
    fn a_coil_signals_span_counts_coils_not_registers() {
        let toml = r#"
[meta]
name = "mb"

[frame.modbus.200]
register_type = "coil"
length = 16

[[frame.modbus.200.signals]]
name = "Mode"
start_bit = 6
bit_length = 4
"#;
        let c = Catalog::parse(toml).unwrap();
        let s = &c.frame(200).unwrap().signals[0];
        // A register bank would put this at 200 + 6/16 = 200, spanning 1.
        assert_eq!(s.modbus_register, Some(206));
        assert_eq!(s.modbus_register_count, Some(4));
    }

    #[test]
    fn protocol_defaults_to_can_and_respects_default_frame() {
        let mixed = r#"
[meta]
name = "x"
default_frame = "serial"
[frame.can.0x1]
length = 8
[frame.serial.0x2]
length = 8
"#;
        assert_eq!(Catalog::parse(mixed).unwrap().protocol, Protocol::Serial);

        let only_can = "[meta]\nname='x'\n[frame.can.0x1]\nlength=8\n";
        assert_eq!(Catalog::parse(only_can).unwrap().protocol, Protocol::Can);
    }

    #[test]
    fn invalid_toml_errors() {
        assert!(matches!(
            Catalog::parse("not = valid = toml ="),
            Err(CatalogError::Toml(_))
        ));
    }

    #[test]
    fn round_trips_through_json() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x123]
length = 8
[[frame.can.0x123.signals]]
name = "A"
start_bit = 0
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
    /// The break that had never worked: detection reports positions from the
    /// *end* of the frame, and the model typed them unsigned — so an exported
    /// checksum was dropped on reload (`start_byte`) or silently re-ranged
    /// (`calc_start_byte`, which defaulted to 0).
    #[test]
    fn end_relative_checksum_offsets_survive_a_reload() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.checksum]]
algorithm = "sum8"
start_byte = -1
calc_start_byte = 1
calc_end_byte = -1
"#;
        let c = Catalog::parse(toml).unwrap();
        let checksum = &c.frame(0x100).unwrap().checksums[0];

        assert_eq!(checksum.start_byte, -1);
        assert_eq!(checksum.calc_start_byte, 1);
        assert_eq!(checksum.calc_end_byte, Some(-1));
    }

    /// A recovered CRC is not one of the eleven, so its parameters ride on the
    /// declaration. Without them a saved answer is unusable.
    #[test]
    fn a_solved_crc_carries_its_parameters() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x101]
length = 8
[[frame.can.0x101.checksum]]
algorithm = "crc_custom"
start_byte = -1
byte_length = 1
polynomial = 77
init = 0
xor_out = 183
reflect_in = false
"#;
        let c = Catalog::parse(toml).unwrap();
        let p = &c.frame(0x101).unwrap().checksums[0].parameters;

        assert_eq!(p.polynomial, Some(77));
        assert_eq!(p.xor_out, Some(183));
        assert_eq!(p.reflect_in, Some(false));
    }

    /// A present-but-unusable offset drops the checksum; see [`byte_offset`].
    #[test]
    fn a_malformed_offset_drops_the_checksum_rather_than_defaulting() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x102]
length = 8
[[frame.can.0x102.checksum]]
algorithm = "sum8"
start_byte = -1
calc_start_byte = "nonsense"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert!(c.frame(0x102).unwrap().checksums.is_empty());
    }

    fn display_json(s: &Signal) -> serde_json::Value {
        serde_json::to_value(s.display.as_ref().expect("a display hint")).unwrap()
    }

    fn widget(s: &Signal) -> &str {
        &s.display.as_ref().expect("a display hint").widget
    }

    #[test]
    fn a_display_hint_is_read_as_a_bare_widget_or_a_table() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "Speed"
start_bit = 0
bit_length = 8
display = "rotary"
[[frame.can.0x100.signals]]
name = "Level"
start_bit = 8
bit_length = 8
display = { widget = "level-bar", orientation = "vertical", max_value = 100 }
[[frame.can.0x100.signals]]
name = "Plain"
start_bit = 16
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x100).unwrap();

        assert_eq!(
            display_json(sig(f, "Speed")),
            serde_json::json!({ "widget": "rotary" })
        );
        assert_eq!(
            display_json(sig(f, "Level")),
            serde_json::json!({ "widget": "level-bar", "orientation": "vertical", "max_value": 100 })
        );
        assert_eq!(sig(f, "Plain").display, None);
        let plain = serde_json::to_value(sig(f, "Plain")).unwrap();
        assert!(plain.get("display").is_none());
    }

    #[test]
    fn a_malformed_display_hint_is_no_hint_and_keeps_its_signal() {
        let toml = r#"
[meta]
name = "x"
[frame.serial.0x01]
length = 8
[[frame.serial.0x01.signals]]
name = "Number"
start_bit = 0
bit_length = 8
display = 5
[[frame.serial.0x01.signals]]
name = "NoWidget"
start_bit = 8
bit_length = 8
display = { orientation = "vertical" }
[[frame.serial.0x01.signals]]
name = "WidgetNotAString"
start_bit = 16
bit_length = 8
display = { widget = 3 }
[[frame.serial.0x01.signals]]
name = "Empty"
start_bit = 24
bit_length = 8
display = ""
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x01).unwrap();
        assert_eq!(f.signals.len(), 4);
        assert!(f.signals.iter().all(|s| s.display.is_none()));
    }

    #[test]
    fn mux_and_mirrored_signals_carry_their_display_hints() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "Gauge"
start_bit = 0
bit_length = 8
display = "gauge"
[frame.can.0x100.mux]
name = "Sel"
start_bit = 8
bit_length = 8
[[frame.can.0x100.mux.1.signals]]
name = "CaseTop"
start_bit = 16
bit_length = 8
display = "sparkline"
[frame.can.0x100.mux.1.mux]
name = "Inner"
start_bit = 24
bit_length = 8
[[frame.can.0x100.mux.1.mux.2.signals]]
name = "CaseNested"
start_bit = 32
bit_length = 8
display = { widget = "level-bar", orientation = "horizontal" }

[frame.can.0x200]
mirror_of = "0x100"
"#;
        let c = Catalog::parse(toml).unwrap();
        let case = &c.frame(0x100).unwrap().mux.as_ref().unwrap().cases["1"];
        assert_eq!(widget(&case.signals[0]), "sparkline");
        let nested = &case.mux.as_ref().unwrap().cases["2"].signals[0];
        assert_eq!(
            display_json(nested),
            serde_json::json!({ "widget": "level-bar", "orientation": "horizontal" })
        );

        let mirror = c.frame(0x200).unwrap();
        assert!(sig(mirror, "Gauge").inherited);
        assert_eq!(widget(sig(mirror, "Gauge")), "gauge");
        let mirrored_case = &mirror.mux.as_ref().unwrap().cases["1"];
        assert_eq!(widget(&mirrored_case.signals[0]), "sparkline");
    }

    #[test]
    fn modbus_signals_carry_display_hints_and_survive_a_malformed_one() {
        let toml = r#"
[meta]
name = "x"
[frame.modbus.battery]
register_number = 13019
register_type = "input"
length = 2
[[frame.modbus.battery.signals]]
name = "SoC"
start_bit = 0
bit_length = 16
display = { widget = "level-bar", orientation = "vertical" }
[[frame.modbus.battery.signals]]
name = "Broken"
start_bit = 16
bit_length = 16
display = [1, 2]

[frame.modbus.0x32F9]
length = 1
[[frame.modbus.0x32F9.signals]]
name = "Power"
start_bit = 0
bit_length = 16
display = { widget = 7 }

[frame.modbus.voltage]
register_number = 5000
unit = "V"
display = "rotary"
"#;
        let c = Catalog::parse(toml).unwrap();
        let modbus: Vec<&Frame> = c
            .frames
            .iter()
            .filter(|f| f.protocol == Protocol::Modbus)
            .collect();
        assert_eq!(modbus.len(), 3, "a bad hint drops no Modbus frame");

        let battery = modbus.iter().find(|f| f.key == "battery").unwrap();
        assert_eq!(
            display_json(sig(battery, "SoC")),
            serde_json::json!({ "widget": "level-bar", "orientation": "vertical" })
        );
        assert_eq!(sig(battery, "Broken").display, None);

        let by_key = modbus.iter().find(|f| f.key == "0x32F9").unwrap();
        assert_eq!(by_key.frame_id, 0x32F9);
        assert_eq!(sig(by_key, "Power").display, None);

        let shorthand = modbus.iter().find(|f| f.key == "voltage").unwrap();
        assert_eq!(shorthand.signals[0].display, None);
    }

    #[test]
    fn a_display_hint_survives_the_json_round_trip() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "Level"
start_bit = 0
bit_length = 8
display = { widget = "level-bar", orientation = "vertical", thresholds = [10, 90] }
"#;
        let c = Catalog::parse(toml).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Catalog>(&json).unwrap(), c);
    }
}
