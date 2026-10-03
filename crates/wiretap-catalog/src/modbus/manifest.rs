//! WireTAP-format Modbus manifest: parse + decode.
//!
//! The manifest is TOML, identical in shape to the catalogues WireTAP
//! reads (`~/src/wired/WireTAP/src-tauri/examples/sungrow_shx.toml`):
//!
//! ```toml
//! [meta.modbus]
//! device_address = 1
//! register_base = 0          # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
//! default_interval = 5000    # ms
//! default_byte_order = "big"
//! default_word_order = "little"
//!
//! [frame.modbus.battery_status]   # one Modbus read of a register block
//! register_number = 13019
//! register_type = "input"          # input | holding | coil | discrete
//! length = 9                       # register count
//! tx.interval_ms = 10000
//!
//! [[frame.modbus.battery_status.signals]]   # a bit-slice of the block
//! name = "Battery_SoC"
//! start_bit = 48
//! bit_length = 16
//! factor = 0.1
//! unit = "%"
//! ```
//!
//! Each `[frame.modbus.<name>]` is ONE Modbus read; its `signals` are
//! bit-slices decoded from the returned register block. A signal may
//! span registers (e.g. a 32-bit value across two), and multi-register
//! values honour `word_order` (Sungrow stores them low-word-first).
//!
//! **Decode:** [`decode_frame`] for an input/holding block, [`decode_coil_frame`]
//! for a coil or discrete one. 16/32/64-bit signed/unsigned, `factor`/`offset`,
//! and — register banks only — byte + word order; a coil block has a single
//! order, eight to a byte and least significant bit first. Skipped: string-ish
//! `format`s (`ascii`/`hex`/`utf8`/`unix_time` — version/firmware/serial
//! frames). An `enum` signal still decodes to its numeric value (its readback
//! entity persists) and may carry a value↔name map.
//! **Encode (writes):** [`encode_signal`]/[`encode_enum`] are the inverse,
//! returning one [`ModbusWrite`] per holding register or per coil, each tagged
//! with its [`WriteBank`]. A coil signal encodes in the order
//! [`decode_coil_frame`] reads it: `start_bit` is the coil offset and the lowest
//! coil the least significant bit. [`merge_register_writes`] resolves co-located
//! bit-fields ([`overlay_register_writes`] where a later write should win);
//! [`group_contiguous`] batches contiguous addresses of one bank for the wire.
//!
//! The decode matches WireTAP's `signalDecode.ts`/`bits.ts`, with one
//! deliberate improvement: WireTAP's per-signal decoder only honours a
//! per-signal `word_order`, silently ignoring `meta.default_word_order`;
//! we apply the meta default too (per-signal still overrides), so the
//! Sungrow manifest — which sets the swap only at meta level — decodes
//! its 32-bit values correctly.

use std::collections::BTreeMap;

use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};

use crate::modbus::protocol::{coils_to_bytes, registers_to_bytes};
use crate::model::{DisplayHint, Endianness, RegisterType, SignalFormat, WriteBank};
use wiretap_decode::{extract_field, scale, BitOrder};

/// Poll interval used when neither the frame nor `[meta.modbus]` sets one.
const DEFAULT_INTERVAL_MS: u64 = 5000;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("manifest defines no [frame.modbus.*] frames")]
    NoFrames,
    #[error("frame '{0}' has no register_number and its name is not a register address (decimal or 0x-hex)")]
    BadRegister(String),
}

/// A single decoded field within a frame's register block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModbusSignal {
    pub name: String,
    pub start_bit: u32,
    pub bit_length: u32,
    #[serde(default)]
    pub factor: Option<f64>,
    #[serde(default)]
    pub offset: Option<f64>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub signed: bool,
    /// Non-numeric format (ascii/hex/enum/…). When set the signal is
    /// skipped by [`decode_frame`].
    #[serde(default)]
    pub format: Option<SignalFormat>,
    /// Per-signal byte order, overriding `[meta.modbus].default_byte_order`.
    /// Accepts the legacy `endianness` key too, matching WireTAP.
    #[serde(default, alias = "endianness")]
    pub byte_order: Option<Endianness>,
    /// Per-signal word order, overriding `[meta.modbus].default_word_order`.
    #[serde(default)]
    pub word_order: Option<Endianness>,
    /// Optional value↔name map for control/state registers, from the TOML
    /// `[…signals.enum]` table (`170 = "charge"`). Keys are the register
    /// value as a string (TOML keys are strings); the value is the label.
    /// Used to encode a write from a canonical name (and, for the readback
    /// panel, to display a label for a decoded value). Independent of
    /// `format`: a signal may carry an `enum` map and still decode to its
    /// numeric value.
    #[serde(default, rename = "enum")]
    pub enum_map: Option<BTreeMap<String, String>>,
    /// Read leniently: a malformed hint is `None`, because one error here
    /// drops every Modbus frame in the catalogue.
    #[serde(
        default,
        deserialize_with = "lenient_display",
        skip_serializing_if = "Option::is_none"
    )]
    pub display: Option<DisplayHint>,
}

fn lenient_display<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DisplayHint>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(DisplayHint::from_authored)
}

impl ModbusSignal {
    /// Numeric signals (no `format`) are the only ones the decoder emits
    /// and the only ones offered as read role bindings.
    pub fn is_numeric(&self) -> bool {
        self.format.is_none()
    }

    /// String-ish formats the decoder skips (version/serial/firmware
    /// frames). `None` and `Enum` are *not* skipped — they decode to a
    /// numeric value so control/state readback entities persist.
    fn is_string_format(&self) -> bool {
        matches!(
            self.format,
            Some(
                SignalFormat::Ascii
                    | SignalFormat::Utf8
                    | SignalFormat::Hex
                    | SignalFormat::UnixTime
                    | SignalFormat::Other
            )
        )
    }

    /// Reverse-resolve a canonical enum name to its register value (e.g.
    /// `"charge"` → `170`). `None` if the signal has no `enum` map, the
    /// name isn't present, or the key isn't a valid integer.
    fn enum_value(&self, name: &str) -> Option<i128> {
        self.enum_map
            .as_ref()?
            .iter()
            .find(|(_, label)| label.as_str() == name)
            .and_then(|(value, _)| value.parse::<i128>().ok())
    }
}

/// One Modbus read: a contiguous register block plus the signals that
/// decode from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModbusFrame {
    /// Frame name (the `[frame.modbus.<name>]` table key).
    pub name: String,
    pub register_number: u16,
    pub register_type: RegisterType,
    /// Register (or coil) count to read.
    pub length: u16,
    /// Resolved poll interval (frame `tx.interval_ms` → meta default →
    /// `DEFAULT_INTERVAL_MS`).
    pub interval_ms: u64,
    /// Operator-set `disabled = true`: the poll task skips this frame
    /// entirely. Used to stop hammering a frame the inverter rejects
    /// (e.g. "Illegal data address") — toggled from the health panel,
    /// written into the manifest by [`set_frame_disabled`].
    pub disabled: bool,
    /// Resolved display name of the slave this register belongs to: the
    /// `[node.<name>]` table whose `device_address` matches [`Self::device_address`],
    /// if any. `None` for an unmatched address. Registers reference their slave by
    /// address (`node_address`), not by name.
    pub node: Option<String>,
    /// Device (slave) address: the register's `node_address`, the legacy
    /// `[meta.modbus].device_address`, else `1`.
    pub device_address: u8,
    pub signals: Vec<ModbusSignal>,
}

/// `[meta.modbus]` connection/decoding defaults. Deserialized straight
/// from the TOML table (the only renamed field is `default_interval` →
/// [`Self::default_interval_ms`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModbusMeta {
    #[serde(default = "default_device_address")]
    pub device_address: u8,
    /// 0 = IEC (0-based protocol addresses); 1 = traditional 1-based with
    /// a type prefix (4xxxx holding, 3xxxx input, …).
    #[serde(default)]
    pub register_base: u8,
    #[serde(default, rename = "default_interval")]
    pub default_interval_ms: Option<u64>,
    #[serde(default)]
    pub default_byte_order: Option<Endianness>,
    #[serde(default)]
    pub default_word_order: Option<Endianness>,
}

impl Default for ModbusMeta {
    fn default() -> Self {
        Self {
            device_address: 1,
            register_base: 0,
            default_interval_ms: None,
            default_byte_order: None,
            default_word_order: None,
        }
    }
}

/// A parsed manifest: connection defaults + the list of frames to poll.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModbusManifest {
    pub meta: ModbusMeta,
    pub frames: Vec<ModbusFrame>,
}

impl ModbusManifest {
    /// Parse a WireTAP-format manifest. Errors on invalid TOML or when
    /// no `[frame.modbus.*]` frames are present (an empty manifest can't
    /// bind any telemetry).
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(text)?;
        let meta = raw.meta.modbus;
        let default_interval = meta.default_interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);

        // Address resolution: a register names its slave's address directly via
        // `node_address`; the `[node.<name>]` table maps that address to a display
        // name. Legacy catalogues without `node_address` fall back to
        // `[meta.modbus]`.
        let addr_to_name: BTreeMap<u8, &str> = raw
            .node
            .iter()
            .filter_map(|(name, n)| n.device_address.map(|a| (a, name.as_str())))
            .collect();
        let legacy_address = meta.device_address;

        // BTreeMap iteration is sorted by frame name, giving stable
        // ordering for the role pickers and the tests.
        let frames: Vec<ModbusFrame> = raw
            .frame
            .modbus
            .into_iter()
            .map(|(name, f)| {
                // Shorthand: the register may be given as the table key
                // (`[frame.modbus.0x32F9]` / `[frame.modbus.13049]`) instead of
                // an explicit `register_number`; the explicit field wins.
                let register_number = match f.register_number {
                    Some(r) => r,
                    None => parse_register_key(&name)
                        .ok_or_else(|| ManifestError::BadRegister(name.clone()))?,
                };
                // Shorthand: a register with no `[[signals]]` but with frame-level
                // decoding fields (format/factor/unit/…) is itself one full-width
                // signal. A bare block with neither stays signal-less, as before.
                let signals = if f.signals.is_empty() {
                    synth_frame_signal(&name, &f).into_iter().collect()
                } else {
                    f.signals
                };
                let device_address = f.node_address.unwrap_or(legacy_address);
                Ok(ModbusFrame {
                    name,
                    register_number,
                    register_type: f.register_type,
                    length: f.length,
                    interval_ms: f
                        .interval_ms
                        .or_else(|| f.tx.and_then(|t| t.interval_ms))
                        .unwrap_or(default_interval),
                    disabled: f.disabled,
                    node: addr_to_name.get(&device_address).map(|s| s.to_string()),
                    device_address,
                    signals,
                })
            })
            .collect::<Result<Vec<ModbusFrame>, ManifestError>>()?;

        if frames.is_empty() {
            return Err(ManifestError::NoFrames);
        }
        Ok(Self { meta, frames })
    }

    /// The protocol-level (0-based) start address for a frame, resolving
    /// `register_base`. Base 0 passes the number through; base 1 strips
    /// the traditional type-prefix offset.
    pub fn protocol_address(&self, frame: &ModbusFrame) -> u16 {
        if self.meta.register_base != 1 {
            return frame.register_number;
        }
        let prefix = frame.register_type.base_one_prefix() as u16;
        frame.register_number.saturating_sub(prefix)
    }

    /// Find a writable signal by name: a signal living in a writable
    /// (holding/coil) frame. Returns the frame + signal so the caller can
    /// resolve the absolute address and encoding. `None` if no such signal
    /// exists or it lives only in read-only (input/discrete) frames.
    pub fn find_write_signal(&self, name: &str) -> Option<(&ModbusFrame, &ModbusSignal)> {
        self.frames
            .iter()
            .filter(|f| f.register_type.is_writable())
            .find_map(|f| f.signals.iter().find(|s| s.name == name).map(|s| (f, s)))
    }

    /// Writable signals paired with their absolute (0-based protocol) address in
    /// their own bank — a coil signal's first coil — for the command editor's
    /// dropdown, which shows the address alongside the name. Sorted +
    /// de-duplicated by name.
    pub fn write_signal_options(&self) -> Vec<(String, u16)> {
        let mut out: Vec<(String, u16)> = Vec::new();
        for f in self.frames.iter().filter(|f| f.register_type.is_writable()) {
            let base = self.protocol_address(f);
            for s in &f.signals {
                let offset = f.register_type.address_offset(s.start_bit);
                out.push((s.name.clone(), base.saturating_add(offset as u16)));
            }
        }
        // De-dup by name (a signal appears once), then order by register so
        // the picker reads in register order.
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out.sort_by_key(|(_, reg)| *reg);
        out
    }

    /// Writable signals that carry an `enum` map, each with its `(label,
    /// value)` entries sorted by register value — for the command editor's
    /// enum value dropdown. Signals without an enum are omitted.
    pub fn write_signal_enums(&self) -> Vec<(String, Vec<(String, i64)>)> {
        let mut out = Vec::new();
        for f in self.frames.iter().filter(|f| f.register_type.is_writable()) {
            for s in &f.signals {
                let Some(em) = &s.enum_map else { continue };
                let mut entries: Vec<(String, i64)> = em
                    .iter()
                    .filter_map(|(v, label)| v.parse::<i64>().ok().map(|n| (label.clone(), n)))
                    .collect();
                if entries.is_empty() {
                    continue;
                }
                entries.sort_by_key(|(_, v)| *v);
                out.push((s.name.clone(), entries));
            }
        }
        out
    }
}

/// One **register's** or one **coil's** worth of a desired write: its `bank`,
/// an absolute (0-based protocol) `address` in that bank, the `value` bits, and
/// a `mask` of which bits this write owns (`0xFFFF` = the whole register; a coil
/// is always `1`, with `value` 0 or 1). The per-address granularity is the
/// canonical unit of comparison; a multi-register or multi-coil signal resolves
/// to several `ModbusWrite`s, and co-located bit-fields merge into one (see
/// [`merge_register_writes`]). A caller batches address-contiguous writes with
/// [`group_contiguous`] and sends each batch as one transaction, read-modify-
/// writing any partially-owned register — the transaction is its own to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ModbusWrite {
    #[serde(default)]
    pub bank: WriteBank,
    pub address: u16,
    pub value: u16,
    #[serde(default = "full_register_mask")]
    pub mask: u16,
}

impl ModbusWrite {
    pub fn holding(address: u16, value: u16, mask: u16) -> Self {
        Self {
            bank: WriteBank::Holding,
            address,
            value,
            mask,
        }
    }

    pub fn coil(address: u16, on: bool) -> Self {
        Self {
            bank: WriteBank::Coil,
            address,
            value: on.into(),
            mask: 1,
        }
    }
}

fn full_register_mask() -> u16 {
    0xFFFF
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    #[error("signal '{0}' is in a read-only bank (input/discrete)")]
    NotWritable(String),
    #[error("signal '{name}' has an unsupported write layout (start_bit {start_bit}, bit_length {bit_length}): v1 supports register-aligned 16/32/48/64-bit, single-register bit-fields and 1–64 coils")]
    UnsupportedLayout {
        name: String,
        start_bit: u32,
        bit_length: u32,
    },
    #[error("signal '{name}' has no enum value for '{value}'")]
    UnknownEnumName { name: String, value: String },
}

/// Encode a numeric value to the register(s) it occupies — the inverse of
/// [`decode_frame`], honouring the signal's scale, sign, bit position and
/// word order. Returns one [`ModbusWrite`] per register (full-mask for an
/// aligned signal; a single masked register for a bit-field) or per coil. v1
/// supports register-aligned 16/32/48/64-bit signals, single-register
/// bit-fields and 1–64 coils; other layouts error rather than mis-pack.
pub fn encode_signal(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    value: f64,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    encode_raw(manifest, frame, signal, scale_to_raw(signal, value))
}

/// Encode a write from a canonical enum name (e.g. `"charge"`), resolving
/// it to the register value via the signal's `enum` map.
pub fn encode_enum(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    name: &str,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    let value = signal
        .enum_value(name)
        .ok_or_else(|| EncodeError::UnknownEnumName {
            name: signal.name.clone(),
            value: name.to_string(),
        })?;
    encode_raw(manifest, frame, signal, value)
}

/// Inverse scale + round + clamp to the signal's bit width. Returns the
/// raw integer to pack (two's-complement representable in `bit_length`).
fn scale_to_raw(signal: &ModbusSignal, value: f64) -> i128 {
    let factor = match signal.factor {
        Some(f) if f != 0.0 => f,
        _ => 1.0,
    };
    let offset = signal.offset.unwrap_or(0.0);
    let raw = ((value - offset) / factor).round();
    let n = signal.bit_length;
    let (lo, hi) = if signal.signed {
        (-(1i128 << (n - 1)), (1i128 << (n - 1)) - 1)
    } else {
        (0, (1i128 << n) - 1)
    };
    (raw as i128).clamp(lo, hi)
}

/// Resolve a clamped raw integer to its writes. Aligned full-width register
/// signals (16/32/48/64-bit) yield one full-mask register each (word order
/// applied across registers); a single-register bit-field (big byte order)
/// yields one masked register; a coil signal yields one write per coil.
fn encode_raw(
    manifest: &ModbusManifest,
    frame: &ModbusFrame,
    signal: &ModbusSignal,
    raw: i128,
) -> Result<Vec<ModbusWrite>, EncodeError> {
    let Some(bank) = frame.register_type.write_bank() else {
        return Err(EncodeError::NotWritable(signal.name.clone()));
    };
    let len = signal.bit_length;
    let start = signal.start_bit;
    let bits_mask: u128 = if len >= 128 {
        u128::MAX
    } else {
        (1u128 << len) - 1
    };
    let raw_bits = (raw as u128) & bits_mask;
    let base = manifest.protocol_address(frame);

    if bank == WriteBank::Coil {
        if !(1..=64).contains(&len) {
            return Err(EncodeError::UnsupportedLayout {
                name: signal.name.clone(),
                start_bit: start,
                bit_length: len,
            });
        }
        return Ok((0..len)
            .map(|i| {
                let address = base.saturating_add((start + i) as u16);
                ModbusWrite::coil(address, (raw_bits >> i) & 1 == 1)
            })
            .collect());
    }

    let reg_index = (start / 16) as u16;

    // Aligned full-register signal (16/32/48/64-bit).
    if start.is_multiple_of(16) && len.is_multiple_of(16) && (16..=64).contains(&len) {
        let nregs = (len / 16) as usize;
        // Big-endian register order: register i (ascending address) holds the
        // i-th most-significant 16-bit word.
        let mut regs: Vec<u16> = (0..nregs)
            .map(|i| ((raw_bits >> (len as usize - 16 * (i + 1))) & 0xffff) as u16)
            .collect();
        let word_order = signal
            .word_order
            .or(manifest.meta.default_word_order)
            .unwrap_or(Endianness::Big);
        // Little word order (Sungrow "CDAB"): low word first on the wire.
        if nregs > 1 && word_order == Endianness::Little {
            regs.reverse();
        }
        return Ok(regs
            .into_iter()
            .enumerate()
            .map(|(i, value)| {
                ModbusWrite::holding(base.saturating_add(reg_index + i as u16), value, 0xffff)
            })
            .collect());
    }

    // Single-register bit-field (fits within one register), big byte order.
    if (1..16).contains(&len) && start / 16 == (start + len - 1) / 16 {
        let bit_in_reg = start % 16; // offset from the register's MSB
        let shift = 16 - bit_in_reg - len; // field's LSB position
        let mask = (((1u32 << len) - 1) << shift) as u16;
        let value = ((raw_bits as u32) << shift) as u16 & mask;
        return Ok(vec![ModbusWrite::holding(
            base.saturating_add(reg_index),
            value,
            mask,
        )]);
    }

    Err(EncodeError::UnsupportedLayout {
        name: signal.name.clone(),
        start_bit: start,
        bit_length: len,
    })
}

/// Merge a sequence of per-address writes, combining bit-fields that share
/// a register (their masks must be disjoint) — the "resolve chunks into
/// registers" step. A coil and a register at the same number are different
/// targets. **First-occurrence order is preserved** (so the operator's command
/// order survives — e.g. EMS mode before the forced command). `Err` if two
/// writes claim overlapping bits of one target.
pub fn merge_register_writes(writes: Vec<ModbusWrite>) -> Result<Vec<ModbusWrite>, String> {
    let mut out: Vec<ModbusWrite> = Vec::with_capacity(writes.len());
    for w in writes {
        if let Some(existing) = out
            .iter_mut()
            .find(|e| (e.bank, e.address) == (w.bank, w.address))
        {
            if existing.mask & w.mask != 0 {
                return Err(format!(
                    "{} {} written by overlapping commands",
                    w.bank.noun(),
                    w.address
                ));
            }
            existing.value |= w.value & w.mask;
            existing.mask |= w.mask;
        } else {
            out.push(w);
        }
    }
    Ok(out)
}

/// As [`merge_register_writes`], except that a later write **wins** on the bits
/// it owns instead of being an `Err` — for concatenating batches from separate
/// sources, where a later batch legitimately overrides an earlier one's target.
pub fn overlay_register_writes(writes: Vec<ModbusWrite>) -> Vec<ModbusWrite> {
    let mut out: Vec<ModbusWrite> = Vec::with_capacity(writes.len());
    for w in writes {
        if let Some(existing) = out
            .iter_mut()
            .find(|e| (e.bank, e.address) == (w.bank, w.address))
        {
            existing.value = (existing.value & !w.mask) | (w.value & w.mask);
            existing.mask |= w.mask;
        } else {
            out.push(w);
        }
    }
    out
}

/// Group writes into runs of **consecutive ascending-contiguous** addresses in
/// one bank, **without reordering** — the "serialise registers into a block"
/// step. A run becomes one multiple-write; a gap, a non-ascending step or a
/// change of bank starts a new transaction, so the operator's order is
/// preserved across transactions. Expects merged input (unique targets).
pub fn group_contiguous(writes: &[ModbusWrite]) -> Vec<Vec<ModbusWrite>> {
    let mut runs: Vec<Vec<ModbusWrite>> = Vec::new();
    for &w in writes {
        match runs.last_mut() {
            Some(run) if continues(run.last().unwrap(), &w) => run.push(w),
            _ => runs.push(vec![w]),
        }
    }
    runs
}

fn continues(last: &ModbusWrite, next: &ModbusWrite) -> bool {
    last.bank == next.bank && last.address.checked_add(1) == Some(next.address)
}

/// Set (`true`) or clear (`false`) a frame's `disabled` flag in a raw
/// manifest, **preserving comments and formatting** (via `toml_edit`).
/// Clearing removes the key rather than writing `disabled = false`, so a
/// re-enabled frame leaves no trace. Returns the edited TOML. `Err` when
/// the text isn't valid TOML or the named frame isn't present.
pub fn set_frame_disabled(text: &str, frame: &str, disabled: bool) -> Result<String, String> {
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("manifest is not valid TOML: {e}"))?;
    let frame_tbl = doc
        .get_mut("frame")
        .and_then(|f| f.get_mut("modbus"))
        .and_then(|m| m.as_table_like_mut())
        .and_then(|m| m.get_mut(frame))
        .and_then(|f| f.as_table_like_mut())
        .ok_or_else(|| format!("manifest has no frame '{frame}'"))?;
    if disabled {
        frame_tbl.insert("disabled", toml_edit::value(true));
    } else {
        frame_tbl.remove("disabled");
    }
    Ok(doc.to_string())
}

/// The per-signal decode loop, shared by both banks: skip the string-ish
/// formats, cut the raw bits out, scale in exact `Decimal`, and skip a signal
/// that can't be scaled. Only where the bits come from differs.
fn decode_signals(signals: &[ModbusSignal], bytes: &[u8], order: BitOrder) -> Vec<DecodedSignal> {
    signals
        .iter()
        .filter(|sig| !sig.is_string_format())
        .filter_map(|sig| {
            let order = order.with_overrides(sig.byte_order, sig.word_order);
            let raw = extract_field(bytes, sig.start_bit, sig.bit_length, order, sig.signed);
            Some(DecodedSignal {
                name: sig.name.clone(),
                // Exact Decimal (shared with the general decode path), so
                // `3374 * 0.1` is `337.4`, not the float-noisy
                // `337.40000000000003`.
                value: scale(raw, sig.factor, sig.offset)?,
                unit: sig.unit.clone(),
            })
        })
        .collect()
}

/// Decode every numeric signal in `frame` from its read register block.
///
/// `regs` is the raw register block returned by the Modbus read (one
/// `u16` per register). Signals with a text-like `format` (ascii, utf8, hex,
/// unix time, other) and any that can't be scaled are skipped; enum signals are
/// kept. The result is `(name, scaled value, unit)` per signal, ready to inject
/// into the entity mirror.
///
/// For a coil or discrete frame use [`decode_coil_frame`] — that block is
/// packed bits, not registers.
pub fn decode_frame(frame: &ModbusFrame, regs: &[u16], meta: &ModbusMeta) -> Vec<DecodedSignal> {
    decode_signals(
        &frame.signals,
        &registers_to_bytes(regs),
        BitOrder::Registers {
            endianness: meta.default_byte_order.unwrap_or(Endianness::Big),
            word_order: meta.default_word_order,
        },
    )
}

/// Decode every numeric signal in a coil or discrete `frame` from the bits its
/// read returned.
///
/// `coils` is one `bool` per coil, in the order the device reported them — what
/// [`crate::ModbusRtuMessage::coils`] and a client's `read_coils` both yield. A
/// signal's `start_bit` is a coil index and its `bit_length` a coil count, and
/// the lowest index is the field's least significant bit. Coils past the end of
/// the block read as zero, as a short register block does.
///
/// Takes no [`ModbusMeta`]: [`BitOrder::Coils`] is the whole ordering, so
/// `byte_order` and `word_order` have nothing to say here.
pub fn decode_coil_frame(frame: &ModbusFrame, coils: &[bool]) -> Vec<DecodedSignal> {
    decode_signals(&frame.signals, &coils_to_bytes(coils), BitOrder::Coils)
}

/// A scaled signal value decoded from a register block.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSignal {
    pub name: String,
    /// Scaled value as an exact `Decimal` so `raw × factor + offset` doesn't
    /// pick up binary-float artifacts (e.g. `3374 × 0.1` is `337.4`, not
    /// `337.40000000000003`) when stringified for display or an entity state.
    pub value: Decimal,
    pub unit: Option<String>,
}

// ---------- raw serde shapes (TOML wire format) ----------

#[derive(Debug, Default, Deserialize)]
struct RawManifest {
    #[serde(default)]
    meta: RawMeta,
    #[serde(default)]
    frame: RawFrames,
    /// `[node.<name>]` tables. A Modbus node owns a `device_address`.
    #[serde(default)]
    node: BTreeMap<String, RawNode>,
}

#[derive(Debug, Default, Deserialize)]
struct RawNode {
    #[serde(default)]
    device_address: Option<u8>,
}

#[derive(Debug, Default, Deserialize)]
struct RawMeta {
    // `[meta.modbus]` deserializes straight into the public ModbusMeta.
    #[serde(default)]
    modbus: ModbusMeta,
}

fn default_device_address() -> u8 {
    1
}

#[derive(Debug, Default, Deserialize)]
struct RawFrames {
    #[serde(default)]
    modbus: BTreeMap<String, RawFrame>,
}

#[derive(Debug, Deserialize)]
struct RawFrame {
    /// Optional: when absent, the register is derived from the table key
    /// (`[frame.modbus.0x32F9]`) — see [`ModbusManifest::parse`].
    #[serde(default)]
    register_number: Option<u16>,
    #[serde(default)]
    register_type: RegisterType,
    #[serde(default = "default_length")]
    length: u16,
    /// Canonical poll interval (ms). The legacy `[tx]` sub-table is still
    /// accepted as a fallback (see [`RawTx`]).
    #[serde(default, alias = "interval")]
    interval_ms: Option<u64>,
    #[serde(default)]
    tx: Option<RawTx>,
    #[serde(default)]
    disabled: bool,
    /// The device (slave) address this register is read from. Matched to a
    /// `[node.<name>]` table by `device_address` for display/grouping.
    #[serde(default)]
    node_address: Option<u8>,
    #[serde(default)]
    signals: Vec<ModbusSignal>,
    // ---- frame-level signal shorthand (used only when `signals` is empty) ----
    /// Name for the synthesised signal; falls back to the frame key.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    format: Option<SignalFormat>,
    #[serde(default)]
    factor: Option<f64>,
    #[serde(default)]
    offset: Option<f64>,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    signed: Option<bool>,
    #[serde(default, rename = "enum")]
    enum_map: Option<BTreeMap<String, String>>,
}

fn default_length() -> u16 {
    1
}

#[derive(Debug, Deserialize)]
struct RawTx {
    #[serde(default, alias = "interval")]
    interval_ms: Option<u64>,
}

/// Parse a frame's table key as a register address: decimal (`13049`) or
/// hex (`0x32F9`/`0X32F9`). `None` for a non-numeric key (a friendly name).
fn parse_register_key(key: &str) -> Option<u16> {
    let k = key.trim();
    match k.strip_prefix("0x").or_else(|| k.strip_prefix("0X")) {
        Some(hex) => u16::from_str_radix(hex, 16).ok(),
        None => k.parse::<u16>().ok(),
    }
}

/// Build the implicit signal for a register defined without an explicit
/// `[[signals]]` block. The signal spans the whole block — `length × 16` bits
/// for a register bank, `length` bits for a coil or discrete one — and takes
/// the frame-level decoding fields. Returns `None` when no such fields are
/// present (a bare register block stays signal-less, exactly as before).
fn synth_frame_signal(key: &str, f: &RawFrame) -> Option<ModbusSignal> {
    let has_fields = f.name.is_some()
        || f.format.is_some()
        || f.factor.is_some()
        || f.offset.is_some()
        || f.unit.is_some()
        || f.signed.is_some()
        || f.enum_map.is_some();
    if !has_fields {
        return None;
    }
    Some(ModbusSignal {
        name: f.name.clone().unwrap_or_else(|| key.to_string()),
        start_bit: 0,
        bit_length: f.register_type.bits_per_address() * f.length as u32,
        factor: f.factor,
        offset: f.offset,
        unit: f.unit.clone(),
        signed: f.signed.unwrap_or(false),
        format: f.format,
        byte_order: None,
        word_order: None,
        enum_map: f.enum_map.clone(),
        display: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    const SUNGROW: &str = include_str!("testdata/sungrow_shx.toml");

    fn parse_fixture() -> ModbusManifest {
        ModbusManifest::parse(SUNGROW).expect("fixture parses")
    }

    fn frame<'a>(m: &'a ModbusManifest, name: &str) -> &'a ModbusFrame {
        m.frames
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("frame {name} present"))
    }

    fn signal<'a>(f: &'a ModbusFrame, name: &str) -> &'a ModbusSignal {
        f.signals
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("signal {name} present"))
    }

    #[test]
    fn parses_frames_and_meta() {
        let m = parse_fixture();
        assert_eq!(m.meta.device_address, 1);
        assert_eq!(m.meta.register_base, 0);
        assert_eq!(m.meta.default_word_order, Some(Endianness::Little));

        let bs = frame(&m, "battery_status");
        assert_eq!(bs.register_number, 13019);
        assert_eq!(bs.length, 9);
        assert_eq!(bs.register_type, RegisterType::Input);
        assert_eq!(bs.interval_ms, 10000); // frame tx override

        let soc = signal(bs, "Battery_SoC");
        assert_eq!(soc.start_bit, 48);
        assert_eq!(soc.bit_length, 16);

        // solar_pv has no per-frame interval → meta default (5000).
        assert_eq!(frame(&m, "solar_pv").interval_ms, 5000);
    }

    #[test]
    fn decodes_register_aligned_soc() {
        let m = parse_fixture();
        let bs = frame(&m, "battery_status");
        // 9 registers; Battery_SoC at start_bit 48 = register index 3.
        let mut regs = [0u16; 9];
        regs[3] = 555; // ×0.1 → 55.5 %
        let decoded = decode_frame(bs, &regs, &m.meta);
        let soc = decoded.iter().find(|d| d.name == "Battery_SoC").unwrap();
        assert_eq!(soc.value, dec!(55.5));
        assert_eq!(soc.unit.as_deref(), Some("%"));
        // The ascii-free battery_status still skips nothing numeric; the
        // signed temperature decodes too.
        assert!(decoded.iter().any(|d| d.name == "Battery_Temperature"));
    }

    #[test]
    fn decodes_word_swapped_signed_32bit_charging() {
        let m = parse_fixture();
        let bp = frame(&m, "battery_power");
        // -1000 W (charging). S32 = 0xFFFFFC18. Sungrow word order is
        // little (low word first), so registers arrive [low, high].
        let regs = [0xFC18u16, 0xFFFFu16];
        let decoded = decode_frame(bp, &regs, &m.meta);
        let p = &decoded[0];
        assert_eq!(p.name, "Battery_Power");
        assert_eq!(p.value, dec!(-1000));
    }

    #[test]
    fn decodes_word_swapped_unsigned_32bit_discharging() {
        let m = parse_fixture();
        let bp = frame(&m, "battery_power");
        // +2000 W: 0x000007D0 → registers [low=0x07D0, high=0x0000].
        let regs = [0x07D0u16, 0x0000u16];
        let p = &decode_frame(bp, &regs, &m.meta)[0];
        assert_eq!(p.value, dec!(2000));
    }

    #[test]
    fn decodes_total_dc_power_mid_block() {
        let m = parse_fixture();
        let pv = frame(&m, "solar_pv");
        // length 8; Total_DC_Power at start_bit 96 = register index 6.
        // 5000 W word-swapped → [low=0x1388, high=0x0000] at idx 6,7.
        let mut regs = [0u16; 8];
        regs[0] = 2500; // MPPT1_Voltage ×0.1 = 250.0 V
        regs[6] = 0x1388;
        regs[7] = 0x0000;
        let decoded = decode_frame(pv, &regs, &m.meta);
        let dc = decoded.iter().find(|d| d.name == "Total_DC_Power").unwrap();
        assert_eq!(dc.value, dec!(5000));
        let v = decoded.iter().find(|d| d.name == "MPPT1_Voltage").unwrap();
        assert_eq!(v.value, dec!(250));
    }

    #[test]
    fn ascii_frame_decodes_to_nothing() {
        let m = parse_fixture();
        let v = frame(&m, "version_1");
        let regs = [0x4142u16; 11];
        assert!(decode_frame(v, &regs, &m.meta).is_empty());
    }

    #[test]
    fn a_catalogues_function_codes_are_no_concern_of_the_manifest() {
        let toml = r#"
[meta.modbus]
default_word_order = "little"
[meta.modbus.function_code.0x60]
name = "Dispatch"
lengths = [{ len = { count_at = 6, overhead = 9 } }]
[meta.modbus.function_code.0x65]

[frame.modbus.misc]
register_number = 100
register_type = "input"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(m.meta.default_word_order, Some(Endianness::Little));
        assert_eq!(m.frames.len(), 1);
    }

    #[test]
    fn decodes_non_register_aligned_signal() {
        // A 16-bit signal at start_bit 8 spans the low byte of reg0 and
        // the high byte of reg1 (no word swap; ≤16 bits).
        let toml = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"

[frame.modbus.misc]
register_number = 100
register_type = "input"
length = 2

[[frame.modbus.misc.signals]]
name = "Spanning"
start_bit = 8
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = frame(&m, "misc");
        // regs = [0x00AB, 0xCD00] → bytes 00 AB CD 00 → bits[8..24] = AB CD.
        let regs = [0x00ABu16, 0xCD00u16];
        let d = &decode_frame(f, &regs, &m.meta)[0];
        assert_eq!(d.value.to_u32().unwrap(), 0xABCD);
    }

    #[test]
    fn register_base_one_strips_type_prefix() {
        let toml = r#"
[meta.modbus]
register_base = 1

[frame.modbus.cfg]
register_number = 40001
register_type = "holding"
length = 1

[[frame.modbus.cfg.signals]]
name = "X"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = frame(&m, "cfg");
        assert_eq!(m.protocol_address(f), 0);
    }

    #[test]
    fn register_base_zero_passes_address_through() {
        let m = parse_fixture();
        let bs = frame(&m, "battery_status");
        assert_eq!(m.protocol_address(bs), 13019);
    }

    #[test]
    fn empty_manifest_is_rejected() {
        assert!(matches!(
            ModbusManifest::parse("[meta.modbus]\nregister_base = 0\n"),
            Err(ManifestError::NoFrames)
        ));
        assert!(matches!(
            ModbusManifest::parse("not = valid = toml ="),
            Err(ManifestError::Toml(_))
        ));
    }

    // ---------- shorthand: register-from-key ----------

    #[test]
    fn register_number_derived_from_hex_key() {
        let toml = r#"
[frame.modbus.0x32F9]
register_type = "holding"
length = 1
[[frame.modbus.0x32F9.signals]]
name = "EMS_Mode"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(m.frames[0].register_number, 0x32F9); // 13049
    }

    #[test]
    fn register_number_from_decimal_key_and_explicit_overrides() {
        let toml = r#"
[frame.modbus.13050]
register_type = "holding"
length = 1
[[frame.modbus.13050.signals]]
name = "A"
start_bit = 0
bit_length = 16

[frame.modbus.named]
register_number = 200
register_type = "holding"
length = 1
[[frame.modbus.named.signals]]
name = "B"
start_bit = 0
bit_length = 16
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert_eq!(frame(&m, "13050").register_number, 13050);
        // Explicit register_number wins even when the key isn't numeric.
        assert_eq!(frame(&m, "named").register_number, 200);
    }

    #[test]
    fn non_numeric_key_without_register_number_errors() {
        let toml = r#"
[frame.modbus.battery_status]
register_type = "input"
length = 1
[[frame.modbus.battery_status.signals]]
name = "A"
start_bit = 0
bit_length = 16
"#;
        assert!(matches!(
            ModbusManifest::parse(toml),
            Err(ManifestError::BadRegister(name)) if name == "battery_status"
        ));
    }

    // ---------- shorthand: signal-less register ----------

    #[test]
    fn signal_less_register_synthesises_full_width_signal() {
        // A register that IS a single scaled value — no [[signals]] block.
        let toml = r#"
[meta.modbus]
default_byte_order = "big"

[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "Inverter_Temperature"
factor = 0.1
unit = "°C"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.register_number, 0x138F);
        assert_eq!(f.signals.len(), 1);
        let s = &f.signals[0];
        assert_eq!(s.name, "Inverter_Temperature");
        assert_eq!(s.start_bit, 0);
        assert_eq!(s.bit_length, 16);
        // 0x0199 = 409 ×0.1 = 40.9.
        let d = &decode_frame(f, &[0x0199], &m.meta)[0];
        assert_eq!(d.value, dec!(40.9));
        assert_eq!(d.unit.as_deref(), Some("°C"));
    }

    #[test]
    fn scaled_value_stringifies_without_float_artifacts() {
        // Regression: f64 `3374 * 0.1` is 337.40000000000003, which
        // stringifies with binary-float noise. Decimal scaling is exact, so
        // the entity state the addon stores reads cleanly.
        let toml = r#"
[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "MPPT_Voltage"
factor = 0.1
unit = "V"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let d = &decode_frame(&m.frames[0], &[3374], &m.meta)[0];
        assert_eq!(d.value, dec!(337.4));
        assert_eq!(d.value.to_string(), "337.4");
    }

    #[test]
    fn a_signal_whose_scale_overflows_is_skipped() {
        let toml = r#"
[frame.modbus.0x100]
register_type = "input"
length = 4
[[frame.modbus.0x100.signals]]
name = "Huge"
start_bit = 0
bit_length = 64
factor = 1e15
[[frame.modbus.0x100.signals]]
name = "Low"
start_bit = 48
bit_length = 16
factor = 0.1
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let d = decode_frame(&m.frames[0], &[0xFFFF; 4], &m.meta);
        let names: Vec<_> = d.iter().map(|d| (d.name.as_str(), d.value)).collect();
        assert_eq!(names, [("Low", dec!(6553.5))]);
    }

    #[test]
    fn signal_less_ascii_register_spans_block_and_skips_decode() {
        let toml = r#"
[frame.modbus.0x1359]
register_type = "input"
length = 11
name = "ARM_Software_Version"
format = "ascii"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.signals.len(), 1);
        assert_eq!(f.signals[0].bit_length, 11 * 16);
        assert_eq!(f.signals[0].format, Some(SignalFormat::Ascii));
        // String formats are skipped by the numeric decoder.
        assert!(decode_frame(f, &[0x4142u16; 11], &m.meta).is_empty());
    }

    #[test]
    fn bare_register_block_without_fields_stays_signal_less() {
        // No signals AND no frame-level fields → still zero signals (raw block).
        let toml = r#"
[frame.modbus.0x100]
register_type = "input"
length = 2
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert!(m.frames[0].signals.is_empty());
    }

    #[test]
    fn combined_shorthands_key_and_signal_less() {
        // Both at once: register from the key, value from frame-level fields.
        let toml = r#"
[frame.modbus.0x145D]
register_type = "input"
length = 1
name = "Battery_Power"
signed = true
unit = "W"
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let f = &m.frames[0];
        assert_eq!(f.register_number, 0x145D);
        assert_eq!(f.signals.len(), 1);
        assert!(f.signals[0].signed);
        // 0xFF69 as signed 16-bit = -151.
        let d = &decode_frame(f, &[0xFF69], &m.meta)[0];
        assert_eq!(d.value, dec!(-151));
    }

    #[test]
    fn round_trips_through_json() {
        let m = parse_fixture();
        let s = serde_json::to_string(&m).unwrap();
        let back: ModbusManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn parses_disabled_frame_flag() {
        let toml = r#"
[frame.modbus.a]
register_number = 100
register_type = "input"
length = 1
disabled = true

[frame.modbus.b]
register_number = 200
register_type = "input"
length = 1
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        assert!(frame(&m, "a").disabled);
        assert!(!frame(&m, "b").disabled); // default
    }

    #[test]
    fn set_frame_disabled_toggles_and_preserves_comments() {
        let toml = r#"# top comment
[frame.modbus.a]
register_number = 100  # inline
register_type = "input"
length = 1

[frame.modbus.b]
register_number = 200
register_type = "input"
length = 1
"#;
        // Disable: flag added under frame a; comments + frame b untouched.
        let disabled = set_frame_disabled(toml, "a", true).unwrap();
        assert!(disabled.contains("# top comment"));
        assert!(disabled.contains("# inline"));
        assert!(disabled.contains("disabled = true"));
        let m = ModbusManifest::parse(&disabled).unwrap();
        assert!(frame(&m, "a").disabled);
        assert!(!frame(&m, "b").disabled);

        // Re-enable: the key is removed, not set to false.
        let enabled = set_frame_disabled(&disabled, "a", false).unwrap();
        assert!(!enabled.contains("disabled"));
        assert!(!ModbusManifest::parse(&enabled).unwrap().frames[0].disabled);

        // Unknown frame is an error.
        assert!(set_frame_disabled(toml, "missing", true).is_err());
    }

    // ---------- coil / discrete decode ----------

    /// Byte and word order are set here *on purpose*: a coil block has neither.
    const COIL_FIXTURE: &str = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"

[frame.modbus.relays]
register_number = 20
register_type = "coil"
length = 24

[[frame.modbus.relays.signals]]
name = "Pump"
start_bit = 0
bit_length = 1

[[frame.modbus.relays.signals]]
name = "Heater"
start_bit = 3
bit_length = 1

[[frame.modbus.relays.signals]]
name = "Mode"
start_bit = 6
bit_length = 4

[[frame.modbus.relays.signals]]
name = "Wide_Flags"
start_bit = 0
bit_length = 20
byte_order = "big"

[[frame.modbus.relays.signals]]
name = "Trim"
start_bit = 10
bit_length = 5
signed = true

[[frame.modbus.relays.signals]]
name = "Serial"
start_bit = 0
bit_length = 16
format = "ascii"

[frame.modbus.inputs]
register_number = 40
register_type = "discrete"
length = 8

[[frame.modbus.inputs.signals]]
name = "Alarm"
start_bit = 2
bit_length = 1

[frame.modbus.pump_running]
register_number = 7
register_type = "coil"
length = 1
name = "Pump_Running"
"#;

    fn coil_manifest() -> ModbusManifest {
        ModbusManifest::parse(COIL_FIXTURE).expect("coil fixture parses")
    }

    /// Coils 0, 3, 8 and 17 on, out of 24. Coil 7 is deliberately off: it is
    /// what big-endian bit numbering would read for coil 0, so leaving it set
    /// would make that assertion pass either way.
    fn relay_coils() -> Vec<bool> {
        let mut coils = vec![false; 24];
        for i in [0, 3, 8, 17] {
            coils[i] = true;
        }
        coils
    }

    #[test]
    fn a_coil_block_decodes_least_significant_bit_first() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        let v = |name: &str| d.iter().find(|d| d.name == name).unwrap().value;
        // Big-endian bit numbering would read coils 7 and 4 for these, both off.
        assert_eq!(v("Pump"), dec!(1));
        assert_eq!(v("Heater"), dec!(1));
    }

    #[test]
    fn a_coil_field_spans_a_byte_boundary_lowest_coil_first() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        // Coils 6,7,8,9 = 0,0,1,0 with coil 6 the least significant bit.
        assert_eq!(d.iter().find(|d| d.name == "Mode").unwrap().value, dec!(4));
    }

    #[test]
    fn coil_decode_ignores_byte_and_word_order() {
        // The regression test. `Wide_Flags` is 20 bits, so the register path
        // would word-swap it under this fixture's meta `little` word order, and
        // its own `byte_order = "big"` would flip the bit numbering again.
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        // Coils 0, 3, 8 and 17 → 1 + 8 + 256 + 131072.
        assert_eq!(
            d.iter().find(|d| d.name == "Wide_Flags").unwrap().value,
            dec!(131337)
        );
    }

    #[test]
    fn a_short_coil_block_reads_zero_past_its_end() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &[true, false, false, true]);
        let v = |name: &str| d.iter().find(|d| d.name == name).unwrap().value;
        assert_eq!(v("Wide_Flags"), dec!(9));
        assert_eq!(v("Mode"), dec!(0));
    }

    #[test]
    fn coil_decode_skips_string_formats() {
        let m = coil_manifest();
        let d = decode_coil_frame(frame(&m, "relays"), &relay_coils());
        assert!(!d.iter().any(|d| d.name == "Serial"));
    }

    #[test]
    fn a_discrete_frame_decodes_like_a_coil_one() {
        let m = coil_manifest();
        let mut coils = vec![false; 8];
        coils[2] = true;
        let d = decode_coil_frame(frame(&m, "inputs"), &coils);
        assert_eq!(d[0].name, "Alarm");
        assert_eq!(d[0].value, dec!(1));
    }

    /// Encode `value` into `name`, lay the writes out as the relay block, and
    /// decode that block again.
    fn coil_round_trip(name: &str, value: f64) -> Decimal {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        let s = signal(f, name);
        let base = m.protocol_address(f);
        let mut coils = vec![false; f.length as usize];
        for w in encode_signal(&m, f, s, value).unwrap() {
            assert_eq!((w.bank, w.mask), (WriteBank::Coil, 1));
            coils[(w.address - base) as usize] = w.value == 1;
        }
        let d = decode_coil_frame(f, &coils);
        d.iter().find(|d| d.name == name).unwrap().value
    }

    #[test]
    fn a_one_coil_signal_encodes_to_its_coil_and_round_trips() {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        assert_eq!(
            encode_signal(&m, f, signal(f, "Heater"), 1.0).unwrap(),
            vec![ModbusWrite::coil(23, true)]
        );
        assert_eq!(coil_round_trip("Heater", 1.0), dec!(1));
        assert_eq!(coil_round_trip("Heater", 0.0), dec!(0));
    }

    #[test]
    fn a_multi_coil_signal_encodes_lowest_coil_first_and_round_trips() {
        let m = coil_manifest();
        let f = frame(&m, "relays");
        // 4 = 0b0100: coils 26..30 read 0, 0, 1, 0.
        assert_eq!(
            encode_signal(&m, f, signal(f, "Mode"), 4.0).unwrap(),
            [(26, false), (27, false), (28, true), (29, false)]
                .map(|(a, on)| ModbusWrite::coil(a, on))
        );
        assert_eq!(coil_round_trip("Mode", 11.0), dec!(11));
        // Byte and word order are ignored on the way out as on the way in.
        assert_eq!(coil_round_trip("Wide_Flags", 131337.0), dec!(131337));
    }

    #[test]
    fn a_signed_coil_signal_round_trips() {
        assert_eq!(coil_round_trip("Trim", -5.0), dec!(-5));
        assert_eq!(coil_round_trip("Trim", -16.0), dec!(-16));
        assert_eq!(coil_round_trip("Trim", 15.0), dec!(15));
    }

    #[test]
    fn a_signal_less_coil_frame_synthesises_one_bit_per_coil() {
        // Was `length × 16`, so a one-coil frame asked for a 16-bit numeric
        // extraction from a one-byte block.
        let m = coil_manifest();
        let f = frame(&m, "pump_running");
        assert_eq!(f.signals[0].bit_length, 1);
        assert_eq!(decode_coil_frame(f, &[true])[0].value, dec!(1));
    }

    // ---------- write/encode (Stage A) ----------

    const WRITE_FIXTURE: &str = r#"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"

[frame.modbus.ems_control]
register_number = 13049
register_type = "holding"
length = 3
tx.interval_ms = 30000

[[frame.modbus.ems_control.signals]]
name = "EMS_Mode"
start_bit = 0
bit_length = 16
[frame.modbus.ems_control.signals.enum]
0 = "self_consume"
2 = "forced"

[[frame.modbus.ems_control.signals]]
name = "Forced_Charge_Discharge_Cmd"
start_bit = 16
bit_length = 16
format = "enum"
[frame.modbus.ems_control.signals.enum]
170 = "charge"
187 = "discharge"
204 = "stop"

[[frame.modbus.ems_control.signals]]
name = "Forced_Charge_Discharge_Power"
start_bit = 32
bit_length = 16
unit = "W"

[frame.modbus.battery_power_limits]
register_number = 33046
register_type = "holding"
length = 2

[[frame.modbus.battery_power_limits.signals]]
name = "Battery_Max_Charge_Power"
start_bit = 0
bit_length = 16
factor = 10
unit = "W"

[frame.modbus.wide]
register_number = 100
register_type = "holding"
length = 2

[[frame.modbus.wide.signals]]
name = "Wide_Signed"
start_bit = 0
bit_length = 32
signed = true

[frame.modbus.readonly_block]
register_number = 5213
register_type = "input"
length = 2

[[frame.modbus.readonly_block.signals]]
name = "Battery_Power"
start_bit = 0
bit_length = 32
signed = true
unit = "W"

[frame.modbus.coil_cmds]
register_number = 300
register_type = "coil"
length = 1

[[frame.modbus.coil_cmds.signals]]
name = "Force_Charge"
start_bit = 0
bit_length = 1
[frame.modbus.coil_cmds.signals.enum]
0 = "off"
1 = "on"
"#;

    fn write_manifest() -> ModbusManifest {
        ModbusManifest::parse(WRITE_FIXTURE).expect("write fixture parses")
    }

    fn wsig<'a>(m: &'a ModbusManifest, name: &str) -> (&'a ModbusFrame, &'a ModbusSignal) {
        m.find_write_signal(name)
            .unwrap_or_else(|| panic!("write signal {name} present"))
    }

    #[test]
    fn parses_enum_map_and_still_decodes_numeric() {
        let m = write_manifest();
        let (_, ems) = wsig(&m, "EMS_Mode");
        let map = ems.enum_map.as_ref().expect("enum map");
        assert_eq!(map.get("0").map(String::as_str), Some("self_consume"));
        assert_eq!(map.get("2").map(String::as_str), Some("forced"));
        // A `format = "enum"` signal still decodes to its numeric value so
        // its readback entity persists.
        let (frame, _) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        let regs = [0u16, 204, 0]; // cmd register = 204 ("stop")
        let decoded = decode_frame(frame, &regs, &m.meta);
        let cmd = decoded
            .iter()
            .find(|d| d.name == "Forced_Charge_Discharge_Cmd")
            .expect("enum signal decodes");
        assert_eq!(cmd.value, dec!(204));
    }

    fn reg(address: u16, value: u16) -> ModbusWrite {
        ModbusWrite::holding(address, value, 0xffff)
    }

    #[test]
    fn encode_enum_resolves_canonical_name() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        assert_eq!(
            encode_enum(&m, f, s, "charge").unwrap(),
            vec![reg(13050, 170)]
        );
        assert_eq!(
            encode_enum(&m, f, s, "stop").unwrap(),
            vec![reg(13050, 204)]
        );
    }

    #[test]
    fn encode_signal_applies_scale_and_address_offset() {
        let m = write_manifest();
        // Forced power: register 13049 + start_bit 32/16 = 13051, factor 1.
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Power");
        assert_eq!(
            encode_signal(&m, f, s, 3000.0).unwrap(),
            vec![reg(13051, 3000)]
        );
        // Max charge: 33046, W/10 (factor 10) → 5000 W encodes to 500.
        let (f, s) = wsig(&m, "Battery_Max_Charge_Power");
        assert_eq!(
            encode_signal(&m, f, s, 5000.0).unwrap(),
            vec![reg(33046, 500)]
        );
    }

    #[test]
    fn encode_decode_round_trips_signed_32bit_word_swapped() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Wide_Signed");
        let writes = encode_signal(&m, f, s, -1000.0).unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].address, 100);
        assert_eq!(writes[1].address, 101);
        // Round-trip the written register block through the decoder.
        let regs: Vec<u16> = writes.iter().map(|w| w.value).collect();
        let decoded = decode_frame(f, &regs, &m.meta);
        assert_eq!(decoded[0].value, dec!(-1000));
    }

    #[test]
    fn encode_clamps_to_bit_width() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Power"); // u16
        assert_eq!(encode_signal(&m, f, s, -50.0).unwrap(), vec![reg(13051, 0)]);
        assert_eq!(
            encode_signal(&m, f, s, 1_000_000.0).unwrap(),
            vec![reg(13051, 65535)]
        );
    }

    #[test]
    fn encode_single_register_bitfield_is_masked() {
        // A 4-bit field at start_bit 4 of a holding register → masked write.
        let toml = r#"
[frame.modbus.flags]
register_number = 200
register_type = "holding"
length = 1

[[frame.modbus.flags.signals]]
name = "Nibble"
start_bit = 4
bit_length = 4
"#;
        let m = ModbusManifest::parse(toml).unwrap();
        let (f, s) = m.find_write_signal("Nibble").unwrap();
        // value 0b1010 = 10, field at bits [4,8) from the MSB → shift 8.
        let w = encode_signal(&m, f, s, 10.0).unwrap();
        assert_eq!(w, vec![ModbusWrite::holding(200, 0x0A00, 0x0F00)]);
    }

    #[test]
    fn merge_combines_bitfields_and_rejects_overlap() {
        let a = ModbusWrite::holding(5, 0x0A00, 0x0F00);
        let b = ModbusWrite::holding(5, 0x000B, 0x000F);
        // Disjoint bit-fields in one register merge into a single write.
        let merged = merge_register_writes(vec![a, b]).unwrap();
        assert_eq!(merged, vec![ModbusWrite::holding(5, 0x0A0B, 0x0F0F)]);
        // Overlapping masks are a conflict.
        let c = ModbusWrite::holding(5, 0x0100, 0x0F00);
        assert_eq!(
            merge_register_writes(vec![a, c]).unwrap_err(),
            "register 5 written by overlapping commands"
        );
    }

    #[test]
    fn a_coil_and_a_register_at_one_number_stay_two_writes() {
        let writes = vec![reg(5, 1), ModbusWrite::coil(5, true)];
        assert_eq!(merge_register_writes(writes.clone()).unwrap(), writes);
        assert_eq!(
            merge_register_writes(vec![
                ModbusWrite::coil(5, true),
                ModbusWrite::coil(5, false)
            ])
            .unwrap_err(),
            "coil 5 written by overlapping commands"
        );
    }

    #[test]
    fn overlay_last_wins_per_register_keeping_order() {
        let out =
            overlay_register_writes(vec![reg(33046, 6000), reg(33047, 6000), reg(33046, 1000)]);
        assert_eq!(out, vec![reg(33046, 1000), reg(33047, 6000)]);
    }

    #[test]
    fn overlay_merges_disjoint_bitfields() {
        let lo = ModbusWrite::holding(13049, 0x0002, 0x00ff);
        let hi = ModbusWrite::holding(13049, 0xAA00, 0xff00);
        assert_eq!(
            overlay_register_writes(vec![lo, hi]),
            vec![ModbusWrite::holding(13049, 0xAA02, 0xffff)]
        );
    }

    #[test]
    fn overlay_keeps_a_coil_and_a_register_at_one_number_apart() {
        let out = overlay_register_writes(vec![
            reg(33046, 6000),
            ModbusWrite::coil(33046, true),
            ModbusWrite::coil(33046, false),
        ]);
        assert_eq!(out, vec![reg(33046, 6000), ModbusWrite::coil(33046, false)]);
    }

    #[test]
    fn overlay_ignores_a_later_writes_bits_outside_its_mask() {
        let hi = ModbusWrite::holding(5, 0x1200, 0xff00);
        let lo_with_stray_bits = ModbusWrite::holding(5, 0xFFAB, 0x00ff);
        assert_eq!(
            overlay_register_writes(vec![hi, lo_with_stray_bits]),
            vec![ModbusWrite::holding(5, 0x12AB, 0xffff)]
        );
    }

    #[test]
    fn group_contiguous_starts_a_run_on_a_change_of_bank() {
        let writes = vec![
            reg(5, 1),
            reg(6, 2),
            ModbusWrite::coil(7, true),
            ModbusWrite::coil(8, false),
            reg(9, 3),
        ];
        let runs = group_contiguous(&writes);
        assert_eq!(
            runs,
            vec![
                writes[..2].to_vec(),
                writes[2..4].to_vec(),
                writes[4..].to_vec()
            ]
        );
    }

    #[test]
    fn a_write_without_a_bank_deserialises_as_holding() {
        let w: ModbusWrite = serde_json::from_str(r#"{"address":5,"value":1}"#).unwrap();
        assert_eq!(w, reg(5, 1));
        let json = serde_json::to_string(&ModbusWrite::coil(5, true)).unwrap();
        assert_eq!(json, r#"{"bank":"coil","address":5,"value":1,"mask":1}"#);
    }

    #[test]
    fn group_contiguous_runs_and_preserves_order() {
        // 13049,13050,13051 contiguous → one run; 13073 a separate run; order
        // kept (13086 before 13073 stays two runs in that order).
        let writes = vec![
            reg(13049, 2),
            reg(13050, 170),
            reg(13051, 3000),
            reg(13086, 1),
            reg(13073, 0),
        ];
        let runs = group_contiguous(&writes);
        assert_eq!(runs.len(), 3);
        assert_eq!(
            runs[0].iter().map(|w| w.address).collect::<Vec<_>>(),
            vec![13049, 13050, 13051]
        );
        assert_eq!(runs[1], vec![reg(13086, 1)]);
        assert_eq!(runs[2], vec![reg(13073, 0)]);
    }

    #[test]
    fn encode_rejects_read_only_and_unknown_enum() {
        let m = write_manifest();
        // A signal that only exists in an input frame isn't a write target.
        assert!(m.find_write_signal("Battery_Power").is_none());
        let (f, s) = wsig(&m, "Forced_Charge_Discharge_Cmd");
        assert_eq!(
            encode_enum(&m, f, s, "frobnicate").unwrap_err(),
            EncodeError::UnknownEnumName {
                name: "Forced_Charge_Discharge_Cmd".into(),
                value: "frobnicate".into(),
            }
        );
    }

    #[test]
    fn coil_signals_are_offered_as_write_targets_at_their_coil() {
        let m = write_manifest();
        assert!(m.find_write_signal("Force_Charge").is_some());
        let opts = m.write_signal_options();
        assert!(opts.contains(&("Force_Charge".into(), 300)), "{opts:?}");
        let enums = m.write_signal_enums();
        assert!(enums.iter().any(|(n, _)| n == "Force_Charge"));
    }

    #[test]
    fn a_coil_signal_encodes_as_a_coil_and_a_read_only_one_is_refused() {
        let m = write_manifest();
        let (f, s) = wsig(&m, "Force_Charge");
        assert_eq!(
            encode_enum(&m, f, s, "on").unwrap(),
            vec![ModbusWrite::coil(300, true)]
        );
        assert_eq!(
            encode_signal(&m, f, s, 0.0).unwrap(),
            vec![ModbusWrite::coil(300, false)]
        );
        let ro = frame(&m, "readonly_block");
        assert_eq!(
            encode_signal(&m, ro, signal(ro, "Battery_Power"), 1.0).unwrap_err(),
            EncodeError::NotWritable("Battery_Power".into())
        );
    }

    #[test]
    fn write_bank_bridges_only_the_writable_register_types() {
        assert_eq!(RegisterType::Holding.write_bank(), Some(WriteBank::Holding));
        assert_eq!(RegisterType::Coil.write_bank(), Some(WriteBank::Coil));
        assert_eq!(RegisterType::Input.write_bank(), None);
        assert_eq!(RegisterType::Discrete.write_bank(), None);
    }

    #[test]
    fn write_signal_options_carry_register_and_list_writable_only() {
        let opts = write_manifest().write_signal_options();
        let reg = |name: &str| opts.iter().find(|(n, _)| n == name).map(|(_, r)| *r);
        // ems_control @ 13049: EMS_Mode @ +0, Forced_Cmd @ +1 (start_bit 16).
        assert_eq!(reg("EMS_Mode"), Some(13049));
        assert_eq!(reg("Forced_Charge_Discharge_Cmd"), Some(13050));
        // battery_power_limits @ 33046.
        assert_eq!(reg("Battery_Max_Charge_Power"), Some(33046));
        // Input-frame signals aren't offered (read-only).
        assert_eq!(reg("Battery_Power"), None);
        // Register-sorted.
        assert!(opts.windows(2).all(|w| w[0].1 <= w[1].1));
    }

    #[test]
    fn write_signal_enums_lists_only_enum_signals_value_sorted() {
        let m = write_manifest();
        let enums = m.write_signal_enums();
        let get = |name: &str| {
            enums
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, e)| e.clone())
        };
        // The enum command register, value-sorted.
        assert_eq!(
            get("Forced_Charge_Discharge_Cmd"),
            Some(vec![
                ("charge".into(), 170),
                ("discharge".into(), 187),
                ("stop".into(), 204),
            ])
        );
        // A plain numeric signal has no enum entry.
        assert_eq!(get("Forced_Charge_Discharge_Power"), None);
    }
}
