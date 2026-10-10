//! Unified catalogue model shared by all protocols (CAN, Serial, Modbus).
//!
//! This is the *resolved* representation produced by [`crate::parse`]: authoring
//! shorthands are expanded, mirror/copy inheritance is applied, and per-frame
//! defaults are folded in. It serialises to JSON for the frontend (camelCase, so
//! the generated TypeScript reads idiomatically) and is the input to
//! [`crate::decode`].
//!
//! The catalogue enums ([`SignalFormat`], [`RegisterType`]) live here; the
//! `modbus` module re-exports them so its public API is unchanged. [`Endianness`]
//! is the protocol-agnostic byte/word ordering — it lives in `wiretap-decode`
//! (the numeric core) and is re-exported here so callers keep using
//! `model::Endianness`.

use std::{collections::BTreeMap, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::modbus_rtu_stream::LengthRule;

/// Byte / word ordering — re-exported from the `wiretap-decode` numeric core.
pub use wiretap_decode::Endianness;

/// Which wire protocol a frame/catalogue uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Can,
    Serial,
    Modbus,
}

impl Protocol {
    /// The same lowercase spelling serde writes, and a frame table's key.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Can => "can",
            Protocol::Serial => "serial",
            Protocol::Modbus => "modbus",
        }
    }
}

/// Modbus register class — determines the function code the poller uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegisterType {
    Input,
    #[default]
    Holding,
    Coil,
    Discrete,
}

impl RegisterType {
    /// Whether this bank is addressed as 16-bit registers (input/holding)
    /// rather than as single bits (coil/discrete). It is the question under
    /// every count: how many bits one address holds, how many bytes a quantity
    /// occupies on the wire, and which decoder a read's block goes to.
    pub fn is_register_bank(self) -> bool {
        matches!(self, RegisterType::Input | RegisterType::Holding)
    }

    /// Whether this register class can be written. In Modbus, `holding`
    /// (FC06/16) and `coil` (FC05/15) are read/write; `input` (FC04) and
    /// `discrete` (FC02) are read-only.
    pub fn is_writable(self) -> bool {
        matches!(self, RegisterType::Holding | RegisterType::Coil)
    }

    /// The bank a write to this class targets, or `None` for a read-only one.
    pub fn write_bank(self) -> Option<WriteBank> {
        match self {
            RegisterType::Holding => Some(WriteBank::Holding),
            RegisterType::Coil => Some(WriteBank::Coil),
            RegisterType::Input | RegisterType::Discrete => None,
        }
    }

    /// The traditional 1-based address prefix for this bank (`register_base = 1`),
    /// which a wire address is offset from. The only place these four numbers
    /// should appear.
    pub fn base_one_prefix(self) -> u32 {
        match self {
            RegisterType::Coil => 1,
            RegisterType::Discrete => 10001,
            RegisterType::Input => 30001,
            RegisterType::Holding => 40001,
        }
    }

    /// Lowercase tag, matching the manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterType::Input => "input",
            RegisterType::Holding => "holding",
            RegisterType::Coil => "coil",
            RegisterType::Discrete => "discrete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Unknown register type '{0}' — use holding, input, coil, or discrete")]
pub struct UnknownRegisterType(pub String);

/// The [`RegisterType::as_str`] tags, in any case.
impl FromStr for RegisterType {
    type Err = UnknownRegisterType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "input" => Ok(RegisterType::Input),
            "holding" => Ok(RegisterType::Holding),
            "coil" => Ok(RegisterType::Coil),
            "discrete" => Ok(RegisterType::Discrete),
            _ => Err(UnknownRegisterType(s.to_owned())),
        }
    }
}

/// The two banks a Modbus write can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteBank {
    #[default]
    Holding,
    Coil,
}

impl WriteBank {
    /// What one address of this bank is called in a message: `register` or `coil`.
    pub fn noun(self) -> &'static str {
        match self {
            WriteBank::Holding => "register",
            WriteBank::Coil => "coil",
        }
    }
}

/// A signal's data format. Any value here marks the signal as non-numeric
/// (string/opaque) — [`crate::decode`] renders it specially rather than as a
/// plain scaled number. Absent = a plain scaled number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalFormat {
    Ascii,
    Utf8,
    Hex,
    Enum,
    UnixTime,
    #[serde(other)]
    Other,
}

/// Reverse-engineering confidence marker (carried through from the catalogue
/// for the editor/discovery UI; not used by decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
}

impl Confidence {
    /// The same lowercase spelling serde writes: `none`, `low`, `medium` or `high`.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// How a dashboard should show a signal: `display = "rotary"`, or a table such as
/// `{ widget = "level-bar", orientation = "vertical" }`. The widget names are the
/// consumer's, and the options keep their keys as authored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayHint {
    pub widget: String,
    #[serde(flatten)]
    pub options: BTreeMap<String, serde_json::Value>,
}

impl DisplayHint {
    /// `None` for anything but a widget name or a table with one as `widget`.
    pub(crate) fn from_authored(value: serde_json::Value) -> Option<Self> {
        let hint = match value {
            serde_json::Value::String(widget) => Self {
                widget,
                options: BTreeMap::new(),
            },
            serde_json::Value::Object(mut table) => match table.remove("widget") {
                Some(serde_json::Value::String(widget)) => Self {
                    widget,
                    options: table.into_iter().collect(),
                },
                _ => return None,
            },
            _ => return None,
        };
        (!hint.widget.is_empty()).then_some(hint)
    }

    pub(crate) fn from_toml(value: &toml::Value) -> Option<Self> {
        serde_json::to_value(value)
            .ok()
            .and_then(Self::from_authored)
    }
}

/// A single decoded field, resolved from the catalogue. Fields are optional
/// because mux-case and inherited signals may carry only overrides; a fully
/// resolved signal for decode has `name`/`start_bit`/`bit_length` set.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_bit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Byte order (the catalogue's legacy key is `endianness`; the newer key is
    /// `byte_order`). Stored here as the resolved byte order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<SignalFormat>,
    /// Value↔label map (`enum` table in the catalogue). Keys are the numeric
    /// register/field value.
    #[serde(default, rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_map: Option<BTreeMap<i64, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<DisplayHint>,
    /// Free-text notes on the signal (`notes` — a string or array in TOML).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// True when this signal was inherited from a mirror/copy source rather
    /// than defined directly on the frame.
    #[serde(default, skip_serializing_if = "is_false")]
    pub inherited: bool,
    /// Modbus-specific: the signal's own register number, synthesised from the
    /// frame's base register plus the signal's bit offset (word registers add
    /// `start_bit / 16`; coils/discretes add `start_bit`). `None` for non-Modbus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register: Option<u32>,
    /// Modbus-specific: how many registers (or coils) this signal spans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register_count: Option<u16>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One case of a multiplexer: the signals (and optional nested mux) active when
/// the selector matches this case's key.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxCase {
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Box<Mux>>,
    /// Free-text notes on the case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A multiplexer: a selector bit-field plus the per-case signal sets. Case keys
/// are kept as strings to preserve the catalogue's range/list syntax
/// (`"0"`, `"0-3"`, `"1,2,5"`); [`crate::decode`] matches them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mux {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
    /// The default case key applied when the selector matches no explicit case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Free-text notes on the multiplexer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub cases: BTreeMap<String, MuxCase>,
    /// The keys of `cases` in [`crate::compare_mux_case_keys`] order, which JSON's object loses.
    #[serde(default)]
    pub case_order: Vec<String>,
}

/// The protocol carried inside a tunnel frame's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    /// Modbus RTU — a byte stream chopped across consecutive frames, with
    /// message boundaries recovered from the RTU length rules and CRC.
    ModbusRtu,
}

/// A frame that carries a tunnelled protocol rather than a fixed bit layout
/// (`[frame.can.<key>.tunnel]`).
///
/// The payloads of consecutive frames with this id concatenate into one byte
/// stream — both directions land on the same id — so decoding needs state
/// across frames, which [`crate::decode`] deliberately does not have. See
/// [`crate::modbus_rtu_stream`] for the decoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FrameTunnel {
    pub protocol: TunnelProtocol,
    /// The Modbus slave address to sync on. Absent means "any valid address"
    /// (`1..=247`), which resyncs more slowly after a dropped frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_address: Option<u8>,
    /// Unmodelled function codes this line is known to carry, beyond the
    /// catalogue's [`ModbusConfig::function_codes`]. Empty means none; unioned
    /// with any the caller adds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendor_functions: Vec<u8>,
    /// Whether this line's master broadcasts to address 0.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_broadcast: bool,
    /// Free-text notes on the tunnel declaration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A per-frame checksum definition (`[[frame.<proto>.<key>.checksum]]`).
/// Distinct from [`ChecksumConfig`] (the serial-level default); a frame may
/// declare several.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameChecksum {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A named algorithm, or one of the parameterised ids
    /// ([`wiretap_checksum::CRC_CUSTOM`], [`wiretap_checksum::SUM8_NEGATED`]).
    pub algorithm: String,
    /// Byte offset of the checksum. **Negative counts from the end**, which is
    /// how detection reports every position — these were `u32`, so no detected
    /// checksum survived a reload.
    pub start_byte: i32,
    #[serde(default = "one")]
    pub byte_length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    /// First byte of the calculation range.
    #[serde(default)]
    pub calc_start_byte: i32,
    /// Last byte of the calculation range, exclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calc_end_byte: Option<i32>,
    /// Parameters for a configuration no named algorithm can express.
    ///
    /// A recovered CRC carries all of `polynomial`/`width`/`init`/`xor_out` and
    /// the two reflections; an offset sum carries only `offset`. Absent for the
    /// eleven named algorithms, which define their own.
    #[serde(flatten)]
    pub parameters: ChecksumParameters,
    /// Free text carried with the declaration. A recovered CRC records here that
    /// its `init`/`xorOut` pair is one of several that fit — the crate is
    /// emphatic that presenting one as *the* answer is wrong, and a catalogue
    /// that stores only the pair would do exactly that.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl FrameChecksum {
    /// A catalogue entry for a configuration discovery worked out.
    ///
    /// Takes the whole solved result rather than its parts: the geometry is five
    /// scalars of near-identical type, and the caller always holds them bundled
    /// already.
    pub fn from_solved(name: Option<String>, solved: &wiretap_checksum::SolvedChecksum) -> Self {
        use wiretap_checksum::ChecksumSpecification;

        let target = solved.target;
        let parameters = match &solved.specification {
            ChecksumSpecification::Named { .. } => ChecksumParameters::default(),
            ChecksumSpecification::Additive { offset, .. } => ChecksumParameters {
                offset: Some(*offset),
                ..Default::default()
            },
            ChecksumSpecification::Crc(crc) => ChecksumParameters {
                polynomial: Some(crc.polynomial),
                init: Some(crc.init),
                xor_out: Some(crc.xor_out),
                reflect_in: Some(crc.reflect_in),
                reflect_out: Some(crc.reflect_out),
                offset: None,
            },
        };

        // The engine is emphatic that `init`/`xorOut` are not separately
        // identifiable from fixed-length payloads. Storing the pair without
        // saying so would present a guess as the answer.
        let mut notes = Vec::new();
        if let ChecksumSpecification::Crc(crc) = &solved.specification {
            if !crc.alternatives.is_empty() {
                notes.push(format!(
                    "init/xorOut are not separately identifiable from fixed-length payloads; {} other pair(s) reproduce this data identically",
                    crc.alternatives.len()
                ));
            }
        }

        Self {
            name,
            algorithm: solved.specification.algorithm_id().to_string(),
            start_byte: target.position,
            byte_length: target.byte_length as u32,
            endianness: (target.byte_length > 1).then_some(if target.big_endian {
                Endianness::Big
            } else {
                Endianness::Little
            }),
            calc_start_byte: target.calc_start_byte,
            calc_end_byte: Some(target.calc_end_byte),
            parameters,
            notes,
        }
    }

    /// The configuration this declaration describes, if it is coherent.
    ///
    /// The inverse of [`from_solved`](Self::from_solved), and the half that was
    /// missing: the algorithm id is not a faithful encoding on its own, because
    /// a plain sum and a sum with an offset are both stored as `sum8` and differ
    /// only by a field the id cannot carry. A reader with just the id
    /// mis-verifies the second as the first.
    pub fn specification(&self) -> Option<wiretap_checksum::ChecksumSpecification> {
        use wiretap_checksum::{
            AdditiveOp, ChecksumAlgorithm, ChecksumSpecification, CrcParameters, CRC_CUSTOM,
            SUM8_NEGATED,
        };
        let p = &self.parameters;

        if self.algorithm == CRC_CUSTOM {
            return Some(ChecksumSpecification::Crc(CrcParameters {
                // The CRC's width *is* how many bytes the checksum occupies;
                // storing it again invites the two to disagree.
                width: (self.byte_length * 8) as u8,
                polynomial: p.polynomial?,
                reflect_in: p.reflect_in.unwrap_or(false),
                reflect_out: p.reflect_out.unwrap_or(false),
                init: p.init.unwrap_or(0),
                xor_out: p.xor_out.unwrap_or(0),
                well_known: false,
                alternatives: Vec::new(),
            }));
        }
        if self.algorithm == SUM8_NEGATED {
            return Some(ChecksumSpecification::Additive {
                op: AdditiveOp::NegatedSum,
                offset: p.offset.unwrap_or(0),
            });
        }

        let algorithm: ChecksumAlgorithm = self.algorithm.parse().ok()?;
        // An offset is precisely what the fixed list cannot express, so a
        // declaration carrying one is the additive family however it is named.
        match (algorithm, p.offset) {
            (ChecksumAlgorithm::Xor, Some(offset)) => Some(ChecksumSpecification::Additive {
                op: AdditiveOp::Xor,
                offset,
            }),
            (ChecksumAlgorithm::Sum8, Some(offset)) => Some(ChecksumSpecification::Additive {
                op: AdditiveOp::Sum,
                offset,
            }),
            _ => Some(ChecksumSpecification::Named { algorithm }),
        }
    }
}

/// The parameters a solved checksum needs and a named one does not.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumParameters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub polynomial: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xor_out: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflect_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflect_out: Option<bool>,
    /// The constant an additive checksum adds after summing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u8>,
}

/// A resolved frame: one CAN message / serial frame / Modbus register read,
/// with its signals, mux, and inheritance applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    /// The authored catalogue table key (CAN: `"0x103"`; serial/modbus: the
    /// frame name). The stable identifier the editor uses for tree paths and
    /// comment-preserving edits — preserved verbatim, unlike the numeric
    /// `frame_id`.
    pub key: String,
    /// Numeric identifier: CAN arbitration ID, serial frame id, or Modbus
    /// register number. [`NAME_KEYED_FRAME_ID`] for a serial frame keyed by a name.
    pub frame_id: u32,
    pub protocol: Protocol,
    /// A CAN frame's `name`, or the catalogue table key when it carries meaning
    /// (e.g. a Modbus frame's `ems_control`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Frame length in bytes.
    pub length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_fd: Option<bool>,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Mux>,
    /// Set when the frame carries a tunnelled protocol instead of a bit layout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<FrameTunnel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_from: Option<String>,
    /// Modbus-specific: register class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register_type: Option<RegisterType>,
    /// Modbus-specific: register count (not bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register_count: Option<u16>,
    /// Modbus-specific: the slave node this register is read from
    /// (`[frame.modbus.<name>].node` → `[node.<name>]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_node: Option<String>,
    /// Modbus-specific: resolved device (slave) address — from the assigned
    /// node, the legacy `[meta.modbus].device_address`, else `1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_device_address: Option<u8>,
    /// Serial-specific: explicit frame delimiter bytes (raw encoding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delimiter: Option<Vec<u8>>,
    /// Free-text notes, normalised from the catalogue's `notes` (a string or an
    /// array of strings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Per-frame checksum definitions (CAN/serial; absent on Modbus).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checksums: Vec<FrameChecksum>,
    /// Names of fields whose value was inherited (from a per-frame default,
    /// a `copy`/`mirror_of` source, or auto-detection) rather than set
    /// explicitly on this frame. Drives the editor's "(inherited)" labels.
    /// Possible entries: `length`, `transmitter`, `interval`, `extended`,
    /// `fd`, `signals` (some are [`Signal::inherited`]), `mux` (all of it, from
    /// a `mirror_of` source), `deviceAddress`, `registerBase`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_fields: Vec<String>,
}

/// The `frame_id` of a serial frame keyed by a name, such as
/// `[frame.serial.heartbeat]`, which has no numeric id.
pub const NAME_KEYED_FRAME_ID: u32 = u32::MAX;

impl Frame {
    /// Whether this is a serial frame keyed by a name rather than an id.
    pub fn is_keyed_by_name(&self) -> bool {
        self.protocol == Protocol::Serial && crate::parse::parse_id(&self.key).is_none()
    }

    /// Every directly defined signal: the frame's own, then each mux case's depth first.
    pub fn own_signals(&self) -> Vec<&Signal> {
        let mut out = Vec::new();
        push_own(&self.signals, &mut out);
        if let Some(mux) = &self.mux {
            push_mux_own(mux, &mut out);
        }
        out
    }
}

fn push_own<'a>(signals: &'a [Signal], out: &mut Vec<&'a Signal>) {
    out.extend(signals.iter().filter(|s| !s.inherited));
}

fn push_mux_own<'a>(mux: &'a Mux, out: &mut Vec<&'a Signal>) {
    for case in mux.cases.values() {
        push_own(&case.signals, out);
        if let Some(inner) = &case.mux {
            push_mux_own(inner, out);
        }
    }
}

/// A header field defined by a bitmask over the frame's header bytes (CAN ID
/// bits, or serial header bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderField {
    pub mask: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shift: Option<u32>,
    /// `hex` or `decimal` display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
}

/// A serial header field with its byte position derived from the mask at parse
/// time (so consumers don't re-derive it). One entry per `[meta.serial.fields]`
/// field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderFieldPosition {
    pub name: String,
    pub mask: u32,
    pub byte_order: Endianness,
    /// `hex` or `decimal` display.
    pub format: String,
    pub start_byte: u32,
    pub bytes: u32,
}

/// `[meta.can]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_fd: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_mask: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, HeaderField>,
}

/// `[meta.serial.checksum]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumConfig {
    pub algorithm: String,
    /// End-relative when negative — see [`FrameChecksum::start_byte`].
    pub start_byte: i32,
    #[serde(default = "one")]
    pub byte_length: u32,
    #[serde(default)]
    pub calc_start_byte: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calc_end_byte: Option<i32>,
    #[serde(default)]
    pub big_endian: bool,
}

fn one() -> u32 {
    1
}

/// `[meta.serial]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialConfig {
    /// `slip` | `cobs` | `raw` | `length_prefixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_mask: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_frame_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<ChecksumConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, HeaderField>,
    // ── Derived from `fields` at parse time (byte positions of named fields) ──
    /// Byte position of the `id` field, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_start_byte: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_byte_order: Option<Endianness>,
    /// Byte position of the `source_address` field, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_start_byte: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_byte_order: Option<Endianness>,
    /// One position entry per header field (the resolved form of `fields`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_fields: Vec<HeaderFieldPosition>,
}

/// `[meta.modbus]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModbusConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_address: Option<u8>,
    /// 0 = IEC (0-based); 1 = traditional 1-based with a type prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_base: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_word_order: Option<Endianness>,
    /// `[meta.modbus.function_code.<code>]`: the vendor codes this catalogue's
    /// devices use, which every serial line and tunnel it describes inherits.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub function_codes: BTreeMap<u8, FunctionCode>,
}

/// A vendor function code a catalogue declares.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCode {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its messages' layouts, tried in order. Empty leaves it to the CRC search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lengths: Vec<LengthRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// `[meta]` — catalogue identity.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub name: String,
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_frame: Option<Protocol>,
}

/// A network node/peer declared under `[node.<name>]`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDef {
    pub name: String,
    /// Modbus-specific: the device (slave) address this node owns
    /// (`[node.<name>].device_address`). `None` for CAN/serial nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_address: Option<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// The defaults decode applies where the catalogue sets none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveDefaults {
    pub can_byte_order: Endianness,
    pub serial_byte_order: Endianness,
    pub modbus_byte_order: Endianness,
    pub modbus_word_order: Endianness,
    /// 0 unless `[meta.modbus] register_base = 1`.
    pub modbus_register_base: u8,
}

impl EffectiveDefaults {
    pub fn of(
        can: Option<&CanConfig>,
        serial: Option<&SerialConfig>,
        modbus: Option<&ModbusConfig>,
    ) -> Self {
        Self {
            can_byte_order: can
                .and_then(|c| c.default_byte_order)
                .unwrap_or(Endianness::Little),
            serial_byte_order: serial
                .and_then(|c| c.byte_order)
                .unwrap_or(Endianness::Little),
            modbus_byte_order: modbus
                .and_then(|c| c.default_byte_order)
                .unwrap_or(Endianness::Big),
            modbus_word_order: modbus
                .and_then(|c| c.default_word_order)
                .unwrap_or(Endianness::Big),
            modbus_register_base: modbus.and_then(|c| c.register_base).unwrap_or(0),
        }
    }
}

impl Catalog {
    /// The defaults decode applies, derived from the configs rather than read
    /// from [`Catalog::effective_defaults`], which a deserialised model may lack.
    pub fn derived_defaults(&self) -> EffectiveDefaults {
        EffectiveDefaults::of(
            self.can.as_ref(),
            self.serial.as_ref(),
            self.modbus.as_ref(),
        )
    }
}

impl Default for EffectiveDefaults {
    fn default() -> Self {
        Self::of(None, None, None)
    }
}

/// A fully parsed, resolved catalogue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub meta: Meta,
    /// The catalogue's dominant protocol (from `meta.default_frame`, else
    /// inferred from which frame sections are present).
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can: Option<CanConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<SerialConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus: Option<ModbusConfig>,
    #[serde(default)]
    pub frames: Vec<Frame>,
    /// Network nodes/peers from the `[node]` table, in key order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeDef>,
    /// The served copy of [`Catalog::derived_defaults`], for consumers.
    #[serde(default)]
    pub effective_defaults: EffectiveDefaults,
}

/// A single validation finding (field path + human message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_signal_names(toml: &str, id: u32) -> Vec<String> {
        let catalog = Catalog::parse(toml).unwrap();
        catalog
            .frame(id)
            .unwrap()
            .own_signals()
            .iter()
            .map(|s| s.name.clone().unwrap())
            .collect()
    }

    #[test]
    fn own_signals_of_a_plain_frame_are_its_signals_in_order() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "a"
start_bit = 0
bit_length = 8
[[frame.can.0x100.signals]]
name = "b"
start_bit = 8
bit_length = 8
"#;
        assert_eq!(own_signal_names(toml, 0x100), ["a", "b"]);
    }

    #[test]
    fn own_signals_follow_with_mux_cases_nested_depth_first_in_case_order() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x300]
length = 8
[[frame.can.0x300.signals]]
name = "top"
start_bit = 56
bit_length = 8
[frame.can.0x300.mux]
start_bit = 0
bit_length = 8
[[frame.can.0x300.mux."0".signals]]
name = "zero"
start_bit = 8
bit_length = 8
[[frame.can.0x300.mux."1".signals]]
name = "one"
start_bit = 8
bit_length = 8
[frame.can.0x300.mux."1".mux]
start_bit = 16
bit_length = 4
[[frame.can.0x300.mux."1".mux."0".signals]]
name = "deep"
start_bit = 24
bit_length = 8
[[frame.can.0x300.mux."2".signals]]
name = "two"
start_bit = 8
bit_length = 8
"#;
        assert_eq!(
            own_signal_names(toml, 0x300),
            ["top", "zero", "one", "deep", "two"]
        );
    }

    #[test]
    fn own_signals_skip_those_a_mirror_inherits() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "inherited"
start_bit = 0
bit_length = 8
[[frame.can.0x100.signals]]
name = "overridden"
start_bit = 8
bit_length = 8
[frame.can.0x101]
mirror_of = "0x100"
[[frame.can.0x101.signals]]
name = "override"
start_bit = 8
bit_length = 8
[[frame.can.0x101.signals]]
name = "added"
start_bit = 16
bit_length = 8
"#;
        assert_eq!(own_signal_names(toml, 0x101), ["override", "added"]);
    }

    #[test]
    fn own_signals_skip_a_mux_a_mirror_inherits() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
[frame.can.0x100.mux]
start_bit = 0
bit_length = 8
[[frame.can.0x100.mux."0".signals]]
name = "case"
start_bit = 8
bit_length = 8
[frame.can.0x100.mux."1".mux]
start_bit = 8
bit_length = 8
[[frame.can.0x100.mux."1".mux."0".signals]]
name = "deep"
start_bit = 16
bit_length = 8
[frame.can.0x101]
mirror_of = "0x100"
[[frame.can.0x101.signals]]
name = "added"
start_bit = 56
bit_length = 8
"#;
        assert_eq!(own_signal_names(toml, 0x100), ["case", "deep"]);
        assert_eq!(own_signal_names(toml, 0x101), ["added"]);
    }

    #[test]
    fn confidence_as_str_matches_its_serde_spelling() {
        for c in [
            Confidence::None,
            Confidence::Low,
            Confidence::Medium,
            Confidence::High,
        ] {
            assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
        }
    }

    #[test]
    fn a_register_type_parses_its_own_tag_in_any_case() {
        use RegisterType::*;
        for rt in [Input, Holding, Coil, Discrete] {
            assert_eq!(serde_json::to_value(rt).unwrap(), rt.as_str());
            assert_eq!(rt.as_str().parse(), Ok(rt));
            assert_eq!(rt.as_str().to_ascii_uppercase().parse(), Ok(rt));
        }
        assert_eq!(
            "Holdin".parse::<RegisterType>(),
            Err(UnknownRegisterType("Holdin".into()))
        );
        assert_eq!(
            UnknownRegisterType("x".into()).to_string(),
            "Unknown register type 'x' — use holding, input, coil, or discrete"
        );
    }

    #[test]
    fn a_validation_error_is_the_gateways_catalog_finding() {
        let error = ValidationError {
            field: "frame.0x100".into(),
            message: "no length".into(),
        };
        let json = serde_json::to_value(&error).unwrap();
        let finding: wiretap_gateway::CatalogFinding =
            serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&finding).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<ValidationError>(json).unwrap(),
            error
        );
    }
}
