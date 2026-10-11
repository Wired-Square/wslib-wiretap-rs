//! WireTAP catalogue library — the canonical parser, validator, decoder, and
//! writer for WireTAP-format device catalogues (TOML), across CAN, Serial, and
//! Modbus.
//!
//! It takes bytes and returns values: **no I/O, no transport, no polling
//! loop**. A consumer drives the device, owns the clock, and brings the bytes
//! back here; [`modbus::PollSchedule`] only says which frames are due when told
//! the time.
//!
//! - [`parse`] — `Catalog::parse` resolves all three frame sections into the
//!   unified [`model`] (`Catalog`/`Frame`/`Signal`/`Mux`).
//! - [`validate`] — field-path + message findings for the editor.
//! - [`decode`] — raw bytes → signal values (the single decode implementation;
//!   [`modbus`] shares its bit-extraction core).
//! - [`mirror`] — live `mirror_of` validation: does a mirrored frame still agree
//!   with its source, over the bytes it inherited?
//! - [`modbus`] — the Modbus register-poll/encode model, shorthands, poll
//!   schedules, a register sweep's plan, and a recovered RTU message as signals.
//! - [`modbus_rtu_stream`] — stateful reassembly of a Modbus RTU byte stream,
//!   off a serial port or chopped across consecutive CAN frames (a tunnel).
//! - [`modbus_rtu_tap`] — that stream off a serial line, each message stamped
//!   by the read its last byte arrived in, on the caller's clock.
//! - [`framing_detect`] — which framing a raw serial byte stream uses (SLIP,
//!   Modbus RTU or a delimiter), and what RTU couldn't frame.
//! - [`serial_framing`] — a serial byte stream cut into frames by SLIP, a
//!   delimiter or Modbus RTU, behind one `SerialFramer`, and where a frame's id
//!   sits in it.
//! - [`summary`] — a catalogue's counts and resolved per-frame rows, across
//!   protocols, for a consumer's report.
//! - [`dbc`] — Vector DBC ↔ catalogue TOML import/export.
//! - [`text`] — a catalogue's source as text: the editor's line diff,
//!   `[meta].name` from a file that may not parse, and the filename rules.
//!
//! The Modbus parser/decoder was originally extracted from the Home Assistant
//! ESS add-on (MIT, © Wired Square) so WireTAP and the add-on share one
//! implementation.

pub mod dbc;
pub mod decode;
pub mod edit;
pub mod framing_detect;
pub mod layout;
pub mod migrate;
pub mod mirror;
pub mod modbus;
pub mod modbus_rtu_stream;
pub mod modbus_rtu_tap;
pub mod model;
pub mod mux_case;
pub mod parse;
pub mod serial_framing;
pub mod summary;
pub mod text;
pub mod validate;

pub use layout::{frame_layout, FrameLayout, LayoutRange, RangeKind};
pub use mirror::{MirrorTracker, MirrorVerdict};
pub use modbus_rtu_stream::{
    CrcPolicy, Direction, DirectionBasis, LengthRule, ModbusRtuMessage, ModbusRtuOptions,
    ModbusRtuStream, Payload, RtuSettings, Selector, VendorLen, VendorLength,
};
pub use modbus_rtu_tap::{
    InvalidLineSettings, LineSettings, LineSettingsError, Parity, RtuTap, TappedMessage,
    UnknownParity,
};
pub use model::{
    CanConfig, Catalog, ChecksumConfig, Confidence, DisplayHint, Endianness, Frame, FrameTunnel,
    FunctionCode, HeaderField, Meta, ModbusConfig, Mux, MuxCase, Protocol, RegisterType,
    SerialConfig, Signal, SignalFormat, TunnelProtocol, UnknownRegisterType, ValidationError,
    WriteBank,
};
pub use model::{EffectiveDefaults, NAME_KEYED_FRAME_ID};
pub use mux_case::{compare_mux_case_keys, is_mux_case_key, mux_case_values, CaseRange};
pub use parse::{rtu_rules, CatalogError, RtuRules, RtuRulesError};
pub use serial_framing::{
    degenerate_framing_field, DegenerateFraming, DelimiterOptions, FrameIdConfig, FramingEncoding,
    FramingMode, SerialFrame, SerialFramer,
};
pub use summary::CatalogSummary;
pub use text::{DiffKind, DiffRow, UnsafeFilename};
