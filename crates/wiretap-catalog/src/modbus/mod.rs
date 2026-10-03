//! Modbus catalogue: manifest model, TOML parse, register and coil decode and
//! encode, the wire-protocol constants every layer that talks to a
//! device shares, and clock-injected poll schedules — per catalogue frame, or
//! per read for any list of reads, such as address ranges chunked to requests;
//! a register sweep's plan for a device with no catalogue; and a recovered RTU
//! message decoded to signals.

mod item_schedule;
pub(crate) mod manifest;
pub mod protocol;
mod ranges;
mod rtu_decode;
mod scan;
mod schedule;
pub use item_schedule::{ItemSchedule, PollItem};
pub use manifest::*;
pub use protocol::*;
pub use ranges::{chunk_ranges, RangeError, RangeSpec, RegisterRange};
pub use rtu_decode::{decode_rtu_message, exception_label, function_label, RtuDecode};
pub use scan::{
    AddressBlock, ReadOutcome, ReadSpan, RegisterSweep, SweepEnd, SweepLimits, SweepProgress,
    SweepStep, DEFAULT_BUSY_RETRIES,
};
pub use schedule::{FrameBackoff, PollSchedule};

// The shared enums now live in `crate::model`; re-export so `modbus::Endianness`
// (and friends) remain part of this module's public API.
pub use crate::model::{
    DisplayHint, Endianness, RegisterType, SignalFormat, UnknownRegisterType, WriteBank,
};
