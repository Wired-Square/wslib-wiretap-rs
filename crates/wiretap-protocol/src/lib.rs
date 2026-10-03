//! The wire protocols WireTAP speaks, as scalars.
//!
//! Every consumer of these codecs has its own captured-frame type, and they are
//! not reconcilable: one is CAN-only and does not store the data length code,
//! the next is multi-protocol and does, and its shape is a contract with a
//! frontend. So nothing here names a consumer's frame type. Encoders take
//! scalars and a caller's buffer; decoders return scalars; each consumer adapts
//! at its own boundary, which every one of them already does. The one frame
//! type is [`can::CanFrame`], the CAN frame as it is on the bus, taken only
//! where a format really is a CAN frame.
//!
//! Consequently: no serde, no async runtime, no driver. A client that speaks
//! one of these protocols should not have to take a capture stack to do it.
//!
//! - [`can`] — the CAN frame and its direction, as every CAN transport in
//!   `wiretap-io` hands them over, and what a SocketCAN error frame reports.
//! - [`dlc`] — the CAN data length code table, and the two directions across
//!   it. Shared by every protocol below and by every archive writer, because
//!   the wire carries a code and a database column stores a length.
//! - [`gvret`] — the GVRET serial protocol, both ends: the host a client
//!   speaks, and the device a capture server imitates.
//! - [`slcan`] — the Lawicel ASCII protocol, with the CANable CAN FD extension.
//! - [`slip`] — SLIP (RFC 1055), both directions.
//! - [`gs_usb`] — the candleLight USB protocol.
//! - [`pcan_usb`] — PEAK-System's classic PCAN-USB protocol.
//! - [`pcan_usb_fd`] — PEAK-System's uCAN protocol: PCAN-USB FD, PCAN-Chip USB,
//!   PCAN-USB Pro FD and PCAN-USB X6. Untested: no device has met it.
//! - [`bittiming`] — the kernel's bit timing search, for the PEAK modules.
//! - [`socketcan`] — Linux's CAN frame layouts. A kernel ABI, not a wire
//!   format; see the module header.
//! - [`testpattern`] — two endpoints proving a CAN link carries what it claims
//!   to, including a sweep across every data length code.
//! - [`ingest`] — the binary ingest protocol, both ends: framing, handshake,
//!   batches of CAN, Modbus and raw serial records, their id-flag layout, and
//!   the catalogue pull, plus the server's session as a sans-io state machine.
//! - [`import`] — the WireTAP desktop's HTTP capture-import record, both ends.
//!   CAN only, with the ingest id-flag layout.
//! - [`candump`] — can-utils' `candump -L` log line, and the `cansend` frame
//!   inside it.
//! - [`savvycan`] — the SavvyCAN/GVRET CSV capture file, in the file's shape.
//! - [`framing`] — the delimiter framer and the [`framing::Framed`] output it
//!   shares with [`slip`].

pub mod bittiming;
pub mod can;
pub mod candump;
mod crc32;
pub mod dlc;
pub mod framing;
pub mod gs_usb;
pub mod gvret;
pub mod import;
pub mod ingest;
pub mod pcan_usb;
pub mod pcan_usb_fd;
pub mod savvycan;
pub mod slcan;
pub mod slip;
pub mod socketcan;
pub mod testpattern;
mod text;

/// Arbitration id masks. Named for the id width rather than for a protocol,
/// because that is what they are: every protocol here masks the same 29 and 11
/// bits, and differs only in where it packs the flags alongside them. Defined
/// once so [`gvret`] and [`ingest`] cannot disagree about the width of a CAN
/// id — which is the whole premise of this crate, applied to itself.
pub const ARB_MASK_EXT: u32 = 0x1FFF_FFFF;
pub const ARB_MASK_STD: u32 = 0x0000_07FF;

pub use dlc::{dlc_to_len, len_to_dlc, payload_dlc, FD_DLC_LEN};
