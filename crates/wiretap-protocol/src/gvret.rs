//! GVRET wire codec, both ends of it.
//!
//! Pure and synchronous, so the bytes either end sees can be asserted without
//! opening a socket. The golden byte strings in the tests below were captured
//! from the Python implementation this replaced.
//!
//! Protocol reference: <https://github.com/collin80/M2RET/blob/master/CommProtocol.txt>,
//! and `docs/gvret.md` for the full opcode surface including the parts nothing
//! here speaks.
//!
//! | Opcode  | host → device        | device → host        |
//! |---------|----------------------|----------------------|
//! | `E7 E7` | enter binary mode    | —                    |
//! | `F1 00` | transmit this frame  | a frame off the bus  |
//! | `F1 01` | ask                  | timebase             |
//! | `F1 06` | ask                  | CAN bus parameters   |
//! | `F1 07` | ask                  | device info          |
//! | `F1 09` | —                    | keepalive            |
//! | `F1 0C` | ask                  | bus count            |
//!
//! # Two ends, one module
//!
//! [`Decoder`] and the `encode_*` reply functions are the **device** end: what a
//! capture server needs to look like a GVRET adapter. [`DeviceDecoder`] and
//! [`encode_transmit`] are the **host** end: what a client needs to talk to one.
//! They are here together so the id packing, the opcode numbers and the data
//! length code table cannot drift apart between the two — which they did, until
//! this module existed.
//!
//! # The trailing checksum byte
//!
//! Every participant in this protocol disagrees about the byte after a frame's
//! payload, and the dialect they all actually speak is written down correctly
//! in none of them. The spec (§4.1) calls it a checksum "currently always
//! `0x00`" on a device→host frame and an XOR on a host→device transmit;
//! `collin80/GVRET`'s firmware emits it and *requires* it — `BUILD_CAN_FRAME`
//! only dispatches once it arrives — while its XOR comparison is commented out;
//! SavvyCAN sends a hardcoded `0`, not an XOR.
//!
//! All four positions this module takes are the ones already in the field, and
//! none of them is the spec:
//!
//! - [`encode_frame_into`] writes `0x00`, which is what the spec says and what
//!   the firmware emits.
//! - [`encode_transmit_into`] appends **nothing**. Real adapters accept that,
//!   and it is what the clients in the field send.
//! - [`Decoder`] does not consume the byte on a transmit, and
//!   [`DeviceDecoder`] does not consume it on a frame. Both are safe rather
//!   than correct: no sender in the field puts `0xF1` there, so the resync scan
//!   discards it, and there is nothing to discard when it is absent.
//!
//! Stated here rather than fixed, because every end of this protocol is a live
//! participant and changing the dialect is a protocol change, not a refactor.

use crate::dlc::{dlc_to_len, payload_dlc};
/// GVRET masks the same CAN id widths every protocol here does; only the flag
/// positions below are its own.
pub use crate::{ARB_MASK_EXT, ARB_MASK_STD};

/// GVRET marks an extended id with the top bit. SocketCAN's `CAN_EFF_FLAG`
/// happens to sit at the same position; the ingest protocol's does not (bit
/// 29). Written out rather than shared, because the coincidence is not a
/// contract.
const GVRET_EFF_BIT: u32 = 0x8000_0000;

/// The handshake that puts a connection into binary mode. A client that opens
/// a socket without sending this reads nothing back, however it asks.
pub const SYNC: [u8; 2] = [0xE7, 0xE7];
const CMD: u8 = 0xF1;

const OP_FRAME: u8 = 0x00;
const OP_TIMEBASE: u8 = 0x01;
const OP_CANBUS_PARAMS: u8 = 0x06;
const OP_DEV_INFO: u8 = 0x07;
const OP_KEEPALIVE: u8 = 0x09;
const OP_NUM_BUSES: u8 = 0x0C;

/// The bare two-byte requests a host sends. Spelled from the same opcodes the
/// device end decodes, so a request and the arm that answers it cannot drift.
pub const REQ_TIMEBASE: [u8; 2] = [CMD, OP_TIMEBASE];
pub const REQ_CANBUS_PARAMS: [u8; 2] = [CMD, OP_CANBUS_PARAMS];
pub const REQ_DEV_INFO: [u8; 2] = [CMD, OP_DEV_INFO];
pub const REQ_KEEPALIVE: [u8; 2] = [CMD, OP_KEEPALIVE];
pub const REQ_NUM_BUSES: [u8; 2] = [CMD, OP_NUM_BUSES];

/// Longest frame this encoder emits: 2 opcode + 4 ts + 4 id + 1 bus/dlc +
/// 64 payload + 1 terminator.
pub const MAX_FRAME_BYTES: usize = 76;

/// Longest transmit this encoder emits: 2 opcode + 4 id + 1 bus + 1 len +
/// 64 payload. One byte shorter than a captured frame despite carrying the same
/// payload — it has no timestamp, and no trailing checksum.
pub const MAX_TRANSMIT_BYTES: usize = 72;

/// Something the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCommand {
    /// `F1 00` — transmit this frame on the bus.
    Transmit {
        bus: u8,
        arb_id: u32,
        extended: bool,
        /// The length byte as sent; `data` holds at most 8 bytes of it.
        declared: u8,
        data: Vec<u8>,
    },
    /// `F1 01`
    Timebase,
    /// `F1 06`
    CanbusParams,
    /// `F1 07`
    DevInfo,
    /// `F1 09`
    Keepalive,
    /// `F1 0C`
    NumBuses,
}

/// Split a GVRET id word into its arbitration id and extended flag.
pub fn split_gvret_id(raw: u32) -> (u32, bool) {
    let extended = raw & GVRET_EFF_BIT != 0;
    (
        raw & if extended { ARB_MASK_EXT } else { ARB_MASK_STD },
        extended,
    )
}

/// The inverse of [`split_gvret_id`].
pub fn make_gvret_id(arb_id: u32, extended: bool) -> u32 {
    if extended {
        (arb_id & ARB_MASK_EXT) | GVRET_EFF_BIT
    } else {
        arb_id & ARB_MASK_STD
    }
}

/// Incremental decoder for one client connection.
#[derive(Debug, Default)]
pub struct Decoder {
    binary: bool,
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Has the client sent the `E7 E7` handshake? Frames are only pushed to a
    /// client in binary mode.
    pub fn is_binary(&self) -> bool {
        self.binary
    }

    /// Feed received bytes, returning every complete command they produced.
    /// Partial commands stay buffered.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<ClientCommand> {
        self.scan_for_handshake(chunk);
        let mut out = Vec::new();
        if !self.binary {
            return out;
        }

        loop {
            // Resync: bytes that cannot start a command are skipped, so a
            // stream that loses framing recovers instead of wedging. This is
            // also what discards a transmit's trailing checksum byte, which
            // `take_transmit` deliberately does not consume.
            let keep = self
                .buf
                .iter()
                .position(|&b| b == CMD)
                .unwrap_or(self.buf.len());
            self.buf.drain(..keep);

            if self.buf.len() < 2 {
                return out;
            }
            let cmd = self.buf[1];

            if cmd == OP_FRAME {
                match self.take_transmit() {
                    Some(c) => out.push(c),
                    // Incomplete: leave it buffered for the next read.
                    None => return out,
                }
                continue;
            }

            self.buf.drain(..2);
            match cmd {
                OP_TIMEBASE => out.push(ClientCommand::Timebase),
                OP_CANBUS_PARAMS => out.push(ClientCommand::CanbusParams),
                OP_DEV_INFO => out.push(ClientCommand::DevInfo),
                OP_KEEPALIVE => out.push(ClientCommand::Keepalive),
                OP_NUM_BUSES => out.push(ClientCommand::NumBuses),
                // Unknown opcode: header consumed, request ignored.
                _ => {}
            }
        }
    }

    /// Append `chunk` and consume everything up to and including the last
    /// `E7 E7`, latching binary mode.
    ///
    /// The scan deliberately runs even once latched — a quirk carried over
    /// from the Python; see `sync_bytes_are_consumed_even_in_binary_mode`.
    ///
    /// Only the appended region can hold a new handshake, plus one byte of
    /// overlap: this function never leaves a `SYNC` behind, and the command
    /// loop only removes prefixes, which cannot create an adjacency. Starting
    /// the scan there is what stops a client that connects and never
    /// handshakes from costing O(n²) — every read would otherwise rescan an
    /// ever-growing buffer.
    fn scan_for_handshake(&mut self, chunk: &[u8]) {
        let from = self.buf.len().saturating_sub(1);
        self.buf.extend_from_slice(chunk);

        let (mut i, mut cut) = (from, 0);
        while i + 1 < self.buf.len() {
            if self.buf[i..i + 2] == SYNC {
                i += 2;
                cut = i;
                self.binary = true;
            } else {
                i += 1;
            }
        }
        self.buf.drain(..cut);
    }

    /// `F1 00 <id:4LE> <bus:1> <len:1> <data:len>`; `None` until complete.
    ///
    /// The trailing checksum byte is left in the buffer for the resync scan;
    /// see this module's header for why that is safe against every sender in
    /// the field.
    fn take_transmit(&mut self) -> Option<ClientCommand> {
        // The caller has already established the two header bytes.
        debug_assert!(self.buf.len() >= 2 && self.buf[0] == CMD && self.buf[1] == OP_FRAME);
        if self.buf.len() < 8 {
            return None;
        }
        // The declared length decides how many bytes to CONSUME, while the
        // payload is clamped to 8. Replicated from the Python so a malformed
        // request desynchronises both implementations identically; see
        // `an_overlong_declared_length_consumes_all_of_it`.
        let declared = self.buf[7];
        let need = 8 + declared as usize;
        if self.buf.len() < need {
            return None;
        }

        let raw_id = u32::from_le_bytes([self.buf[2], self.buf[3], self.buf[4], self.buf[5]]);
        let bus = self.buf[6];
        let data = self.buf[8..8 + declared.min(8) as usize].to_vec();
        self.buf.drain(..need);

        let (arb_id, extended) = split_gvret_id(raw_id);
        Some(ClientCommand::Transmit {
            bus,
            arb_id,
            extended,
            declared,
            data,
        })
    }
}

/// `F1 07` — device info. The constants are what the Python advertised and
/// what clients have been parsing; they are not derived from anything.
pub fn encode_dev_info() -> Vec<u8> {
    let build: u16 = 400;
    let mut v = vec![CMD, OP_DEV_INFO];
    v.extend_from_slice(&build.to_le_bytes());
    v.extend_from_slice(&[1, 0, 0, 0]); // eeprom version, file type, auto start, single wire
    v
}

/// `F1 06` — CAN bus parameters. This legacy field describes at most two
/// buses; further buses are only visible through `F1 0C`.
pub fn encode_canbus_params(bus_count: u8, speeds: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(12);
    v.extend_from_slice(&[CMD, OP_CANBUS_PARAMS]);
    for i in 0..2 {
        let enabled = bus_count as usize > i;
        let speed = if enabled {
            speeds.get(i).copied().unwrap_or(0)
        } else {
            0
        };
        v.push(u8::from(enabled)); // listen-only, bit 4, is always 0
        v.extend_from_slice(&speed.to_le_bytes());
    }
    v
}

/// `F1 0C` — number of buses.
pub fn encode_num_buses(n: u8) -> Vec<u8> {
    vec![CMD, OP_NUM_BUSES, n]
}

/// `F1 01` — microseconds since the connection opened.
pub fn encode_timebase(us: u32) -> Vec<u8> {
    let mut v = vec![CMD, OP_TIMEBASE];
    v.extend_from_slice(&us.to_le_bytes());
    v
}

/// `F1 09` — keepalive, with its fixed `DE AD` body.
pub fn encode_keepalive() -> Vec<u8> {
    vec![CMD, OP_KEEPALIVE, 0xDE, 0xAD]
}

/// Append `F1 00` — a captured frame — to `out`.
///
/// Takes a buffer rather than returning one because this runs once per frame
/// per connected client: a busy 1 Mbit/s bus is ~15k frames/s, so an owned
/// `Vec` per frame is that many allocations per client per second. The bytes
/// cannot be encoded once and shared — `ts_us` counts from the connection that
/// is being written to — so a caller reuses one buffer per client and lets a
/// burst leave as a single write.
///
/// The byte packing `bus` and `dlc` carries the **data length code** in its
/// low nibble, not the byte count. Above 8 bytes on CAN FD those differ, and a
/// client's parser depends on getting the code.
///
/// A payload whose length has no exact code is **zero-padded up to the one it
/// gets**, because this protocol has no other framing: a reader takes exactly
/// as many bytes as the code names, so a frame that claimed twelve and wrote
/// nine would swallow the head of the next one and there is nothing to
/// resynchronise on until the next byte that happens to be `0xF1`. CAN FD has
/// no 9, 10 or 11 byte length, so a real bus cannot produce one — but an ingest
/// client can send one, and a stream that cannot be parsed is worse than three
/// bytes that were not on the wire.
///
/// `ts_us` is microseconds since the client's connection opened, and it is a
/// `u32`: the timebase **wraps every 71m34s**, which is the protocol's rule and
/// not this encoder's choice. A caller computing it from an elapsed duration
/// must truncate rather than saturate, or the two ends disagree about when the
/// wrap happened.
#[inline]
pub fn encode_frame_into(
    out: &mut Vec<u8>,
    ts_us: u32,
    arb_id: u32,
    extended: bool,
    bus: u8,
    data: &[u8],
    is_fd: bool,
) {
    let dlc = payload_dlc(data.len(), is_fd);
    let len = dlc_to_len(dlc, is_fd);
    // The code may round up past what the caller supplied; never read beyond it.
    let take = len.min(data.len());

    out.reserve(12 + len);
    out.extend_from_slice(&[CMD, OP_FRAME]);
    out.extend_from_slice(&ts_us.to_le_bytes());
    out.extend_from_slice(&make_gvret_id(arb_id, extended).to_le_bytes());
    out.push(((bus & 0x0F) << 4) | (dlc & 0x0F));
    out.extend_from_slice(&data[..take]);
    out.resize(out.len() + (len - take), 0);
    // The trailing checksum byte; see this module's header.
    out.push(0x00);
}

/// [`encode_frame_into`] into a fresh buffer. For tests and one-off sends;
/// the per-client fan-out should use the `_into` form.
pub fn encode_frame(
    ts_us: u32,
    arb_id: u32,
    extended: bool,
    bus: u8,
    data: &[u8],
    is_fd: bool,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAX_FRAME_BYTES);
    encode_frame_into(&mut v, ts_us, arb_id, extended, bus, data, is_fd);
    v
}

// ---------------------------------------------------------------------------
// The host end: what a client speaks to a device.
// ---------------------------------------------------------------------------

/// How much unsynchronised rubbish a device stream may accumulate before the
/// decoder stops hoping and drops it.
///
/// Only reached when a read contains no `0xF1` at all — a partial frame that
/// *starts* with one is kept however long the stream stalls, because it is a
/// message in progress rather than noise.
pub const MAX_RESYNC_BYTES: usize = 1024;

/// Something a device said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceMessage {
    /// `F1 00` — a frame off the bus.
    ///
    /// `dlc` is the **data length code**, not `data.len()`: above 8 bytes on
    /// CAN FD the two differ, and only the code was on the wire. GVRET carries
    /// no FD flag of its own, so a caller that needs one infers it from the
    /// payload length, which is what every client already does.
    ///
    /// `ts_us` is the device's own microsecond counter, which wraps every
    /// 71m34s and is unrelated to any host clock. A client that wants wall time
    /// substitutes its own; it is returned rather than dropped because dropping
    /// it here would put it out of every caller's reach.
    Frame {
        ts_us: u32,
        bus: u8,
        arb_id: u32,
        extended: bool,
        dlc: u8,
        data: Vec<u8>,
    },
    /// `F1 01` — microseconds since the connection opened.
    Timebase(u32),
    /// `F1 06` — the legacy two-bus view. Further buses are only visible
    /// through [`DeviceMessage::NumBuses`].
    CanbusParams {
        enabled: [bool; 2],
        speeds: [u32; 2],
    },
    /// `F1 07`
    DevInfo {
        build: u16,
        eeprom_version: u8,
        file_type: u8,
        auto_start: u8,
        single_wire: u8,
    },
    /// `F1 09`. The fixed `DE AD` body is consumed but not checked — a device
    /// that sends something else is still sending a keepalive.
    Keepalive,
    /// `F1 0C` — how many buses the device has. Not range-checked here; what
    /// counts as a plausible answer is the client's policy.
    NumBuses(u8),
}

/// Incremental decoder for the stream one device is sending.
///
/// The mirror of [`Decoder`], and the same shape: feed it whatever a read
/// returned, take whatever that completed, leave the rest buffered.
#[derive(Debug, Default)]
pub struct DeviceDecoder {
    buf: Vec<u8>,
}

impl DeviceDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes, returning every complete message they produced.
    ///
    /// A byte that cannot start a message is skipped rather than stalling the
    /// connection, which is also what discards a frame's trailing checksum
    /// byte — see this module's header for why that is left alone.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<DeviceMessage> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        loop {
            match self.buf.iter().position(|&b| b == CMD) {
                Some(at) => self.buf.drain(..at),
                None => {
                    // Nothing here can begin a message. Holding it costs memory
                    // for no possible gain, so past a bound it is dropped.
                    if self.buf.len() > MAX_RESYNC_BYTES {
                        self.buf.clear();
                    }
                    return out;
                }
            };

            if self.buf.len() < 2 {
                return out;
            }

            if self.buf[1] == OP_FRAME {
                match self.take_frame() {
                    Some(m) => out.push(m),
                    // Incomplete: leave it buffered for the next read.
                    None => return out,
                }
                continue;
            }

            // Every reply below is fixed-length, so the whole of it has to be
            // here before any of it is consumed.
            let (len, decode): (usize, fn(&[u8]) -> DeviceMessage) = match self.buf[1] {
                OP_TIMEBASE => (6, |b| DeviceMessage::Timebase(le_u32(&b[2..6]))),
                OP_CANBUS_PARAMS => (12, |b| DeviceMessage::CanbusParams {
                    enabled: [b[2] & 1 != 0, b[7] & 1 != 0],
                    speeds: [le_u32(&b[3..7]), le_u32(&b[8..12])],
                }),
                OP_DEV_INFO => (8, |b| DeviceMessage::DevInfo {
                    build: u16::from_le_bytes([b[2], b[3]]),
                    eeprom_version: b[4],
                    file_type: b[5],
                    auto_start: b[6],
                    single_wire: b[7],
                }),
                OP_KEEPALIVE => (4, |_| DeviceMessage::Keepalive),
                OP_NUM_BUSES => (3, |b| DeviceMessage::NumBuses(b[2])),
                _ => {
                    // Unknown opcode: drop the sync byte alone and resync from
                    // the next one. Dropping the opcode too would swallow a
                    // real header that happened to follow.
                    self.buf.drain(..1);
                    continue;
                }
            };

            if self.buf.len() < len {
                return out;
            }
            out.push(decode(&self.buf[..len]));
            self.buf.drain(..len);
        }
    }

    /// `F1 00 <ts:4LE> <id:4LE> <bus|dlc:1> <data:dlc_to_len>`; `None` until
    /// complete. The trailing checksum byte is left for the resync scan.
    fn take_frame(&mut self) -> Option<DeviceMessage> {
        const HEADER: usize = 2 + 4 + 4 + 1;
        // The caller has already established the two header bytes.
        debug_assert!(self.buf.len() >= 2 && self.buf[0] == CMD && self.buf[1] == OP_FRAME);
        if self.buf.len() < HEADER {
            return None;
        }

        let bus_dlc = self.buf[10];
        let dlc = bus_dlc & 0x0F;
        // Decoded as FD unconditionally: GVRET has no FD flag, so a code above
        // 8 can only mean an FD payload. Reading it as classic would cap the
        // length at 8 and desynchronise the rest of the stream.
        let len = dlc_to_len(dlc, true);
        if self.buf.len() < HEADER + len {
            return None;
        }

        let (arb_id, extended) = split_gvret_id(le_u32(&self.buf[6..10]));
        let msg = DeviceMessage::Frame {
            ts_us: le_u32(&self.buf[2..6]),
            bus: (bus_dlc >> 4) & 0x0F,
            arb_id,
            extended,
            dlc,
            data: self.buf[HEADER..HEADER + len].to_vec(),
        };
        self.buf.drain(..HEADER + len);
        Some(msg)
    }
}

/// A four-byte little-endian read that cannot fail, for slices this module has
/// already length-checked.
#[inline]
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Append `F1 00` — a frame to transmit — to `out`.
///
/// Note this is **not** the inverse of [`encode_frame_into`]: a transmit has no
/// timestamp, and it carries a byte *count* where a captured frame carries a
/// data length code. That asymmetry is the protocol's, not this module's.
///
/// The payload is clamped to what a CAN FD frame can carry. No trailing
/// checksum byte is written; see this module's header.
#[inline]
pub fn encode_transmit_into(out: &mut Vec<u8>, arb_id: u32, extended: bool, bus: u8, data: &[u8]) {
    let take = data.len().min(64);
    out.reserve(8 + take);
    out.extend_from_slice(&[CMD, OP_FRAME]);
    out.extend_from_slice(&make_gvret_id(arb_id, extended).to_le_bytes());
    out.push(bus);
    out.push(take as u8);
    out.extend_from_slice(&data[..take]);
}

/// [`encode_transmit_into`] into a fresh buffer.
pub fn encode_transmit(arb_id: u32, extended: bool, bus: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAX_TRANSMIT_BYTES);
    encode_transmit_into(&mut v, arb_id, extended, bus, data);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary_decoder() -> Decoder {
        let mut d = Decoder::new();
        assert!(d.feed(&SYNC).is_empty());
        assert!(d.is_binary());
        d
    }

    // --- golden bytes, captured from the Python implementation -------------

    #[test]
    fn dev_info_bytes() {
        assert_eq!(
            encode_dev_info(),
            vec![0xF1, 0x07, 0x90, 0x01, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn keepalive_bytes() {
        assert_eq!(encode_keepalive(), vec![0xF1, 0x09, 0xDE, 0xAD]);
    }

    #[test]
    fn num_buses_bytes() {
        assert_eq!(encode_num_buses(2), vec![0xF1, 0x0C, 0x02]);
    }

    #[test]
    fn timebase_bytes() {
        assert_eq!(
            encode_timebase(0x0001_E240),
            vec![0xF1, 0x01, 0x40, 0xE2, 0x01, 0x00]
        );
    }

    #[test]
    fn canbus_params_advertise_two_buses() {
        assert_eq!(
            encode_canbus_params(2, &[500_000, 250_000]),
            vec![0xF1, 0x06, 0x01, 0x20, 0xA1, 0x07, 0x00, 0x01, 0x90, 0xD0, 0x03, 0x00]
        );
    }

    #[test]
    fn canbus_params_zero_the_second_bus_when_only_one_exists() {
        assert_eq!(
            encode_canbus_params(1, &[500_000]),
            vec![0xF1, 0x06, 0x01, 0x20, 0xA1, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn standard_frame_bytes() {
        // bus 0, 11-bit id 0x123, 8 bytes.
        let out = encode_frame(0x1234, 0x123, false, 0, &[1, 2, 3, 4, 5, 6, 7, 8], false);
        assert_eq!(
            out,
            vec![
                0xF1, 0x00, 0x34, 0x12, 0x00, 0x00, // ts
                0x23, 0x01, 0x00, 0x00, // id, no EFF bit
                0x08, // bus 0, dlc 8
                1, 2, 3, 4, 5, 6, 7, 8, 0x00,
            ]
        );
    }

    #[test]
    fn extended_frame_sets_the_top_id_bit() {
        let out = encode_frame(0, 0x18DA_F110, true, 1, &[0xAA], false);
        assert_eq!(&out[6..10], &[0x10, 0xF1, 0xDA, 0x98]); // 0x18DAF110 | 0x80000000
        assert_eq!(out[10], 0x11); // bus 1, dlc 1
    }

    /// The one that is easy to get wrong: for FD the low nibble is the data
    /// length *code*, not the byte count.
    #[test]
    fn fd_frame_packs_the_dlc_code_not_the_length() {
        let out = encode_frame(0, 0x100, false, 0, &[0u8; 32], true);
        assert_eq!(out[10] & 0x0F, 13, "32 bytes is code 13");
        assert_eq!(
            out.len(),
            12 + 32,
            "2 opcode + 4 ts + 4 id + 1 bus/dlc + data + terminator"
        );

        let out = encode_frame(0, 0x100, false, 2, &[0u8; 64], true);
        assert_eq!(out[10], (2 << 4) | 15, "bus 2, 64 bytes is code 15");
        assert_eq!(out.len(), MAX_FRAME_BYTES);
    }

    #[test]
    fn classic_frames_truncate_at_eight_bytes() {
        let out = encode_frame(0, 0x100, false, 0, &[0xFFu8; 20], false);
        assert_eq!(out[10] & 0x0F, 8);
        assert_eq!(out.len(), 12 + 8);
    }

    /// An FD payload whose length has no exact code rounds the code up, and the
    /// frame must then carry as many bytes as the code names. Writing fewer
    /// leaves a reader consuming the head of the next frame — this protocol has
    /// no framing to recover with.
    #[test]
    fn fd_frame_with_an_inexact_length_is_padded_up_to_its_code() {
        let out = encode_frame(0, 0x100, false, 0, &[0xABu8; 9], true);
        assert_eq!(out[10] & 0x0F, 9, "9 bytes rounds up to code 9, meaning 12");
        assert_eq!(out.len(), 12 + 12);
        assert_eq!(&out[11..20], &[0xAB; 9]);
        assert_eq!(&out[20..23], &[0, 0, 0], "padded, not truncated");
    }

    #[test]
    fn encode_frame_into_appends_rather_than_replacing() {
        let mut buf = vec![0xEE];
        encode_frame_into(&mut buf, 0, 0x123, false, 0, &[1, 2], false);
        encode_frame_into(&mut buf, 0, 0x124, false, 0, &[3], false);
        assert_eq!(buf[0], 0xEE);
        assert_eq!(buf.len(), 1 + (12 + 2) + (12 + 1));
    }

    #[test]
    fn gvret_ids_round_trip() {
        for (arb, ext) in [
            (0x123u32, false),
            (0x7FF, false),
            (0x18DA_F110, true),
            (0, true),
        ] {
            let (back, back_ext) = split_gvret_id(make_gvret_id(arb, ext));
            assert_eq!((back, back_ext), (arb, ext), "id {arb:#x} extended {ext}");
        }
    }

    // --- decoding ----------------------------------------------------------

    #[test]
    fn nothing_is_decoded_before_the_handshake() {
        let mut d = Decoder::new();
        assert!(!d.is_binary());
        assert_eq!(d.feed(&[0xF1, 0x07]), vec![]);
        assert!(!d.is_binary());
    }

    #[test]
    fn fixed_commands_decode_after_the_handshake() {
        let mut d = binary_decoder();
        let got = d.feed(&[0xF1, 0x07, 0xF1, 0x06, 0xF1, 0x0C, 0xF1, 0x01, 0xF1, 0x09]);
        assert_eq!(
            got,
            vec![
                ClientCommand::DevInfo,
                ClientCommand::CanbusParams,
                ClientCommand::NumBuses,
                ClientCommand::Timebase,
                ClientCommand::Keepalive,
            ]
        );
    }

    #[test]
    fn the_handshake_may_arrive_after_leading_noise() {
        let mut d = Decoder::new();
        let got = d.feed(&[0x00, 0xFF, 0xE7, 0xE7, 0xF1, 0x07]);
        assert!(d.is_binary());
        assert_eq!(got, vec![ClientCommand::DevInfo]);
    }

    /// Overlapping sync bytes are not "seek to the last pair": `E7 E7 E7`
    /// consumes the first pair and leaves one byte behind.
    #[test]
    fn overlapping_sync_bytes_leave_the_odd_byte() {
        let mut d = Decoder::new();
        let got = d.feed(&[0xE7, 0xE7, 0xE7, 0xF1, 0x07]);
        assert!(d.is_binary());
        // The stray 0xE7 is then dropped by the resync, and DevInfo decodes.
        assert_eq!(got, vec![ClientCommand::DevInfo]);
    }

    /// A handshake split across two reads must still be seen — the scan keeps
    /// one byte of overlap for exactly this.
    #[test]
    fn a_handshake_split_across_reads_is_found() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[0x00, 0xE7]), vec![]);
        assert!(!d.is_binary());
        let got = d.feed(&[0xE7, 0xF1, 0x07]);
        assert!(d.is_binary(), "the pair spans the read boundary");
        assert_eq!(got, vec![ClientCommand::DevInfo]);
    }

    /// Deliberate stream recovery: a byte that cannot start a command is
    /// dropped rather than stalling the connection.
    #[test]
    fn resync_discards_leading_non_command_bytes() {
        let mut d = binary_decoder();
        let got = d.feed(&[0x00, 0x11, 0x22, 0xF1, 0x07]);
        assert_eq!(got, vec![ClientCommand::DevInfo]);
    }

    #[test]
    fn unknown_opcodes_are_ignored_without_desynchronising() {
        let mut d = binary_decoder();
        let got = d.feed(&[0xF1, 0x42, 0xF1, 0x07]);
        assert_eq!(got, vec![ClientCommand::DevInfo]);
    }

    #[test]
    fn a_split_command_waits_for_the_rest() {
        let mut d = binary_decoder();
        assert_eq!(d.feed(&[0xF1]), vec![]);
        assert_eq!(d.feed(&[0x07]), vec![ClientCommand::DevInfo]);
    }

    #[test]
    fn transmit_decodes_a_standard_frame() {
        let mut d = binary_decoder();
        let got = d.feed(&[
            0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x01, 0x03, 0xAA, 0xBB, 0xCC,
        ]);
        assert_eq!(
            got,
            vec![ClientCommand::Transmit {
                bus: 1,
                arb_id: 0x123,
                extended: false,
                declared: 3,
                data: vec![0xAA, 0xBB, 0xCC],
            }]
        );
    }

    #[test]
    fn transmit_decodes_an_extended_frame() {
        let mut d = binary_decoder();
        let got = d.feed(&[0xF1, 0x00, 0x10, 0xF1, 0xDA, 0x98, 0x00, 0x01, 0x55]);
        assert_eq!(
            got,
            vec![ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x18DA_F110,
                extended: true,
                declared: 1,
                data: vec![0x55],
            }]
        );
    }

    /// SavvyCAN's own transmit: a trailing checksum byte, hardcoded `0x00`.
    /// This end does not consume it, and the resync scan discards it — the
    /// dialect note in this module's header, asserted rather than argued.
    #[test]
    fn a_trailing_checksum_byte_does_not_desynchronise_the_stream() {
        let mut d = binary_decoder();
        let got = d.feed(&[
            0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x01, 0x01, 0xAA, 0x00, // checksum
            0xF1, 0x07, // and the next command is still found
        ]);
        assert_eq!(
            got,
            vec![
                ClientCommand::Transmit {
                    bus: 1,
                    arb_id: 0x123,
                    extended: false,
                    declared: 1,
                    data: vec![0xAA],
                },
                ClientCommand::DevInfo,
            ]
        );
    }

    /// A partial transmit must not be consumed, or the rest of the stream is
    /// parsed as garbage.
    #[test]
    fn a_partial_transmit_is_left_buffered() {
        let mut d = binary_decoder();
        assert_eq!(
            d.feed(&[0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01]),
            vec![]
        );
        let got = d.feed(&[0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            got,
            vec![ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x123,
                extended: false,
                declared: 8,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }]
        );
    }

    /// Replicated quirk: the implementation this replaced behaved this way, and
    /// a malformed request must desynchronise both of them identically.
    #[test]
    fn an_overlong_declared_length_consumes_all_of_it() {
        let mut d = binary_decoder();
        let mut msg = vec![0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x00, 10];
        msg.extend_from_slice(&[9u8; 10]);
        msg.extend_from_slice(&[0xF1, 0x07]); // must still be found afterwards
        let got = d.feed(&msg);
        assert_eq!(
            got,
            vec![
                ClientCommand::Transmit {
                    bus: 0,
                    arb_id: 0x123,
                    extended: false,
                    declared: 10,
                    data: vec![9; 8],
                },
                ClientCommand::DevInfo,
            ]
        );
    }

    /// Replicated quirk: the implementation this replaced behaved this way, and
    /// a malformed request must desynchronise both of them identically.
    #[test]
    fn sync_bytes_are_consumed_even_in_binary_mode() {
        let mut d = binary_decoder();
        let got = d.feed(&[0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x00, 0x02, 0xE7, 0xE7]);
        assert_eq!(
            got,
            vec![],
            "the payload's E7 E7 is eaten by the handshake scan"
        );
    }

    // --- the host end ------------------------------------------------------

    #[test]
    fn transmit_bytes() {
        // bus 1, 11-bit id 0x123, 3 bytes. No timestamp, no checksum.
        assert_eq!(
            encode_transmit(0x123, false, 1, &[0xAA, 0xBB, 0xCC]),
            vec![0xF1, 0x00, 0x23, 0x01, 0x00, 0x00, 0x01, 0x03, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn an_extended_transmit_sets_the_top_id_bit() {
        let out = encode_transmit(0x18DA_F110, true, 0, &[0x55]);
        assert_eq!(&out[2..6], &[0x10, 0xF1, 0xDA, 0x98]);
    }

    /// A transmit carries a byte count, not a data length code — the one place
    /// the two directions of this protocol disagree about that byte.
    #[test]
    fn a_transmit_carries_a_length_not_a_code() {
        let out = encode_transmit(0x100, false, 0, &[0u8; 12]);
        assert_eq!(out[7], 12, "12, not code 9");
        assert_eq!(out.len(), 8 + 12);

        let out = encode_transmit(0x100, false, 0, &[0u8; 64]);
        assert_eq!(out.len(), MAX_TRANSMIT_BYTES);
    }

    #[test]
    fn a_transmit_clamps_at_what_a_frame_can_carry() {
        let out = encode_transmit(0x100, false, 0, &[0xFFu8; 80]);
        assert_eq!(out[7], 64);
        assert_eq!(out.len(), MAX_TRANSMIT_BYTES);
    }

    /// The pair a client and a server have to agree on, asserted as a pair:
    /// what one end encodes is what the other decodes.
    #[test]
    fn a_captured_frame_round_trips_between_the_two_ends() {
        for (arb, ext, bus, len, fd) in [
            (0x123u32, false, 0u8, 8usize, false),
            (0x18DA_F110, true, 1, 3, false),
            (0x7FF, false, 2, 32, true),
            (0x100, false, 0, 64, true),
            (0x200, false, 0, 0, false),
        ] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let wire = encode_frame(0x1234, arb, ext, bus, &data, fd);
            let got = DeviceDecoder::new().feed(&wire);
            assert_eq!(
                got,
                vec![DeviceMessage::Frame {
                    ts_us: 0x1234,
                    bus,
                    arb_id: arb,
                    extended: ext,
                    dlc: payload_dlc(len, fd),
                    data,
                }],
                "id {arb:#x} len {len} fd {fd}"
            );
        }
    }

    #[test]
    fn every_control_reply_round_trips_between_the_two_ends() {
        let mut wire = encode_timebase(0x0001_E240);
        wire.extend(encode_canbus_params(2, &[500_000, 250_000]));
        wire.extend(encode_dev_info());
        wire.extend(encode_keepalive());
        wire.extend(encode_num_buses(3));

        assert_eq!(
            DeviceDecoder::new().feed(&wire),
            vec![
                DeviceMessage::Timebase(0x0001_E240),
                DeviceMessage::CanbusParams {
                    enabled: [true, true],
                    speeds: [500_000, 250_000],
                },
                DeviceMessage::DevInfo {
                    build: 400,
                    eeprom_version: 1,
                    file_type: 0,
                    auto_start: 0,
                    single_wire: 0,
                },
                DeviceMessage::Keepalive,
                DeviceMessage::NumBuses(3),
            ]
        );
    }

    /// The device info reply is eight bytes, not seven. Reading seven leaves a
    /// byte behind that only survives because it is never `0xF1` — the WireTAP
    /// desktop got away with it for exactly that reason.
    #[test]
    fn device_info_consumes_all_eight_of_its_bytes() {
        let mut wire = encode_dev_info();
        assert_eq!(wire.len(), 8);
        wire.extend(encode_num_buses(1));
        let mut d = DeviceDecoder::new();
        assert_eq!(d.feed(&wire).len(), 2);
        assert!(d.buf.is_empty(), "nothing left over");
    }

    /// The FD trap from the other direction: the low nibble is a code, and
    /// reading it as a byte count would take 13 bytes for a 32-byte frame and
    /// then parse the remaining payload as commands.
    #[test]
    fn an_fd_frame_decodes_by_its_code_not_its_nibble() {
        let wire = encode_frame(0, 0x100, false, 0, &[0xAB; 32], true);
        match &DeviceDecoder::new().feed(&wire)[0] {
            DeviceMessage::Frame { dlc, data, .. } => {
                assert_eq!(*dlc, 13);
                assert_eq!(data.len(), 32);
            }
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    /// A device's trailing checksum byte, which this end does not consume —
    /// the dialect note in this module's header, asserted rather than argued.
    #[test]
    fn a_frames_trailing_checksum_does_not_desynchronise_the_stream() {
        let mut d = DeviceDecoder::new();
        let got = d.feed(&[
            0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, // ts
            0x23, 0x01, 0x00, 0x00, // id 0x123
            0x01, 0xAA, // bus 0 dlc 1, payload
            0x00, // checksum
            0xF1, 0x09, 0xDE, 0xAD, // and the next message is still found
        ]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1], DeviceMessage::Keepalive);
    }

    /// A frame split across two reads must survive the boundary — the whole
    /// point of an incremental decoder, and the case a per-read parser gets
    /// wrong.
    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let wire = encode_frame(7, 0x321, false, 0, &[1, 2, 3, 4, 5, 6, 7, 8], false);
        for split in 1..wire.len() {
            let mut d = DeviceDecoder::new();
            let mut got = d.feed(&wire[..split]);
            got.extend(d.feed(&wire[split..]));
            assert_eq!(got.len(), 1, "split at {split}");
        }
    }

    #[test]
    fn resync_discards_leading_rubbish_from_a_device() {
        let mut wire = vec![0x00, 0x11, 0x22];
        wire.extend(encode_num_buses(2));
        assert_eq!(
            DeviceDecoder::new().feed(&wire),
            vec![DeviceMessage::NumBuses(2)]
        );
    }

    /// An unknown opcode drops only the sync byte: dropping the opcode too
    /// would swallow a real header that happened to be the very next byte.
    #[test]
    fn an_unknown_device_opcode_resyncs_without_swallowing_the_next() {
        let mut d = DeviceDecoder::new();
        assert_eq!(
            d.feed(&[0xF1, 0xF1, 0x0C, 0x02]),
            vec![DeviceMessage::NumBuses(2)]
        );
    }

    /// Unsynchronised noise must not grow without bound. A device that is
    /// mid-frame is not noise, however slowly the rest arrives — the bound only
    /// applies to a buffer with no sync byte in it at all.
    #[test]
    fn noise_is_bounded_but_a_partial_frame_is_not_dropped() {
        let mut d = DeviceDecoder::new();
        assert!(d.feed(&vec![0xEE; MAX_RESYNC_BYTES + 1]).is_empty());
        assert!(d.buf.is_empty(), "noise past the bound is dropped");

        // A header claiming 64 payload bytes, with 40 of them here.
        let header = [0xF1, 0x00, 0, 0, 0, 0, 0x23, 0x01, 0, 0, 0x0F];
        assert!(d.feed(&header).is_empty());
        assert!(d.feed(&[0xAA; 40]).is_empty());
        assert_eq!(d.buf.len(), header.len() + 40, "still waiting for the rest");

        match &d.feed(&[0xAA; 24])[0] {
            DeviceMessage::Frame { data, .. } => assert_eq!(data.len(), 64),
            other => panic!("expected a frame, got {other:?}"),
        }
    }
}
