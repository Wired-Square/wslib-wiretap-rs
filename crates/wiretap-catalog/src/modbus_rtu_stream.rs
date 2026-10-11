//! Modbus RTU reassembly: recovering messages from a byte stream, whether it
//! arrives on a serial port or chopped across consecutive frames.
//!
//! [`crate::decode`] is stateless — one frame's bytes in, that frame's signals
//! out. A tunnel breaks that: a Sungrow SBR's CAN `0x1E0` carries a Modbus RTU
//! stream where a 17-byte response arrives as 8 + 8 + 1, and both the request
//! and the reply land on the same CAN id. Nothing in a bit-layout catalogue can
//! express "concatenate the next N payloads", so the framing lives here and the
//! catalogue only declares that the frame *is* a tunnel ([`FrameTunnel`]).
//!
//! There is no transport header — no sequence numbers, no length prefix, no
//! first/consecutive frame distinction. Message boundaries come from the Modbus
//! RTU length rules alone, gated by CRC-16/Modbus. Ported from the offline
//! Python reassembler used for the 0x1F0 firmware extraction, with one change:
//! that parser held the whole stream, so a CRC failure meant "resync". Here a
//! failure usually means "the rest hasn't arrived yet", so we wait until the
//! buffer is provably longer than any candidate before dropping a byte.
//!
//! The same reassembler serves a real serial port, where the RTU stream is not
//! tunnelled inside anything — which is why the type is named for the stream it
//! recovers rather than for the CAN tunnel it was written for.
//! [`ModbusRtuStream::push`] counts frames, [`ModbusRtuStream::push_bytes`] does
//! not, and [`ModbusRtuStream::interpret`] takes a boundary somebody else
//! already found. [`CrcPolicy::Lenient`] relaxes the CRC gate for a line whose
//! CRCs cannot be trusted; see its docs for the cost.
//!
//! **A line is not obliged to be stock Modbus.** The length rules cover the codes
//! the spec defines, and a real bus may carry vendor codes alongside them — on a
//! Sungrow logger's RS-485 line, three of them are 90% of the traffic, and its
//! master broadcasts commands nothing replies to. Neither is reachable by
//! default, because guessing at either is how a framer invents messages out of
//! noise. Both are declared, from either end and unioned: a catalogue in its
//! `[…tunnel]` table ([`FrameTunnel`]), a caller through
//! [`ModbusRtuStream::with_vendor_functions`] and
//! [`ModbusRtuStream::allow_broadcast`]. [`ModbusRtuOptions`] carries a line's
//! settings as one value.
//!
//! A declared code is framed by a CRC search, which can stop short where a
//! message's prefix happens to validate. A [`VendorLength`] rule states the
//! layout instead, and is exact: only the lengths it declares are tried.
//!
//! A catalogue's `[meta.modbus.function_code.<code>]` tables are where its
//! devices' vendor codes and their layouts are declared.
//! [`Catalog::rtu_options`] builds a serial line from them, and
//! [`Catalog::tunnel_stream`] gives every tunnel in the catalogue them too.
//!
//! **A tap is not a decoder**, and wants the opposite default. A decoder
//! declares the codes it can read; a tap stores bytes, so a code nobody thought
//! to declare is traffic lost, and a vendor's codes are not known until the line
//! has been captured. [`ModbusRtuStream::frame_any_function`] is that posture:
//! frame everything, decode what is modelled.
//!
//! A tap also has to say *when* a message arrived, and this one emits nothing
//! until it has synced — so the messages a sync releases all land in the read
//! that completed them. [`ModbusRtuMessage::end_offset`] and
//! [`ModbusRtuStream::bytes_fed`] are the input positions to back-date them
//! from; the clock stays outside, as everything else here does.
//! [`crate::modbus_rtu_tap`] puts a caller's clock to them.

use crate::modbus::protocol::{
    bytes_to_coils, bytes_to_registers, registers_to_bytes, MAX_DATA_BYTES, MAX_RTU_LEN,
    MIN_RTU_LEN,
};
use crate::model::{Catalog, FrameTunnel, FunctionCode, RegisterType, TunnelProtocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wiretap_checksum::algorithms::crc16_modbus_valid;

/// Which side of the exchange a message came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// What decided a message's [`Direction`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionBasis {
    /// The message's layout fits one side only: a standard read or
    /// write-multiple, or an exception.
    Layout,
    /// FC05/FC06, whose request and echo share a layout: a Response when an
    /// outstanding request of the same code was seen since the stream started.
    Pairing,
    /// An unmodelled (vendor) code, sided by request/response alternation on
    /// the line. A guess.
    Alternation,
}

/// The values a message carries.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A register bank's values: an FC03/04 response, FC06, an FC16 request.
    Registers(Vec<u16>),
    /// A coil or discrete bank's states: an FC01/02 response, FC05, an FC15 request.
    Coils(Vec<bool>),
    /// No values: a read request, a write-multiple echo, an exception.
    None,
    /// A body nothing here parses: a vendor code, or a coil read response whose
    /// request went unseen. [`ModbusRtuMessage::data_block`] has the bytes.
    Opaque,
}

/// What a boundary that fails its CRC is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrcPolicy {
    /// Only a CRC-valid boundary is a message. A stream is never guessed at.
    #[default]
    Strict,
    /// A CRC-valid boundary still wins outright; only where [`CrcPolicy::Strict`]
    /// would give up and drop a byte does this emit the longest *structurally
    /// plausible* candidate instead, flagged `crc_valid: false`. On a stream
    /// whose CRCs are correct the two policies are identical.
    ///
    /// For a device with a broken CRC, or a line dropping bytes — the cases
    /// where strict framing shows nothing at all. The cost is real: with no
    /// declared `device_address` on a genuinely noisy line this will fabricate
    /// messages out of anything shaped like an address and a function code, and
    /// a fabricated request updates the outstanding-request state, so it can
    /// mis-pair the message after it. The `crc_valid` flag on every message is
    /// what keeps that honest.
    Lenient,
}

/// One complete Modbus RTU message recovered from the stream. CRC-validated
/// unless [`CrcPolicy::Lenient`] is in force — check `crc_valid`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ModbusRtuMessage {
    pub direction: Direction,
    pub direction_basis: DirectionBasis,
    pub device_address: u8,
    pub function: u8,
    /// First register. Present on requests and on write responses, which echo
    /// it; a read response carries only data, so this is filled in from the
    /// request it answers.
    pub start_register: Option<u16>,
    /// Register/coil count. Same provenance as `start_register`.
    pub quantity: Option<u16>,
    pub payload: Payload,
    /// Exception code, when the function code had its high bit set.
    pub exception: Option<u8>,
    /// The reassembled message, CRC included.
    pub raw: Vec<u8>,
    /// Whether the trailing CRC matches the body. Only ever false under
    /// [`CrcPolicy::Lenient`], where the boundary came from the length rules
    /// alone.
    pub crc_valid: bool,
    /// How many frames contributed bytes to this message. Always 1 for a
    /// message recovered from a raw byte stream or handed over already framed.
    pub frame_count: u32,
    /// Where this message ended in the input: bytes fed to the stream, counted
    /// from its start, up to and including this message's last byte. It starts
    /// at `end_offset - raw.len()`.
    ///
    /// Against [`ModbusRtuStream::bytes_fed`] this gives the bytes that arrived
    /// after the message, which is what back-dates one the framer had buffered
    /// before it synced. [`ModbusRtuStream::interpret`] consumes no stream, so a
    /// message from it reports the cursor unmoved — no correction, which is the
    /// right answer for a boundary the caller found itself.
    pub end_offset: u64,
}

impl ModbusRtuMessage {
    /// The register values, empty unless the payload is [`Payload::Registers`].
    pub fn registers(&self) -> &[u16] {
        match &self.payload {
            Payload::Registers(registers) => registers,
            _ => &[],
        }
    }

    /// The coil states, empty unless the payload is [`Payload::Coils`].
    pub fn coils(&self) -> &[bool] {
        match &self.payload {
            Payload::Coils(coils) => coils,
            _ => &[],
        }
    }

    /// The register block as big-endian bytes, for [`crate::decode`]. Register
    /// banks only; a coil frame's bytes are [`Self::data_block`].
    pub fn register_bytes(&self) -> Vec<u8> {
        registers_to_bytes(self.registers())
    }

    fn read_payload(&self) -> Payload {
        match (self.function, self.direction) {
            (f, _) if f & 0x80 != 0 => Payload::None,
            (0x01..=0x04, Direction::Request) | (0x0F | 0x10, Direction::Response) => Payload::None,
            (0x03 | 0x04, Direction::Response) | (0x10, Direction::Request) => {
                Payload::Registers(bytes_to_registers(self.data_block()))
            }
            (0x06, _) => Payload::Registers(bytes_to_registers(&self.raw[4..6])),
            // A packed block, sized by the quantity rather than by its length.
            (0x01 | 0x02, Direction::Response) | (0x0F, Direction::Request) => {
                self.quantity.map_or(Payload::Opaque, |q| {
                    Payload::Coils(bytes_to_coils(self.data_block(), q as usize))
                })
            }
            // Write single coil: on is 0xFF00 and off is 0x0000. The spec
            // defines no third value, so anything else is not a coil state.
            (0x05, _) => match be(&self.raw, 4) {
                0xFF00 => Payload::Coils(vec![true]),
                0x0000 => Payload::Coils(vec![false]),
                _ => Payload::Opaque,
            },
            _ => Payload::Opaque,
        }
    }

    /// The message's data block: everything after the protocol header, before
    /// the CRC.
    ///
    /// Where the wire declares a `byte_count` the block starts after it, so for
    /// a register read response this is exactly the bytes
    /// [`Self::register_bytes`] yields — which is what lets a tapped read and a
    /// polled one be compared byte for byte. Where it does not — a request, or a
    /// function code nothing models — the block is everything between the
    /// function code and the CRC.
    ///
    /// **This is the only way to reach the body of an unmodelled message.**
    /// Its payload is [`Payload::Opaque`], because nothing knows how to parse
    /// it, and on a measured Sungrow RS-485 line that is 94.5% of messages and
    /// 85% of the body bytes on the wire. Without this a caller has to slice `raw`
    /// itself, which means reimplementing the header rules this module exists
    /// to own.
    pub fn data_block(&self) -> &[u8] {
        let end = self.raw.len().saturating_sub(2);
        let start = match (self.function, self.direction) {
            // The only two layouts that declare a byte count before their data.
            (0x01..=0x04, Direction::Response) => 3,
            (0x0F | 0x10, Direction::Request) => 7,
            // Everything else carries its body straight after the function
            // code: requests, write echoes, any vendor layout, and an
            // exception — whose code has the high bit set, so it never reaches
            // the arms above.
            _ => 2,
        };
        self.raw.get(start..end).unwrap_or_default()
    }
}

/// Buffer ceiling. Two full messages of slack is enough to hold a
/// request/response pair mid-reassembly; past that the stream is desynced and
/// holding more bytes only delays recovery.
const MAX_BUFFER: usize = MAX_RTU_LEN * 2;

/// A candidate message layout at the head of the buffer.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    len: usize,
    direction: Direction,
}

/// What one pass over the head of the buffer achieved.
enum Step {
    Message(ModbusRtuMessage),
    /// No message starts here. The caller decides what that means: mid-stream a
    /// byte is junk and gets dropped, at end of stream it is the head of the
    /// residue and gets kept.
    NoMessage,
    /// Nothing to do until more bytes arrive.
    NeedMore,
}

/// Reassembles one tunnel's byte stream and yields complete Modbus RTU messages.
///
/// One instance per (session, frame id) — the buffer is the tunnel's serial
/// line, and interleaving two tunnels into it would corrupt both.
#[derive(Debug)]
pub struct ModbusRtuStream {
    buf: Vec<u8>,
    device_address: Option<u8>,
    policy: CrcPolicy,
    /// Frames whose bytes are still sitting unconsumed in `buf`, so a completed
    /// message can report how many frames it spanned.
    pending_frames: u32,
    /// The last request seen, as `(function, start_register, quantity)`. Read
    /// responses carry no register address, and FC06's request and response are
    /// byte-identical in shape, so both lean on this.
    last_request: Option<(u8, u16, u16)>,
    /// Function codes this library does not model, which the line is nonetheless
    /// known to carry. Empty by default — see [`Self::with_vendor_functions`].
    vendor_functions: Vec<u8>,
    /// See [`Self::with_vendor_lengths`].
    vendor_lengths: Vec<VendorLength>,
    /// The last unmodelled function code seen as a request. Kept apart from
    /// `last_request` on purpose: nothing is known about a vendor body, so it can
    /// offer no register address, and letting it share the slot would hand a
    /// standard read response an address that was never asked for.
    last_vendor_request: Option<u8>,
    /// Whether address 0 may start a message. See [`Self::allow_broadcast`].
    allow_broadcast: bool,
    /// Whether every code is framed, declared or not. See
    /// [`Self::frame_any_function`].
    any_function: bool,
    /// Input offset of `buf[0]`: bytes fed and since taken or dropped. With
    /// `buf.len()` it is the stream cursor — see [`Self::bytes_fed`].
    consumed: u64,
    /// See [`Self::rule_rejections`].
    rule_rejections: BTreeMap<u8, usize>,
}

impl ModbusRtuStream {
    /// A tunnel, with everything its table declares. A caller may add more of
    /// either; the two sources union. [`Catalog::tunnel_stream`] adds the
    /// catalogue's function codes as well.
    pub fn new(tunnel: &FrameTunnel) -> Self {
        debug_assert!(matches!(tunnel.protocol, TunnelProtocol::ModbusRtu));
        let mut stream = Self::for_address(tunnel.device_address);
        stream.vendor_functions.clone_from(&tunnel.vendor_functions);
        stream.allow_broadcast = tunnel.allow_broadcast;
        stream
    }

    /// An RTU stream nothing in a catalogue describes — a serial port, where the
    /// device address comes from the io profile rather than a `[…tunnel]` table.
    pub fn for_address(device_address: Option<u8>) -> Self {
        Self::with_crc_policy(device_address, CrcPolicy::Strict)
    }

    pub fn with_crc_policy(device_address: Option<u8>, policy: CrcPolicy) -> Self {
        Self {
            buf: Vec::with_capacity(MAX_RTU_LEN),
            device_address,
            policy,
            pending_frames: 0,
            last_request: None,
            vendor_functions: Vec::new(),
            vendor_lengths: Vec::new(),
            last_vendor_request: None,
            allow_broadcast: false,
            any_function: false,
            consumed: 0,
            rule_rejections: BTreeMap::new(),
        }
    }

    /// Declare function codes this library does not model but that the line
    /// carries — a vendor extension on top of standard Modbus RTU.
    ///
    /// Message boundaries normally come from a table of the codes the spec
    /// defines, so an unmodelled code yields no candidate at all and the stream
    /// resyncs a byte at a time through it forever. For a declared code the
    /// boundary comes from a **CRC
    /// search** instead: the shortest length in `4..=MAX_RTU_LEN` whose trailing
    /// two bytes check out wins.
    ///
    /// Shortest-first is deliberate, and is the opposite of the rule a modelled
    /// code follows. There the choice is between two candidates the length table
    /// derived, and the longer is a real layout; here it is between up to 253
    /// arbitrary lengths, where longer only means more opportunity to swallow the
    /// message behind it. Measured over 34 MB of a Sungrow RS-485 line:
    /// shortest-first recovers 99.88% of the bytes, longest-first 94.80%.
    ///
    /// **This is a declared allow-list, not a blanket fallback**, because the
    /// search is guessing. Bounded to codes the caller knows are real, a stray
    /// noise byte cannot trigger it; unbounded, roughly one resync in 260 would
    /// fabricate a message. Nothing changes for a caller that declares none.
    ///
    /// Shortest-first also stops short wherever a message minus its last bytes
    /// happens to validate. A code whose layout is known should declare it with
    /// [`Self::with_vendor_lengths`], which beats the search.
    ///
    /// Adds to whatever [`FrameTunnel::vendor_functions`] and the catalogue's
    /// `[meta.modbus.function_code]` declared rather than replacing it; the
    /// sources union.
    #[must_use]
    pub fn with_vendor_functions(mut self, functions: &[u8]) -> Self {
        self.vendor_functions.extend_from_slice(functions);
        self
    }

    /// Declare how long a vendor code's messages are, which also declares the
    /// code as [`Self::with_vendor_functions`] does.
    ///
    /// The rules whose selector matches are the message's possible layouts, tried
    /// in order: the first whose length CRC-validates is the message, and if none
    /// does the head is not a message, with no fallback to the search. One code
    /// can need several, as when a request and a response share a selector.
    /// Only when no selector matches is the code searched for. Inert for a
    /// modelled code. Appended to the catalogue's rules, so those are tried
    /// first.
    #[must_use]
    pub fn with_vendor_lengths(mut self, rules: &[VendorLength]) -> Self {
        self.vendor_lengths.extend_from_slice(rules);
        self
    }

    /// Let address 0 start a message.
    ///
    /// Off by default, and the default is right for stock Modbus: a broadcast is
    /// never replied to, so treating 0 as an address only invents messages out of
    /// payload bytes. It is wrong for a line whose master broadcasts commands
    /// nothing answers — on the Sungrow line measured above that is 19% of the
    /// traffic, every one of it a real message.
    ///
    /// Takes no argument: an "off" could not revoke a catalogue's
    /// [`FrameTunnel::allow_broadcast`], so there is nothing for it to mean.
    #[must_use]
    pub fn allow_broadcast(mut self) -> Self {
        self.allow_broadcast = true;
        self
    }

    /// Frame every function code, declared or not.
    ///
    /// [`Self::with_vendor_functions`] is an allow-list because a decoder
    /// declares what it can read, and a CRC search turned loose on any unknown
    /// code fabricates a message about once in 260 resyncs. A **tap** trades the
    /// other way: it stores bytes rather than reading them, so a code nobody
    /// thought to declare is traffic lost, and a vendor's codes are not known
    /// until the line has been captured. Undeclared, the Sungrow RS-485 line
    /// measured above framed 8.6% of its bytes; with every code framed, 99.97%.
    ///
    /// Exactly equivalent to declaring all 256 codes, and alike in every other
    /// respect — a modelled code keeps its length rules, because "unmodelled" is
    /// what the candidate table says and not what this flag does. The costs are
    /// that fabrication rate, and resync time: while the framer is lost a false
    /// head is searched until the buffer holds [`MAX_RTU_LEN`] bytes.
    #[must_use]
    pub fn frame_any_function(mut self) -> Self {
        self.any_function = true;
        self
    }

    /// Bytes fed to this stream so far, in the count
    /// [`ModbusRtuMessage::end_offset`] reports — one past the newest byte,
    /// buffered or not.
    ///
    /// `bytes_fed() - msg.end_offset` is how many bytes arrived after a message.
    /// Over a known line rate that is how long before this read it ended, which
    /// is what back-dates the burst a sync releases at once. The clock is the
    /// caller's; a byte count is the part of the answer this module can know.
    pub fn bytes_fed(&self) -> u64 {
        self.consumed + self.buf.len() as u64
    }

    /// The input offset of the oldest byte still buffered: every message yet to
    /// come ends past it.
    pub(crate) fn buffer_start(&self) -> u64 {
        self.consumed
    }

    /// Heads dropped because a [`VendorLength`] rule selected them and no
    /// length it gave CRC-validated, by function code.
    pub(crate) fn rule_rejections(&self) -> &BTreeMap<u8, usize> {
        &self.rule_rejections
    }

    /// Feed one frame's payload; return every message it completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<ModbusRtuMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.pending_frames += 1;
        self.push_bytes(bytes)
    }

    /// Feed raw bytes from a serial line. Same reassembly as [`Self::push`],
    /// without the frame accounting — there are no frames to count, so every
    /// message reports `frame_count: 1`.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Vec<ModbusRtuMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        let out = self.drain_messages(false);

        // A desynced stream would otherwise grow without bound.
        if self.buf.len() > MAX_BUFFER {
            self.drop_front(self.buf.len() - MAX_BUFFER);
        }
        out
    }

    /// One message somebody else already framed — a serial reader that framed
    /// the port, or a replayed frame that holds a whole message.
    ///
    /// The boundary is taken as given: this reports whether the CRC agrees
    /// rather than using it to find the boundary, so a CRC-invalid message comes
    /// back flagged under either policy instead of being swallowed. It reads the
    /// same candidate table as [`Self::push_bytes`], so a message framed here and
    /// one recovered from a byte stream are labelled identically. The reassembly
    /// buffer is never touched, so the two can share an instance — which they
    /// must, because the outstanding-request state lives here.
    pub fn interpret(&mut self, raw: &[u8]) -> Option<ModbusRtuMessage> {
        if raw.len() < 4 || !self.address_matches(raw[0]) {
            return None;
        }
        let table = candidates(raw);
        // A declared vendor code has no length rule to agree with, so a valid CRC
        // is the whole of the evidence — the same bar `vendor_search` sets, and
        // for the same reason. Without one there is nothing here to check.
        if self.is_vendor(&table, raw[1]) {
            return crc16_modbus_valid(raw)
                .then(|| self.build(raw.to_vec(), Direction::Request, true, self.bytes_fed()));
        }
        let chosen = table
            .into_iter()
            .flatten()
            .filter(|c| c.len == raw.len())
            .min_by_key(|c| !within_quantity_cap(raw, c))?;
        let crc_valid = crc16_modbus_valid(raw);
        // A CRC that agrees vouches for the message outright, implausible header
        // or not — the length table does not model every function code, and the
        // checksum is far stronger evidence than the table is. Without one, the
        // header has to be self-consistent, which is the same bar
        // [`CrcPolicy::Lenient`] sets for a boundary it guessed. Otherwise any
        // five bytes that open like an address and a function code would be
        // reported as a response carrying no registers.
        if !crc_valid && !is_plausible(raw, &chosen) {
            return None;
        }
        Some(self.build(raw.to_vec(), chosen.direction, crc_valid, self.bytes_fed()))
    }

    /// End of stream: no more bytes are coming.
    ///
    /// [`Self::push_bytes`] withholds a message while a longer candidate could
    /// still be completed by bytes that have not arrived. At end of stream they
    /// never will, so that rule is dropped and whatever the buffer can still
    /// yield is yielded. Returns the messages recovered and the bytes left over,
    /// which are by construction not a message — a truncated message is reported
    /// whole rather than resynced away a byte at a time.
    pub fn finish(&mut self) -> (Vec<ModbusRtuMessage>, Vec<u8>) {
        let out = self.drain_messages(true);
        self.pending_frames = 0;
        let residue = std::mem::take(&mut self.buf);
        self.consumed += residue.len() as u64;
        (out, residue)
    }

    /// Drain every message the buffer can yield. `at_end` also drops the
    /// wait-for-a-longer-candidate rule: a byte that starts nothing is junk to
    /// be dropped, unless no message follows it at end of stream, where it is
    /// the head of the residue.
    fn drain_messages(&mut self, at_end: bool) -> Vec<ModbusRtuMessage> {
        let mut out = Vec::new();
        let mut residue = None;
        loop {
            self.skip_to_address();
            match self.take_message(at_end) {
                Step::Message(msg) => {
                    residue = None;
                    // Bytes still buffered came from the newest frame, so it is
                    // shared with whatever message comes next.
                    self.pending_frames = u32::from(!self.buf.is_empty());
                    out.push(msg);
                }
                // The real message may be right behind the byte we drop.
                Step::NoMessage => {
                    if at_end && residue.is_none() {
                        residue = Some((
                            self.buf.clone(),
                            self.consumed,
                            self.rule_rejections.clone(),
                        ));
                    }
                    self.drop_front(1);
                }
                Step::NeedMore => break,
            }
        }
        if let Some((buf, consumed, rule_rejections)) = residue {
            (self.buf, self.consumed, self.rule_rejections) = (buf, consumed, rule_rejections);
        }
        out
    }

    /// Discard anything before a plausible address byte; a message can only
    /// start there.
    fn skip_to_address(&mut self) {
        let skip = self
            .buf
            .iter()
            .position(|&b| self.address_matches(b))
            .unwrap_or(self.buf.len());
        self.drop_front(skip);
    }

    /// Drop `n` bytes off the head of the buffer, moving the input cursor with
    /// them. Every byte that leaves `buf` goes through here or through
    /// [`Self::take`], which is what keeps [`Self::bytes_fed`] true.
    fn drop_front(&mut self, n: usize) {
        self.buf.drain(..n);
        self.consumed += n as u64;
    }

    fn address_matches(&self, byte: u8) -> bool {
        // A broadcast reaches every device, so it counts on both arms — pinning
        // an address must not hide it, which is the combination a catalogue
        // declares. Undeclared it starts nothing; 248..=255 are reserved.
        let broadcast = self.allow_broadcast && byte == 0;
        match self.device_address {
            Some(addr) => byte == addr || broadcast,
            None => (1..=247).contains(&byte) || broadcast,
        }
    }

    /// Try to consume one message from the head of the buffer. `at_end` drops
    /// the "wait for a longer candidate" rule, which only makes sense while more
    /// bytes could still arrive.
    fn take_message(&mut self, at_end: bool) -> Step {
        let buffered = self.buf.len();
        if buffered < 4 {
            return Step::NeedMore;
        }
        let candidates = candidates(&self.buf);

        // An unmodelled code the caller declared: no length table applies, so the
        // boundary comes from a declared rule, or else a CRC search.
        if self.is_vendor(&candidates, self.buf[1]) {
            return self
                .take_by_rule(at_end)
                .unwrap_or_else(|| self.vendor_search(at_end));
        }

        // Candidates come longest-first, so the first CRC hit is also the
        // longest: a data-bearing message outranks a short one that might
        // coincidentally validate. A 16-bit check is overwhelming evidence, so
        // it is not second-guessed by the structural rules below — except a
        // request for more than the spec allows, which is how a response plus
        // the next message's address byte can pass for a longer request.
        let valid = candidates.into_iter().flatten().find(|c| {
            c.len <= buffered
                && within_quantity_cap(&self.buf, c)
                && crc16_modbus_valid(&self.buf[..c.len])
        });
        if let Some(c) = valid {
            return self.take(c, true);
        }

        // Only give up on a CRC hit once no candidate could still be completed
        // by more bytes — otherwise we would eat the head of a split message.
        // A candidate that contradicts its own header is not one we could be
        // halfway through, so it does not earn the wait; without that, one
        // corrupt byte where a `byte_count` should be invents a 200-byte
        // candidate and stalls the stream until `MAX_BUFFER` evicts it.
        if !at_end
            && candidates
                .into_iter()
                .flatten()
                .find(|c| is_plausible(&self.buf, c))
                .is_some_and(|c| c.len > buffered)
        {
            return Step::NeedMore;
        }

        // Nothing validated, and nothing more is coming for these candidates.
        if self.policy == CrcPolicy::Lenient {
            let guess = candidates
                .into_iter()
                .flatten()
                .find(|c| c.len <= buffered && is_plausible(&self.buf, c));
            if let Some(c) = guess {
                return self.take(c, false);
            }
        }

        Step::NoMessage
    }

    /// Whether the code at the head of a message is a declared vendor code.
    ///
    /// "Unmodelled" is defined by the table rather than by a list of codes:
    /// [`candidates`] offers at least one layout for every code it knows, so an
    /// empty table means it knows none. That is what makes declaring a *modelled*
    /// code harmless — it keeps its length rules.
    fn is_vendor(&self, table: &[Option<Candidate>; 2], func: u8) -> bool {
        table.iter().all(Option::is_none) && self.declares(func)
    }

    fn declares(&self, func: u8) -> bool {
        self.any_function
            || self.vendor_functions.contains(&func)
            || self.vendor_lengths.iter().any(|r| r.function == func)
    }

    /// Whether messages of `func` are framed at all: modelled, or declared.
    pub(crate) fn frames_function(&self, func: u8) -> bool {
        self.declares(func) || is_modelled_function(func)
    }

    /// Frame the head by its code's [`VendorLength`] rules, or `None` when no
    /// rule's selector matches.
    ///
    /// The selected rules are tried in order and the first whose length
    /// CRC-validates wins; a rule still missing bytes is waited for. When none
    /// validates the head is not a message. [`CrcPolicy::Lenient`] is not
    /// consulted, as in [`Self::vendor_search`].
    fn take_by_rule(&mut self, at_end: bool) -> Option<Step> {
        let buf = &self.buf;
        let mut selected = false;
        let mut found = None;
        for rule in self.vendor_lengths.iter().filter(|r| r.function == buf[1]) {
            let len = match rule.match_head(buf) {
                RuleMatch::Unselected => continue,
                RuleMatch::Unread if at_end => continue,
                RuleMatch::Unread => return Some(Step::NeedMore),
                RuleMatch::Len(len) => len,
            };
            selected = true;
            if (MIN_RTU_LEN..=MAX_RTU_LEN).contains(&len) && crc16_modbus_valid(&buf[..len]) {
                found = Some(len);
                break;
            }
        }
        match found {
            Some(len) => Some(self.take(
                Candidate {
                    len,
                    direction: Direction::Request,
                },
                true,
            )),
            None if selected => {
                *self.rule_rejections.entry(self.buf[1]).or_default() += 1;
                Some(Step::NoMessage)
            }
            None => None,
        }
    }

    /// Find the boundary of an unmodelled message by CRC alone.
    ///
    /// Shortest-first, from the smallest message the wire format allows. See
    /// [`Self::with_vendor_functions`] for why shortest and not longest.
    ///
    /// [`CrcPolicy::Lenient`] has no meaning here and is not consulted: with no
    /// length rule and no header to check, "structurally plausible" would mean
    /// "any two bytes", so a guess would be pure fabrication. An unmodelled
    /// message is CRC-validated or it is not a message.
    fn vendor_search(&mut self, at_end: bool) -> Step {
        let buffered = self.buf.len();
        if let Some(len) =
            (MIN_RTU_LEN..=buffered.min(MAX_RTU_LEN)).find(|&n| crc16_modbus_valid(&self.buf[..n]))
        {
            // Direction is genuinely unknown for a code nothing models; `build`
            // resolves it from the alternation and documents the limit.
            let boundary = Candidate {
                len,
                direction: Direction::Request,
            };
            return self.take(boundary, true);
        }
        // No boundary yet. Bytes still to come could complete one, so hold —
        // unless the buffer is already longer than any message can be, in which
        // case there is nothing here and the head byte is junk.
        if !at_end && buffered < MAX_RTU_LEN {
            return Step::NeedMore;
        }
        Step::NoMessage
    }

    /// Consume a candidate's bytes off the head of the buffer as a message.
    fn take(&mut self, candidate: Candidate, crc_valid: bool) -> Step {
        let raw: Vec<u8> = self.buf.drain(..candidate.len).collect();
        // The cursor now sits one past the message's last byte: its `end_offset`.
        self.consumed += candidate.len as u64;
        Step::Message(self.build(raw, candidate.direction, crc_valid, self.consumed))
    }

    /// Turn validated bytes into a message, resolving what the wire leaves out.
    fn build(
        &mut self,
        raw: Vec<u8>,
        direction: Direction,
        crc_valid: bool,
        end_offset: u64,
    ) -> ModbusRtuMessage {
        let device_address = raw[0];
        let function = raw[1];
        // 0 on the byte-stream and pre-framed paths, which count no frames.
        let frame_count = self.pending_frames.max(1);

        let mut msg = ModbusRtuMessage {
            direction,
            direction_basis: DirectionBasis::Layout,
            device_address,
            function,
            start_register: None,
            quantity: None,
            payload: Payload::Opaque,
            exception: None,
            raw,
            crc_valid,
            frame_count,
            end_offset,
        };

        match (function, direction) {
            // Exception: a bare code, answering whatever was outstanding.
            (f, _) if f & 0x80 != 0 => msg.exception = Some(msg.raw[2]),
            // Read request, or a write-multiple response echoing its header.
            (0x01..=0x04, Direction::Request) | (0x0F | 0x10, Direction::Response) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(be(&msg.raw, 4));
            }
            // Read response: data only — the address comes from the request.
            (0x01..=0x04, Direction::Response) => {}
            // Write single: the value is the payload. Identical on both sides,
            // so the outstanding request decides which this is.
            (0x05 | 0x06, _) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(1);
                msg.direction_basis = DirectionBasis::Pairing;
                msg.direction = match self.last_request.take() {
                    Some((f, _, _)) if f == function => Direction::Response,
                    _ => Direction::Request,
                };
            }
            // Write-multiple request: header plus the data being written.
            (0x0F | 0x10, Direction::Request) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(be(&msg.raw, 4));
            }
            // Unmodelled: every modelled code is handled above, so this arm is
            // the vendor codes. Nothing is known about the body, and the wire
            // says nothing about which side sent it — only the alternation does,
            // and only on a line that alternates. Treat the direction as a hint.
            _ => {
                msg.direction_basis = DirectionBasis::Alternation;
                msg.direction = match self.last_vendor_request {
                    Some(f) if f == function => {
                        self.last_vendor_request = None;
                        Direction::Response
                    }
                    _ => {
                        self.last_vendor_request = Some(function);
                        Direction::Request
                    }
                };
                return msg;
            }
        }

        // A response that carries no address of its own takes the outstanding
        // request's — the only record of what was asked for.
        if msg.direction == Direction::Response && msg.start_register.is_none() {
            if let Some((_, start, qty)) = self.last_request.take() {
                msg.start_register = Some(start);
                msg.quantity = Some(qty);
            }
        }
        if msg.direction == Direction::Request {
            self.last_request = Some((
                function,
                msg.start_register.unwrap_or(0),
                msg.quantity.unwrap_or(0),
            ));
        }
        msg.payload = msg.read_payload();
        msg
    }
}

/// The length of a vendor code's messages, for the ones `when` selects. See
/// [`ModbusRtuStream::with_vendor_lengths`]. A catalogue writes it as a
/// [`LengthRule`] under its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorLength {
    pub function: u8,
    /// `None` selects every message of the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Selector>,
    pub len: VendorLen,
}

/// What a [`VendorLength`] rule makes of the message at the head of a buffer.
enum RuleMatch {
    Unselected,
    /// The rule needs bytes that have not arrived.
    Unread,
    /// Buffered, unless it is outside what the wire format allows.
    Len(usize),
}

impl VendorLength {
    fn match_head(&self, buf: &[u8]) -> RuleMatch {
        let byte = |at: u8| buf.get(usize::from(at)).copied();
        if let Some(selector) = self.when {
            match byte(selector.offset) {
                None => return RuleMatch::Unread,
                Some(b) if b != selector.value => return RuleMatch::Unselected,
                Some(_) => {}
            }
        }
        let len = match self.len {
            VendorLen::Fixed(n) => usize::from(n),
            VendorLen::Counted { count_at, overhead } => match byte(count_at) {
                None => return RuleMatch::Unread,
                Some(n) => usize::from(overhead) + usize::from(n),
            },
        };
        if (MIN_RTU_LEN..=MAX_RTU_LEN).contains(&len) && len > buf.len() {
            RuleMatch::Unread
        } else {
            RuleMatch::Len(len)
        }
    }
}

/// A [`VendorLength`] without its function code, which a catalogue's
/// `[meta.modbus.function_code.<code>]` table keys it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LengthRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<Selector>,
    pub len: VendorLen,
}

/// Selects the messages whose byte at `offset` is `value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selector {
    pub offset: u8,
    pub value: u8,
}

/// A message's total length, CRC included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "VendorLenForm", into = "VendorLenForm")]
pub enum VendorLen {
    Fixed(u16),
    /// `overhead` plus the byte at `count_at`.
    Counted {
        count_at: u8,
        overhead: u16,
    },
}

/// [`VendorLen`] as the catalogue writes it: `{ fixed = 11 }` or
/// `{ count_at = 6, overhead = 9 }`.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum VendorLenForm {
    Fixed {
        fixed: u16,
    },
    Counted {
        #[serde(rename = "countAt")]
        count_at: u8,
        overhead: u16,
    },
}

impl From<VendorLenForm> for VendorLen {
    fn from(form: VendorLenForm) -> Self {
        match form {
            VendorLenForm::Fixed { fixed } => Self::Fixed(fixed),
            VendorLenForm::Counted { count_at, overhead } => Self::Counted { count_at, overhead },
        }
    }
}

impl From<VendorLen> for VendorLenForm {
    fn from(len: VendorLen) -> Self {
        match len {
            VendorLen::Fixed(fixed) => Self::Fixed { fixed },
            VendorLen::Counted { count_at, overhead } => Self::Counted { count_at, overhead },
        }
    }
}

/// Everything a [`ModbusRtuStream`] for one line is built from.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct ModbusRtuOptions {
    /// `None` syncs on any address.
    pub device_address: Option<u8>,
    pub crc: CrcPolicy,
    /// See [`ModbusRtuStream::with_vendor_functions`].
    pub vendor_functions: Vec<u8>,
    /// See [`ModbusRtuStream::allow_broadcast`].
    pub allow_broadcast: bool,
    /// See [`ModbusRtuStream::frame_any_function`].
    pub any_function: bool,
    /// See [`ModbusRtuStream::with_vendor_lengths`].
    pub vendor_lengths: Vec<VendorLength>,
}

impl ModbusRtuOptions {
    /// Every code framed, and address 0 may start a message.
    pub fn tapped() -> Self {
        Self::default().allow_broadcast().frame_any_function()
    }

    #[must_use]
    pub fn with_device_address(mut self, device_address: Option<u8>) -> Self {
        self.device_address = device_address;
        self
    }

    #[must_use]
    pub fn with_crc_policy(mut self, crc: CrcPolicy) -> Self {
        self.crc = crc;
        self
    }

    #[must_use]
    pub fn with_vendor_functions(mut self, functions: &[u8]) -> Self {
        self.vendor_functions.extend_from_slice(functions);
        self
    }

    #[must_use]
    pub fn allow_broadcast(mut self) -> Self {
        self.allow_broadcast = true;
        self
    }

    #[must_use]
    pub fn frame_any_function(mut self) -> Self {
        self.any_function = true;
        self
    }

    #[must_use]
    pub fn with_vendor_lengths(mut self, rules: &[VendorLength]) -> Self {
        self.vendor_lengths.extend_from_slice(rules);
        self
    }

    /// A stream built from these options.
    pub fn stream(&self) -> ModbusRtuStream {
        let mut stream = ModbusRtuStream::with_crc_policy(self.device_address, self.crc)
            .with_vendor_functions(&self.vendor_functions)
            .with_vendor_lengths(&self.vendor_lengths);
        stream.allow_broadcast = self.allow_broadcast;
        stream.any_function = self.any_function;
        stream
    }

    /// A line's options: what `catalog` declares, with `settings` on top. The
    /// codes and both opt-ins union; the address and the CRC policy are the
    /// settings'.
    pub fn from_settings(settings: &RtuSettings, catalog: Option<&Catalog>) -> Self {
        let crc = if settings.validate_crc {
            CrcPolicy::Strict
        } else {
            CrcPolicy::Lenient
        };
        let mut options = catalog
            .map(Catalog::rtu_options)
            .unwrap_or_default()
            .with_vendor_functions(&settings.vendor_functions)
            .with_device_address(settings.device_address)
            .with_crc_policy(crc);
        options.allow_broadcast |= settings.allow_broadcast;
        options.any_function |= settings.any_function;
        options
    }
}

/// A line's RTU settings as a user picks and stores them, before a catalogue
/// adds its codes; [`ModbusRtuOptions::from_settings`] joins the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(rename = "ModbusRtuOptions"))]
#[serde(default)]
pub struct RtuSettings {
    /// Device address filter (1-247). `None` syncs on any valid address.
    #[cfg_attr(feature = "ts", ts(optional))]
    pub device_address: Option<u8>,
    /// Whether a message has to pass its CRC to be framed. `false` is a lenient
    /// mode, not "no framing" — see `CrcPolicy::Lenient`.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub validate_crc: bool,
    /// Function codes the RTU length rules do not model but this line carries.
    /// Framed by CRC search instead; empty leaves stock Modbus untouched.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub vendor_functions: Vec<u8>,
    /// Whether address 0 may start a message, for a master that broadcasts.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub allow_broadcast: bool,
    /// Frame every function code, declared or not. What a tap on an unknown
    /// line wants, at the cost of a fabricated message about once in 260
    /// resyncs — see `ModbusRtuStream::frame_any_function`.
    #[cfg_attr(feature = "ts", ts(optional = nullable))]
    pub any_function: bool,
}

/// Stock Modbus: CRC enforced, no vendor codes, no broadcast.
impl Default for RtuSettings {
    fn default() -> Self {
        Self {
            device_address: None,
            validate_crc: true,
            vendor_functions: Vec::new(),
            allow_broadcast: false,
            any_function: false,
        }
    }
}

impl RtuSettings {
    /// A line somebody else already framed, such as an archive's whole
    /// messages: every code and address interprets.
    pub fn tapped() -> Self {
        Self {
            any_function: true,
            allow_broadcast: true,
            ..Default::default()
        }
    }

    /// A stream for this line with no catalogue.
    pub fn stream(&self) -> ModbusRtuStream {
        ModbusRtuOptions::from_settings(self, None).stream()
    }
}

pub(crate) fn rtu_options_for(codes: &BTreeMap<u8, FunctionCode>) -> ModbusRtuOptions {
    let functions: Vec<u8> = codes.keys().copied().collect();
    let rules: Vec<VendorLength> = codes
        .iter()
        .flat_map(|(&function, code)| {
            code.lengths.iter().map(move |rule| VendorLength {
                function,
                when: rule.when,
                len: rule.len,
            })
        })
        .collect();
    ModbusRtuOptions::default()
        .with_vendor_functions(&functions)
        .with_vendor_lengths(&rules)
}

impl Catalog {
    /// A serial line carrying this catalogue's devices: its function codes
    /// declared, with their length rules. Everything else is the default, for
    /// the caller to set.
    pub fn rtu_options(&self) -> ModbusRtuOptions {
        self.modbus
            .as_ref()
            .map(|m| rtu_options_for(&m.function_codes))
            .unwrap_or_default()
    }

    /// The stream for one of this catalogue's tunnels: what its table declares,
    /// plus the catalogue's function codes.
    pub fn tunnel_stream(&self, tunnel: &FrameTunnel) -> ModbusRtuStream {
        let codes = self.rtu_options();
        ModbusRtuStream::new(tunnel)
            .with_vendor_functions(&codes.vendor_functions)
            .with_vendor_lengths(&codes.vendor_lengths)
    }
}

/// Whether the length table frames `function` itself, which leaves nothing for
/// a vendor declaration to do.
pub(crate) fn is_modelled_function(function: u8) -> bool {
    candidates(&[0, function]).iter().any(Option::is_some)
}

/// Candidate layouts for the function code at the head of `buf`, longest first.
///
/// There are never more than two, so this is an array rather than a `Vec`: it is
/// built once per byte fed on the byte-stream path, where an allocation and a
/// sort per byte are the whole cost. `buf` must be at least 2 bytes. Lengths a
/// `byte_count` decides are only offered once that byte has arrived.
fn candidates(buf: &[u8]) -> [Option<Candidate>; 2] {
    let func = buf[1];
    let req = |len: usize| {
        Some(Candidate {
            len,
            direction: Direction::Request,
        })
    };
    let resp = |len: usize| {
        Some(Candidate {
            len,
            direction: Direction::Response,
        })
    };
    // `byte_count` at `idx`, when that byte has arrived.
    let bc = |idx: usize| buf.get(idx).map(|&b| b as usize);

    let pair = match func {
        // Exception: address, function, code, CRC.
        f if f & 0x80 != 0 => (resp(5), None),
        // Reads: an 8-byte request, or a `5 + byte_count` response. For FC03/04
        // the two cannot collide, because a register byte count is even. For
        // FC01/02 they can: 17..=24 coils pack into 3 bytes, making an 8-byte
        // response. The tie below goes to the request, so that one case reads as
        // a request unless its quantity is out of range — wrong, but consistently
        // so, and `interpret` shares this table precisely so both paths agree.
        0x01..=0x04 => (req(8), bc(2).and_then(|n| resp(5 + n))),
        // Write single coil/register: request and response are identical.
        // Direction comes from `last_request` in `build`.
        0x05 | 0x06 => (req(8), None),
        // Write multiple: `9 + byte_count` request, 8-byte response.
        0x0F | 0x10 => (resp(8), bc(6).and_then(|n| req(9 + n))),
        _ => (None, None),
    };
    // Longest first, swapping only on strictly longer so an equal-length pair
    // keeps the order above.
    match pair {
        (Some(first), Some(second)) if second.len > first.len => [pair.1, pair.0],
        _ => [pair.0, pair.1],
    }
}

/// Whether a candidate's own header is self-consistent — the only evidence left
/// when the CRC has already failed to vouch for it.
///
/// Used for two things: deciding which candidates earn the "wait for a longer
/// one" rule, and gating what [`CrcPolicy::Lenient`] is willing to guess.
/// Without it, line noise fabricates a message out of every byte pair that looks
/// like an address and a function code.
///
/// Only checks what the wire format guarantees independently of the CRC, so a
/// real message can never be rejected. A candidate whose header bytes have not
/// arrived yet is undecidable, and counts as plausible so that it still earns
/// the wait. The fixed-length layouts have nothing left to check — their length
/// rule *is* the check.
fn is_plausible(buf: &[u8], candidate: &Candidate) -> bool {
    let func = buf[1];
    match (func, candidate.direction) {
        // Exception: a code that actually exists. 0x0B is the highest the spec
        // defines, and there is no exception 0 — without this, any noise byte
        // with its high bit set invents a five-byte exception.
        (f, _) if f & 0x80 != 0 => buf.get(2).is_none_or(|&code| (0x01..=0x0B).contains(&code)),
        (0x01..=0x04, Direction::Request) => within_quantity_cap(buf, candidate),
        // Read response: a data block, two bytes per register for the register
        // banks. Coil banks pack eight to a byte, so any count is possible.
        (0x01..=0x04, Direction::Response) => {
            let register_bank =
                RegisterType::from_function_code(func).is_some_and(RegisterType::is_register_bank);
            buf.get(2).is_none_or(|&n| {
                let n = n as usize;
                (1..=MAX_DATA_BYTES).contains(&n) && (!register_bank || n.is_multiple_of(2))
            })
        }
        // Write-multiple request: the byte count has to match the quantity it
        // claims to be writing, packed as the bank packs it.
        (0x0F | 0x10, Direction::Request) => {
            within_quantity_cap(buf, candidate)
                && RegisterType::from_function_code(func).is_some_and(|bank| {
                    be_at(buf, 4)
                        .zip(buf.get(6))
                        .is_none_or(|(quantity, &n)| n as usize == bank.data_bytes(quantity))
                })
        }
        _ => true,
    }
}

/// Whether a request asks for a quantity its bank can serve in one message, per
/// the spec's per-request caps. Layouts with no quantity field pass, as does a
/// quantity that has not arrived yet.
fn within_quantity_cap(buf: &[u8], candidate: &Candidate) -> bool {
    let bank = RegisterType::from_function_code(buf[1]);
    let cap = match (buf[1], candidate.direction) {
        (0x01..=0x04, Direction::Request) => bank.map(RegisterType::max_per_read),
        (0x0F | 0x10, Direction::Request) => bank.and_then(RegisterType::max_per_write),
        _ => return true,
    };
    be_at(buf, 4).is_none_or(|quantity| cap.is_some_and(|max| (1..=max).contains(&quantity)))
}

/// Big-endian `u16` at `i`.
fn be(raw: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([raw[i], raw[i + 1]])
}

/// Big-endian `u16` at `i`, when both its bytes have arrived.
fn be_at(raw: &[u8], i: usize) -> Option<u16> {
    raw.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiretap_checksum::algorithms::crc16_modbus_checksum;

    /// A tunnel declaring nothing but its address, which is the shape almost
    /// every test wants.
    fn tunnel(device_address: Option<u8>) -> FrameTunnel {
        FrameTunnel {
            protocol: TunnelProtocol::ModbusRtu,
            device_address,
            vendor_functions: Vec::new(),
            allow_broadcast: false,
            notes: Vec::new(),
        }
    }

    fn strict(device_address: Option<u8>) -> ModbusRtuStream {
        ModbusRtuStream::new(&tunnel(device_address))
    }

    fn lenient(device_address: Option<u8>) -> ModbusRtuStream {
        ModbusRtuStream::with_crc_policy(device_address, CrcPolicy::Lenient)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A message body plus the CRC the device would append.
    fn with_crc(body: &str) -> Vec<u8> {
        let mut m = hex(body);
        m.extend(crc16_modbus_checksum(&m).to_le_bytes());
        m
    }

    /// A message body with a CRC that is definitely wrong.
    fn with_bad_crc(body: &str) -> Vec<u8> {
        let mut m = with_crc(body);
        *m.last_mut().expect("crc appended") ^= 0xFF;
        m
    }

    /// Feed a message the way CAN carries it: split at 8-byte boundaries.
    fn push_chunked(t: &mut ModbusRtuStream, msg: &[u8]) -> Vec<ModbusRtuMessage> {
        msg.chunks(8).flat_map(|c| t.push(c)).collect()
    }

    // The four exchanges observed on a Sungrow SBR's CAN 0x1E0.

    #[test]
    fn decodes_read_input_request() {
        let mut t = strict(Some(1));
        let msgs = push_chunked(&mut t, &hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].function, 0x04);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].quantity, Some(2));
        assert_eq!(msgs[0].frame_count, 1);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn decodes_read_input_response_split_8_plus_1() {
        let mut t = strict(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers(), [500, 0]);
        // Inherited from the request it answers.
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 2);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn decodes_read_holding_response_split_8_plus_8_plus_1() {
        let mut t = strict(Some(1));
        let req = push_chunked(&mut t, &hex("01034DE200067292"));
        assert_eq!(req[0].quantity, Some(6));

        let msgs = push_chunked(&mut t, &hex("01030C01F40000012C000000C80000D570"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers(), [500, 0, 300, 0, 200, 0]);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 3);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn register_bytes_are_big_endian() {
        let mut t = strict(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs[0].register_bytes(), hex("01F40000"));
    }

    #[test]
    fn a_partial_message_yields_nothing_until_complete() {
        let mut t = strict(Some(1));
        assert!(t.push(&hex("01030C01F40000012C")).is_empty());
        assert!(t.push(&hex("000000C80000")).is_empty());
        assert_eq!(t.push(&hex("D570")).len(), 1);
    }

    #[test]
    fn resyncs_past_leading_junk() {
        let mut t = strict(Some(1));
        // A stray byte that is not the device address is skipped outright.
        let msgs = t.push(&hex("FF01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn resyncs_past_a_false_address_byte() {
        let mut t = strict(Some(1));
        // A leading 0x01 that starts nothing valid must be dropped, not left to
        // block the real message behind it.
        let msgs = t.push(&hex("0101044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x04);
    }

    #[test]
    fn back_to_back_messages_in_one_push() {
        let mut t = strict(Some(1));
        let msgs = t.push(&hex("01044DE20002C69101040401F40000BB8A"));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[1].direction, Direction::Response);
        assert_eq!(msgs[1].registers(), [500, 0]);
    }

    #[test]
    fn decodes_exception_response() {
        let mut t = strict(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        // Illegal data address.
        let msgs = t.push(&with_crc("018402"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].exception, Some(0x02));
        assert_eq!(msgs[0].direction, Direction::Response);
        // It answers the request, so it names the register that failed.
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn write_single_pairs_request_then_response() {
        let mut t = strict(Some(1));
        let raw = with_crc("0106138800C8");
        let first = t.push(&raw);
        assert_eq!(first[0].direction, Direction::Request);
        assert_eq!(first[0].registers(), [0xC8]);
        // The echo is byte-identical; only the outstanding request tells them
        // apart.
        let second = t.push(&raw);
        assert_eq!(second[0].direction, Direction::Response);
    }

    #[test]
    fn decodes_write_multiple_request_and_response() {
        let mut t = strict(Some(1));
        let msgs = push_chunked(&mut t, &with_crc("0110138800020400C801F4"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].registers(), [0xC8, 0x01F4]);

        let msgs = t.push(&with_crc("011013880002"));
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].start_register, Some(0x1388));
        assert_eq!(msgs[0].payload, Payload::None);
    }

    // ---- Coil banks ----

    /// Ten coils: 0xCD is the first eight, LSB first, and only two bits of the
    /// second byte are coils at all.
    const TEN_COILS: [bool; 10] = [
        true, false, true, true, false, false, true, true, true, false,
    ];

    #[test]
    fn a_coil_response_decodes_as_coils_and_not_as_registers() {
        // FC01 reads coils and FC02 discrete inputs; both pack their bits.
        for func in ["01", "02"] {
            let mut t = strict(Some(1));
            push_chunked(&mut t, &with_crc(&format!("01{func}006E000A")));
            let msgs = t.push(&with_crc(&format!("01{func}02CD01")));
            assert_eq!(msgs.len(), 1);
            assert_eq!(msgs[0].direction, Direction::Response);
            assert_eq!(msgs[0].coils(), TEN_COILS);
            assert!(msgs[0].registers().is_empty());
            assert_eq!(msgs[0].data_block(), hex("CD01"));
        }
    }

    #[test]
    fn a_coil_response_with_no_request_behind_it_is_opaque() {
        // Only the quantity says how many of the second byte's bits are coils,
        // and it comes from the request. Without one, up to seven are invented.
        let msgs = strict(Some(1)).push(&with_crc("010102CD01"));
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].quantity.is_none());
        assert_eq!(msgs[0].payload, Payload::Opaque);
        assert_eq!(msgs[0].data_block(), hex("CD01"));
    }

    #[test]
    fn write_multiple_coils_decodes_the_block_it_writes() {
        let mut t = strict(Some(1));
        let msgs = push_chunked(&mut t, &with_crc("010F0013000A02CD01"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].quantity, Some(10));
        assert_eq!(msgs[0].coils(), TEN_COILS);
        assert!(msgs[0].registers().is_empty());
        // The echo carries a header only.
        let echo = t.push(&with_crc("010F0013000A"));
        assert_eq!(echo[0].direction, Direction::Response);
        assert_eq!(echo[0].payload, Payload::None);
    }

    #[test]
    fn write_single_coil_is_on_off_rather_than_a_register_value() {
        let mut t = strict(Some(1));
        let on = t.push(&with_crc("010500ACFF00"));
        assert_eq!(on[0].payload, Payload::Coils(vec![true]));
        let off = t.push(&with_crc("010500AC0000"));
        assert_eq!(off[0].payload, Payload::Coils(vec![false]));
        // A value the spec does not define says nothing about a coil.
        let undefined = t.push(&with_crc("010500AC0001"));
        assert_eq!(undefined[0].payload, Payload::Opaque);
    }

    #[test]
    fn a_register_bank_carries_no_coils() {
        let msgs = strict(Some(1)).push(&with_crc("01040401F40000"));
        assert_eq!(msgs[0].registers(), [500, 0]);
        assert!(msgs[0].coils().is_empty());
    }

    // ---- Payload and direction basis ----

    #[test]
    fn a_read_pair_is_sided_by_layout() {
        let mut t = strict(Some(1));
        let request = t.push(&with_crc("01044DE20002"));
        assert_eq!(request[0].direction_basis, DirectionBasis::Layout);
        assert_eq!(request[0].payload, Payload::None);
        let response = t.push(&with_crc("01040401F40000"));
        assert_eq!(response[0].direction_basis, DirectionBasis::Layout);
        assert_eq!(response[0].payload, Payload::Registers(vec![500, 0]));
    }

    #[test]
    fn a_write_single_register_pair_is_sided_by_pairing() {
        let mut t = strict(Some(1));
        for direction in [Direction::Request, Direction::Response] {
            let msgs = t.push(&with_crc("0106138801F4"));
            assert_eq!(msgs[0].direction, direction);
            assert_eq!(msgs[0].direction_basis, DirectionBasis::Pairing);
            assert_eq!(msgs[0].payload, Payload::Registers(vec![500]));
        }
    }

    #[test]
    fn a_vendor_code_is_sided_by_alternation_and_opaque() {
        let msgs = sungrow().push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs[0].direction_basis, DirectionBasis::Alternation);
        assert_eq!(msgs[0].payload, Payload::Opaque);
    }

    #[test]
    fn an_exception_carries_no_values_and_is_sided_by_layout() {
        let mut t = strict(Some(1));
        t.push(&with_crc("01034DE20002"));
        let msgs = t.push(&with_crc("018302"));
        assert_eq!(msgs[0].exception, Some(2));
        assert_eq!(msgs[0].direction_basis, DirectionBasis::Layout);
        assert_eq!(msgs[0].payload, Payload::None);
    }

    #[test]
    fn unconstrained_address_accepts_any_slave() {
        let mut t = strict(None);
        let msgs = t.push(&with_crc("2A044DE20002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].device_address, 42);
    }

    #[test]
    fn a_desynced_stream_does_not_grow_without_bound() {
        let mut t = strict(Some(1));
        // 0x01 0x07 is a valid address but an unhandled function, so nothing
        // ever completes.
        for _ in 0..500 {
            t.push(&hex("0107010101010101"));
        }
        assert!(t.buf.len() <= MAX_BUFFER);
    }

    #[test]
    fn for_address_matches_the_catalogue_constructor() {
        let stream = with_crc("01044DE20002");
        let declared = strict(Some(1)).push_bytes(&stream);
        let bare = ModbusRtuStream::for_address(Some(1)).push_bytes(&stream);
        assert_eq!(declared, bare);
        assert_eq!(declared.len(), 1);
    }

    // ---- Lenient CRC policy ----

    #[test]
    fn lenient_emits_the_bad_crc_message_strict_discards() {
        let bytes = with_bad_crc("01040401F40000");
        assert!(strict(Some(1)).push_bytes(&bytes).is_empty());

        let msgs = lenient(Some(1)).push_bytes(&bytes);
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].crc_valid);
        // The boundary came from the length rules, so the block still decodes.
        assert_eq!(msgs[0].registers(), [500, 0]);
    }

    #[test]
    fn lenient_still_prefers_a_valid_crc_candidate() {
        // An 8-byte read request whose CRC is good sits inside the buffer at the
        // same head as a longer response candidate that is not valid. The valid
        // one must win outright rather than the guess consuming it.
        let mut t = lenient(Some(1));
        let msgs = t.push_bytes(&with_crc("01044DE20002"));
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].crc_valid);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn lenient_waits_for_the_longest_candidate_before_guessing() {
        let mut t = lenient(Some(1));
        // Eight bytes of a 17-byte FC03 response. The 8-byte request candidate
        // fits, but the response candidate could still be completed, so nothing
        // may be emitted yet.
        assert!(t.push_bytes(&hex("01030C01F40000012C")).is_empty());
    }

    #[test]
    fn lenient_recovers_after_a_bad_crc_message() {
        let mut t = lenient(Some(1));
        let mut stream = with_bad_crc("01044DE20002");
        stream.extend(with_crc("01040401F40000"));
        let msgs = t.push_bytes(&stream);
        assert_eq!(msgs.len(), 2);
        assert!(!msgs[0].crc_valid);
        assert!(msgs[1].crc_valid);
        assert_eq!(msgs[1].registers(), [500, 0]);
    }

    #[test]
    fn lenient_rejects_an_implausible_byte_count() {
        // An FC04 response claiming an odd byte count cannot be real: registers
        // are two bytes each. Without the plausibility gate this fabricates a
        // message.
        let mut t = lenient(Some(1));
        assert!(t.push_bytes(&with_bad_crc("01040301F400")).is_empty());
        // And a zero byte count.
        let mut t = lenient(Some(1));
        assert!(t.push_bytes(&with_bad_crc("010400")).is_empty());
    }

    #[test]
    fn lenient_rejects_a_write_multiple_whose_count_contradicts_its_quantity() {
        // Claims two registers but carries six bytes, so the 15-byte request
        // reading contradicts itself and must never be emitted. (The shorter
        // response reading of the same head has nothing left to contradict; a
        // guess is a guess, and it is flagged as one.)
        let mut t = lenient(Some(1));
        let msgs = t.push_bytes(&with_bad_crc("0110138800020600C801F40000"));
        assert!(msgs.iter().all(|m| m.raw.len() != 15), "{msgs:?}");
        assert!(msgs.iter().all(|m| !m.crc_valid));
    }

    #[test]
    fn lenient_drops_a_byte_when_no_candidate_exists() {
        // 0x07 is an unhandled function, so there is nothing to guess at; the
        // real message behind it must still be found.
        let mut t = lenient(Some(1));
        let mut stream = hex("0107");
        stream.extend(with_crc("01044DE20002"));
        let msgs = t.push_bytes(&stream);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].crc_valid);
        assert_eq!(msgs[0].function, 0x04);
    }

    // ---- interpret: one already-framed message ----

    /// Without a CRC to vouch for it, a candidate whose own header contradicts
    /// itself is not a message. Five bytes opening like an address and a read
    /// function code match the `5 + byte_count` response layout with a byte
    /// count of zero — which no device sends.
    #[test]
    fn interpret_rejects_an_implausible_message_with_a_bad_crc() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        assert!(t.interpret(&hex("0103006B00")).is_none());
    }

    /// A CRC that agrees still wins, whatever the length table makes of it.
    #[test]
    fn interpret_trusts_a_valid_crc_over_the_length_table() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let framed = with_crc("010300");
        assert!(t.interpret(&framed).is_some());
    }

    #[test]
    fn interpret_reads_one_framed_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let msg = t.interpret(&hex("01044DE20002C691")).unwrap();
        assert_eq!(msg.direction, Direction::Request);
        assert_eq!(msg.start_register, Some(0x4DE2));
        assert_eq!(msg.quantity, Some(2));
        assert_eq!(msg.frame_count, 1);
        assert!(msg.crc_valid);
    }

    #[test]
    fn interpret_pairs_a_response_with_the_preceding_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        t.interpret(&hex("01044DE20002C691")).unwrap();
        let msg = t.interpret(&hex("01040401F40000BB8A")).unwrap();
        assert_eq!(msg.direction, Direction::Response);
        assert_eq!(msg.registers(), [500, 0]);
        assert_eq!(msg.start_register, Some(0x4DE2));
    }

    #[test]
    fn interpret_resolves_write_single_direction_from_the_outstanding_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let raw = with_crc("0106138800C8");
        assert_eq!(t.interpret(&raw).unwrap().direction, Direction::Request);
        assert_eq!(t.interpret(&raw).unwrap().direction, Direction::Response);
    }

    #[test]
    fn interpret_rejects_a_length_no_candidate_explains() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        assert!(t.interpret(&hex("01044DE2000200")).is_none());
        assert!(t.interpret(&hex("0104")).is_none());
        // Wrong slave.
        assert!(t.interpret(&hex("02044DE20002B441")).is_none());
    }

    #[test]
    fn interpret_flags_a_bad_crc_rather_than_rejecting_it() {
        // The caller supplied the boundary, so the CRC is a verdict, not a gate
        // — in either policy.
        for mut t in [ModbusRtuStream::for_address(Some(1)), lenient(Some(1))] {
            let msg = t.interpret(&with_bad_crc("01044DE20002")).unwrap();
            assert!(!msg.crc_valid);
            assert_eq!(msg.start_register, Some(0x4DE2));
        }
    }

    #[test]
    fn interpret_prefers_the_request_reading_when_lengths_collide() {
        // An FC01 response for 17..=24 coils packs into 3 bytes, making it 8
        // bytes long — exactly a request. Both paths must read it the same way.
        let raw = with_crc("010103010203");
        let framed = ModbusRtuStream::for_address(Some(1))
            .interpret(&raw)
            .unwrap()
            .direction;
        let streamed = ModbusRtuStream::for_address(Some(1)).push_bytes(&raw)[0].direction;
        assert_eq!(framed, streamed);
        assert_eq!(framed, Direction::Request);
    }

    #[test]
    fn interpret_leaves_the_buffer_untouched() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        // Half a message in the reassembly buffer.
        t.push_bytes(&hex("01030C01F40000012C"));
        let buffered = t.buf.clone();
        t.interpret(&hex("01044DE20002C691")).unwrap();
        assert_eq!(t.buf, buffered);
    }

    // ---- byte streams and end of stream ----

    #[test]
    fn push_bytes_reassembles_a_message_fed_one_byte_at_a_time() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let raw = hex("01030C01F40000012C000000C80000D570");
        let msgs: Vec<_> = raw.iter().flat_map(|b| t.push_bytes(&[*b])).collect();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].registers(), [500, 0, 300, 0, 200, 0]);
        // 17 separate pushes, and still one message spanning no frames at all.
        assert_eq!(msgs[0].frame_count, 1);
    }

    #[test]
    fn back_to_back_messages_fed_one_byte_at_a_time() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let mut stream = with_crc("01044DE20002");
        stream.extend(with_crc("01040401F40000"));
        let msgs: Vec<_> = stream.iter().flat_map(|b| t.push_bytes(&[*b])).collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].registers(), [500, 0]);
        let (rest, residue) = t.finish();
        assert!(rest.is_empty());
        assert!(residue.is_empty());
    }

    #[test]
    fn finish_emits_a_candidate_the_wait_for_longest_rule_withheld() {
        let mut t = lenient(Some(1));
        // A complete but CRC-invalid 8-byte read request whose third byte also
        // reads as a plausible `byte_count` of 4, so a 9-byte response candidate
        // might still arrive. Mid-stream that candidate earns the wait.
        assert!(t.push_bytes(&with_bad_crc("010304000002")).is_empty());
        // At end of stream it never will, so the guess is finally made.
        let (msgs, residue) = t.finish();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].crc_valid);
        assert_eq!(msgs[0].raw.len(), 8);
        assert!(residue.is_empty());
    }

    #[test]
    fn finish_reports_a_truncated_message_whole() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        // Nine bytes of a 17-byte response: not a message, and not noise either.
        let partial = hex("01030C01F40000012C00");
        t.push_bytes(&partial);
        let (msgs, residue) = t.finish();
        assert!(msgs.is_empty());
        assert_eq!(residue, partial);
        // And the buffer is now empty.
        assert!(t.buf.is_empty());
    }

    #[test]
    fn finish_recovers_a_message_then_reports_the_residue() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let mut stream = with_crc("01044DE20002");
        stream.extend(hex("010401"));
        let streamed = t.push_bytes(&stream);
        let (finished, residue) = t.finish();
        // The valid message came out as soon as its CRC closed; the trailing
        // three bytes are not a message and are handed back whole.
        assert_eq!(streamed.len(), 1);
        assert_eq!(streamed[0].start_register, Some(0x4DE2));
        assert!(finished.is_empty());
        assert_eq!(residue, hex("010401"));
    }

    #[test]
    fn finish_resyncs_past_a_head_that_can_never_complete() {
        let mut t = ModbusRtuStream::for_address(None);
        // Opens like a 192-byte FC01 response that a finite sample never finishes.
        let mut stream = hex("0401BB0000");
        let pairs: Vec<_> = [with_crc("01044DE20002"), with_crc("01040401F40000")]
            .iter()
            .cycle()
            .take(6)
            .cloned()
            .collect();
        stream.extend(pairs.concat());
        stream.extend(hex("010401"));
        let mut msgs = t.push_bytes(&stream);
        assert!(msgs.is_empty(), "held for the long candidate");

        let (finished, residue) = t.finish();
        msgs.extend(finished);
        let raws: Vec<_> = msgs.into_iter().map(|m| m.raw).collect();
        assert_eq!(raws, pairs);
        assert_eq!(residue, hex("010401"));
        assert_eq!(t.bytes_fed(), stream.len() as u64);
    }

    #[test]
    fn finish_is_idempotent() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        t.push_bytes(&hex("01030C01F4"));
        let first = t.finish();
        assert!(!first.1.is_empty());
        assert_eq!(t.finish(), (Vec::new(), Vec::new()));
    }

    // Vendor function codes and broadcast. The traffic shapes below are the ones
    // measured on a Sungrow logger's RS-485 line, where 0x20 (battery), 0x60
    // (dispatch, broadcast) and 0x65 (inverter telemetry) are 90% of the bus.

    /// A stream configured the way that line needs.
    fn sungrow() -> ModbusRtuStream {
        ModbusRtuStream::for_address(None)
            .with_vendor_functions(&[0x20, 0x60, 0x65])
            .allow_broadcast()
    }

    #[test]
    fn an_undeclared_vendor_code_is_not_framed() {
        // The default has no length rule for 0x20 and must not guess one.
        let mut t = ModbusRtuStream::for_address(None);
        assert!(t.push_bytes(&with_crc("012001C803111A0002")).is_empty());
    }

    #[test]
    fn a_declared_vendor_code_is_framed_by_its_crc() {
        let msg = with_crc("012001C803111A0002");
        let msgs = sungrow().push_bytes(&msg);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x20);
        assert_eq!(msgs[0].device_address, 1);
        assert_eq!(msgs[0].raw, msg);
        assert!(msgs[0].crc_valid);
        // Nothing is known about a vendor body, so nothing is claimed about it.
        assert_eq!(msgs[0].start_register, None);
        assert_eq!(msgs[0].quantity, None);
        assert!(msgs[0].registers().is_empty());
    }

    #[test]
    fn a_declared_vendor_code_still_needs_a_valid_crc() {
        assert!(sungrow()
            .push_bytes(&with_bad_crc("012001C803111A0002"))
            .is_empty());
    }

    #[test]
    fn broadcast_starts_a_message_only_when_allowed() {
        let dispatch = with_crc("0060000000050A000401BB03E808");
        assert!(ModbusRtuStream::for_address(None)
            .with_vendor_functions(&[0x60])
            .push_bytes(&dispatch)
            .is_empty());
        let msgs = sungrow().push_bytes(&dispatch);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].device_address, 0);
        assert_eq!(msgs[0].function, 0x60);
    }

    #[test]
    fn a_catalogue_can_declare_what_the_builder_can() {
        let declared = FrameTunnel {
            vendor_functions: vec![0x20, 0x60, 0x65],
            allow_broadcast: true,
            ..tunnel(None)
        };
        let msgs = ModbusRtuStream::new(&declared).push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x20);
    }

    #[test]
    fn catalogue_and_builder_vendor_codes_are_unioned() {
        let declared = FrameTunnel {
            vendor_functions: vec![0x20],
            ..tunnel(None)
        };
        let mut t = ModbusRtuStream::new(&declared).with_vendor_functions(&[0x65]);

        // The catalogue's code survives the builder call...
        let msgs = t.push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs.len(), 1, "catalogue-declared 0x20");
        // ...and the builder's is framed too.
        let msgs = t.push_bytes(&with_crc("0165020BB8"));
        assert_eq!(msgs.len(), 1, "builder-declared 0x65");
        assert_eq!(msgs[0].function, 0x65);
    }

    /// A tunnel normally pins an address, so a declaration that only worked on
    /// address-less streams would be dead config.
    #[test]
    fn a_pinned_address_still_admits_a_declared_broadcast() {
        let dispatch = with_crc("0060000000050A000401BB03E808");
        let declared = FrameTunnel {
            vendor_functions: vec![0x60],
            allow_broadcast: true,
            ..tunnel(Some(1))
        };
        let msgs = ModbusRtuStream::new(&declared).push_bytes(&dispatch);
        assert_eq!(msgs.len(), 1, "a broadcast reaches address 1 as well");
        assert_eq!(msgs[0].device_address, 0);

        // Undeclared, a pinned stream still ignores it.
        let quiet = FrameTunnel {
            vendor_functions: vec![0x60],
            ..tunnel(Some(1))
        };
        assert!(ModbusRtuStream::new(&quiet)
            .push_bytes(&dispatch)
            .is_empty());
    }

    #[test]
    fn the_vendor_search_takes_the_shortest_crc_valid_length() {
        // A complete vendor message, then more bytes behind it. Longest-first
        // would be free to swallow the follower; shortest-first stops at the
        // real boundary. Measured over 34 MB, that difference is 99.88% of the
        // bytes recovered against 94.80%.
        let first = with_crc("0165000200");
        let mut stream = first.clone();
        stream.extend(with_crc("0165000201"));
        let msgs = sungrow().push_bytes(&stream);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].raw, first);
    }

    #[test]
    fn a_split_vendor_message_waits_rather_than_resyncing_through_itself() {
        let msg = with_crc("012001C803111A0002");
        let mut t = sungrow();
        // Every byte but the last: no CRC closes, and the head must be held.
        assert!(t.push_bytes(&msg[..msg.len() - 1]).is_empty());
        let msgs = t.push_bytes(&msg[msg.len() - 1..]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].raw, msg);
    }

    #[test]
    fn a_vendor_message_does_not_steal_a_read_responses_address() {
        // The regression this guards: vendor traffic interleaves with standard
        // polling, and a read response takes its address from the outstanding
        // request. If a vendor message shared that slot it would consume the
        // request, and the response would report an address nobody asked for.
        let mut t = sungrow();
        t.push_bytes(&with_crc("01044DE20002"));
        t.push_bytes(&with_crc("012001C803111A0002"));
        let msgs = t.push_bytes(&with_crc("010404CAFEF00D"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].quantity, Some(2));
    }

    #[test]
    fn interpret_accepts_a_pre_framed_vendor_message() {
        // `interpret` shares the candidate table with the byte-stream path, so
        // it has to share the vendor rule too or the two label differently.
        let msg = with_crc("012001C803111A0002");
        let got = sungrow().interpret(&msg).expect("declared vendor code");
        assert_eq!(got.function, 0x20);
        assert_eq!(got.raw, msg);
        assert!(got.crc_valid);
        assert!(ModbusRtuStream::for_address(None).interpret(&msg).is_none());
    }

    #[test]
    fn a_read_responses_data_block_is_its_register_bytes() {
        // The property that lets a tapped read and a polled one be compared:
        // both are the register block, big-endian, byte count stripped.
        let mut t = ModbusRtuStream::for_address(Some(1));
        t.push_bytes(&with_crc("01044DE20002"));
        let msgs = t.push_bytes(&with_crc("010404CAFEF00D"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].data_block(), &hex("CAFEF00D")[..]);
        assert_eq!(msgs[0].data_block(), msgs[0].register_bytes());
    }

    #[test]
    fn a_vendor_messages_data_block_is_everything_between_func_and_crc() {
        // The whole point: the payload is opaque for a code nothing models, so
        // without this the body is unreachable.
        let msgs = sungrow().push_bytes(&with_crc("012001C803111A0002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, Payload::Opaque);
        assert!(msgs[0].register_bytes().is_empty());
        assert_eq!(msgs[0].data_block(), &hex("01C803111A0002")[..]);
    }

    #[test]
    fn a_data_block_is_never_out_of_bounds() {
        // Every shape, including the shortest message the wire allows and an
        // exception, which is the one case shorter than its own header rule.
        let mut t = sungrow();
        for body in ["0120", "018100", "01044DE20002", "0110000100020400010002"] {
            for m in t.push_bytes(&with_crc(body)) {
                let n = m.data_block().len();
                assert!(
                    n <= m.raw.len(),
                    "{body}: block {n} exceeds raw {}",
                    m.raw.len()
                );
            }
        }
    }

    #[test]
    fn declaring_a_modelled_code_leaves_its_length_rules_alone() {
        // 0x04 is modelled; declaring it must not demote it to a CRC search.
        let mut t = ModbusRtuStream::for_address(Some(1)).with_vendor_functions(&[0x04]);
        let msgs = t.push_bytes(&hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    // Declared vendor lengths, in the layouts the Sungrow line uses.

    const DISPATCH: VendorLength = VendorLength {
        function: 0x60,
        when: None,
        len: VendorLen::Counted {
            count_at: 6,
            overhead: 9,
        },
    };
    const BATTERY_REQUEST: VendorLength = VendorLength {
        function: 0x20,
        when: Some(Selector {
            offset: 4,
            value: 0x03,
        }),
        len: VendorLen::Fixed(11),
    };
    const BATTERY_RESPONSE: VendorLength = VendorLength {
        function: 0x20,
        when: Some(Selector {
            offset: 4,
            value: 0x04,
        }),
        len: VendorLen::Counted {
            count_at: 5,
            overhead: 8,
        },
    };

    /// A request with a response's selector.
    const BATTERY_READ: VendorLength = VendorLength {
        function: 0x20,
        when: Some(Selector {
            offset: 4,
            value: 0x04,
        }),
        len: VendorLen::Fixed(11),
    };

    fn sungrow_with_lengths() -> ModbusRtuStream {
        sungrow().with_vendor_lengths(&[DISPATCH, BATTERY_REQUEST, BATTERY_RESPONSE, BATTERY_READ])
    }

    /// A 19-byte dispatch whose first 18 bytes also pass as a message.
    fn dispatch_short_by_one() -> Vec<u8> {
        let msg = with_crc("0060123400010A01020304050607000064");
        assert!(
            crc16_modbus_valid(&msg[..18]),
            "the fixture is not ambiguous"
        );
        msg
    }

    fn raws(msgs: &[ModbusRtuMessage]) -> Vec<&[u8]> {
        msgs.iter().map(|m| m.raw.as_slice()).collect()
    }

    #[test]
    fn the_search_frames_a_self_validating_prefix_one_byte_short() {
        let msg = dispatch_short_by_one();
        let mut t = sungrow();
        let mut got = t.push_bytes(&msg);
        got.extend(t.finish().0);
        assert_eq!(raws(&got), [&msg[..18]]);
    }

    #[test]
    fn a_counted_rule_frames_the_whole_message() {
        let msg = dispatch_short_by_one();
        for chunks in every_chunking(&msg) {
            let mut t = sungrow_with_lengths();
            let got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            assert_eq!(raws(&got), [&msg[..]], "chunked as {chunks:02X?}");
            assert!(got[0].crc_valid);
        }
    }

    #[test]
    fn a_selector_chooses_between_a_codes_layouts() {
        // The request's sixth byte would read as a count of 0x11 under the
        // response layout.
        let request = with_crc("0120ABCD0311223344");
        let response = with_crc("0120ABCD0404CAFEF00D");
        let line = [&request[..], &response[..]].concat();
        for chunks in every_chunking(&line) {
            let mut t = sungrow_with_lengths();
            let got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            assert_eq!(raws(&got), [&request[..], &response[..]]);
        }
    }

    #[test]
    fn rules_sharing_a_selector_are_alternatives_tried_in_order() {
        // Read as a response, the request's sixth byte counts 0x11 bytes that
        // never come; the rule behind it is the request's layout.
        let request = with_crc("0120ABCD0411223344");
        let response = with_crc("0120ABCD0404CAFEF00D");
        let line = [&request[..], &response[..], &request[..]].concat();
        for chunks in every_chunking(&line) {
            let mut t = sungrow_with_lengths();
            let mut got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            got.extend(t.finish().0);
            assert_eq!(raws(&got), [&request[..], &response[..], &request[..]]);
        }
    }

    #[test]
    fn a_fixed_rule_needs_nothing_past_its_selector() {
        let mut t = ModbusRtuStream::for_address(None).with_vendor_lengths(&[BATTERY_REQUEST]);
        let request = with_crc("0120ABCD0311223344");
        assert_eq!(raws(&t.push_bytes(&request)), [&request[..]]);
    }

    #[test]
    fn a_crc_failure_at_the_declared_length_is_not_searched_past() {
        // The search would frame the 18-byte prefix, which still validates.
        let mut corrupt = dispatch_short_by_one();
        corrupt[18] ^= 0xFF;
        let follower = with_crc("0120ABCD0311223344");
        let line = [&corrupt[..], &follower[..]].concat();
        let mut t = sungrow_with_lengths();
        let mut got = t.push_bytes(&line);
        got.extend(t.finish().0);
        assert_eq!(raws(&got), [&follower[..]]);
    }

    #[test]
    fn a_code_whose_selectors_all_miss_falls_back_to_the_search() {
        let msg = with_crc("0120ABCD0711223344");
        let mut t = sungrow_with_lengths();
        assert_eq!(raws(&t.push_bytes(&msg)), [&msg[..]]);
    }

    #[test]
    fn a_code_without_rules_is_still_searched() {
        let first = with_crc("0165000200");
        let line = [&first[..], &with_crc("0165000201")].concat();
        let msgs = sungrow_with_lengths().push_bytes(&line);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].raw, first);
    }

    #[test]
    fn a_rule_leaves_a_modelled_code_alone() {
        let rule = VendorLength {
            function: 0x04,
            when: None,
            len: VendorLen::Fixed(11),
        };
        let mut t = ModbusRtuStream::for_address(Some(1)).with_vendor_lengths(&[rule]);
        let msgs = t.push_bytes(&hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    /// The dispatch's layout, and 0x65 declared with none.
    const DISPATCH_CATALOGUE: &str = r#"
[meta]
name = "x"
[meta.modbus.function_code.0x60]
name = "Dispatch"
lengths = [{ len = { count_at = 6, overhead = 9 } }]
[meta.modbus.function_code.0x65]
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "modbus_rtu"
allow_broadcast = true
"#;

    fn dispatch_catalogue() -> Catalog {
        Catalog::parse(DISPATCH_CATALOGUE).unwrap()
    }

    #[test]
    fn a_tunnel_inherits_the_catalogues_function_codes() {
        let catalog = dispatch_catalogue();
        let tunnel = catalog.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        let dispatch = dispatch_short_by_one();
        let bare = with_crc("0165000200");
        let line = [&dispatch[..], &bare[..]].concat();
        for chunks in every_chunking(&line) {
            let mut t = catalog.tunnel_stream(tunnel);
            let mut got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            got.extend(t.finish().0);
            assert_eq!(raws(&got), [&dispatch[..], &bare[..]]);
        }

        let mut t = ModbusRtuStream::new(tunnel);
        assert!(t.push_bytes(&dispatch).is_empty(), "no catalogue, no codes");
    }

    #[test]
    fn catalogue_and_builder_rules_are_unioned() {
        let catalog = dispatch_catalogue();
        let tunnel = catalog.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        let mut t = catalog
            .tunnel_stream(tunnel)
            .with_vendor_lengths(&[BATTERY_REQUEST]);
        let request = with_crc("0120ABCD0311223344");
        let dispatch = dispatch_short_by_one();
        let line = [&request[..], &dispatch[..]].concat();
        assert_eq!(raws(&t.push_bytes(&line)), [&request[..], &dispatch[..]]);
    }

    #[test]
    fn rtu_options_carry_the_catalogues_codes_and_rules() {
        let options = dispatch_catalogue().rtu_options();
        let expected = ModbusRtuOptions::default()
            .with_vendor_functions(&[0x60, 0x65])
            .with_vendor_lengths(&[DISPATCH]);
        assert_eq!(options, expected);
        assert_eq!(
            Catalog::parse("[meta]\nname = \"x\"\n")
                .unwrap()
                .rtu_options(),
            ModbusRtuOptions::default()
        );
    }

    #[test]
    fn rtu_rules_read_what_the_full_parse_reads() {
        for text in [DISPATCH_CATALOGUE, "[meta]\nname = \"x\"\n"] {
            let full = Catalog::parse(text).unwrap();
            let lean = crate::rtu_rules(text).unwrap();
            assert_eq!(lean.options, full.rtu_options());
            assert_eq!(lean.name, full.meta.name);
        }
    }

    /// The full parse drops the rule and frames 0x60 by CRC search; the lean
    /// read refuses, naming it as `validate` would.
    #[test]
    fn rtu_rules_refuse_a_rule_the_parser_would_drop() {
        let text =
            "[meta]\nname = \"x\"\n[meta.modbus.function_code.0x60]\nlengths = [{ len = { fixed = 9, count_at = 2 } }]\n";
        assert!(Catalog::parse(text).is_ok());
        match crate::rtu_rules(text) {
            Err(e @ crate::RtuRulesError::Rules(_)) => assert!(
                e.to_string()
                    .starts_with("meta.modbus.function_code.0x60.lengths[0]: "),
                "{e}"
            ),
            other => panic!("expected the rule refused, got {other:?}"),
        }
        assert!(matches!(
            crate::rtu_rules("[meta"),
            Err(crate::RtuRulesError::Toml(_))
        ));
    }

    /// The name is the one field besides the rules that `rtu_rules` returns, so
    /// a catalogue without one is refused as `validate` refuses it.
    #[test]
    fn rtu_rules_refuse_a_catalogue_without_a_name() {
        for (text, field) in [("", "meta"), ("[meta]\nversion = 1\n", "meta.name")] {
            let e = crate::rtu_rules(text).unwrap_err().to_string();
            assert!(e.starts_with(&format!("{field}: ")), "{e}");
        }
    }

    #[test]
    fn rtu_rules_refuse_a_name_that_is_not_a_string() {
        let e = crate::rtu_rules("[meta]\nname = 5\n")
            .unwrap_err()
            .to_string();
        assert_eq!(e, "meta.name: Catalog name must be a string");
    }

    #[test]
    fn a_tap_on_catalogue_options_frames_ruled_codes_by_rule_and_the_rest_by_search() {
        let options = dispatch_catalogue()
            .rtu_options()
            .allow_broadcast()
            .frame_any_function();
        let dispatch = dispatch_short_by_one();
        let declared_bare = with_crc("0165000200");
        let undeclared = with_crc("017701020304");
        let line = [&dispatch[..], &declared_bare[..], &undeclared[..]].concat();
        assert_eq!(
            framed(&options, &line),
            [dispatch, declared_bare, undeclared]
        );
    }

    #[test]
    fn options_built_by_their_setters_carry_every_field() {
        let options = ModbusRtuOptions::default()
            .with_device_address(Some(1))
            .with_crc_policy(CrcPolicy::Lenient)
            .with_vendor_functions(&[0x65])
            .allow_broadcast()
            .frame_any_function()
            .with_vendor_lengths(&[DISPATCH]);
        let expected = ModbusRtuOptions {
            device_address: Some(1),
            crc: CrcPolicy::Lenient,
            vendor_functions: vec![0x65],
            allow_broadcast: true,
            any_function: true,
            vendor_lengths: vec![DISPATCH],
        };
        assert_eq!(options, expected);

        let msg = dispatch_short_by_one();
        assert_eq!(framed(&options, &msg), [msg]);
    }

    // A tap's two needs: frame every code, and say where each message sat in
    // the input so a consumer can back-date the burst a sync releases.

    /// What a tap did before there was a builder for it. The two must be the
    /// same framer, byte for byte.
    fn all_codes() -> ModbusRtuStream {
        let all: [u8; 256] = std::array::from_fn(|i| i as u8);
        ModbusRtuStream::for_address(None)
            .with_vendor_functions(&all)
            .allow_broadcast()
    }

    fn any_code() -> ModbusRtuStream {
        ModbusRtuStream::for_address(None)
            .frame_any_function()
            .allow_broadcast()
    }

    /// A stretch of line carrying every shape a tap has to survive: modelled
    /// codes, the Sungrow vendor codes, one nothing has ever declared, a
    /// broadcast, and junk at both ends.
    fn mixed_line() -> Vec<u8> {
        let mut line = hex("FFFE");
        for body in [
            "01044DE20002",
            "01040401F40000",
            "012001C803111A0002",
            "0060000000050A000401BB03E808",
            "0165000200",
            "017701020304",
        ] {
            line.extend(with_crc(body));
        }
        line.extend(hex("FF"));
        line
    }

    /// The equivalence the builder is asked to preserve, at four read sizes.
    /// Messages compare whole, `end_offset` included, so this pins the offsets
    /// against the chunking as well.
    #[test]
    fn frame_any_function_matches_declaring_all_256_codes() {
        let line = mixed_line();
        for chunk in [1, 3, 64, line.len()] {
            let mut declared = all_codes();
            let mut any = any_code();
            let a: Vec<_> = line
                .chunks(chunk)
                .flat_map(|c| declared.push_bytes(c))
                .collect();
            let b: Vec<_> = line.chunks(chunk).flat_map(|c| any.push_bytes(c)).collect();
            assert!(!a.is_empty(), "{chunk}-byte reads framed nothing");
            assert_eq!(a, b, "{chunk}-byte reads");
            assert_eq!(declared.finish(), any.finish(), "{chunk}-byte reads");
        }
    }

    #[test]
    fn frame_any_function_frames_a_code_nobody_declared() {
        let msg = with_crc("017701020304");
        assert!(sungrow().push_bytes(&msg).is_empty(), "0x77 is undeclared");
        let msgs = any_code().push_bytes(&msg);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x77);
        assert_eq!(msgs[0].raw, msg);
    }

    #[test]
    fn frame_any_function_leaves_a_modelled_codes_length_rules_alone() {
        // The search takes the shortest CRC-valid prefix; the length table
        // still owns 0x04, so the whole request comes back.
        let msgs = ModbusRtuStream::for_address(Some(1))
            .frame_any_function()
            .push_bytes(&hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn end_offset_brackets_the_message_and_counts_the_junk_before_it() {
        let msg = with_crc("01044DE20002");
        let line = [hex("FFFF"), msg.clone(), hex("FF")].concat();
        let mut t = any_code();
        let msgs = t.push_bytes(&line);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].end_offset, 2 + msg.len() as u64);
        assert_eq!(msgs[0].end_offset - msgs[0].raw.len() as u64, 2);
        assert_eq!(t.bytes_fed(), line.len() as u64, "the trailing junk counts");
    }

    /// What the offsets are for: one read releases several messages, and each
    /// still says where it ended, so the caller can put the line rate to them.
    #[test]
    fn messages_released_by_one_read_still_carry_their_own_offsets() {
        let line = mixed_line();
        let mut t = any_code();
        let msgs = t.push_bytes(&line);

        let ends: Vec<u64> = msgs.iter().map(|m| m.end_offset).collect();
        assert!(ends.len() >= 5, "{ends:?}");
        assert!(ends.windows(2).all(|w| w[0] < w[1]), "{ends:?}");
        assert_eq!(t.bytes_fed(), line.len() as u64);
        assert!(ends.last().is_some_and(|&e| e <= t.bytes_fed()));
        for m in &msgs {
            let start = (m.end_offset - m.raw.len() as u64) as usize;
            assert_eq!(&line[start..start + m.raw.len()], &m.raw[..]);
        }
    }

    /// Offsets add no variance of their own: they say where the framer's own
    /// boundaries fell, so they are exactly as stable as the framing is.
    #[test]
    fn offsets_do_not_depend_on_how_the_reads_were_chunked() {
        let line = mixed_line();
        let ends = |chunk: usize| -> Vec<u64> {
            let mut t = any_code();
            line.chunks(chunk)
                .flat_map(|c| t.push_bytes(c))
                .map(|m| m.end_offset)
                .collect()
        };
        let baseline = ends(64);
        assert!(!baseline.is_empty());
        for chunk in [1, 3, 4096] {
            assert_eq!(ends(chunk), baseline, "{chunk}-byte reads");
        }
    }

    /// A desynced stream drops bytes off the head of the buffer. None may go
    /// missing from the count, or every offset after them is wrong.
    #[test]
    fn the_cursor_counts_bytes_the_framer_threw_away() {
        let msg = with_crc("01044DE20002");
        // A plausible address that starts nothing, at length, then the message.
        let mut line = vec![0x01u8; 600];
        line.extend_from_slice(&msg);

        let mut t = any_code();
        let msgs = t.push_bytes(&line);
        assert_eq!(t.bytes_fed(), line.len() as u64);
        for m in &msgs {
            let start = (m.end_offset - m.raw.len() as u64) as usize;
            assert_eq!(&line[start..start + m.raw.len()], &m.raw[..]);
        }
    }

    #[test]
    fn interpret_reports_the_cursor_unmoved() {
        let mut t = any_code();
        t.push_bytes(&hex("0104")); // half a message, still buffered
        let msg = t.interpret(&with_crc("01044DE20002")).expect("framed");
        assert_eq!(msg.end_offset, t.bytes_fed(), "nothing to back-date by");
        assert_eq!(t.bytes_fed(), 2);
    }

    #[test]
    fn finish_counts_the_residue_it_hands_back() {
        let mut t = any_code();
        t.push_bytes(&hex("0104"));
        let (msgs, residue) = t.finish();
        assert!(msgs.is_empty());
        assert_eq!(residue, hex("0104"));
        assert_eq!(t.bytes_fed(), 2, "the cursor does not go backwards");
    }

    fn framed(options: &ModbusRtuOptions, line: &[u8]) -> Vec<Vec<u8>> {
        options
            .stream()
            .push_bytes(line)
            .into_iter()
            .map(|m| m.raw)
            .collect()
    }

    #[test]
    fn any_function_frames_the_undeclared_and_keeps_the_length_rules() {
        let request = with_crc("01044DE20002");
        let response = with_crc("010404CAFEF00D");
        let vendor = with_crc("0165030000010001");
        let line = [&request[..], &response[..], &vendor[..]].concat();

        assert_eq!(
            framed(&ModbusRtuOptions::default(), &line),
            [request.clone(), response.clone()]
        );
        let any = ModbusRtuOptions {
            any_function: true,
            ..Default::default()
        };
        assert_eq!(framed(&any, &line), [request, response, vendor]);
    }

    #[test]
    fn tapped_also_frames_a_broadcast() {
        let request = with_crc("01044DE20002");
        let broadcast = with_crc("00600000000501");
        let line = [&request[..], &broadcast[..]].concat();

        assert_eq!(
            framed(&ModbusRtuOptions::default(), &line),
            std::slice::from_ref(&request)
        );
        assert_eq!(
            framed(&ModbusRtuOptions::tapped(), &line),
            [request, broadcast]
        );
    }

    /// Every way a line can arrive: byte by byte, split once at each point, and
    /// whole.
    fn every_chunking(line: &[u8]) -> Vec<Vec<Vec<u8>>> {
        let mut chunkings = vec![line.chunks(1).map(<[u8]>::to_vec).collect()];
        chunkings.extend((1..line.len()).map(|at| vec![line[..at].to_vec(), line[at..].to_vec()]));
        chunkings.push(vec![line.to_vec()]);
        chunkings
    }

    /// A single-register read response whose CRC, with the broadcast address
    /// behind it, also validates as an 8-byte read request — for a quantity no
    /// device may be asked for.
    fn assert_response_then_broadcast(response: &[u8], broadcast: &[u8]) {
        let line = [response, broadcast].concat();
        assert!(
            crc16_modbus_valid(&line[..8]),
            "the fixture is not ambiguous"
        );
        for chunks in every_chunking(&line) {
            let mut t = ModbusRtuOptions::tapped().stream();
            let got: Vec<_> = chunks.iter().flat_map(|c| t.push_bytes(c)).collect();
            let raws: Vec<_> = got.iter().map(|m| m.raw.as_slice()).collect();
            assert_eq!(raws, [response, broadcast], "chunked as {chunks:02X?}");
            assert_eq!(got[0].direction, Direction::Response);
        }
    }

    #[test]
    fn a_read_response_is_not_swallowed_by_the_broadcast_behind_it() {
        let response = with_crc("020402FFFF");
        assert_eq!(response, hex("020402FFFFFC80"));
        let dispatch = with_crc("0060000000050A000401BB03E806650000");
        assert_eq!(dispatch[17..], [0xFD, 0x38]);
        assert_response_then_broadcast(&response, &dispatch);
    }

    #[test]
    fn a_holding_read_response_keeps_the_write_broadcast_behind_it() {
        let response = with_crc("0103021450");
        assert_eq!(response, hex("0103021450B778"));
        assert_response_then_broadcast(&response, &with_crc("001000000001020001"));
    }

    #[test]
    fn a_request_beyond_the_spec_cap_is_not_framed_whatever_its_crc() {
        let mut t = strict(Some(1));
        assert!(t.push_bytes(&with_crc("01030000007E")).is_empty());
        assert!(t.interpret(&with_crc("01030000007E")).is_some());
    }

    #[test]
    fn the_catalogues_codes_and_rules_union_under_the_pickers_settings() {
        let picker = RtuSettings {
            device_address: Some(3),
            validate_crc: false,
            vendor_functions: vec![0x20],
            allow_broadcast: true,
            any_function: false,
        };
        let manual = ModbusRtuOptions::default()
            .with_device_address(Some(3))
            .with_crc_policy(CrcPolicy::Lenient)
            .allow_broadcast();

        assert_eq!(
            ModbusRtuOptions::from_settings(&picker, Some(&dispatch_catalogue())),
            manual
                .clone()
                .with_vendor_functions(&[0x60, 0x65, 0x20])
                .with_vendor_lengths(&[DISPATCH])
        );
        assert_eq!(
            ModbusRtuOptions::from_settings(&picker, None),
            manual.with_vendor_functions(&[0x20])
        );
    }

    #[test]
    fn stock_and_tapped_settings_are_the_stock_and_tapped_options() {
        assert_eq!(
            ModbusRtuOptions::from_settings(&RtuSettings::default(), None),
            ModbusRtuOptions::default()
        );
        assert_eq!(
            ModbusRtuOptions::from_settings(&RtuSettings::tapped(), None),
            ModbusRtuOptions::tapped()
        );
    }

    #[test]
    fn rtu_settings_keep_the_desktops_snake_case_shape_and_defaults() {
        let defaults: RtuSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults, RtuSettings::default());
        assert!(defaults.validate_crc);
        assert_eq!(
            serde_json::to_string(&RtuSettings::tapped()).unwrap(),
            r#"{"device_address":null,"validate_crc":true,"vendor_functions":[],"allow_broadcast":true,"any_function":true}"#
        );
    }
}
