//! Test Pattern: two endpoints proving a CAN link carries what it claims to.
//!
//! One end initiates and measures — drops, duplicates, ordering, latency — and
//! the other echoes. See `docs/test-pattern.md` for the wire contract.
//!
//! Both ends live here, as they do for [`crate::gvret`], so an initiator and a
//! responder cannot disagree about what a run means. [`Responder`] is the whole
//! reply side as a sans-io state machine: feed it a frame, transmit whatever it
//! hands back. A consumer supplies sockets, timers and a clock; nothing here
//! knows about any of them.
//!
//! # Why there are two message classes
//!
//! The framed messages — ping, latency, control, status — carry an 8-byte
//! header, which is what lets them share a bus and identify themselves.
//!
//! The **sweep** deliberately has no header, because the thing it tests is
//! length itself. A frame carrying a header cannot be shorter than 8 bytes, and
//! 8 is exactly where a payload length and a data length *code* are the same
//! number — so a header-carrying protocol is blind to the entire class of fault
//! where one is mistaken for the other. Sweep frames put the code in the
//! arbitration id instead and give the whole payload over to test bytes, which
//! makes all sixteen codes reachable, including zero.

use crate::dlc::dlc_to_len;

// ---------------------------------------------------------------------------
// Framed messages
// ---------------------------------------------------------------------------

/// Every framed message is exactly this long. The wire has no length field —
/// a CAN frame's own length is it — so a shorter payload is not a truncated
/// message, it is not one of these at all.
pub const HEADER_BYTES: usize = 8;

/// Message type, byte 0.
pub mod tag {
    pub const PING_REQUEST: u8 = 0x01;
    pub const PING_REPLY: u8 = 0x02;
    pub const THROUGHPUT: u8 = 0x03;
    pub const LATENCY_PROBE: u8 = 0x04;
    pub const LATENCY_REPLY: u8 = 0x05;
    pub const CONTROL: u8 = 0x06;
    pub const STATUS: u8 = 0x07;
}

/// Control command, byte 4 of a `CONTROL` message.
pub mod cmd {
    pub const START: u8 = 0x01;
    pub const STOP: u8 = 0x02;
    pub const SET_RATE: u8 = 0x03;
    pub const REQUEST_STATUS: u8 = 0x04;
    /// "Is anyone there?" — broadcast, and the only message a responder answers
    /// while it is idle.
    pub const HELLO: u8 = 0x05;
    /// The answer to [`HELLO`]. The high bit marks it as a reply so a second
    /// initiator listening on the bus cannot mistake it for another request.
    pub const HELLO_REPLY: u8 = 0x85;
}

/// Which counter a `STATUS` message carries, byte 4.
pub mod status_field {
    pub const RX_COUNT: u8 = 0x00;
    pub const TX_COUNT: u8 = 0x01;
    pub const DROPS: u8 = 0x02;
    pub const FPS: u8 = 0x03;
}

/// What a responder says it can do, in a [`cmd::HELLO_REPLY`].
pub mod capability {
    /// Answers CAN FD sweep codes, not just the classic ones.
    pub const FD: u8 = 1 << 0;
    /// Answers on the extended-id range as well as the standard one.
    pub const EXTENDED: u8 = 1 << 1;
}

/// Arbitration ids, standard range. A message's type decides its id, so a
/// receiver can filter the bus before parsing anything.
pub const ID_PING_REQUEST: u32 = 0x7F0;
pub const ID_PING_REPLY: u32 = 0x7F1;
pub const ID_THROUGHPUT_TX: u32 = 0x7F2;
pub const ID_THROUGHPUT_RX: u32 = 0x7F3;
pub const ID_LATENCY_PROBE: u32 = 0x7F4;
pub const ID_LATENCY_REPLY: u32 = 0x7F5;
pub const ID_CONTROL: u32 = 0x7F6;
pub const ID_STATUS: u32 = 0x7F7;

/// The same eight ids on a 29-bit id, for exercising extended addressing.
///
/// A standard id is `ID_BASE + n`; the extended one is this `+ n`. Both are
/// recognised, and [`extended_id`] converts.
pub const ID_EXTENDED_BASE: u32 = 0x1F00_07F0;
const ID_BASE: u32 = 0x7F0;

/// Sweep request ids: the low nibble is the data length code being tested.
pub const SWEEP_REQUEST_BASE: u32 = 0x7E0;
/// Sweep echo ids, mirroring [`SWEEP_REQUEST_BASE`].
pub const SWEEP_ECHO_BASE: u32 = 0x7C0;

/// The extended-id form of a framed Test Pattern id, or `None` for any other id.
pub fn extended_id(arb_id: u32) -> Option<u32> {
    (ID_BASE..=ID_STATUS)
        .contains(&arb_id)
        .then(|| ID_EXTENDED_BASE + (arb_id - ID_BASE))
}

/// Is this frame any part of the protocol — framed or swept, on its id width?
///
/// A receiver uses this to decide what to hand to a decoder at all, so it is
/// deliberately wider than any single message class. The 11-bit ids are 11-bit
/// only: an extended frame that is numerically `0x7E5` is someone else's.
pub fn is_test_pattern_frame(arb_id: u32, extended: bool) -> bool {
    if extended {
        (ID_EXTENDED_BASE..=ID_EXTENDED_BASE + 7).contains(&arb_id)
    } else {
        (ID_BASE..=ID_STATUS).contains(&arb_id) || sweep_code(arb_id).is_some()
    }
}

/// The length code a sweep id names, and whether it is an echo rather than a
/// request. `None` for anything that is not a sweep id.
pub fn sweep_code(arb_id: u32) -> Option<(u8, bool)> {
    match arb_id {
        id if (SWEEP_REQUEST_BASE..SWEEP_REQUEST_BASE + 16).contains(&id) => {
            Some(((id - SWEEP_REQUEST_BASE) as u8, false))
        }
        id if (SWEEP_ECHO_BASE..SWEEP_ECHO_BASE + 16).contains(&id) => {
            Some(((id - SWEEP_ECHO_BASE) as u8, true))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Byte 1 of a framed message.
///
/// `run` is what makes two initiators on one bus safe. It occupies the four
/// bits the protocol reserved and never used: a receiver drops any framed
/// message whose run tag is not its own, so one run's sequence numbers cannot
/// be counted as another's drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// The payload rode a byte stream rather than a CAN frame.
    pub bytes_mode: bool,
    /// Which interface of a multi-bus endpoint, 0–7.
    pub interface: u8,
    /// Which run this frame belongs to, 0–15.
    pub run: u8,
}

impl Flags {
    /// Flags for a run on one interface.
    pub fn new(interface: u8, run: u8) -> Self {
        Self {
            bytes_mode: false,
            interface: interface & 0x07,
            run: run & 0x0F,
        }
    }

    fn encode(self) -> u8 {
        u8::from(self.bytes_mode) | ((self.interface & 0x07) << 1) | ((self.run & 0x0F) << 4)
    }

    fn decode(b: u8) -> Self {
        Self {
            bytes_mode: b & 1 != 0,
            interface: (b >> 1) & 0x07,
            run: (b >> 4) & 0x0F,
        }
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A control command, and whatever it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Begin a run: this mode, under this run tag.
    Start {
        mode: u8,
        run: u8,
    },
    Stop,
    SetRate {
        fps: u16,
    },
    RequestStatus,
    Hello,
    HelloReply {
        capabilities: u8,
        bus: u8,
    },
    /// A command this build does not know. Carried rather than dropped so a
    /// newer peer's traffic is visibly unhandled instead of silently ignored.
    Unknown {
        code: u8,
        body: [u8; 3],
    },
}

/// One framed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    PingRequest {
        seq: u16,
    },
    PingReply {
        seq: u16,
    },
    Throughput {
        seq: u16,
        pattern: u8,
    },
    /// `ts_us` is the low 32 bits of the sender's microsecond clock. It wraps
    /// every 71m34s; an initiator that keeps its own copy need never read it
    /// back, and one that does must difference it modulo 2³².
    LatencyProbe {
        seq: u16,
        ts_us: u32,
    },
    LatencyReply {
        seq: u16,
        ts_us: u32,
    },
    Control(Command),
    Status {
        field: u8,
        value: u32,
    },
}

/// Payload fill pattern ids, for [`Message::Throughput`].
pub mod pattern {
    pub const SEQUENTIAL: u8 = 0x00;
    pub const WALKING_BIT: u8 = 0x01;
    pub const COUNTER: u8 = 0x02;
    pub const ALTERNATING: u8 = 0x03;
    pub const NONE: u8 = 0xFF;
}

impl Message {
    /// The arbitration id this message is sent on.
    pub fn arb_id(&self) -> u32 {
        match self {
            Message::PingRequest { .. } => ID_PING_REQUEST,
            Message::PingReply { .. } => ID_PING_REPLY,
            Message::Throughput { .. } => ID_THROUGHPUT_TX,
            Message::LatencyProbe { .. } => ID_LATENCY_PROBE,
            Message::LatencyReply { .. } => ID_LATENCY_REPLY,
            Message::Control(_) => ID_CONTROL,
            Message::Status { .. } => ID_STATUS,
        }
    }

    fn parts(&self) -> (u8, u16, [u8; 4]) {
        match *self {
            Message::PingRequest { seq } => (tag::PING_REQUEST, seq, [0; 4]),
            Message::PingReply { seq } => (tag::PING_REPLY, seq, [0; 4]),
            Message::Throughput { seq, pattern } => (tag::THROUGHPUT, seq, [pattern, 0, 0, 0]),
            Message::LatencyProbe { seq, ts_us } => (tag::LATENCY_PROBE, seq, ts_us.to_be_bytes()),
            Message::LatencyReply { seq, ts_us } => (tag::LATENCY_REPLY, seq, ts_us.to_be_bytes()),
            // Control and status frames carry no sequence; the field is zero
            // rather than reused, so a receiver's tracker never sees them.
            Message::Control(c) => (tag::CONTROL, 0, command_body(c)),
            Message::Status { field, value } => (
                tag::STATUS,
                0,
                [field, (value >> 16) as u8, (value >> 8) as u8, value as u8],
            ),
        }
    }
}

fn command_body(c: Command) -> [u8; 4] {
    match c {
        Command::Start { mode, run } => [cmd::START, mode, run & 0x0F, 0],
        Command::Stop => [cmd::STOP, 0, 0, 0],
        Command::SetRate { fps } => {
            let [hi, lo] = fps.to_be_bytes();
            [cmd::SET_RATE, hi, lo, 0]
        }
        Command::RequestStatus => [cmd::REQUEST_STATUS, 0, 0, 0],
        Command::Hello => [cmd::HELLO, 0, 0, 0],
        Command::HelloReply { capabilities, bus } => [cmd::HELLO_REPLY, capabilities, bus, 0],
        Command::Unknown { code, body } => [code, body[0], body[1], body[2]],
    }
}

fn parse_command(body: [u8; 4]) -> Command {
    let [code, a, b, _] = body;
    match code {
        cmd::START => Command::Start {
            mode: a,
            run: b & 0x0F,
        },
        cmd::STOP => Command::Stop,
        cmd::SET_RATE => Command::SetRate {
            fps: u16::from_be_bytes([a, b]),
        },
        cmd::REQUEST_STATUS => Command::RequestStatus,
        cmd::HELLO => Command::Hello,
        cmd::HELLO_REPLY => Command::HelloReply {
            capabilities: a,
            bus: b,
        },
        _ => Command::Unknown {
            code,
            body: [body[1], body[2], body[3]],
        },
    }
}

/// Encode a framed message.
pub fn encode(msg: Message, flags: Flags) -> [u8; HEADER_BYTES] {
    let (tag, seq, extra) = msg.parts();
    let [hi, lo] = seq.to_be_bytes();
    [
        tag,
        flags.encode(),
        hi,
        lo,
        extra[0],
        extra[1],
        extra[2],
        extra[3],
    ]
}

/// Decode a framed message, or `None` if `data` is not one.
///
/// Bytes past the eighth are ignored: a CAN FD frame carrying a framed message
/// pads out to its length code, and the padding is not part of the message.
pub fn decode(data: &[u8]) -> Option<(Message, Flags)> {
    if data.len() < HEADER_BYTES {
        return None;
    }
    let flags = Flags::decode(data[1]);
    let seq = u16::from_be_bytes([data[2], data[3]]);
    let extra = [data[4], data[5], data[6], data[7]];
    let ts = || u32::from_be_bytes(extra);

    let msg = match data[0] {
        tag::PING_REQUEST => Message::PingRequest { seq },
        tag::PING_REPLY => Message::PingReply { seq },
        tag::THROUGHPUT => Message::Throughput {
            seq,
            pattern: extra[0],
        },
        tag::LATENCY_PROBE => Message::LatencyProbe { seq, ts_us: ts() },
        tag::LATENCY_REPLY => Message::LatencyReply { seq, ts_us: ts() },
        tag::CONTROL => Message::Control(parse_command(extra)),
        tag::STATUS => Message::Status {
            field: extra[0],
            value: u32::from_be_bytes([0, extra[1], extra[2], extra[3]]),
        },
        _ => return None,
    };
    Some((msg, flags))
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// Byte `i` of the sweep payload for length code `code`.
///
/// Varies with both the position and the code, so a truncation, a byte repeated
/// by a stuck buffer, and a frame answered under the wrong code are all visible
/// in the echo rather than all looking like zeros.
fn sweep_byte(code: u8, i: usize) -> u8 {
    (i as u8).wrapping_mul(0x1F) ^ code.wrapping_mul(0x55)
}

/// The payload a sweep request for `code` carries: exactly the length that code
/// names, filled deterministically so both ends agree without negotiating.
pub fn sweep_payload(code: u8, fd: bool) -> Vec<u8> {
    let code = code & 0x0F;
    (0..dlc_to_len(code, fd))
        .map(|i| sweep_byte(code, i))
        .collect()
}

/// The length codes a sweep covers.
///
/// Classic CAN stops at 8 — codes above it are legal on the wire and still mean
/// 8 bytes, so sweeping them would test the same length nine times. CAN FD
/// covers all sixteen.
pub fn sweep_codes(fd: bool) -> impl Iterator<Item = u8> {
    0..=if fd { 15 } else { 8 }
}

/// Does an echo match what a request of this code should have carried?
///
/// The comparison is against the payload the *code* names rather than against
/// what was sent, which is the point: an endpoint that answered with a
/// different length has failed even if every byte it did send was right.
pub fn sweep_echo_matches(code: u8, fd: bool, echoed: &[u8]) -> bool {
    echoed == sweep_payload(code, fd)
}

// ---------------------------------------------------------------------------
// Sequence tracking
// ---------------------------------------------------------------------------

/// What a stream of sequence numbers says about the link under it.
///
/// The rules are the protocol's, not an implementation's, which is why this is
/// here: two ends comparing counters have to have counted the same way.
#[derive(Debug)]
pub struct SequenceTracker {
    /// `None` until the first frame. A tracker that assumed zero would count
    /// everything before the first sequence number it saw as dropped, so a
    /// responder joining a run already in progress would report a broken link.
    expected: Option<u16>,
    seen: Vec<u64>,
    pub rx_count: u64,
    pub drops: u64,
    pub duplicates: u64,
    pub out_of_order: u64,
    pub gaps: Vec<(u16, u16)>,
}

/// A backwards jump larger than half the sequence space is the counter
/// wrapping, not sixty thousand frames arriving late.
const WRAP_THRESHOLD: u16 = 32768;

/// One bit per sequence number, 65536 of them.
const SEEN_WORDS: usize = 1024;

impl Default for SequenceTracker {
    /// Written out rather than derived: a derived one would leave `seen` empty,
    /// and `track` indexes it on the first frame.
    fn default() -> Self {
        Self {
            expected: None,
            seen: vec![0; SEEN_WORDS],
            rx_count: 0,
            drops: 0,
            duplicates: 0,
            out_of_order: 0,
            gaps: Vec::new(),
        }
    }
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one received sequence number.
    pub fn track(&mut self, seq: u16) {
        self.rx_count += 1;

        if self.mark_seen(seq) {
            self.duplicates += 1;
        }

        let Some(expected) = self.expected else {
            // The first frame defines where the stream starts.
            self.expected = Some(seq.wrapping_add(1));
            return;
        };

        if seq == expected {
            self.expected = Some(expected.wrapping_add(1));
            return;
        }

        let ahead = seq.wrapping_sub(expected);
        if ahead < WRAP_THRESHOLD {
            // A gap: everything between expected and seq never arrived.
            self.drops += u64::from(ahead);
            self.gaps.push((expected, seq));
            self.expected = Some(seq.wrapping_add(1));
        } else {
            // Behind what we expected — a frame that overtook another, or one
            // this tracker already counted as dropped.
            self.out_of_order += 1;
        }
    }

    /// Set `seq`'s bit, returning whether it was already set.
    ///
    /// A 64 Kbit bitmap rather than a set: it is 8 KiB, allocated once, and a
    /// long run cannot grow it. The Python this replaces cleared a `set` at
    /// 70,000 entries, which silently stopped detecting duplicates thereafter.
    fn mark_seen(&mut self, seq: u16) -> bool {
        let (word, bit) = (usize::from(seq) / 64, usize::from(seq) % 64);
        let was = self.seen[word] & (1 << bit) != 0;
        self.seen[word] |= 1 << bit;
        was
    }
}

// ---------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------

/// Round-trip times over a run, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LatencyStats {
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub count: u64,
}

/// Collects round-trip samples and reduces them to [`LatencyStats`].
#[derive(Debug, Default)]
pub struct Latencies {
    samples: Vec<u64>,
}

impl Latencies {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, rtt_us: u64) {
        self.samples.push(rtt_us);
    }

    /// `None` until something has been recorded.
    pub fn stats(&self) -> Option<LatencyStats> {
        if self.samples.is_empty() {
            return None;
        }
        let mut s = self.samples.clone();
        s.sort_unstable();
        let n = s.len();
        // Nearest-rank: the p-th percentile is the ceil(p·n)-th sample. Scaling
        // by n and truncating instead reports the sample *below* the one asked
        // for, which understates a tail — the opposite of what a tail is for.
        let rank = |p: u64| s[(((n as u64 * p).div_ceil(100) as usize).max(1) - 1).min(n - 1)];
        Some(LatencyStats {
            min_us: s[0],
            max_us: s[n - 1],
            mean_us: s.iter().sum::<u64>() / n as u64,
            p50_us: rank(50),
            p95_us: rank(95),
            p99_us: rank(99),
            count: n as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// The responder
// ---------------------------------------------------------------------------

/// A frame a responder wants put on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub arb_id: u32,
    pub extended: bool,
    pub fd: bool,
    pub data: Vec<u8>,
}

/// The reply half of the protocol, as a state machine.
///
/// Feed it every Test Pattern frame that arrives; transmit what it returns.
/// It answers `Hello` while idle, adopts a run on `Start`, echoes sweeps and
/// pings while that run is live, and reports its counters on request.
///
/// Returns a `Vec` rather than an `Option` because a status request is answered
/// by four frames, one per counter. An empty `Vec` does not allocate, so the
/// common case — a frame needing no reply — costs nothing.
#[derive(Debug)]
pub struct Responder {
    capabilities: u8,
    bus: u8,
    run: Option<u8>,
    started_us: u64,
    pub tx_count: u64,
    pub sequence: SequenceTracker,
}

impl Responder {
    /// `capabilities` is a mask from [`capability`]; `bus` is the interface
    /// this responder answers on, reported to whoever says hello.
    pub fn new(capabilities: u8, bus: u8) -> Self {
        Self {
            capabilities,
            bus,
            run: None,
            started_us: 0,
            tx_count: 0,
            sequence: SequenceTracker::new(),
        }
    }

    /// The run this responder is bound to, if any.
    pub fn run(&self) -> Option<u8> {
        self.run
    }

    fn fd(&self) -> bool {
        self.capabilities & capability::FD != 0
    }

    /// Handle one received frame.
    ///
    /// `now_us` is the caller's clock, used only to derive a frame rate for a
    /// status report — nothing here needs it to be any particular epoch.
    pub fn on_frame(
        &mut self,
        arb_id: u32,
        extended: bool,
        fd: bool,
        data: &[u8],
        now_us: u64,
    ) -> Vec<Reply> {
        if !is_test_pattern_frame(arb_id, extended) {
            return Vec::new();
        }
        // A sweep frame carries no header; its id is the whole of its meaning.
        if let Some((code, is_echo)) = sweep_code(arb_id) {
            // An echo is another responder's, or our own coming back on a
            // loopback. Either way it is not ours to answer.
            if is_echo || self.run.is_none() {
                return Vec::new();
            }
            self.sequence.rx_count += 1;
            self.tx_count += 1;
            return vec![Reply {
                arb_id: SWEEP_ECHO_BASE + u32::from(code),
                extended,
                fd,
                // Echoed verbatim: what the initiator compares against is what
                // this end actually received, not what it thinks it should have.
                data: data.to_vec(),
            }];
        }

        let Some((msg, flags)) = decode(data) else {
            return Vec::new();
        };

        if let Message::Control(c) = msg {
            return self.on_control(c, flags, extended, fd, now_us);
        }

        // Everything else belongs to a run, and only to ours.
        if self.run != Some(flags.run) {
            return Vec::new();
        }

        // Everything the initiator numbered is counted, answered or not.
        if let Message::PingRequest { seq }
        | Message::LatencyProbe { seq, .. }
        | Message::Throughput { seq, .. } = msg
        {
            self.sequence.track(seq);
        }

        // Throughput is one-way by definition, so it is the one that is counted
        // and not answered.
        let reply = match msg {
            Message::PingRequest { seq } => Some(Message::PingReply { seq }),
            // The probe's own timestamp goes back untouched: the initiator
            // measures against its own clock, and reading this one would make
            // the result depend on two clocks agreeing.
            Message::LatencyProbe { seq, ts_us } => Some(Message::LatencyReply { seq, ts_us }),
            _ => None,
        };

        reply
            .into_iter()
            .map(|m| self.frame(m, flags, extended, fd))
            .collect()
    }

    fn on_control(
        &mut self,
        c: Command,
        flags: Flags,
        extended: bool,
        fd: bool,
        now_us: u64,
    ) -> Vec<Reply> {
        match c {
            Command::Hello => vec![self.frame(
                Message::Control(Command::HelloReply {
                    capabilities: self.capabilities,
                    bus: self.bus,
                }),
                flags,
                extended,
                fd,
            )],
            Command::Start { run, .. } => {
                self.run = Some(run);
                self.started_us = now_us;
                self.tx_count = 0;
                self.sequence = SequenceTracker::new();
                Vec::new()
            }
            Command::Stop => {
                self.run = None;
                Vec::new()
            }
            Command::RequestStatus => {
                let elapsed = now_us.saturating_sub(self.started_us);
                let fps = self
                    .sequence
                    .rx_count
                    .checked_mul(1_000_000)
                    .and_then(|f| f.checked_div(elapsed))
                    .unwrap_or(0);
                [
                    (status_field::RX_COUNT, self.sequence.rx_count),
                    (status_field::TX_COUNT, self.tx_count),
                    (status_field::DROPS, self.sequence.drops),
                    (status_field::FPS, fps),
                ]
                .into_iter()
                .map(|(field, value)| {
                    self.frame(
                        Message::Status {
                            // A counter is 24 bits on this wire; a longer run
                            // saturates rather than wrapping to a small number
                            // that reads as success. Clamped while still 64 bits
                            // wide, because narrowing first wraps past 2³² and
                            // leaves nothing for this to clamp.
                            value: value.min(0x00FF_FFFF) as u32,
                            field,
                        },
                        flags,
                        extended,
                        fd,
                    )
                })
                .collect()
            }
            _ => Vec::new(),
        }
    }

    /// Build a reply frame, matching the request's id width and frame type so a
    /// run testing extended ids or CAN FD is answered in kind.
    fn frame(&mut self, msg: Message, flags: Flags, extended: bool, fd: bool) -> Reply {
        self.tx_count += 1;
        let arb_id = msg.arb_id();
        let mut data = encode(msg, flags).to_vec();
        // An FD frame must carry a whole length code's worth of bytes.
        if fd && self.fd() {
            data.resize(dlc_to_len(crate::len_to_dlc(data.len()), true), 0);
        }
        Reply {
            arb_id: if extended {
                extended_id(arb_id).expect("a framed message has a framed id")
            } else {
                arb_id
            },
            extended,
            fd: fd && self.fd(),
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: u8 = 0xA;

    fn flags() -> Flags {
        Flags::new(2, RUN)
    }

    // --- framed messages ---------------------------------------------------

    #[test]
    fn every_message_round_trips() {
        for msg in [
            Message::PingRequest { seq: 0x1234 },
            Message::PingReply { seq: 0xFFFF },
            Message::Throughput {
                seq: 7,
                pattern: pattern::WALKING_BIT,
            },
            Message::LatencyProbe {
                seq: 1,
                ts_us: 0xDEAD_BEEF,
            },
            Message::LatencyReply {
                seq: 1,
                ts_us: 0xDEAD_BEEF,
            },
            Message::Control(Command::Start { mode: 3, run: RUN }),
            Message::Control(Command::Stop),
            Message::Control(Command::SetRate { fps: 1000 }),
            Message::Control(Command::RequestStatus),
            Message::Control(Command::Hello),
            Message::Control(Command::HelloReply {
                capabilities: capability::FD | capability::EXTENDED,
                bus: 1,
            }),
            Message::Status {
                field: status_field::DROPS,
                value: 0x00FF_FFFF,
            },
        ] {
            let wire = encode(msg, flags());
            assert_eq!(wire.len(), HEADER_BYTES, "{msg:?}");
            assert_eq!(decode(&wire), Some((msg, flags())), "{msg:?}");
        }
    }

    /// The run tag is what keeps two initiators on one bus apart, so it has to
    /// survive the round trip alongside the interface index it shares a byte
    /// with.
    #[test]
    fn flags_carry_the_run_tag_and_the_interface() {
        for run in 0..16u8 {
            for interface in 0..8u8 {
                let f = Flags::new(interface, run);
                let (_, back) = decode(&encode(Message::PingRequest { seq: 0 }, f)).unwrap();
                assert_eq!(back, f, "run {run} interface {interface}");
                assert_eq!(back.run, run);
                assert_eq!(back.interface, interface);
                assert!(!back.bytes_mode);
            }
        }
    }

    #[test]
    fn a_short_payload_is_not_a_message() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[tag::PING_REQUEST; 7]).is_none());
    }

    /// An FD frame pads to its length code, and the padding is not part of the
    /// message.
    #[test]
    fn padding_past_the_header_is_ignored() {
        let mut wire = encode(Message::PingRequest { seq: 9 }, flags()).to_vec();
        wire.resize(64, 0);
        assert_eq!(
            decode(&wire),
            Some((Message::PingRequest { seq: 9 }, flags()))
        );
    }

    #[test]
    fn an_unknown_command_is_carried_rather_than_dropped() {
        let wire = encode(
            Message::Control(Command::Unknown {
                code: 0x42,
                body: [1, 2, 3],
            }),
            flags(),
        );
        assert_eq!(
            decode(&wire).unwrap().0,
            Message::Control(Command::Unknown {
                code: 0x42,
                body: [1, 2, 3]
            })
        );
    }

    #[test]
    fn each_message_has_its_own_id() {
        let ids: Vec<u32> = [
            Message::PingRequest { seq: 0 },
            Message::PingReply { seq: 0 },
            Message::Throughput { seq: 0, pattern: 0 },
            Message::LatencyProbe { seq: 0, ts_us: 0 },
            Message::LatencyReply { seq: 0, ts_us: 0 },
            Message::Control(Command::Stop),
            Message::Status { field: 0, value: 0 },
        ]
        .iter()
        .map(Message::arb_id)
        .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "ids collide: {ids:x?}");
        assert!(ids.iter().all(|id| is_test_pattern_frame(*id, false)));
    }

    /// The extended range has to be recognised, or a run that asks for 29-bit
    /// ids sends frames nothing will answer.
    #[test]
    fn both_id_widths_are_recognised() {
        for id in ID_PING_REQUEST..=ID_STATUS {
            assert!(is_test_pattern_frame(id, false), "{id:#x}");
            let ext = extended_id(id).unwrap();
            assert!(is_test_pattern_frame(ext, true), "{ext:#x}");
            assert_eq!(ext & 0x1FFF_FFFF, ext, "must fit a 29-bit id");
        }
        assert!(!is_test_pattern_frame(0x7EF + 0x11, false));
        assert!(!is_test_pattern_frame(0x123, false));
    }

    #[test]
    fn an_extended_id_in_the_standard_ranges_is_not_ours() {
        for id in [
            ID_PING_REQUEST,
            ID_STATUS,
            SWEEP_REQUEST_BASE + 5,
            SWEEP_ECHO_BASE,
        ] {
            assert!(!is_test_pattern_frame(id, true), "{id:#x}");
        }
        assert!(!is_test_pattern_frame(ID_EXTENDED_BASE, false));
    }

    #[test]
    fn only_a_framed_id_has_an_extended_form() {
        for id in [SWEEP_ECHO_BASE, SWEEP_REQUEST_BASE + 0xF, ID_STATUS + 1, 0] {
            assert_eq!(extended_id(id), None, "{id:#x}");
        }
    }

    // --- the sweep ---------------------------------------------------------

    #[test]
    fn a_sweep_id_names_its_length_code() {
        for code in 0..16u8 {
            assert_eq!(
                sweep_code(SWEEP_REQUEST_BASE + u32::from(code)),
                Some((code, false))
            );
            assert_eq!(
                sweep_code(SWEEP_ECHO_BASE + u32::from(code)),
                Some((code, true))
            );
        }
        assert_eq!(sweep_code(ID_PING_REQUEST), None);
        assert_eq!(sweep_code(SWEEP_REQUEST_BASE - 1), None);
        assert_eq!(sweep_code(SWEEP_REQUEST_BASE + 16), None);
    }

    /// The whole point: every code carries exactly the length it names, so a
    /// codec that confuses a length for a code fails at a nameable byte count.
    #[test]
    fn a_sweep_payload_is_exactly_the_length_its_code_names() {
        for code in sweep_codes(true) {
            assert_eq!(
                sweep_payload(code, true).len(),
                dlc_to_len(code, true),
                "code {code}"
            );
        }
        assert_eq!(sweep_payload(0, false).len(), 0, "length zero is reachable");
        assert_eq!(sweep_payload(15, true).len(), 64);
    }

    #[test]
    fn a_classic_sweep_stops_at_eight() {
        let codes: Vec<u8> = sweep_codes(false).collect();
        assert_eq!(codes, (0..=8).collect::<Vec<u8>>());
        assert_eq!(sweep_codes(true).count(), 16);
    }

    /// Two codes must not produce the same bytes, or an endpoint answering the
    /// wrong code would pass.
    #[test]
    fn sweep_payloads_differ_between_codes() {
        for a in sweep_codes(true) {
            for b in sweep_codes(true) {
                let (pa, pb) = (sweep_payload(a, true), sweep_payload(b, true));
                if a != b && pa.len() == pb.len() && !pa.is_empty() {
                    assert_ne!(pa, pb, "codes {a} and {b}");
                }
            }
        }
    }

    #[test]
    fn an_echo_is_checked_against_the_code_not_against_what_was_sent() {
        assert!(sweep_echo_matches(13, true, &sweep_payload(13, true)));
        // Right bytes, wrong length — an endpoint that truncated.
        let mut short = sweep_payload(13, true);
        short.pop();
        assert!(!sweep_echo_matches(13, true, &short));
        // Right length, wrong bytes.
        let mut wrong = sweep_payload(13, true);
        wrong[0] ^= 0xFF;
        assert!(!sweep_echo_matches(13, true, &wrong));
    }

    // --- sequence tracking -------------------------------------------------

    #[test]
    fn a_clean_stream_reports_nothing_wrong() {
        let mut t = SequenceTracker::new();
        for seq in 0..1000u16 {
            t.track(seq);
        }
        assert_eq!(t.rx_count, 1000);
        assert_eq!((t.drops, t.duplicates, t.out_of_order), (0, 0, 0));
        assert!(t.gaps.is_empty());
    }

    #[test]
    fn a_gap_is_counted_and_named() {
        let mut t = SequenceTracker::new();
        for seq in [0u16, 1, 5, 6] {
            t.track(seq);
        }
        assert_eq!(t.drops, 3, "2, 3 and 4 never arrived");
        assert_eq!(t.gaps, vec![(2, 5)]);
        assert_eq!(t.rx_count, 4);
    }

    /// The one the old tracker could not see at all: it had no memory of what
    /// it had received, so `duplicates` was always zero and every pass
    /// predicate testing it was vacuous.
    #[test]
    fn a_repeated_sequence_number_is_a_duplicate() {
        let mut t = SequenceTracker::new();
        for seq in [0u16, 1, 2, 1, 3] {
            t.track(seq);
        }
        assert_eq!(t.duplicates, 1);
        assert_eq!(t.rx_count, 5);
    }

    #[test]
    fn a_late_frame_is_out_of_order_not_a_drop() {
        let mut t = SequenceTracker::new();
        for seq in [0u16, 1, 3, 2, 4] {
            t.track(seq);
        }
        assert_eq!(t.out_of_order, 1);
        assert_eq!(t.drops, 1, "2 was counted missing before it arrived");
    }

    /// A responder that joins a run already in progress has missed nothing —
    /// it was not listening. Assuming a stream starts at zero would report
    /// every frame before the first one it saw as a drop.
    #[test]
    fn a_tracker_starts_wherever_the_stream_does() {
        let mut t = SequenceTracker::new();
        for seq in 5000..5010u16 {
            t.track(seq);
        }
        assert_eq!((t.drops, t.out_of_order), (0, 0));
        assert_eq!(t.rx_count, 10);
    }

    /// The counter wraps every 65,536 frames, and a run longer than that must
    /// not report sixty thousand drops when it does.
    #[test]
    fn the_sequence_counter_wraps_without_inventing_drops() {
        let mut t = SequenceTracker::new();
        for seq in (65530..=65535u16).chain(0..=5) {
            t.track(seq);
        }
        assert_eq!(t.drops, 0, "the wrap is not a gap");
        assert_eq!(t.out_of_order, 0);
        assert_eq!(t.rx_count, 12);
    }

    /// Duplicate detection must not degrade over a long run — the Python this
    /// replaces cleared its set at 70,000 entries and silently stopped
    /// detecting them.
    #[test]
    fn duplicate_detection_survives_a_full_sequence_space() {
        let mut t = SequenceTracker::new();
        for seq in 0..=65535u16 {
            t.track(seq);
        }
        assert_eq!(t.duplicates, 0);
        t.track(40_000);
        assert_eq!(t.duplicates, 1, "still remembered after 65,536 frames");
    }

    /// `Default` is public, so it has to produce a tracker that works. A derived
    /// one leaves the bitmap unallocated and the first frame panics.
    #[test]
    fn a_default_tracker_tracks() {
        let mut t = SequenceTracker::default();
        t.track(7);
        t.track(7);
        assert_eq!((t.rx_count, t.duplicates), (2, 1));
    }

    // --- latency -----------------------------------------------------------

    #[test]
    fn latency_is_none_until_something_is_recorded() {
        assert_eq!(Latencies::new().stats(), None);
    }

    /// Nearest-rank percentiles: the p99 of a hundred samples is the largest,
    /// not the second largest. Scaling and truncating reports the sample below
    /// the one asked for, which understates exactly the tail a percentile is
    /// for.
    #[test]
    fn percentiles_do_not_understate_the_tail() {
        let mut l = Latencies::new();
        for us in 1..=100u64 {
            l.record(us);
        }
        let s = l.stats().expect("stats");
        assert_eq!((s.min_us, s.max_us, s.count), (1, 100, 100));
        assert_eq!(s.mean_us, 50);
        assert_eq!(s.p50_us, 50);
        assert_eq!(s.p95_us, 95);
        assert_eq!(s.p99_us, 99);
    }

    #[test]
    fn a_single_sample_is_every_percentile() {
        let mut l = Latencies::new();
        l.record(42);
        let s = l.stats().expect("stats");
        assert_eq!(
            (s.min_us, s.max_us, s.p50_us, s.p95_us, s.p99_us),
            (42, 42, 42, 42, 42)
        );
    }

    // --- the responder -----------------------------------------------------

    fn started() -> Responder {
        let mut r = Responder::new(capability::FD | capability::EXTENDED, 1);
        r.on_frame(
            ID_CONTROL,
            false,
            false,
            &encode(
                Message::Control(Command::Start { mode: 0, run: RUN }),
                flags(),
            ),
            0,
        );
        assert_eq!(r.run(), Some(RUN));
        r
    }

    fn feed(r: &mut Responder, msg: Message) -> Vec<Reply> {
        r.on_frame(msg.arb_id(), false, false, &encode(msg, flags()), 1_000_000)
    }

    #[test]
    fn a_ping_is_answered_with_its_own_sequence_number() {
        let mut r = started();
        let out = feed(&mut r, Message::PingRequest { seq: 77 });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].arb_id, ID_PING_REPLY);
        assert_eq!(
            decode(&out[0].data).unwrap().0,
            Message::PingReply { seq: 77 }
        );
    }

    /// The probe's timestamp goes back untouched — the initiator measures
    /// against its own clock, so trusting this one would make the answer
    /// depend on two clocks agreeing.
    #[test]
    fn a_latency_probe_is_echoed_with_its_timestamp_intact() {
        let mut r = started();
        let out = feed(
            &mut r,
            Message::LatencyProbe {
                seq: 3,
                ts_us: 0x1234_5678,
            },
        );
        assert_eq!(
            decode(&out[0].data).unwrap().0,
            Message::LatencyReply {
                seq: 3,
                ts_us: 0x1234_5678
            }
        );
    }

    #[test]
    fn throughput_is_counted_and_not_answered() {
        let mut r = started();
        let out = feed(
            &mut r,
            Message::Throughput {
                seq: 1,
                pattern: pattern::NONE,
            },
        );
        assert!(out.is_empty(), "one-way by definition");
        assert_eq!(r.sequence.rx_count, 1);
    }

    /// The whole reason the run tag exists: another initiator's run must not be
    /// answered, and must not touch this one's counters.
    #[test]
    fn another_runs_traffic_is_ignored() {
        let mut r = started();
        let other = Flags::new(2, RUN ^ 0x1);
        let msg = Message::PingRequest { seq: 1 };
        let out = r.on_frame(msg.arb_id(), false, false, &encode(msg, other), 0);
        assert!(out.is_empty());
        assert_eq!(r.sequence.rx_count, 0, "not counted either");
    }

    #[test]
    fn nothing_is_answered_before_a_run_starts() {
        let mut r = Responder::new(capability::FD, 0);
        assert!(feed(&mut r, Message::PingRequest { seq: 1 }).is_empty());
        assert!(r
            .on_frame(SWEEP_REQUEST_BASE, false, false, &[], 0)
            .is_empty());
    }

    #[test]
    fn stop_ends_the_run() {
        let mut r = started();
        r.on_frame(
            ID_CONTROL,
            false,
            false,
            &encode(Message::Control(Command::Stop), flags()),
            0,
        );
        assert_eq!(r.run(), None);
        assert!(feed(&mut r, Message::PingRequest { seq: 1 }).is_empty());
    }

    /// Hello is the one thing an idle responder answers — it is how an
    /// initiator finds out anything is there at all.
    #[test]
    fn hello_is_answered_while_idle_and_reports_capabilities() {
        let mut r = Responder::new(capability::FD, 3);
        let out = r.on_frame(
            ID_CONTROL,
            false,
            false,
            &encode(Message::Control(Command::Hello), flags()),
            0,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            decode(&out[0].data).unwrap().0,
            Message::Control(Command::HelloReply {
                capabilities: capability::FD,
                bus: 3
            })
        );
    }

    #[test]
    fn a_sweep_request_is_echoed_verbatim_on_the_matching_id() {
        let mut r = started();
        for code in sweep_codes(true) {
            let sent = sweep_payload(code, true);
            let out = r.on_frame(SWEEP_REQUEST_BASE + u32::from(code), false, true, &sent, 0);
            assert_eq!(out.len(), 1, "code {code}");
            assert_eq!(out[0].arb_id, SWEEP_ECHO_BASE + u32::from(code));
            assert_eq!(out[0].data, sent, "code {code}");
            assert!(sweep_echo_matches(code, true, &out[0].data));
        }
    }

    /// An echo is somebody else's answer, or our own on a loopback. Answering
    /// one would put two endpoints in a loop that never ends.
    #[test]
    fn a_sweep_echo_is_not_itself_answered() {
        let mut r = started();
        assert!(r
            .on_frame(SWEEP_ECHO_BASE + 4, false, false, &[0; 4], 0)
            .is_empty());
    }

    #[test]
    fn a_status_request_is_answered_with_every_counter() {
        let mut r = started();
        feed(&mut r, Message::PingRequest { seq: 0 });
        feed(&mut r, Message::PingRequest { seq: 4 });

        let out = r.on_frame(
            ID_CONTROL,
            false,
            false,
            &encode(Message::Control(Command::RequestStatus), flags()),
            2_000_000,
        );
        assert_eq!(out.len(), 4, "one frame per counter");

        let fields: Vec<(u8, u32)> = out
            .iter()
            .map(|r| match decode(&r.data).unwrap().0 {
                Message::Status { field, value } => (field, value),
                other => panic!("expected a status frame, got {other:?}"),
            })
            .collect();
        assert_eq!(fields[0], (status_field::RX_COUNT, 2));
        assert_eq!(fields[2], (status_field::DROPS, 3), "1, 2 and 3 missing");
        assert!(out.iter().all(|r| r.arb_id == ID_STATUS));
    }

    /// A counter is 24 bits on this wire. A longer run must saturate rather
    /// than wrap to a small number that reads as a healthy link.
    ///
    /// `0x1_0000_0000` is the case the clamp alone does not cover: a counter
    /// narrowed to 32 bits before being clamped arrives as 0, and a run that
    /// received four billion frames reports receiving none.
    #[test]
    fn a_counter_past_the_wire_width_saturates() {
        for count in [0x0100_0000, 0x1_0000_0000, u64::MAX] {
            let mut r = started();
            r.sequence.rx_count = count;
            let out = r.on_frame(
                ID_CONTROL,
                false,
                false,
                &encode(Message::Control(Command::RequestStatus), flags()),
                1,
            );
            match decode(&out[0].data).unwrap().0 {
                Message::Status { value, .. } => {
                    assert_eq!(value, 0x00FF_FFFF, "rx_count {count:#x}")
                }
                other => panic!("expected a status frame, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_live_run_ignores_an_extended_sweep_id() {
        let mut r = started();
        let out = r.on_frame(SWEEP_REQUEST_BASE + 5, true, false, &[0; 5], 0);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn a_live_run_ignores_a_framed_message_on_an_extended_standard_id() {
        let mut r = started();
        let msg = Message::PingRequest { seq: 1 };
        assert!(r
            .on_frame(msg.arb_id(), true, false, &encode(msg, flags()), 0)
            .is_empty());
    }

    /// A run asking for 29-bit ids has to be answered on 29-bit ids, or the
    /// initiator hears nothing and reports a dead link.
    #[test]
    fn a_reply_matches_the_request_id_width() {
        let mut r = started();
        let msg = Message::PingRequest { seq: 1 };
        let out = r.on_frame(
            extended_id(msg.arb_id()).unwrap(),
            true,
            false,
            &encode(msg, flags()),
            0,
        );
        assert!(out[0].extended);
        assert_eq!(Some(out[0].arb_id), extended_id(ID_PING_REPLY));
    }

    #[test]
    fn a_responder_without_fd_answers_classically() {
        let mut r = Responder::new(0, 0);
        r.on_frame(
            ID_CONTROL,
            false,
            false,
            &encode(
                Message::Control(Command::Start { mode: 0, run: RUN }),
                flags(),
            ),
            0,
        );
        let msg = Message::PingRequest { seq: 1 };
        let out = r.on_frame(msg.arb_id(), false, true, &encode(msg, flags()), 0);
        assert!(!out[0].fd, "it said it could not");
        assert_eq!(out[0].data.len(), HEADER_BYTES);
    }
}
