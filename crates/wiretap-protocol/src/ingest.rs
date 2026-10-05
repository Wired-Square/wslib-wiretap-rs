//! The WireTAP binary ingest protocol (`docs/ingest.md`), both ends: what a
//! capture device or a forwarding capture server sends, and what a gateway
//! parses. All integers little-endian; every message is
//! `len u16 | type u8 | body | crc32 u32` with the CRC over type+body.
//!
//! **Both ends live here**, which is the whole reason this is one module. The
//! gateway parses what the capture server encodes, and the protocol was
//! hand-written four times before it existed — once in WireTAP-Server, twice in
//! the Python (server side and forward-client side), and again in the test
//! client. A format where one side is `<IIBB>` and the other is four
//! `to_le_bytes` calls is a format that drifts.
//!
//! Message types are grouped by who sends them, not by name: a client sends
//! `HELLO`, `BATCH`, `PING`, `CATALOG_GET` and `CATALOG_STATUS`; a server
//! answers `HELLO_ACK`, `ACK`, `PONG`, `CATALOG` and `CLOSE`.
//!
//! Version 2 changed the `BATCH` record in place so it can carry more than a
//! CAN frame: each record names its [`RecordKind`]. Version 3 added the daemon
//! id and device map to `HELLO`, catalogue assignments to `HELLO_ACK`, the
//! catalogue pull and status, `CLOSE`, and raw serial records. The older
//! layouts are still parsed, through [`batch_parser`], so a server can take a
//! client that has not been upgraded yet.
//!
//! The id-flag positions differ from GVRET's, which marks an extended id with
//! the top bit rather than bit 29. Only the id width is common, and it comes
//! from [`crate::ARB_MASK_EXT`] so the two cannot drift. The WireTAP desktop's
//! HTTP import record packs its id the same way; it is [`crate::import`].

use crate::crc32::crc32;

mod server;
pub use server::{Action, CloseReason, IncomingBatch, ServerConfig, ServerSession, ShortBatch};

pub const PROTO_VERSION: u8 = 3;
pub const MAGIC: &[u8; 4] = b"WTAP";

pub const MSG_HELLO: u8 = 0x01;
pub const MSG_BATCH: u8 = 0x02;
pub const MSG_PING: u8 = 0x03;
pub const MSG_CATALOG_GET: u8 = 0x04;
pub const MSG_CATALOG_STATUS: u8 = 0x05;
pub const MSG_HELLO_ACK: u8 = 0x81;
pub const MSG_ACK: u8 = 0x82;
pub const MSG_PONG: u8 = 0x83;
pub const MSG_CATALOG: u8 = 0x84;
pub const MSG_CLOSE: u8 = 0x85;

pub const HELLO_FLAG_TIME_RELATIVE: u8 = 0x01;

pub const HELLO_OK: u8 = 0;
pub const HELLO_BAD_AUTH: u8 = 1;
pub const HELLO_BAD_VERSION: u8 = 2;
pub const HELLO_BAD_DATABASE: u8 = 3;
/// Not yet: the database can't be served right now, so back off and retry.
pub const HELLO_UNAVAILABLE: u8 = 4;

pub const ACK_OK: u8 = 0;
pub const ACK_CRC: u8 = 1;
pub const ACK_MALFORMED: u8 = 2;
pub const ACK_OVERLOADED: u8 = 3;

pub const CATALOG_OK: u8 = 0;
pub const CATALOG_UNKNOWN: u8 = 1;
/// Not now: the blob can't be read at the moment, so back off and retry.
pub const CATALOG_UNAVAILABLE: u8 = 2;
/// The offset is past the end; `total_len` is the blob's.
pub const CATALOG_BAD_OFFSET: u8 = 3;

/// The session's catalogue assignment changed; reconnect and read the new one.
pub const CLOSE_REASSIGNED: u8 = 0;

/// The most data one `CATALOG` carries.
pub const MAX_CATALOG_CHUNK: usize = 65_504;

/// `status u8 | blob_sha [20] | total_len u32 | offset u32`.
const CATALOG_HEADER: usize = 29;

/// Bit 29: the arbitration id is 29-bit rather than 11-bit.
pub const ID_EXTENDED: u32 = 1 << 29;
/// Bit 30: a CAN FD frame.
pub const ID_FD: u32 = 1 << 30;
/// Bit 31: a frame this device transmitted, rather than one it observed.
pub const ID_TX: u32 = 1 << 31;
/// What is left once the three flags are masked off.
pub const ID_ARB_MASK: u32 = crate::ARB_MASK_EXT;
/// A raw serial record's read sequence, which wraps at 2^31 under [`ID_TX`].
pub const ID_SEQ_MASK: u32 = !ID_TX;

/// A Modbus record's flag byte: bit 0 is whether the message's CRC matched.
/// A CAN record's flags are all in its `id_flags` word and its byte is 0.
pub const FLAG_CRC_VALID: u8 = 0x01;

/// What a record's `id_flags` and payload mean. The discriminant is the wire
/// byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// `id_flags` is the arbitration id with [`ID_EXTENDED`], [`ID_FD`] and
    /// [`ID_TX`] packed in; the payload is one frame's data.
    Can = 0,
    /// `id_flags` is [`modbus_id`] — unit and function code — with [`ID_TX`]
    /// meaning this server sent it; the payload is the whole message, CRC
    /// included.
    Modbus = 1,
    /// Version 3 on: `id_flags` is [`raw_serial_id`] — the read sequence —
    /// and the payload is the bytes one read returned.
    RawSerial = 2,
}

impl RecordKind {
    pub fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(RecordKind::Can),
            1 => Some(RecordKind::Modbus),
            2 => Some(RecordKind::RawSerial),
            _ => None,
        }
    }

    /// The largest payload the kind can carry: one CAN FD frame, the
    /// longest Modbus RTU message, or one raw serial chunk. Both ends enforce it.
    pub fn max_payload(self) -> usize {
        match self {
            RecordKind::Can => 64,
            RecordKind::Modbus | RecordKind::RawSerial => 256,
        }
    }

    /// The smallest payload the kind can carry. The parser enforces it.
    pub fn min_payload(self) -> usize {
        match self {
            RecordKind::RawSerial => 1,
            RecordKind::Can | RecordKind::Modbus => 0,
        }
    }
}

/// Records per `BATCH`. A client must chunk at this, because it is the default
/// a gateway checks against — over it, the batch is NACKed as malformed rather
/// than accepted and truncated.
pub const MAX_BATCH_RECORDS: usize = 256;

/// The largest body a message can carry: the length field is a `u16` that
/// counts the type byte too. A batch of full-size Modbus records reaches it
/// well before [`MAX_BATCH_RECORDS`], so a client has to chunk by bytes as
/// well — see [`record_wire_len`]. Past it the length prefix wraps and the
/// far end loses framing.
pub const MAX_BODY: usize = u16::MAX as usize - 1;

/// `seq u32 | base_ts_us u64 | count u16`.
pub const BATCH_HEADER: usize = 14;

/// `delta_us u32 | kind u8 | flags u8 | bus u8 | len u16 | id_flags u32`.
pub const RECORD_HEADER: usize = 13;

/// How many bytes of a `BATCH` body one record takes, once its payload is
/// clamped as [`encode_record_into`] clamps it.
pub fn record_wire_len(kind: RecordKind, payload_len: usize) -> usize {
    RECORD_HEADER + payload_len.min(kind.max_payload())
}

pub fn encode_message(mtype: u8, body: &[u8]) -> Vec<u8> {
    debug_assert!(
        body.len() <= MAX_BODY,
        "body of {} bytes overflows the length field",
        body.len()
    );
    let len = (1 + body.len()) as u16;
    let mut out = Vec::with_capacity(2 + 1 + body.len() + 4);
    out.extend_from_slice(&len.to_le_bytes());
    out.push(mtype);
    out.extend_from_slice(body);
    let crc = crc32(&out[2..]);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// One parsed wire frame: type, body, and whether the CRC matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub mtype: u8,
    pub body: Vec<u8>,
    pub crc_ok: bool,
}

/// Try to consume one complete frame from the front of `buf`.
/// `Ok(None)` = need more bytes; `Err` = unrecoverable garbage (drop client).
/// Drains per call; a streaming caller wants [`parse_frame`].
pub fn take_frame(buf: &mut Vec<u8>) -> Result<Option<WireFrame>, String> {
    let parsed = parse_frame(buf)?;
    Ok(parsed.map(|(frame, consumed)| {
        buf.drain(..consumed);
        frame
    }))
}

/// [`take_frame`] for a caller that holds its own offset, returning the bytes consumed.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(WireFrame, usize)>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len < 1 {
        return Err("zero-length frame".into());
    }
    let total = 2 + len + 4;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = &buf[2..2 + len];
    let crc = u32::from_le_bytes([buf[2 + len], buf[3 + len], buf[4 + len], buf[5 + len]]);
    let frame = WireFrame {
        mtype: payload[0],
        body: payload[1..].to_vec(),
        crc_ok: crc32(payload) == crc,
    };
    Ok(Some((frame, total)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub time_relative: bool,
    pub token: Vec<u8>,
    pub database: String,
    /// Version 3 on, and empty before it or for an anonymous client. Otherwise
    /// [`valid_daemon_id`].
    pub daemon_id: String,
    /// Version 3 on: the buses this session's records name, and the interface
    /// behind each. No bus or name twice, no empty name, and none without a
    /// daemon id.
    pub devices: Vec<Device>,
}

impl Hello {
    /// A version 2 `HELLO`, which has no daemon id or devices.
    pub fn v2(token: &[u8], database: &str, time_relative: bool) -> Self {
        Self {
            version: 2,
            time_relative,
            token: token.to_vec(),
            database: database.into(),
            daemon_id: String::new(),
            devices: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub bus: u8,
    /// `can0`, `/dev/ttyUSB0`, a by-id path: unique per daemon, unlike the bus.
    pub name: String,
}

/// Exactly 3, not 3 on: a later `HELLO` must still parse far enough to be
/// refused by its version.
fn is_v3(version: u8) -> bool {
    version == 3
}

/// A body read front to back, each read naming what it was after.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err(format!("truncated {what}"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.bytes(1, what)?[0])
    }

    /// A `len u8` and that many bytes.
    fn short(&mut self, what: &str) -> Result<&'a [u8], String> {
        let len = self.u8(what)?;
        self.bytes(len.into(), what)
    }
}

pub fn parse_hello(body: &[u8]) -> Result<Hello, String> {
    if body.len() < 7 || &body[0..4] != MAGIC {
        return Err("bad magic".into());
    }
    let version = body[4];
    let flags = body[5];
    let mut r = Reader(&body[6..]);
    let token = r.short("token")?.to_vec();
    // An absent database is the default, for clients older than the field.
    let database = if r.0.is_empty() && !is_v3(version) {
        String::new()
    } else {
        String::from_utf8_lossy(r.short("database")?).into_owned()
    };
    let mut hello = Hello {
        version,
        time_relative: flags & HELLO_FLAG_TIME_RELATIVE != 0,
        token,
        database,
        daemon_id: String::new(),
        devices: Vec::new(),
    };
    if is_v3(version) {
        hello.daemon_id = utf8(r.short("daemon id")?, "daemon id")?;
        for _ in 0..r.u8("device count")? {
            let bus = r.u8("device")?;
            let name = utf8(r.short("device name")?, "device name")?;
            hello.devices.push(Device { bus, name });
        }
        check_daemon_fields(&hello.daemon_id, &hello.devices)?;
    }
    Ok(hello)
}

fn utf8(bytes: &[u8], what: &str) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| format!("{what} is not UTF-8"))
}

/// What both ends hold a version 3 `HELLO` to.
fn check_daemon_fields(daemon_id: &str, devices: &[Device]) -> Result<(), String> {
    if !daemon_id.is_empty() && !valid_daemon_id(daemon_id) {
        return Err(format!("bad daemon id {daemon_id:?}"));
    }
    if daemon_id.is_empty() && !devices.is_empty() {
        return Err("an anonymous HELLO names no devices".into());
    }
    for (i, d) in devices.iter().enumerate() {
        if d.name.is_empty() {
            return Err(format!("bus {} has no device name", d.bus));
        }
        if let Some(e) = devices[..i]
            .iter()
            .find(|e| e.bus == d.bus || e.name == d.name)
        {
            return Err(format!("{d:?} repeats {e:?}"));
        }
    }
    Ok(())
}

/// A gateway's catalogue for one bus, by the SHA-1 of its blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assignment {
    pub bus: u8,
    pub blob_sha: [u8; 20],
}

/// Whether a `HELLO_ACK` carries `count` and the assignments. A refusal never
/// does, so every version reads it in the same 10 bytes.
fn carries_assignments(status: u8, accepted_version: u8) -> bool {
    status == HELLO_OK && is_v3(accepted_version)
}

/// `assignments` go only into a [`HELLO_OK`] for version 3, and more than 255
/// of them are refused.
pub fn encode_hello_ack(
    status: u8,
    accepted_version: u8,
    server_time_us: u64,
    assignments: &[Assignment],
) -> Result<Vec<u8>, String> {
    let mut body = vec![status, accepted_version];
    body.extend_from_slice(&server_time_us.to_le_bytes());
    if carries_assignments(status, accepted_version) {
        body.push(
            u8::try_from(assignments.len())
                .map_err(|_| format!("{} assignments", assignments.len()))?,
        );
        for a in assignments {
            body.push(a.bus);
            body.extend_from_slice(&a.blob_sha);
        }
    }
    Ok(encode_message(MSG_HELLO_ACK, &body))
}

pub fn encode_ack(seq: u32, status: u8, queue_pct: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&seq.to_le_bytes());
    body.push(status);
    body.push(queue_pct);
    encode_message(MSG_ACK, &body)
}

#[derive(Debug)]
pub struct Record {
    pub delta_us: u32,
    pub kind: RecordKind,
    pub flags: u8,
    pub bus: u8,
    pub id_flags: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Batch {
    pub seq: u32,
    pub base_ts_us: u64,
    pub records: Vec<Record>,
}

impl Batch {
    /// The timestamp each record's `delta_us` is added to.
    ///
    /// A time-relative session's base is an epoch the receiver knows nothing
    /// about, so the newest record is stamped `arrival_us` and the rest are
    /// back-dated from it. The newest is the *largest* delta, not the last: a
    /// sender interleaving two buses need not sort, and taking the last would
    /// stamp the real newest ahead of its own arrival.
    pub fn base_ts_us(&self, time_relative: bool, arrival_us: u64) -> u64 {
        if !time_relative {
            return self.base_ts_us;
        }
        let newest = self.records.iter().map(|r| r.delta_us).max().unwrap_or(0);
        arrival_us.saturating_sub(u64::from(newest))
    }

    /// Each record with its epoch-µs stamp, on the base [`Batch::base_ts_us`] gives.
    pub fn stamped(
        self,
        time_relative: bool,
        arrival_us: u64,
    ) -> impl Iterator<Item = (u64, Record)> {
        let base = self.base_ts_us(time_relative, arrival_us);
        self.records
            .into_iter()
            .map(move |r| (base.saturating_add(u64::from(r.delta_us)), r))
    }
}

/// A BATCH parser: `Err(seq)` = malformed but seq was readable (NACK it);
/// outer `None` = too short to even carry a seq (drop client).
pub type BatchParser = fn(&[u8], usize) -> Option<Result<Batch, u32>>;

/// The parser for the version a client announced, or `None` for a version
/// nothing here speaks. Which of these a server takes is its
/// [`ServerConfig::versions`].
pub fn batch_parser(version: u8) -> Option<BatchParser> {
    match version {
        3 => Some(parse_batch),
        2 => Some(parse_batch_v2),
        1 => Some(parse_batch_v1),
        _ => None,
    }
}

/// A record header as read from the body: everything but the payload, and
/// how long the payload is.
type RecordHeader = fn(&[u8]) -> Option<(Record, usize)>;

fn v3_header(b: &[u8]) -> Option<(Record, usize)> {
    let kind = RecordKind::from_wire(b[4])?;
    let plen = u16::from_le_bytes(b[7..9].try_into().unwrap()) as usize;
    let record = Record {
        delta_us: u32::from_le_bytes(b[0..4].try_into().unwrap()),
        kind,
        flags: b[5],
        bus: b[6],
        id_flags: u32::from_le_bytes(b[9..13].try_into().unwrap()),
        payload: Vec::new(),
    };
    Some((record, plen))
}

fn v2_header(b: &[u8]) -> Option<(Record, usize)> {
    v3_header(b).filter(|(record, _)| record.kind != RecordKind::RawSerial)
}

/// `delta_us u32 | id_flags u32 | bus u8 | len u8`: CAN only, so every record
/// comes back as [`RecordKind::Can`] and a gateway handles both versions
/// through one path.
fn v1_header(b: &[u8]) -> Option<(Record, usize)> {
    let record = Record {
        delta_us: u32::from_le_bytes(b[0..4].try_into().unwrap()),
        kind: RecordKind::Can,
        flags: 0,
        bus: b[8],
        id_flags: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        payload: Vec::new(),
    };
    Some((record, b[9] as usize))
}

fn parse_records(
    body: &[u8],
    max_frames: usize,
    header_len: usize,
    header: RecordHeader,
) -> Option<Result<Batch, u32>> {
    if body.len() < BATCH_HEADER {
        return None;
    }
    let seq = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let base_ts_us = u64::from_le_bytes(body[4..12].try_into().unwrap());
    let count = u16::from_le_bytes(body[12..14].try_into().unwrap()) as usize;
    if count > max_frames {
        return Some(Err(seq));
    }
    let mut records = Vec::with_capacity(count);
    let mut off = BATCH_HEADER;
    for _ in 0..count {
        let Some((mut record, plen)) = body.get(off..off + header_len).and_then(header) else {
            return Some(Err(seq));
        };
        off += header_len;
        if !(record.kind.min_payload()..=record.kind.max_payload()).contains(&plen)
            || body.len() < off + plen
        {
            return Some(Err(seq));
        }
        record.payload = body[off..off + plen].to_vec();
        records.push(record);
        off += plen;
    }
    Some(Ok(Batch {
        seq,
        base_ts_us,
        records,
    }))
}

/// Parse a BATCH body. See [`BatchParser`] for the contract.
pub fn parse_batch(body: &[u8], max_frames: usize) -> Option<Result<Batch, u32>> {
    parse_records(body, max_frames, RECORD_HEADER, v3_header)
}

/// Parse a version 2 BATCH body, which has no [`RecordKind::RawSerial`].
pub fn parse_batch_v2(body: &[u8], max_frames: usize) -> Option<Result<Batch, u32>> {
    parse_records(body, max_frames, RECORD_HEADER, v2_header)
}

/// Parse a version 1 BATCH body, whose records are all [`RecordKind::Can`].
pub fn parse_batch_v1(body: &[u8], max_frames: usize) -> Option<Result<Batch, u32>> {
    parse_records(body, max_frames, 10, v1_header)
}

// --- client side -----------------------------------------------------------
//
// The inverse of everything above: what a capture server sends and what it
// reads back. Asserted against the server half in the tests, so neither can
// move without the other.

/// `HELLO` — announce the protocol version, authenticate, name a database and,
/// from version 3, the daemon and its devices. Laid out for `hello.version`.
///
/// An empty `database` means the gateway's default, and a name it does not know
/// is created where the gateway permits it, so a new capture server can
/// provision its own database on first connect.
///
/// `time_relative` is false for WireTAP-Server's forward client, which sends
/// absolute timestamps: a batch carries the base itself.
///
/// Refuses a field over its length byte, a daemon id or device map the parser
/// would refuse, or a `HELLO` over [`MAX_BODY`].
pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>, String> {
    let mut body = MAGIC.to_vec();
    body.push(hello.version);
    body.push(if hello.time_relative {
        HELLO_FLAG_TIME_RELATIVE
    } else {
        0
    });
    push_short(&mut body, &hello.token, "token")?;
    push_short(&mut body, hello.database.as_bytes(), "database")?;
    if is_v3(hello.version) {
        check_daemon_fields(&hello.daemon_id, &hello.devices)?;
        push_short(&mut body, hello.daemon_id.as_bytes(), "daemon id")?;
        body.push(
            u8::try_from(hello.devices.len())
                .map_err(|_| format!("{} devices", hello.devices.len()))?,
        );
        for d in &hello.devices {
            body.push(d.bus);
            push_short(&mut body, d.name.as_bytes(), "device name")?;
        }
    } else if !hello.daemon_id.is_empty() || !hello.devices.is_empty() {
        return Err(format!(
            "a version {} HELLO has no daemon id or devices",
            hello.version
        ));
    }
    if body.len() > MAX_BODY {
        return Err(format!(
            "a HELLO of {} bytes is over the length field",
            body.len()
        ));
    }
    Ok(encode_message(MSG_HELLO, &body))
}

fn push_short(out: &mut Vec<u8>, bytes: &[u8], what: &str) -> Result<(), String> {
    let len = u8::try_from(bytes.len()).map_err(|_| format!("{what} of {} bytes", bytes.len()))?;
    out.push(len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Whether `id` names a daemon: a lowercase ASCII letter or digit, then those,
/// `.`, `_` or `-`, at most 63 bytes. `""` is not an id — in `HELLO` it means
/// an anonymous client.
pub fn valid_daemon_id(id: &str) -> bool {
    id.len() <= 63
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_".contains(&b))
}

/// Whether the gateway takes `name` as a capture database: a lowercase ASCII
/// letter, then lowercase letters, digits or `_`, at most 63 bytes. `""` is
/// not a name — in `HELLO` it means the default, and that is the caller's branch.
pub fn valid_database_name(name: &str) -> bool {
    name.len() <= 63
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// What a gateway said about a `HELLO`.
#[derive(Debug, PartialEq, Eq)]
pub struct HelloAck {
    pub status: u8,
    /// The version the gateway speaks. A client speaks one version and there
    /// is no negotiation; this is reported so a refused client can say which
    /// side is behind.
    pub accepted_version: u8,
    pub server_time_us: u64,
    /// A version 3 [`HELLO_OK`]'s. A bus with none has no gateway assignment.
    pub assignments: Vec<Assignment>,
}

pub fn parse_hello_ack(body: &[u8]) -> Result<HelloAck, String> {
    if body.len() < 10 {
        return Err("truncated HELLO_ACK".into());
    }
    let accepted_version = body[1];
    let mut assignments = Vec::new();
    if carries_assignments(body[0], accepted_version) {
        let mut r = Reader(&body[10..]);
        for _ in 0..r.u8("assignment count")? {
            let bus = r.u8("assignment")?;
            let blob_sha = r.bytes(20, "assignment")?.try_into().unwrap();
            assignments.push(Assignment { bus, blob_sha });
        }
    }
    Ok(HelloAck {
        status: body[0],
        accepted_version,
        server_time_us: u64::from_le_bytes(body[2..10].try_into().unwrap()),
        assignments,
    })
}

/// The id word a CAN record carries: the arbitration id with its flags packed in.
///
/// Not the GVRET packing, which puts the extended bit at 31 — the same three
/// facts, three different layouts, which is exactly why this is written once.
pub fn record_id_flags(arb_id: u32, extended: bool, is_fd: bool, transmitted: bool) -> u32 {
    let mut id = arb_id & ID_ARB_MASK;
    if extended {
        id |= ID_EXTENDED;
    }
    if is_fd {
        id |= ID_FD;
    }
    if transmitted {
        id |= ID_TX;
    }
    id
}

/// The inverse of [`record_id_flags`]: `(arb_id, extended, is_fd, transmitted)`.
pub fn record_id_fields(id_flags: u32) -> (u32, bool, bool, bool) {
    (
        id_flags & ID_ARB_MASK,
        id_flags & ID_EXTENDED != 0,
        id_flags & ID_FD != 0,
        id_flags & ID_TX != 0,
    )
}

/// The id word a Modbus record carries: `unit << 8 | func`, which is also the
/// `id` the archive stores, so an inventory groups by conversation.
pub fn modbus_id(unit: u8, func: u8) -> u32 {
    (u32::from(unit) << 8) | u32::from(func)
}

/// The inverse of [`modbus_id`].
pub fn modbus_unit_func(id_flags: u32) -> (u8, u8) {
    ((id_flags >> 8) as u8, id_flags as u8)
}

/// The id word a raw serial record carries: the read sequence, counted from
/// the port's open and wrapping at 2^31.
pub fn raw_serial_id(seq: u32) -> u32 {
    seq & ID_SEQ_MASK
}

/// A record's `id_flags` and `flags`, unpacked for its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFields {
    Can {
        arb_id: u32,
        extended: bool,
        fd: bool,
        transmitted: bool,
    },
    Modbus {
        unit: u8,
        func: u8,
        crc_valid: bool,
        transmitted: bool,
    },
    RawSerial {
        seq: u32,
        transmitted: bool,
    },
}

impl RecordFields {
    pub fn from_wire(kind: RecordKind, id_flags: u32, flags: u8) -> Self {
        let transmitted = id_flags & ID_TX != 0;
        match kind {
            RecordKind::Can => {
                let (arb_id, extended, fd, _) = record_id_fields(id_flags);
                RecordFields::Can {
                    arb_id,
                    extended,
                    fd,
                    transmitted,
                }
            }
            RecordKind::Modbus => {
                let (unit, func) = modbus_unit_func(id_flags);
                RecordFields::Modbus {
                    unit,
                    func,
                    crc_valid: flags & FLAG_CRC_VALID != 0,
                    transmitted,
                }
            }
            RecordKind::RawSerial => RecordFields::RawSerial {
                seq: raw_serial_id(id_flags),
                transmitted,
            },
        }
    }

    /// `(id_flags, flags)`.
    pub fn to_wire(&self) -> (u32, u8) {
        match *self {
            RecordFields::Can {
                arb_id,
                extended,
                fd,
                transmitted,
            } => (record_id_flags(arb_id, extended, fd, transmitted), 0),
            RecordFields::Modbus {
                unit,
                func,
                crc_valid,
                transmitted,
            } => (
                modbus_id(unit, func) | if transmitted { ID_TX } else { 0 },
                if crc_valid { FLAG_CRC_VALID } else { 0 },
            ),
            RecordFields::RawSerial { seq, transmitted } => {
                (raw_serial_id(seq) | if transmitted { ID_TX } else { 0 }, 0)
            }
        }
    }

    pub fn kind(&self) -> RecordKind {
        match self {
            RecordFields::Can { .. } => RecordKind::Can,
            RecordFields::Modbus { .. } => RecordKind::Modbus,
            RecordFields::RawSerial { .. } => RecordKind::RawSerial,
        }
    }
}

/// The front of a sender's queue that goes in one `BATCH`: see [`fit_batch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchFit {
    /// How many frames from the front.
    pub len: usize,
    /// Their earliest stamp, 0 when `len` is.
    pub base_ts_us: u64,
}

/// How many `(ts_us, kind, payload_len)` frames from the front fit one `BATCH`.
///
/// At most [`MAX_BATCH_RECORDS`], spanning at most `u32::MAX` µs between the
/// earliest and latest stamp in whatever order they come, and a body within
/// [`MAX_BODY`]. The first frame always fits.
pub fn fit_batch(frames: impl IntoIterator<Item = (u64, RecordKind, usize)>) -> BatchFit {
    let mut frames = frames.into_iter();
    let Some((ts_us, kind, payload_len)) = frames.next() else {
        return BatchFit {
            len: 0,
            base_ts_us: 0,
        };
    };
    let (mut lo, mut hi) = (ts_us, ts_us);
    let mut bytes = BATCH_HEADER + record_wire_len(kind, payload_len);
    let mut len = 1;
    for (ts_us, kind, payload_len) in frames.take(MAX_BATCH_RECORDS - 1) {
        let (next_lo, next_hi) = (lo.min(ts_us), hi.max(ts_us));
        bytes += record_wire_len(kind, payload_len);
        if next_hi - next_lo > u64::from(u32::MAX) || bytes > MAX_BODY {
            break;
        }
        (lo, hi, len) = (next_lo, next_hi, len + 1);
    }
    BatchFit {
        len,
        base_ts_us: lo,
    }
}

/// Append one record: `delta_us u32 | kind u8 | flags u8 | bus u8 | len u16 |
/// id_flags u32 | payload`.
///
/// **The base must be the batch's earliest frame, and its span must fit a
/// `u32` of microseconds.** Neither is checked by the wire format: a delta
/// below the base saturates to zero and one above 71.6 minutes wraps, and both
/// file the frame at a time it did not happen. Callers, not this function, are
/// where those hold — see [`fit_batch`].
#[allow(clippy::too_many_arguments)]
pub fn encode_record_into(
    out: &mut Vec<u8>,
    base_ts_us: u64,
    ts_us: u64,
    kind: RecordKind,
    flags: u8,
    bus: u8,
    id_flags: u32,
    payload: &[u8],
) {
    debug_assert!(
        ts_us >= base_ts_us,
        "the base must be the batch's earliest frame: {ts_us} is before {base_ts_us}"
    );
    let payload = &payload[..payload.len().min(kind.max_payload())];
    out.reserve(record_wire_len(kind, payload.len()));
    out.extend_from_slice(&(ts_us.saturating_sub(base_ts_us) as u32).to_le_bytes());
    out.push(kind as u8);
    out.push(flags);
    out.push(bus);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&id_flags.to_le_bytes());
    out.extend_from_slice(payload);
}

/// `BATCH` — a sequence number, the base timestamp, and `count` records.
///
/// `records` is the buffer [`encode_record_into`] was appended to, and `count`
/// is how many went into it; they are separate because the caller is the only
/// thing that knows both, and a record's length is not fixed.
pub fn encode_batch(seq: u32, base_ts_us: u64, count: u16, records: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(BATCH_HEADER + records.len());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&base_ts_us.to_le_bytes());
    body.extend_from_slice(&count.to_le_bytes());
    body.extend_from_slice(records);
    encode_message(MSG_BATCH, &body)
}

/// What a gateway said about a `BATCH`.
#[derive(Debug, PartialEq, Eq)]
pub struct Ack {
    pub seq: u32,
    pub status: u8,
    /// How full the gateway's own queue is, as a percentage.
    pub queue_pct: u8,
}

pub fn parse_ack(body: &[u8]) -> Result<Ack, String> {
    if body.len() < 6 {
        return Err("truncated ACK".into());
    }
    Ok(Ack {
        seq: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        status: body[4],
        queue_pct: body[5],
    })
}

// --- the catalogue pull ----------------------------------------------------

/// A request for one chunk of a catalogue blob, by its SHA-1, which the
/// protocol carries as opaque bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogGet {
    pub blob_sha: [u8; 20],
    pub offset: u32,
}

pub fn encode_catalog_get(get: &CatalogGet) -> Vec<u8> {
    let mut body = get.blob_sha.to_vec();
    body.extend_from_slice(&get.offset.to_le_bytes());
    encode_message(MSG_CATALOG_GET, &body)
}

pub fn parse_catalog_get(body: &[u8]) -> Result<CatalogGet, String> {
    if body.len() < 24 {
        return Err("truncated CATALOG_GET".into());
    }
    Ok(CatalogGet {
        blob_sha: body[0..20].try_into().unwrap(),
        offset: u32::from_le_bytes(body[20..24].try_into().unwrap()),
    })
}

/// One chunk of a catalogue blob, or why there is none.
#[derive(Debug, PartialEq, Eq)]
pub struct Catalog {
    pub status: u8,
    pub blob_sha: [u8; 20],
    pub total_len: u32,
    pub offset: u32,
    pub data: Vec<u8>,
}

impl Catalog {
    /// The request for the chunk after this one, or `None` once the blob is
    /// whole or the answer was not [`CATALOG_OK`].
    pub fn next(&self) -> Option<CatalogGet> {
        let offset = self.offset.saturating_add(self.data.len() as u32);
        (self.status == CATALOG_OK && offset < self.total_len).then_some(CatalogGet {
            blob_sha: self.blob_sha,
            offset,
        })
    }
}

/// The `CATALOG` answering `get`: the chunk of `blob` at its offset, at most
/// [`MAX_CATALOG_CHUNK`] bytes, or no data and `Err`'s status. An offset past
/// the end gets no data and [`CATALOG_BAD_OFFSET`].
pub fn encode_catalog(get: &CatalogGet, blob: Result<&[u8], u8>) -> Vec<u8> {
    let (status, total_len, data) = match blob {
        Ok(blob) => {
            debug_assert!(
                u32::try_from(blob.len()).is_ok(),
                "a {} byte blob",
                blob.len()
            );
            let total_len = blob.len() as u32;
            match blob.get(get.offset as usize..) {
                Some(rest) => (
                    CATALOG_OK,
                    total_len,
                    &rest[..rest.len().min(MAX_CATALOG_CHUNK)],
                ),
                None => (CATALOG_BAD_OFFSET, total_len, &[][..]),
            }
        }
        Err(status) => (status, 0, &[][..]),
    };
    let mut body = Vec::with_capacity(CATALOG_HEADER + data.len());
    body.push(status);
    body.extend_from_slice(&get.blob_sha);
    body.extend_from_slice(&total_len.to_le_bytes());
    body.extend_from_slice(&get.offset.to_le_bytes());
    body.extend_from_slice(data);
    encode_message(MSG_CATALOG, &body)
}

/// Refuses a chunk over [`MAX_CATALOG_CHUNK`], and a [`CATALOG_OK`] one that
/// runs past `total_len` or stops short of it with no data.
pub fn parse_catalog(body: &[u8]) -> Result<Catalog, String> {
    if body.len() < CATALOG_HEADER {
        return Err("truncated CATALOG".into());
    }
    let catalog = Catalog {
        status: body[0],
        blob_sha: body[1..21].try_into().unwrap(),
        total_len: u32::from_le_bytes(body[21..25].try_into().unwrap()),
        offset: u32::from_le_bytes(body[25..29].try_into().unwrap()),
        data: body[CATALOG_HEADER..].to_vec(),
    };
    let end = u64::from(catalog.offset) + catalog.data.len() as u64;
    if catalog.data.len() > MAX_CATALOG_CHUNK {
        return Err(format!("a chunk of {} bytes", catalog.data.len()));
    }
    if catalog.status == CATALOG_OK
        && (end > u64::from(catalog.total_len)
            || (catalog.data.is_empty() && end < u64::from(catalog.total_len)))
    {
        return Err(format!(
            "{} bytes at {} of {}",
            catalog.data.len(),
            catalog.offset,
            catalog.total_len
        ));
    }
    Ok(catalog)
}

// --- the catalogue status --------------------------------------------------

/// A daemon's catalogue on every bus in its device map: the whole state, which
/// replaces what the server held, not a change to merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogStatus {
    pub entries: Vec<CatalogStatusEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogStatusEntry {
    pub bus: u8,
    pub active: ActiveCatalog,
    /// The blob the daemon last turned down for this bus, and why.
    pub refused: Option<([u8; 20], Refusal)>,
}

/// The catalogue a bus decodes with, by the git blob SHA-1 of its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveCatalog {
    None,
    /// The daemon's own file under `/etc`.
    Local([u8; 20]),
    Assigned([u8; 20]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    HashMismatch,
    DidNotParse,
    FetchFailed,
    /// A reason added after this crate, so not malformed.
    Other(u8),
}

impl Refusal {
    fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            0 => None,
            1 => Some(Refusal::HashMismatch),
            2 => Some(Refusal::DidNotParse),
            3 => Some(Refusal::FetchFailed),
            n => Some(Refusal::Other(n)),
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            Refusal::HashMismatch => 1,
            Refusal::DidNotParse => 2,
            Refusal::FetchFailed => 3,
            Refusal::Other(n) => n,
        }
    }
}

/// `bus u8 | source u8 | active_sha [20] | refused_sha [20] | refusal u8`.
const CATALOG_STATUS_ENTRY: usize = 43;

fn encode_status_entry(e: &CatalogStatusEntry) -> [u8; CATALOG_STATUS_ENTRY] {
    let (source, active_sha) = match e.active {
        ActiveCatalog::None => (0, [0; 20]),
        ActiveCatalog::Local(sha) => (1, sha),
        ActiveCatalog::Assigned(sha) => (2, sha),
    };
    let (refused_sha, refusal) = e
        .refused
        .map_or(([0; 20], 0), |(sha, r)| (sha, r.to_wire()));
    let mut out = [0; CATALOG_STATUS_ENTRY];
    out[0] = e.bus;
    out[1] = source;
    out[2..22].copy_from_slice(&active_sha);
    out[22..42].copy_from_slice(&refused_sha);
    out[42] = refusal;
    out
}

fn parse_status_entry(b: &[u8]) -> Result<CatalogStatusEntry, String> {
    let bus = b[0];
    let active_sha: [u8; 20] = b[2..22].try_into().unwrap();
    let refused_sha: [u8; 20] = b[22..42].try_into().unwrap();
    let active = match (b[1], active_sha == [0; 20]) {
        (0, true) => ActiveCatalog::None,
        (1, false) => ActiveCatalog::Local(active_sha),
        (2, false) => ActiveCatalog::Assigned(active_sha),
        (source @ 0..=2, _) => {
            return Err(format!("bus {bus}: source {source} does not fit its SHA"))
        }
        (source, _) => return Err(format!("bus {bus}: source {source}")),
    };
    let refused = match (Refusal::from_wire(b[42]), refused_sha == [0; 20]) {
        (None, true) => None,
        (Some(refusal), false) => Some((refused_sha, refusal)),
        (_, _) => return Err(format!("bus {bus}: refusal {} does not fit its SHA", b[42])),
    };
    Ok(CatalogStatusEntry {
        bus,
        active,
        refused,
    })
}

fn check_buses_unique(entries: &[CatalogStatusEntry]) -> Result<(), String> {
    for (i, e) in entries.iter().enumerate() {
        if entries[..i].iter().any(|seen| seen.bus == e.bus) {
            return Err(format!("bus {} twice", e.bus));
        }
    }
    Ok(())
}

/// Refuses more than 255 entries, a bus twice, and an entry that would not
/// parse back as itself: an all-zero SHA, or a [`Refusal::Other`] of 0–3.
pub fn encode_catalog_status(status: &CatalogStatus) -> Result<Vec<u8>, String> {
    let count = u8::try_from(status.entries.len())
        .map_err(|_| format!("{} catalogue status entries", status.entries.len()))?;
    check_buses_unique(&status.entries)?;
    let mut body = Vec::with_capacity(1 + CATALOG_STATUS_ENTRY * status.entries.len());
    body.push(count);
    for e in &status.entries {
        let wire = encode_status_entry(e);
        if parse_status_entry(&wire).as_ref() != Ok(e) {
            return Err(format!("{e:?} does not survive the wire"));
        }
        body.extend_from_slice(&wire);
    }
    Ok(encode_message(MSG_CATALOG_STATUS, &body))
}

pub fn parse_catalog_status(body: &[u8]) -> Result<CatalogStatus, String> {
    let mut r = Reader(body);
    let count = r.u8("catalogue status count")?;
    let entries = (0..count)
        .map(|_| parse_status_entry(r.bytes(CATALOG_STATUS_ENTRY, "catalogue status")?))
        .collect::<Result<Vec<_>, _>>()?;
    check_buses_unique(&entries)?;
    Ok(CatalogStatus { entries })
}

// --- the close -------------------------------------------------------------

/// Why the server closed the session; an unknown reason is still a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close {
    pub reason: u8,
}

pub fn encode_close(reason: u8) -> Vec<u8> {
    encode_message(MSG_CLOSE, &[reason])
}

pub fn parse_close(body: &[u8]) -> Result<Close, String> {
    let &[reason, ..] = body else {
        return Err("truncated CLOSE".into());
    };
    Ok(Close { reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_body(token: &[u8], database: &str, flags: u8) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.push(2);
        b.push(flags);
        b.push(token.len() as u8);
        b.extend_from_slice(token);
        b.push(database.len() as u8);
        b.extend_from_slice(database.as_bytes());
        b
    }

    fn v2_hello(token: &[u8], database: &str, time_relative: bool) -> Vec<u8> {
        encode_hello(&Hello::v2(token, database, time_relative)).unwrap()
    }

    fn batch_header(seq: u32, base_ts_us: u64, count: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&base_ts_us.to_le_bytes());
        b.extend_from_slice(&count.to_le_bytes());
        b
    }

    #[test]
    fn frame_round_trip() {
        let msg = encode_message(MSG_PING, b"");
        let mut buf = msg.clone();
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.mtype, MSG_PING);
        assert!(frame.crc_ok);
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frame_waits_for_more() {
        let msg = encode_message(MSG_PING, b"");
        let mut buf = msg[..3].to_vec();
        assert!(take_frame(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn parse_frame_returns_the_bytes_consumed() {
        let msg = encode_message(MSG_BATCH, &[7; 14]);
        let buf = [&msg[..], &msg[..3]].concat();
        let frame = WireFrame {
            mtype: MSG_BATCH,
            body: vec![7; 14],
            crc_ok: true,
        };
        assert_eq!(parse_frame(&buf), Ok(Some((frame, msg.len()))));
    }

    #[test]
    fn walking_an_offset_reads_what_repeated_takes_read() {
        let mut buf = Vec::new();
        for i in 0..200u8 {
            buf.extend_from_slice(&encode_message(i, &vec![i; i as usize]));
        }
        let mut read = 0;
        let mut by_offset = Vec::new();
        while let Some((frame, consumed)) = parse_frame(&buf[read..]).unwrap() {
            read += consumed;
            by_offset.push(frame);
        }
        assert_eq!(read, buf.len());
        let taken: Vec<_> = std::iter::from_fn(|| take_frame(&mut buf).unwrap()).collect();
        assert_eq!(by_offset, taken);
        assert_eq!(taken.len(), 200);
    }

    #[test]
    fn corrupt_crc_detected() {
        let mut msg = encode_message(MSG_BATCH, &[0u8; 14]);
        let n = msg.len();
        msg[n - 1] ^= 0xFF;
        let mut buf = msg;
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert!(!frame.crc_ok);
    }

    #[test]
    fn hello_with_database() {
        let h = parse_hello(&hello_body(
            b"sekrit",
            "vehicle_1",
            HELLO_FLAG_TIME_RELATIVE,
        ))
        .unwrap();
        assert_eq!(h.token, b"sekrit");
        assert_eq!(h.database, "vehicle_1");
        assert!(h.time_relative);
    }

    #[test]
    fn hello_minimal_no_database_field() {
        // Back-compat: token but no db_len byte at all
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&[2, 0, 3]);
        b.extend_from_slice(b"abc");
        let h = parse_hello(&b).unwrap();
        assert_eq!(h.database, "");
    }

    #[test]
    fn batch_parse_and_limits() {
        let mut body = batch_header(7, 1_000_000, 2);
        for (delta, id) in [(0u32, 0x123u32), (1000, 0x18FF50E5 | ID_EXTENDED)] {
            body.extend_from_slice(&delta.to_le_bytes());
            body.push(0); // kind: CAN
            body.push(0); // flags
            body.push(1); // bus
            body.extend_from_slice(&3u16.to_le_bytes());
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(&[1, 2, 3]);
        }
        let batch = parse_batch(&body, 256).unwrap().unwrap();
        assert_eq!(batch.seq, 7);
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[1].kind, RecordKind::Can);
        assert_eq!(batch.records[1].id_flags & ID_ARB_MASK, 0x18FF50E5);
        assert!(batch.records[1].id_flags & ID_EXTENDED != 0);

        // count over the limit is malformed-with-seq
        let mut over = body.clone();
        over[12..14].copy_from_slice(&5000u16.to_le_bytes());
        assert!(matches!(parse_batch(&over, 256), Some(Err(7))));
    }

    #[test]
    fn an_unknown_kind_is_malformed_with_seq() {
        let mut body = batch_header(9, 0, 1);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(7); // no such kind
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(parse_batch(&body, 256), Some(Err(9))));
    }

    /// The old layout, as a v1 daemon still sends it, comes through the v1
    /// parser as CAN records — which is what lets a gateway take both.
    #[test]
    fn a_v1_batch_parses_as_can_records() {
        let mut body = batch_header(3, 500, 1);
        body.extend_from_slice(&42u32.to_le_bytes());
        body.extend_from_slice(&(0x7E0 | ID_TX).to_le_bytes());
        body.push(2); // bus
        body.push(2); // len
        body.extend_from_slice(&[0xAA, 0xBB]);
        let batch = parse_batch_v1(&body, 256).unwrap().unwrap();
        let r = &batch.records[0];
        assert_eq!((batch.seq, r.delta_us, r.bus), (3, 42, 2));
        assert_eq!((r.kind, r.flags), (RecordKind::Can, 0));
        assert_eq!(r.id_flags, 0x7E0 | ID_TX);
        assert_eq!(r.payload, [0xAA, 0xBB]);

        // A v1 body is not a v2 body: the v2 parser must not accept it.
        assert!(matches!(parse_batch(&body, 256), Some(Err(3))));

        // And a malformed v1 body is refused the same way a v2 one is.
        assert!(matches!(
            parse_batch_v1(&body[..body.len() - 1], 256),
            Some(Err(3))
        ));

        // The version map hands out the right parser, and no parser at all
        // for a version nothing speaks.
        let v1 = batch_parser(1).expect("v1 is still accepted");
        assert!(v1(&body, 256).unwrap().is_ok());
        let v2 = batch_parser(2).expect("the current version");
        assert!(matches!(v2(&body, 256), Some(Err(3))));
        assert!(batch_parser(99).is_none());
    }

    // --- the two halves, against each other ------------------------------

    /// What the client encodes is what the server parses. Neither half can be
    /// changed without this failing, which is the point of them sharing a
    /// crate.
    #[test]
    fn a_hello_round_trips_through_the_server_half() {
        let msg = v2_hello(b"sekrit", "vehicle_1", false);
        let mut buf = msg;
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.mtype, MSG_HELLO);
        assert!(frame.crc_ok);

        let hello = parse_hello(&frame.body).unwrap();
        assert_eq!(hello.version, 2);
        assert_eq!(hello.token, b"sekrit");
        assert_eq!(hello.database, "vehicle_1");
        assert!(!hello.time_relative, "the forward client sends absolute");

        // An empty database is the gateway's default, and must still carry its
        // length byte rather than being omitted.
        let mut buf = v2_hello(b"k", "", true);
        let frame = take_frame(&mut buf).unwrap().unwrap();
        let hello = parse_hello(&frame.body).unwrap();
        assert_eq!(hello.database, "");
        assert!(hello.time_relative);
    }

    #[test]
    fn a_batch_round_trips_through_the_server_half() {
        const BASE: u64 = 1_700_000_000_000_000;
        let mut records = Vec::new();
        encode_record_into(
            &mut records,
            BASE,
            BASE,
            RecordKind::Can,
            0,
            0,
            record_id_flags(0x123, false, false, false),
            &[1, 2, 3],
        );
        encode_record_into(
            &mut records,
            BASE,
            BASE + 1000,
            RecordKind::Can,
            0,
            1,
            record_id_flags(0x18FF_50E5, true, true, true),
            &[0xAA; 64],
        );
        encode_record_into(
            &mut records,
            BASE,
            BASE + 2000,
            RecordKind::Modbus,
            FLAG_CRC_VALID,
            2,
            modbus_id(1, 0x20),
            &[
                0x01, 0x20, 0x01, 0xC8, 0x03, 0x11, 0x1A, 0x00, 0x02, 0xE4, 0xCA,
            ],
        );

        let mut buf = encode_batch(7, BASE, 3, &records);
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(frame.mtype, MSG_BATCH);
        assert!(frame.crc_ok);

        let batch = parse_batch(&frame.body, MAX_BATCH_RECORDS)
            .expect("carries a seq")
            .expect("well formed");
        assert_eq!((batch.seq, batch.base_ts_us), (7, BASE));
        assert_eq!(batch.records[0].delta_us, 0);
        assert_eq!(batch.records[0].payload, [1, 2, 3]);

        let second = &batch.records[1];
        assert_eq!(second.delta_us, 1000);
        assert_eq!(second.bus, 1);
        assert_eq!(second.kind, RecordKind::Can);
        assert_eq!(second.id_flags & ID_ARB_MASK, 0x18FF_50E5);
        assert!(second.id_flags & ID_EXTENDED != 0);
        assert!(second.id_flags & ID_FD != 0);
        assert!(second.id_flags & ID_TX != 0, "a frame this server sent");
        assert_eq!(second.payload.len(), RecordKind::Can.max_payload());

        let third = &batch.records[2];
        assert_eq!(
            (third.kind, third.flags, third.bus),
            (RecordKind::Modbus, FLAG_CRC_VALID, 2)
        );
        assert_eq!(modbus_unit_func(third.id_flags), (1, 0x20));
        assert_eq!(third.id_flags & ID_TX, 0, "a tap sends nothing");
        assert_eq!(third.payload.len(), 11);

        assert_eq!(
            record_id_fields(second.id_flags),
            (0x18FF_50E5, true, true, true),
            "the inverse of record_id_flags"
        );
    }

    /// The saturation this asserts against is what a field defect looked like:
    /// a batch based on its first frame rather than its earliest filed every
    /// older frame at the head's time. A release build still saturates rather
    /// than wrapping, which is why the caller is where the invariant lives and
    /// this is only the backstop.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the base must be the batch's earliest frame")]
    fn a_record_before_the_base_is_a_caller_error() {
        encode_record_into(
            &mut Vec::new(),
            5_000,
            1_000,
            RecordKind::Can,
            0,
            0,
            0x123,
            &[],
        );
    }

    /// A payload longer than its kind allows is truncated on encode, not
    /// refused — and refused on parse, so the two ends agree on the cap.
    #[test]
    fn a_modbus_payload_may_be_256_bytes_and_a_can_one_may_not() {
        let mut records = Vec::new();
        encode_record_into(&mut records, 0, 0, RecordKind::Can, 0, 0, 0x1, &[0xFF; 200]);
        assert_eq!(records.len(), record_wire_len(RecordKind::Can, 200));
        assert_eq!(u16::from_le_bytes([records[7], records[8]]), 64);

        let mut records = Vec::new();
        encode_record_into(
            &mut records,
            0,
            0,
            RecordKind::Modbus,
            0,
            0,
            0x1,
            &[0xFF; 300],
        );
        assert_eq!(records.len(), record_wire_len(RecordKind::Modbus, 300));
        let batch = parse_batch(&[batch_header(1, 0, 1), records].concat(), 256)
            .unwrap()
            .unwrap();
        assert_eq!(batch.records[0].payload.len(), 256);

        // The same 256 bytes claimed by a CAN record are over its cap.
        let mut body = batch_header(4, 0, 1);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&256u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&[0; 256]);
        assert!(matches!(parse_batch(&body, 256), Some(Err(4))));
    }

    /// The arithmetic [`fit_batch`] has to respect: a batch of
    /// full-size Modbus records does not fit the length field, and a batch of
    /// full-size CAN records does — which is why the byte bound was never hit
    /// before there was a second kind.
    #[test]
    fn a_full_modbus_batch_would_not_fit_a_frame() {
        let modbus = BATCH_HEADER + MAX_BATCH_RECORDS * record_wire_len(RecordKind::Modbus, 256);
        let can = BATCH_HEADER + MAX_BATCH_RECORDS * record_wire_len(RecordKind::Can, 64);
        assert!(
            modbus > MAX_BODY,
            "{modbus} fits, so the byte bound is dead code"
        );
        assert!(
            can <= MAX_BODY,
            "{can} does not fit, so CAN batching would have to split"
        );
    }

    fn can_at(ts_us: u64) -> (u64, RecordKind, usize) {
        (ts_us, RecordKind::Can, 8)
    }

    #[test]
    fn a_batch_splits_at_the_record_count() {
        let fit = fit_batch((0..300).map(can_at));
        assert_eq!(
            fit,
            BatchFit {
                len: MAX_BATCH_RECORDS,
                base_ts_us: 0
            }
        );
    }

    #[test]
    fn a_batch_may_span_exactly_a_u32_of_microseconds() {
        let span = u64::from(u32::MAX);
        assert_eq!(fit_batch([can_at(0), can_at(span)]).len, 2);
        assert_eq!(fit_batch([can_at(0), can_at(span + 1), can_at(1)]).len, 1);
    }

    /// A disk-cache drain reorders stamps, so the span is max − min and the
    /// base is the earliest, not the first.
    #[test]
    fn an_out_of_order_span_is_measured_from_the_earliest() {
        let span = u64::from(u32::MAX);
        let frames = [can_at(1_000), can_at(0), can_at(span), can_at(span + 1)];
        assert_eq!(
            fit_batch(frames),
            BatchFit {
                len: 3,
                base_ts_us: 0
            }
        );
    }

    /// 243 full-size Modbus records leave 153 bytes, which a 140-byte payload
    /// fills to the byte and a 141-byte one overruns.
    #[test]
    fn a_batch_splits_at_the_byte_the_body_overruns() {
        let full = (0, RecordKind::Modbus, 256);
        let batch = |last: usize| {
            let frames = std::iter::repeat_n(full, 243);
            fit_batch(frames.chain([(0, RecordKind::Modbus, last), full]))
        };
        let wire = |n| record_wire_len(RecordKind::Modbus, n);
        assert_eq!(BATCH_HEADER + 243 * wire(256) + wire(140), MAX_BODY);
        assert_eq!(batch(140).len, 244);
        assert_eq!(batch(141).len, 243);
    }

    #[test]
    fn one_frame_always_fits_and_none_is_an_empty_batch() {
        assert_eq!(
            fit_batch([can_at(42)]),
            BatchFit {
                len: 1,
                base_ts_us: 42
            }
        );
        assert_eq!(
            fit_batch([]),
            BatchFit {
                len: 0,
                base_ts_us: 0
            }
        );
    }

    #[test]
    fn acks_round_trip() {
        let mut buf = encode_hello_ack(HELLO_BAD_AUTH, 2, 42, &[]).unwrap();
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(
            parse_hello_ack(&frame.body).unwrap(),
            HelloAck {
                status: HELLO_BAD_AUTH,
                accepted_version: 2,
                server_time_us: 42,
                assignments: Vec::new(),
            }
        );

        let mut buf = encode_ack(9, ACK_OVERLOADED, 87);
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert_eq!(
            parse_ack(&frame.body).unwrap(),
            Ack {
                seq: 9,
                status: ACK_OVERLOADED,
                queue_pct: 87,
            }
        );
    }

    #[test]
    fn a_truncated_reply_is_an_error_rather_than_a_panic() {
        assert!(parse_hello_ack(&[0, 1]).is_err());
        assert!(parse_ack(&[0, 0, 0]).is_err());
    }

    /// The three flags and the id must partition the word: no overlap, and
    /// nothing spare. An overlap would let a 29-bit id set a flag; a gap would
    /// be a bit the protocol cannot spell, which is the constraint that makes a
    /// new message type the only way to carry anything but a CAN frame.
    #[test]
    fn the_flags_and_the_id_partition_the_word() {
        assert_eq!(ID_ARB_MASK | ID_EXTENDED | ID_FD | ID_TX, u32::MAX, "a gap");
        assert_eq!(ID_ARB_MASK & (ID_EXTENDED | ID_FD | ID_TX), 0, "an overlap");
    }

    #[test]
    fn can_record_fields_round_trip() {
        let fields = RecordFields::Can {
            arb_id: 0x18DA_F110,
            extended: true,
            fd: true,
            transmitted: true,
        };
        let (id_flags, flags) = fields.to_wire();
        assert_eq!((id_flags, flags), (0xF8DA_F110, 0));
        assert_eq!(
            RecordFields::from_wire(RecordKind::Can, id_flags, flags),
            fields
        );
        assert_eq!(fields.kind(), RecordKind::Can);
        let std_rx = RecordFields::Can {
            arb_id: 0x7FF,
            extended: false,
            fd: false,
            transmitted: false,
        };
        assert_eq!(std_rx.to_wire(), (0x7FF, 0));
        assert_eq!(RecordFields::from_wire(RecordKind::Can, 0x7FF, 0), std_rx);
    }

    #[test]
    fn modbus_record_fields_round_trip_with_dir_in_bit_31() {
        let fields = RecordFields::Modbus {
            unit: 0x01,
            func: 0x20,
            crc_valid: true,
            transmitted: false,
        };
        assert_eq!(fields.to_wire(), (0x0120, FLAG_CRC_VALID));
        assert_eq!(
            RecordFields::from_wire(RecordKind::Modbus, 0x0120, FLAG_CRC_VALID),
            fields
        );
        assert_eq!(fields.kind(), RecordKind::Modbus);
        let sent = RecordFields::Modbus {
            unit: 0xF7,
            func: 0x03,
            crc_valid: false,
            transmitted: true,
        };
        assert_eq!(sent.to_wire(), (ID_TX | 0xF703, 0));
        assert_eq!(
            RecordFields::from_wire(RecordKind::Modbus, ID_TX | 0xF703, 0),
            sent
        );
    }

    #[test]
    fn a_database_name_is_a_lowercase_letter_then_up_to_62_more() {
        for ok in ["a", "wiretap", "vehicle_1", "a_", &"x".repeat(63)] {
            assert!(valid_database_name(ok), "{ok:?}");
        }
        let too_long = "x".repeat(64);
        for bad in [
            "",
            too_long.as_str(),
            "1leading_digit",
            "_leading_underscore",
            "Upper",
            "lowerThenUpper",
            "has-dash",
            "has space",
            "name;drop table",
            "é",
        ] {
            assert!(!valid_database_name(bad), "{bad:?}");
        }
    }

    // --- against the server's crate --------------------------------------

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// What WireTAP-Server's `wiretap-ingest-proto` encoded at `27c877a`, the
    /// last commit before the codec moved here, from the same calls.
    #[test]
    fn the_encoders_match_the_server_crate_byte_for_byte() {
        assert_eq!(encode_message(MSG_PING, b""), unhex("01000337be0b4b"));
        assert_eq!(
            v2_hello(b"sekrit", "vehicle_1", false),
            unhex("1800015754415002000673656b7269740976656869636c655f3180bea49a")
        );
        assert_eq!(
            v2_hello(b"k", "", true),
            unhex("0a0001575441500201016b00af485260")
        );
        assert_eq!(
            encode_hello_ack(HELLO_BAD_AUTH, 2, 42, &[]).unwrap(),
            unhex("0b008101022a0000000000000095666a74")
        );
        assert_eq!(
            encode_ack(9, ACK_OVERLOADED, 87),
            unhex("070082090000000357f9e2c87b")
        );
        let (here, server) = server_batch();
        assert_eq!(here, server);
    }

    /// The server's batch, encoded here, and its bytes as the server encoded it.
    fn server_batch() -> (Vec<u8>, Vec<u8>) {
        const BASE: u64 = 1_700_000_000_000_000;
        let mut records = Vec::new();
        encode_record_into(
            &mut records,
            BASE,
            BASE,
            RecordKind::Can,
            0,
            0,
            record_id_flags(0x123, false, false, false),
            &[1, 2, 3],
        );
        encode_record_into(
            &mut records,
            BASE,
            BASE + 1000,
            RecordKind::Can,
            0,
            1,
            record_id_flags(0x18FF_50E5, true, true, true),
            &[0xAA; 12],
        );
        encode_record_into(
            &mut records,
            BASE,
            BASE + 2000,
            RecordKind::Modbus,
            FLAG_CRC_VALID,
            2,
            modbus_id(1, 0x20),
            &[
                0x01, 0x20, 0x01, 0xC8, 0x03, 0x11, 0x1A, 0x00, 0x02, 0xE4, 0xCA,
            ],
        );
        (
            encode_batch(7, BASE, 3, &records),
            unhex(
                "5000020700000000401e18240a0600030000000000000000030023010000010203\
                 e80300000000010c00e550fff8aaaaaaaaaaaaaaaaaaaaaaaa\
                 d00700000101020b0020010000012001c803111a0002e4ca3d94ba23",
            ),
        )
    }

    /// The other direction: the server's bytes parse to what it encoded.
    #[test]
    fn the_server_crates_batch_parses_here() {
        let mut buf = server_batch().1;
        let frame = take_frame(&mut buf).unwrap().unwrap();
        assert!(frame.crc_ok);
        let batch = parse_batch(&frame.body, MAX_BATCH_RECORDS)
            .unwrap()
            .unwrap();
        assert_eq!((batch.seq, batch.base_ts_us), (7, 1_700_000_000_000_000));
        let deltas: Vec<u32> = batch.records.iter().map(|r| r.delta_us).collect();
        assert_eq!(deltas, [0, 1000, 2000]);
        assert_eq!(
            record_id_fields(batch.records[1].id_flags),
            (0x18FF_50E5, true, true, true)
        );
        assert_eq!(batch.records[1].payload, [0xAA; 12]);
        assert_eq!(batch.records[2].kind, RecordKind::Modbus);
        assert_eq!(modbus_unit_func(batch.records[2].id_flags), (1, 0x20));
    }

    // --- version 3 -------------------------------------------------------

    fn device(bus: u8, name: &str) -> Device {
        Device {
            bus,
            name: name.into(),
        }
    }

    fn v3_hello(daemon_id: &str, devices: Vec<Device>) -> Hello {
        Hello {
            version: 3,
            time_relative: false,
            token: b"k".to_vec(),
            database: String::new(),
            daemon_id: daemon_id.into(),
            devices,
        }
    }

    fn body_of(msg: &[u8]) -> Vec<u8> {
        parse_frame(msg).unwrap().unwrap().0.body
    }

    fn sha() -> [u8; 20] {
        std::array::from_fn(|i| i as u8)
    }

    #[test]
    fn a_v3_hello_matches_its_golden_bytes_and_round_trips() {
        let hello = v3_hello(
            "bench-1",
            vec![device(0, "can0"), device(2, "/dev/ttyUSB0")],
        );
        let msg = encode_hello(&hello).unwrap();
        assert_eq!(
            msg,
            unhex(
                "270001575441500300016b000762656e63682d3102000463616e30\
                 020c2f6465762f74747955534230f474163b"
            )
        );
        assert_eq!(parse_hello(&body_of(&msg)), Ok(hello));

        let mut anonymous = v3_hello("", Vec::new());
        anonymous.time_relative = true;
        let msg = encode_hello(&anonymous).unwrap();
        assert_eq!(msg, unhex("0c0001575441500301016b0000009d1036b6"));
        assert_eq!(parse_hello(&body_of(&msg)), Ok(anonymous));
    }

    #[test]
    fn a_v3_hello_carries_every_field() {
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(&[3, 0, 1, b'k']);
        assert_eq!(parse_hello(&body), Err("truncated database".into()));
        body.push(0);
        assert_eq!(parse_hello(&body), Err("truncated daemon id".into()));
        body.push(0);
        assert_eq!(parse_hello(&body), Err("truncated device count".into()));
        body.extend_from_slice(&[1, 0, 4, b'c']);
        assert_eq!(parse_hello(&body), Err("truncated device name".into()));
    }

    #[test]
    fn a_v3_hello_with_a_bad_id_or_device_map_does_not_parse_or_encode() {
        for (id, devices) in [
            ("Bench", vec![]),
            ("-bench", vec![]),
            ("bench 1", vec![]),
            ("bench", vec![device(0, "")]),
            ("bench", vec![device(0, "can0"), device(0, "can1")]),
            ("bench", vec![device(0, "can0"), device(1, "can0")]),
            ("", vec![device(0, "can0")]),
        ] {
            let hello = v3_hello(id, devices.clone());
            assert!(encode_hello(&hello).is_err(), "{id:?} {devices:?}");

            let mut body = hello_body(b"k", "", 0);
            body[4] = 3;
            body.push(id.len() as u8);
            body.extend_from_slice(id.as_bytes());
            body.push(devices.len() as u8);
            for d in &devices {
                body.extend_from_slice(&[d.bus, d.name.len() as u8]);
                body.extend_from_slice(d.name.as_bytes());
            }
            assert!(parse_hello(&body).is_err(), "{id:?} {devices:?}");
        }
    }

    #[test]
    fn a_v2_hello_has_no_daemon_id_or_devices() {
        let mut hello = Hello::v2(b"k", "", false);
        hello.daemon_id = "bench".into();
        assert!(encode_hello(&hello).is_err());
    }

    #[test]
    fn a_hello_over_the_length_field_is_refused() {
        let name = |bus: u8| format!("{bus:0>255}");
        let fits = (0..254).map(|bus| device(bus, &name(bus))).collect();
        assert!(encode_hello(&v3_hello("bench", fits)).is_ok());
        let over = (0..255).map(|bus| device(bus, &name(bus))).collect();
        assert_eq!(
            encode_hello(&v3_hello("bench", over)),
            Err("a HELLO of 65551 bytes is over the length field".into())
        );
        let mut long_token = v3_hello("", Vec::new());
        long_token.token = vec![0; 256];
        assert!(encode_hello(&long_token).is_err());
    }

    #[test]
    fn a_daemon_id_is_a_lowercase_letter_or_digit_then_up_to_62_more() {
        for ok in ["a", "0", "bench-1", "site.rack_2", &"x".repeat(63)] {
            assert!(valid_daemon_id(ok), "{ok:?}");
        }
        let too_long = "x".repeat(64);
        for bad in ["", &too_long, ".a", "_a", "-a", "Upper", "has space", "é"] {
            assert!(!valid_daemon_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_v3_hello_ack_matches_its_golden_bytes_and_round_trips() {
        let assignments = [
            Assignment {
                bus: 0,
                blob_sha: [0x11; 20],
            },
            Assignment {
                bus: 2,
                blob_sha: sha(),
            },
        ];
        let msg = encode_hello_ack(HELLO_OK, 3, 42, &assignments).unwrap();
        assert_eq!(
            msg,
            unhex(
                "36008100032a000000000000000200111111111111111111111111111111111111111102\
                 000102030405060708090a0b0c0d0e0f10111213421f1630"
            )
        );
        assert_eq!(
            parse_hello_ack(&body_of(&msg)),
            Ok(HelloAck {
                status: HELLO_OK,
                accepted_version: 3,
                server_time_us: 42,
                assignments: assignments.to_vec(),
            })
        );
        assert_eq!(
            encode_hello_ack(HELLO_OK, 3, 42, &[]).unwrap(),
            unhex("0c008100032a0000000000000000de565f7c")
        );
    }

    #[test]
    fn only_an_ok_v3_hello_ack_carries_assignments() {
        let one = [Assignment {
            bus: 0,
            blob_sha: sha(),
        }];
        assert_eq!(
            encode_hello_ack(HELLO_OK, 2, 42, &one).unwrap(),
            encode_hello_ack(HELLO_OK, 2, 42, &[]).unwrap()
        );
        let v3 = body_of(&encode_hello_ack(HELLO_OK, 3, 42, &one).unwrap());
        assert!(parse_hello_ack(&v3[..v3.len() - 1]).is_err());
        assert!(
            parse_hello_ack(&v3[..10]).is_err(),
            "a v3 count is required"
        );

        let refused = body_of(&encode_hello_ack(HELLO_BAD_AUTH, 3, 42, &one).unwrap());
        assert_eq!(refused.len(), 10, "a refusal is the v2 shape");
        assert_eq!(
            parse_hello_ack(&refused).unwrap().assignments,
            [],
            "and is read as one"
        );
    }

    #[test]
    fn more_than_255_assignments_are_refused() {
        let many: Vec<_> = (0..=255)
            .map(|bus| Assignment {
                bus,
                blob_sha: sha(),
            })
            .collect();
        assert!(encode_hello_ack(HELLO_OK, 3, 42, &many[..255]).is_ok());
        assert_eq!(
            encode_hello_ack(HELLO_OK, 3, 42, &many),
            Err("256 assignments".into())
        );
    }

    #[test]
    fn a_catalog_get_matches_its_golden_bytes_and_round_trips() {
        let get = CatalogGet {
            blob_sha: sha(),
            offset: 65_504,
        };
        let msg = encode_catalog_get(&get);
        assert_eq!(
            msg,
            unhex("190004000102030405060708090a0b0c0d0e0f10111213e0ff000054cc1c01")
        );
        assert_eq!(parse_catalog_get(&body_of(&msg)), Ok(get));
        assert!(parse_catalog_get(&body_of(&msg)[..23]).is_err());
    }

    #[test]
    fn a_catalog_matches_its_golden_bytes_and_round_trips() {
        let get = CatalogGet {
            blob_sha: sha(),
            offset: 2,
        };
        let msg = encode_catalog(&get, Ok(b"abcde"));
        assert_eq!(
            msg,
            unhex(
                "21008400000102030405060708090a0b0c0d0e0f10111213050000000200000063646535\
                 62c9d6"
            )
        );
        assert_eq!(
            parse_catalog(&body_of(&msg)),
            Ok(Catalog {
                status: CATALOG_OK,
                blob_sha: sha(),
                total_len: 5,
                offset: 2,
                data: b"cde".to_vec(),
            })
        );

        let msg = encode_catalog(&get, Err(CATALOG_UNKNOWN));
        assert_eq!(
            msg,
            unhex("1e008401000102030405060708090a0b0c0d0e0f10111213000000000200000008c23828")
        );
        let refused = parse_catalog(&body_of(&msg)).unwrap();
        assert_eq!((refused.status, refused.data.len()), (CATALOG_UNKNOWN, 0));
        assert_eq!(refused.next(), None);
    }

    #[test]
    fn a_blob_is_paged_at_the_chunk_cap_until_total_len() {
        let blob: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();
        let mut get = Some(CatalogGet {
            blob_sha: sha(),
            offset: 0,
        });
        let (mut assembled, mut chunks) = (Vec::new(), Vec::new());
        while let Some(g) = get {
            let catalog = parse_catalog(&body_of(&encode_catalog(&g, Ok(&blob)))).unwrap();
            assert_eq!((catalog.offset, catalog.total_len), (g.offset, 150_000));
            chunks.push(catalog.data.len());
            assembled.extend_from_slice(&catalog.data);
            get = catalog.next();
        }
        assert_eq!(chunks, [MAX_CATALOG_CHUNK, MAX_CATALOG_CHUNK, 18_992]);
        assert_eq!(assembled, blob);
    }

    #[test]
    fn an_empty_blob_is_one_empty_chunk() {
        let get = CatalogGet {
            blob_sha: sha(),
            offset: 0,
        };
        let catalog = parse_catalog(&body_of(&encode_catalog(&get, Ok(&[])))).unwrap();
        assert_eq!((catalog.total_len, catalog.next()), (0, None));
    }

    #[test]
    fn an_offset_past_the_end_gets_bad_offset_and_the_real_length() {
        let past_end = CatalogGet {
            blob_sha: sha(),
            offset: 6,
        };
        let msg = encode_catalog(&past_end, Ok(b"abcde"));
        assert_eq!(
            msg,
            unhex("1e008403000102030405060708090a0b0c0d0e0f10111213050000000600000073e9b529")
        );
        let catalog = parse_catalog(&body_of(&msg)).unwrap();
        assert_eq!(
            (catalog.status, catalog.total_len, catalog.offset),
            (CATALOG_BAD_OFFSET, 5, 6)
        );
        assert_eq!((catalog.data.len(), catalog.next()), (0, None));

        let at_end = CatalogGet {
            offset: 5,
            ..past_end
        };
        let catalog = parse_catalog(&body_of(&encode_catalog(&at_end, Ok(b"abcde")))).unwrap();
        assert_eq!((catalog.status, catalog.next()), (CATALOG_OK, None));
    }

    #[test]
    fn a_chunk_past_the_end_short_and_empty_or_over_the_cap_does_not_parse() {
        let mut past_end = vec![CATALOG_OK];
        past_end.extend_from_slice(&sha());
        past_end.extend_from_slice(&5u32.to_le_bytes());
        past_end.extend_from_slice(&6u32.to_le_bytes());
        assert!(parse_catalog(&past_end).is_err());

        let mut header = vec![CATALOG_OK];
        header.extend_from_slice(&sha());
        header.extend_from_slice(&100u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_catalog(&header).is_err(), "short of the end, no data");

        let mut over = header.clone();
        over[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
        over.resize(CATALOG_HEADER + MAX_CATALOG_CHUNK, 0);
        assert!(parse_catalog(&over).is_ok());
        over.push(0);
        assert!(parse_catalog(&over).is_err());
    }

    fn status_entry(bus: u8, active: ActiveCatalog) -> CatalogStatusEntry {
        CatalogStatusEntry {
            bus,
            active,
            refused: None,
        }
    }

    fn status_body(entries: &[[u8; 43]]) -> Vec<u8> {
        [&[entries.len() as u8][..], &entries.concat()].concat()
    }

    /// `bus` 0, `source` 1, `active_sha` [`sha`], nothing refused.
    fn raw_entry() -> [u8; 43] {
        let mut entry = [0; 43];
        entry[1] = 1;
        entry[2..22].copy_from_slice(&sha());
        entry
    }

    #[test]
    fn a_catalog_status_matches_its_golden_bytes_and_round_trips() {
        let status = CatalogStatus {
            entries: vec![
                CatalogStatusEntry {
                    refused: Some(([0x22; 20], Refusal::HashMismatch)),
                    ..status_entry(0, ActiveCatalog::Assigned([0x11; 20]))
                },
                status_entry(2, ActiveCatalog::Local(sha())),
                CatalogStatusEntry {
                    refused: Some(([0x33; 20], Refusal::FetchFailed)),
                    ..status_entry(3, ActiveCatalog::None)
                },
            ],
        };
        let msg = encode_catalog_status(&status).unwrap();
        assert_eq!(
            msg,
            unhex(
                "830005030002111111111111111111111111111111111111111122222222222222222222\
                 22222222222222222222010201000102030405060708090a0b0c0d0e0f10111213000000\
                 000000000000000000000000000000000000030000000000000000000000000000000000\
                 000000003333333333333333333333333333333333333333036d4555e6"
            )
        );
        assert_eq!(parse_catalog_status(&body_of(&msg)), Ok(status));

        let empty = CatalogStatus { entries: vec![] };
        let msg = encode_catalog_status(&empty).unwrap();
        assert_eq!(parse_catalog_status(&body_of(&msg)), Ok(empty));
    }

    #[test]
    fn every_refusal_round_trips_and_one_added_later_is_other() {
        for refusal in [
            Refusal::HashMismatch,
            Refusal::DidNotParse,
            Refusal::FetchFailed,
            Refusal::Other(4),
            Refusal::Other(255),
        ] {
            let status = CatalogStatus {
                entries: vec![CatalogStatusEntry {
                    refused: Some((sha(), refusal)),
                    ..status_entry(0, ActiveCatalog::None)
                }],
            };
            let msg = encode_catalog_status(&status).unwrap();
            assert_eq!(parse_catalog_status(&body_of(&msg)), Ok(status));
        }
        let mut entry = raw_entry();
        entry[22..42].copy_from_slice(&sha());
        entry[42] = 4;
        let parsed = parse_catalog_status(&status_body(&[entry])).unwrap();
        assert_eq!(parsed.entries[0].refused, Some((sha(), Refusal::Other(4))));
    }

    #[test]
    fn a_malformed_catalog_status_does_not_parse() {
        let ok = raw_entry();
        assert!(parse_catalog_status(&status_body(&[ok])).is_ok());
        let with = |edit: fn(&mut [u8; 43])| {
            let mut entry = ok;
            edit(&mut entry);
            status_body(&[entry])
        };
        let body = status_body(&[ok]);
        for (bad, why) in [
            (vec![], "no count"),
            (body[..body.len() - 1].to_vec(), "short of 1 + 43 × count"),
            (status_body(&[ok, ok]), "a bus twice"),
            (with(|e| e[1] = 3), "source above 2"),
            (with(|e| e[1] = 0), "source 0 with a SHA"),
            (with(|e| e[2..22].fill(0)), "source 1 with a zero SHA"),
            (
                with(|e| {
                    e[1] = 2;
                    e[2..22].fill(0)
                }),
                "source 2 with a zero SHA",
            ),
            (with(|e| e[30] = 1), "refusal 0 with a SHA"),
            (with(|e| e[42] = 2), "refusal 2 with a zero SHA"),
            (with(|e| e[42] = 9), "refusal 9 with a zero SHA"),
        ] {
            assert!(parse_catalog_status(&bad).is_err(), "{why}");
        }
        let mut trailing = body;
        trailing.push(0xFF);
        assert!(
            parse_catalog_status(&trailing).is_ok(),
            "bytes after the last entry"
        );
    }

    #[test]
    fn a_catalog_status_the_parser_would_refuse_does_not_encode() {
        let entries: Vec<_> = (0..=255)
            .map(|bus| status_entry(bus, ActiveCatalog::Local(sha())))
            .collect();
        assert!(encode_catalog_status(&CatalogStatus {
            entries: entries[..255].to_vec()
        })
        .is_ok());
        assert_eq!(
            encode_catalog_status(&CatalogStatus { entries }),
            Err("256 catalogue status entries".into())
        );
        for entries in [
            vec![status_entry(1, ActiveCatalog::None); 2],
            vec![status_entry(0, ActiveCatalog::Assigned([0; 20]))],
            vec![CatalogStatusEntry {
                refused: Some(([0; 20], Refusal::DidNotParse)),
                ..status_entry(0, ActiveCatalog::None)
            }],
            vec![CatalogStatusEntry {
                refused: Some((sha(), Refusal::Other(1))),
                ..status_entry(0, ActiveCatalog::None)
            }],
        ] {
            assert!(
                encode_catalog_status(&CatalogStatus {
                    entries: entries.clone()
                })
                .is_err(),
                "{entries:?}"
            );
        }
    }

    #[test]
    fn a_close_matches_its_golden_bytes_and_round_trips() {
        let msg = encode_close(CLOSE_REASSIGNED);
        assert_eq!(msg, unhex("02008500f17e2d07"));
        assert_eq!(
            parse_close(&body_of(&msg)),
            Ok(Close {
                reason: CLOSE_REASSIGNED
            })
        );
    }

    #[test]
    fn a_close_with_no_reason_does_not_parse() {
        assert_eq!(parse_close(&[]), Err("truncated CLOSE".into()));
    }

    #[test]
    fn an_unknown_close_reason_parses_and_trailing_bytes_are_ignored() {
        assert_eq!(parse_close(&[0xEE, 1]), Ok(Close { reason: 0xEE }));
    }

    #[test]
    fn a_raw_serial_batch_matches_its_golden_bytes() {
        let mut records = Vec::new();
        encode_record_into(
            &mut records,
            0,
            5,
            RecordKind::RawSerial,
            0,
            3,
            raw_serial_id(u32::MAX),
            &[0x55, 0xAA],
        );
        let msg = encode_batch(1, 0, 1, &records);
        assert_eq!(
            msg,
            unhex("1e00020100000000000000000000000100050000000200030200ffffff7f55aa0b70e0d2")
        );
        let batch = parse_batch(&body_of(&msg), MAX_BATCH_RECORDS)
            .unwrap()
            .unwrap();
        let r = &batch.records[0];
        assert_eq!(
            (r.kind, r.bus, r.payload.as_slice()),
            (RecordKind::RawSerial, 3, &[0x55, 0xAA][..])
        );
        assert_eq!(
            RecordFields::from_wire(r.kind, r.id_flags, r.flags),
            RecordFields::RawSerial {
                seq: 0x7FFF_FFFF,
                transmitted: false
            }
        );
    }

    #[test]
    fn kind_2_is_malformed_in_a_v2_batch() {
        let mut records = Vec::new();
        encode_record_into(&mut records, 0, 0, RecordKind::RawSerial, 0, 0, 1, &[1]);
        let body = [batch_header(6, 0, 1), records].concat();
        assert!(parse_batch(&body, 256).unwrap().is_ok());
        assert!(matches!(parse_batch_v2(&body, 256), Some(Err(6))));
        assert!(matches!(batch_parser(2).unwrap()(&body, 256), Some(Err(6))));
    }

    #[test]
    fn a_raw_serial_payload_is_1_to_256_bytes() {
        let batch_of_one = |len: usize| {
            let mut body = batch_header(4, 0, 1);
            body.extend_from_slice(&[0, 0, 0, 0, 2, 0, 0]);
            body.extend_from_slice(&(len as u16).to_le_bytes());
            body.extend_from_slice(&[0; 4]);
            body.extend_from_slice(&vec![0; len]);
            parse_batch(&body, 256).unwrap()
        };
        assert!(batch_of_one(1).is_ok());
        assert!(batch_of_one(256).is_ok());
        assert!(matches!(batch_of_one(0), Err(4)));
        assert!(matches!(batch_of_one(257), Err(4)));
    }

    #[test]
    fn the_read_sequence_wraps_at_2_31_and_leaves_dir_alone() {
        assert_eq!(raw_serial_id(0x7FFF_FFFF), 0x7FFF_FFFF);
        assert_eq!(raw_serial_id(0x8000_0000), 0);
        assert_eq!(raw_serial_id(0x8000_0005), 5);
        let sent = RecordFields::RawSerial {
            seq: 0x8000_0005,
            transmitted: true,
        };
        assert_eq!(sent.to_wire(), (ID_TX | 5, 0));
        assert_eq!(
            RecordFields::from_wire(RecordKind::RawSerial, ID_TX | 5, 0),
            RecordFields::RawSerial {
                seq: 5,
                transmitted: true
            }
        );
        assert_eq!(ID_SEQ_MASK | ID_TX, u32::MAX);
    }

    // --- re-basing -------------------------------------------------------

    fn batch_of(base_ts_us: u64, deltas: &[u32]) -> Batch {
        Batch {
            seq: 0,
            base_ts_us,
            records: deltas
                .iter()
                .map(|&delta_us| Record {
                    delta_us,
                    kind: RecordKind::Can,
                    flags: 0,
                    bus: 0,
                    id_flags: 0,
                    payload: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_relative_batch_stamps_its_newest_record_at_arrival() {
        let batch = batch_of(0, &[0, 400, 1000]);
        assert_eq!(batch.base_ts_us(true, 50_000), 49_000);
    }

    /// Two buses interleaved: the newest record is not the last one.
    #[test]
    fn the_newest_record_is_the_largest_delta_not_the_last() {
        let batch = batch_of(0, &[100, 1000, 300, 700]);
        let base = batch.base_ts_us(true, 50_000);
        assert_eq!(base, 49_000);
        let newest = batch.records.iter().map(|r| base + u64::from(r.delta_us));
        assert_eq!(newest.max(), Some(50_000));
    }

    #[test]
    fn an_absolute_batch_keeps_its_own_base() {
        let batch = batch_of(1_700_000_000_000_000, &[0, 1000]);
        assert_eq!(batch.base_ts_us(false, 50_000), 1_700_000_000_000_000);
    }

    #[test]
    fn an_empty_relative_batch_is_based_at_arrival() {
        assert_eq!(batch_of(0, &[]).base_ts_us(true, 50_000), 50_000);
    }

    /// A clock reading before the epoch, or a delta past it, bases the batch
    /// at the epoch rather than wrapping to the far future.
    #[test]
    fn a_delta_beyond_arrival_saturates_at_the_epoch() {
        assert_eq!(batch_of(0, &[2_000]).base_ts_us(true, 500), 0);
    }

    fn stamps(batch: Batch, time_relative: bool, arrival_us: u64) -> Vec<u64> {
        batch
            .stamped(time_relative, arrival_us)
            .map(|(ts_us, _)| ts_us)
            .collect()
    }

    #[test]
    fn a_relative_batch_is_stamped_back_from_arrival() {
        assert_eq!(
            stamps(batch_of(0, &[100, 1000, 300]), true, 50_000),
            [49_100, 50_000, 49_300]
        );
    }

    #[test]
    fn an_absolute_batch_is_stamped_from_its_own_base() {
        assert_eq!(
            stamps(batch_of(1_700_000_000_000_000, &[0, 1000]), false, 50_000),
            [1_700_000_000_000_000, 1_700_000_000_001_000]
        );
    }

    #[test]
    fn a_stamp_past_u64_max_saturates() {
        assert_eq!(
            stamps(batch_of(u64::MAX - 10, &[0, 100]), false, 0),
            [u64::MAX - 10, u64::MAX]
        );
    }
}
