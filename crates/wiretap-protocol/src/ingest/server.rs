//! The server end of a session, as a sans-io state machine. Feed it what the
//! socket reads with [`ServerSession::receive`], act on what
//! [`ServerSession::poll`] returns, and write what [`ServerSession::answer_hello`],
//! [`ServerSession::ack`] and [`ServerSession::answer_catalog`] return.
//!
//! Authentication, the database, an ACK's status and `queue_pct`, and the idle
//! timeout stay the caller's; the machine reads no clock. Everything else a
//! gateway and a capture daemon must agree on is here, with their differences
//! as [`ServerConfig`] options.

use std::ops::RangeInclusive;
use std::time::Duration;

use super::*;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// The `HELLO` versions taken. A refusal names the newest of them. Not
    /// empty, and ending at most at [`PROTO_VERSION`]: [`ServerSession::new`]
    /// panics otherwise.
    pub versions: RangeInclusive<u8>,
    /// Records per `BATCH`; clamped to at least 1.
    pub max_records: usize,
    pub short_batch: ShortBatch,
    /// Keepalive × 3, handed back by [`ServerSession::idle_limit`].
    pub idle_limit: Option<Duration>,
}

/// What a `BATCH` too short to carry its header gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortBatch {
    Close,
    /// An [`ACK_MALFORMED`] for seq 0, and the session carries on.
    NackSeqZero,
}

/// What the caller does next. After [`Action::Hello`] or
/// [`Action::HelloRefused`], `poll` returns `None` until
/// [`ServerSession::answer_hello`]; after [`Action::Batch`] or [`Action::Nack`],
/// until [`ServerSession::ack`]; after [`Action::CatalogGet`], until
/// [`ServerSession::answer_catalog`]. [`Action::CatalogStatus`] owes nothing.
#[derive(Debug)]
pub enum Action {
    Reply(Vec<u8>),
    /// Authenticate it and route its database; [`ServerSession::version`] is
    /// `Some` when a `HELLO` was already accepted.
    Hello(Hello),
    /// A `HELLO` the machine refuses itself, with this status.
    HelloRefused(u8),
    Batch(IncomingBatch),
    /// A `BATCH` refused with this status; its bytes come from `ack`.
    Nack {
        seq: u32,
        status: u8,
    },
    /// Look the blob up; a version 3 session only.
    CatalogGet(CatalogGet),
    /// Replace the session's catalogue status with this; a version 3 session only.
    CatalogStatus(CatalogStatus),
    /// Close the connection, after writing anything already returned.
    Close(CloseReason),
}

#[derive(Debug)]
pub struct IncomingBatch {
    pub batch: Batch,
    /// From the latest accepted `HELLO`, as is `version`.
    pub time_relative: bool,
    pub version: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Framing,
    BadHello,
    BatchBeforeHello,
    CatalogGetBeforeHello,
    BadCatalogGet,
    CatalogStatusBeforeHello,
    BadCatalogStatus,
    ShortBatch,
    Refused(u8),
    /// The caller's, from [`ServerSession::close_reassigned`].
    Reassigned,
}

#[derive(Debug)]
struct Accepted {
    hello: Hello,
    parser: BatchParser,
}

#[derive(Debug)]
enum Gate {
    Open,
    /// `None` when the machine refused the version itself.
    Hello(Option<Accepted>),
    Ack(u32),
    Catalog(CatalogGet),
    Closing(CloseReason),
    Closed,
}

#[derive(Debug)]
pub struct ServerSession {
    config: ServerConfig,
    buf: Vec<u8>,
    read: usize,
    gate: Gate,
    accepted: Option<Accepted>,
    reassigned: bool,
}

impl ServerSession {
    pub fn new(mut config: ServerConfig) -> Self {
        assert!(
            !config.versions.is_empty() && *config.versions.end() <= PROTO_VERSION,
            "ServerConfig::versions {:?} must be non-empty and end at most at {PROTO_VERSION}",
            config.versions
        );
        config.max_records = config.max_records.max(1);
        Self {
            config,
            buf: Vec::new(),
            read: 0,
            gate: Gate::Open,
            accepted: None,
            reassigned: false,
        }
    }

    pub fn idle_limit(&self) -> Option<Duration> {
        self.config.idle_limit
    }

    pub fn receive(&mut self, bytes: &[u8]) {
        if matches!(self.gate, Gate::Closed) {
            return;
        }
        // Moves no more than was consumed since the last move, so stays linear.
        if self.read * 2 >= self.buf.len() {
            self.buf.drain(..self.read);
            self.read = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    pub fn poll(&mut self) -> Option<Action> {
        match self.gate {
            Gate::Open if self.reassigned => return Some(self.close(CloseReason::Reassigned)),
            Gate::Open => {}
            Gate::Closing(reason) => return Some(self.close(reason)),
            _ => return None,
        }
        loop {
            let frame = match parse_frame(&self.buf[self.read..]) {
                Ok(Some((frame, consumed))) => {
                    self.read += consumed;
                    frame
                }
                Ok(None) => return None,
                Err(_) => return Some(self.close(CloseReason::Framing)),
            };
            if let Some(action) = self.handle(frame) {
                return Some(action);
            }
        }
    }

    /// The `HELLO_ACK` for the owed verdict, with `assignments` if it is
    /// [`HELLO_OK`] for version 3. A refusal closes the session. More than 255
    /// assignments are an `Err`, and the verdict is still owed.
    pub fn answer_hello(
        &mut self,
        status: u8,
        server_time_us: u64,
        assignments: &[Assignment],
    ) -> Result<Vec<u8>, String> {
        debug_assert!(
            matches!(self.gate, Gate::Hello(_)),
            "no HELLO verdict is owed, {:?} is",
            self.gate
        );
        let newest = *self.config.versions.end();
        let gate = std::mem::replace(&mut self.gate, Gate::Open);
        let Gate::Hello(pending) = gate else {
            self.gate = gate;
            return encode_hello_ack(status, newest, server_time_us, &[]);
        };
        let version = pending.as_ref().map_or(newest, |p| p.hello.version);
        match pending {
            Some(pending) if status == HELLO_OK => {
                let ack = encode_hello_ack(status, version, server_time_us, assignments);
                match ack {
                    Ok(_) => self.accepted = Some(pending),
                    Err(_) => self.gate = Gate::Hello(Some(pending)),
                }
                ack
            }
            pending => {
                debug_assert!(
                    pending.is_some() || status == HELLO_BAD_VERSION,
                    "the machine refused this HELLO's version, not {status}"
                );
                let status = pending.map_or(HELLO_BAD_VERSION, |_| status);
                self.gate = Gate::Closing(CloseReason::Refused(status));
                encode_hello_ack(status, version, server_time_us, &[])
            }
        }
    }

    /// The `ACK` for the owed batch or `Nack`.
    pub fn ack(&mut self, seq: u32, status: u8, queue_pct: u8) -> Vec<u8> {
        debug_assert!(
            matches!(self.gate, Gate::Ack(owed) if owed == seq),
            "ACK for seq {seq}, but {:?} is owed",
            self.gate
        );
        if matches!(self.gate, Gate::Ack(_)) {
            self.gate = Gate::Open;
        }
        encode_ack(seq, status, queue_pct)
    }

    /// The `CATALOG` for the owed `CATALOG_GET`: `blob`'s chunk at its offset,
    /// or no data and `Err`'s status. Nothing when none is owed.
    pub fn answer_catalog(&mut self, blob: Result<&[u8], u8>) -> Vec<u8> {
        debug_assert!(
            matches!(self.gate, Gate::Catalog(_)),
            "no CATALOG is owed, {:?} is",
            self.gate
        );
        let Gate::Catalog(get) = self.gate else {
            return Vec::new();
        };
        self.gate = Gate::Open;
        encode_catalog(&get, blob)
    }

    /// Close once any owed reply is answered: the session's catalogue
    /// assignment changed, and a reconnect reads the new one.
    pub fn close_reassigned(&mut self) {
        self.reassigned = true;
    }

    /// The version of the latest accepted `HELLO`.
    pub fn version(&self) -> Option<u8> {
        self.hello().map(|h| h.version)
    }

    /// The latest accepted `HELLO`, whose daemon id and device map the
    /// session's batches and catalogue requests come under.
    pub fn hello(&self) -> Option<&Hello> {
        self.accepted.as_ref().map(|a| &a.hello)
    }

    fn close(&mut self, reason: CloseReason) -> Action {
        self.gate = Gate::Closed;
        self.buf = Vec::new();
        self.read = 0;
        Action::Close(reason)
    }

    fn nack(&mut self, seq: u32, status: u8) -> Option<Action> {
        self.gate = Gate::Ack(seq);
        Some(Action::Nack { seq, status })
    }

    fn handle(&mut self, frame: WireFrame) -> Option<Action> {
        if !frame.crc_ok {
            if frame.mtype == MSG_BATCH && frame.body.len() >= 4 {
                let seq = u32::from_le_bytes(frame.body[0..4].try_into().unwrap());
                return self.nack(seq, ACK_CRC);
            }
            return None;
        }
        match frame.mtype {
            MSG_HELLO => Some(self.take_hello(&frame.body)),
            MSG_PING => Some(Action::Reply(encode_message(MSG_PONG, b""))),
            MSG_BATCH => self.batch(&frame.body),
            MSG_CATALOG_GET => self.catalog_get(&frame.body),
            MSG_CATALOG_STATUS => self.catalog_status(&frame.body),
            _ => None,
        }
    }

    fn take_hello(&mut self, body: &[u8]) -> Action {
        let Ok(hello) = parse_hello(body) else {
            return self.close(CloseReason::BadHello);
        };
        let version = hello.version;
        let accepted = batch_parser(version)
            .filter(|_| self.config.versions.contains(&version))
            .map(|parser| Accepted {
                hello: hello.clone(),
                parser,
            });
        let action = match accepted {
            Some(_) => Action::Hello(hello),
            None => Action::HelloRefused(HELLO_BAD_VERSION),
        };
        self.gate = Gate::Hello(accepted);
        action
    }

    fn batch(&mut self, body: &[u8]) -> Option<Action> {
        let Some(session) = &self.accepted else {
            return Some(self.close(CloseReason::BatchBeforeHello));
        };
        let (time_relative, version) = (session.hello.time_relative, session.hello.version);
        match (session.parser)(body, self.config.max_records) {
            Some(Ok(batch)) => {
                self.gate = Gate::Ack(batch.seq);
                Some(Action::Batch(IncomingBatch {
                    batch,
                    time_relative,
                    version,
                }))
            }
            Some(Err(seq)) => self.nack(seq, ACK_MALFORMED),
            None => match self.config.short_batch {
                ShortBatch::Close => Some(self.close(CloseReason::ShortBatch)),
                ShortBatch::NackSeqZero => self.nack(0, ACK_MALFORMED),
            },
        }
    }

    /// A version 3 message, or `Err` the close: before `HELLO`, or when it does
    /// not parse. An unknown type to an older session, so `None` there.
    fn v3_message<T>(
        &mut self,
        body: &[u8],
        parse: fn(&[u8]) -> Result<T, String>,
        before_hello: CloseReason,
        malformed: CloseReason,
    ) -> Option<Result<T, Action>> {
        let Some(session) = &self.accepted else {
            return Some(Err(self.close(before_hello)));
        };
        if !is_v3(session.hello.version) {
            return None;
        }
        Some(parse(body).map_err(|_| self.close(malformed)))
    }

    fn catalog_get(&mut self, body: &[u8]) -> Option<Action> {
        let parsed = self.v3_message(
            body,
            parse_catalog_get,
            CloseReason::CatalogGetBeforeHello,
            CloseReason::BadCatalogGet,
        )?;
        Some(match parsed {
            Ok(get) => {
                self.gate = Gate::Catalog(get);
                Action::CatalogGet(get)
            }
            Err(close) => close,
        })
    }

    fn catalog_status(&mut self, body: &[u8]) -> Option<Action> {
        let parsed = self.v3_message(
            body,
            parse_catalog_status,
            CloseReason::CatalogStatusBeforeHello,
            CloseReason::BadCatalogStatus,
        )?;
        Some(parsed.map_or_else(|close| close, Action::CatalogStatus))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 1_700_000_000_000_000;

    fn daemon() -> ServerSession {
        ServerSession::new(ServerConfig {
            versions: 2..=3,
            max_records: MAX_BATCH_RECORDS,
            short_batch: ShortBatch::Close,
            idle_limit: Some(Duration::from_secs(90)),
        })
    }

    fn gateway() -> ServerSession {
        ServerSession::new(ServerConfig {
            versions: 2..=3,
            max_records: MAX_BATCH_RECORDS,
            short_batch: ShortBatch::NackSeqZero,
            idle_limit: None,
        })
    }

    fn with_versions(versions: RangeInclusive<u8>) -> ServerSession {
        ServerSession::new(ServerConfig {
            versions,
            ..gateway().config
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hello_v(version: u8, time_relative: bool) -> Vec<u8> {
        let mut body = MAGIC.to_vec();
        body.extend_from_slice(&[version, u8::from(time_relative), 1, b'k', 0]);
        encode_message(MSG_HELLO, &body)
    }

    fn hello() -> Vec<u8> {
        hello_v(2, false)
    }

    fn batch(seq: u32, records: usize) -> Vec<u8> {
        let mut body = Vec::new();
        for i in 0..records as u64 {
            encode_record_into(
                &mut body,
                BASE,
                BASE + i,
                RecordKind::Can,
                0,
                0,
                0x123,
                &[i as u8],
            );
        }
        encode_batch(seq, BASE, records as u16, &body)
    }

    fn v1_batch(seq: u32) -> Vec<u8> {
        let mut body = seq.to_le_bytes().to_vec();
        body.extend_from_slice(&BASE.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&5u32.to_le_bytes());
        body.extend_from_slice(&0x7E0u32.to_le_bytes());
        body.extend_from_slice(&[0, 1, 0xAA]);
        encode_message(MSG_BATCH, &body)
    }

    fn corrupt(mut msg: Vec<u8>) -> Vec<u8> {
        *msg.last_mut().unwrap() ^= 0xFF;
        msg
    }

    fn accepted(mut s: ServerSession) -> ServerSession {
        s.receive(&hello());
        assert!(matches!(s.poll(), Some(Action::Hello(_))));
        s.answer_hello(HELLO_OK, 0, &[]).unwrap();
        s
    }

    fn closed(s: &mut ServerSession) -> CloseReason {
        match s.poll() {
            Some(Action::Close(reason)) => reason,
            other => panic!("expected a close, got {other:?}"),
        }
    }

    fn nack(s: &mut ServerSession) -> (u32, u8) {
        match s.poll() {
            Some(Action::Nack { seq, status }) => (seq, status),
            other => panic!("expected a NACK, got {other:?}"),
        }
    }

    fn incoming(s: &mut ServerSession) -> IncomingBatch {
        match s.poll() {
            Some(Action::Batch(b)) => b,
            other => panic!("expected a batch, got {other:?}"),
        }
    }

    #[test]
    fn a_ping_gets_a_pong_before_hello_too() {
        for mut s in [daemon(), gateway()] {
            s.receive(&encode_message(MSG_PING, b""));
            let Some(Action::Reply(pong)) = s.poll() else {
                panic!("no PONG")
            };
            assert_eq!(pong, unhex("010083173db3a6"));
            assert!(s.poll().is_none());
        }
    }

    #[test]
    fn a_corrupt_batch_is_nacked_by_seq_before_hello_too() {
        for mut s in [daemon(), gateway()] {
            s.receive(&corrupt(batch(0xDEAD_BEEF, 1)));
            assert_eq!(nack(&mut s), (0xDEAD_BEEF, ACK_CRC));
            assert_eq!(
                s.ack(0xDEAD_BEEF, ACK_CRC, 55),
                unhex("070082efbeadde01372b76b053")
            );
        }
    }

    #[test]
    fn any_other_corrupt_message_is_ignored() {
        for mut s in [daemon(), gateway()] {
            s.receive(&corrupt(encode_message(MSG_BATCH, &[1, 2, 3])));
            s.receive(&corrupt(hello()));
            s.receive(&corrupt(encode_message(MSG_PING, b"")));
            s.receive(&encode_message(0x7F, b"from the future"));
            assert!(s.poll().is_none());
            assert_eq!(s.version(), None);
        }
    }

    #[test]
    fn a_zero_length_frame_closes_and_nothing_after_it_is_read() {
        for mut s in [daemon(), gateway()] {
            s.receive(&[0, 0]);
            s.receive(&encode_message(MSG_PING, b""));
            assert_eq!(closed(&mut s), CloseReason::Framing);
            s.receive(&encode_message(MSG_PING, b""));
            assert!(s.poll().is_none());
        }
    }

    #[test]
    fn a_hello_that_does_not_parse_closes_without_an_answer() {
        for mut s in [daemon(), gateway()] {
            s.receive(&encode_message(MSG_HELLO, b"WTAX\x02\x00\x00"));
            assert_eq!(closed(&mut s), CloseReason::BadHello);
        }
    }

    #[test]
    fn v1_is_taken_only_where_configured() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello_v(1, false));
            assert!(matches!(
                s.poll(),
                Some(Action::HelloRefused(HELLO_BAD_VERSION))
            ));
        }
        let mut s = with_versions(1..=3);
        s.receive(&hello_v(1, false));
        assert!(matches!(s.poll(), Some(Action::Hello(h)) if h.version == 1));
    }

    #[test]
    fn an_unknown_version_is_refused_before_auth_and_closes() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello_v(99, false));
            s.receive(&encode_message(MSG_PING, b""));
            assert!(matches!(
                s.poll(),
                Some(Action::HelloRefused(HELLO_BAD_VERSION))
            ));
            assert!(s.poll().is_none(), "the verdict is owed");
            assert_eq!(
                s.answer_hello(HELLO_BAD_VERSION, 42, &[]).unwrap(),
                unhex("0b008102032a00000000000000d5c92688")
            );
            assert_eq!(closed(&mut s), CloseReason::Refused(HELLO_BAD_VERSION));
            assert!(s.poll().is_none(), "the PING after it is never answered");
        }
    }

    #[test]
    fn an_accepted_hello_answers_ok_and_opens_the_session() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello());
            s.receive(&encode_message(MSG_PING, b""));
            let Some(Action::Hello(h)) = s.poll() else {
                panic!("no HELLO")
            };
            assert_eq!((h.token.as_slice(), h.version), (&b"k"[..], 2));
            assert_eq!(s.version(), None, "not a repeat");
            assert!(s.poll().is_none(), "the verdict is owed");
            assert_eq!(
                s.answer_hello(HELLO_OK, BASE, &[]).unwrap(),
                unhex("0b0081000200401e18240a0600dda3c4aa")
            );
            assert_eq!(s.version(), Some(2));
            assert!(matches!(s.poll(), Some(Action::Reply(_))));
        }
    }

    #[test]
    fn a_hello_the_caller_refuses_closes_after_its_answer() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello());
            assert!(matches!(s.poll(), Some(Action::Hello(_))));
            let ack = s.answer_hello(HELLO_BAD_AUTH, 42, &[]).unwrap();
            assert_eq!(ack, unhex("0b008101022a0000000000000095666a74"));
            assert_eq!(closed(&mut s), CloseReason::Refused(HELLO_BAD_AUTH));
            assert_eq!(s.version(), None);
        }
    }

    #[test]
    fn a_retryable_refusal_closes_like_a_fatal_one() {
        for status in [HELLO_BAD_AUTH, HELLO_BAD_DATABASE, HELLO_UNAVAILABLE] {
            for mut s in [daemon(), gateway()] {
                s.receive(&hello());
                assert!(matches!(s.poll(), Some(Action::Hello(_))));
                assert_eq!(
                    s.answer_hello(status, 0, &[]).unwrap(),
                    encode_hello_ack(status, 2, 0, &[]).unwrap()
                );
                assert_eq!(closed(&mut s), CloseReason::Refused(status));
                assert_eq!(s.version(), None);
            }
        }
    }

    #[test]
    fn a_refused_re_hello_closes_even_after_an_accepted_one() {
        for s in [daemon(), gateway()] {
            let mut s = accepted(s);
            s.receive(&hello());
            assert!(matches!(s.poll(), Some(Action::Hello(_))));
            assert_eq!(s.version(), Some(2), "a repeat");
            s.answer_hello(HELLO_BAD_DATABASE, 0, &[]).unwrap();
            assert_eq!(closed(&mut s), CloseReason::Refused(HELLO_BAD_DATABASE));
        }
    }

    #[test]
    fn a_batch_before_hello_closes() {
        for mut s in [daemon(), gateway()] {
            s.receive(&batch(1, 1));
            assert_eq!(closed(&mut s), CloseReason::BatchBeforeHello);
        }
    }

    #[test]
    fn a_short_batch_closes_the_daemon_and_is_nacked_as_seq_0_by_the_gateway() {
        let short = encode_message(MSG_BATCH, &[7, 0, 0, 0, 0]);

        let mut d = accepted(daemon());
        d.receive(&short);
        assert_eq!(closed(&mut d), CloseReason::ShortBatch);

        let mut g = accepted(gateway());
        g.receive(&short);
        assert_eq!(nack(&mut g), (0, ACK_MALFORMED));
        assert_eq!(
            g.ack(0, ACK_MALFORMED, 0),
            unhex("0700820000000002002746d3b0")
        );
        assert!(g.poll().is_none());
    }

    #[test]
    fn a_malformed_batch_is_nacked_by_seq() {
        let mut unknown_kind = seq_and_header(9);
        unknown_kind.extend_from_slice(&[0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut over_cap = seq_and_header(10);
        over_cap.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
        over_cap.extend_from_slice(&65u16.to_le_bytes());
        over_cap.extend_from_slice(&[0; 4 + 65]);

        for s in [daemon(), gateway()] {
            let mut s = accepted(s);
            s.receive(&batch(8, MAX_BATCH_RECORDS + 1));
            s.receive(&encode_message(MSG_BATCH, &unknown_kind));
            s.receive(&encode_message(MSG_BATCH, &over_cap));
            for seq in [8, 9, 10] {
                assert_eq!(nack(&mut s), (seq, ACK_MALFORMED));
                s.ack(seq, ACK_MALFORMED, 0);
            }
            assert!(s.poll().is_none());
        }
    }

    fn seq_and_header(seq: u32) -> Vec<u8> {
        let mut body = seq.to_le_bytes().to_vec();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body
    }

    #[test]
    fn max_records_is_at_least_one() {
        let mut s = accepted(ServerSession::new(ServerConfig {
            max_records: 0,
            ..daemon().config
        }));
        s.receive(&batch(1, 1));
        s.receive(&batch(2, 2));
        assert_eq!(incoming(&mut s).batch.records.len(), 1);
        s.ack(1, ACK_OK, 0);
        assert_eq!(nack(&mut s), (2, ACK_MALFORMED));
    }

    #[test]
    fn nothing_more_is_read_until_a_batch_is_acked() {
        for s in [daemon(), gateway()] {
            let mut s = accepted(s);
            s.receive(&[batch(7, 2), batch(8, 1)].concat());
            let b = incoming(&mut s);
            assert_eq!((b.batch.seq, b.batch.records.len()), (7, 2));
            assert!(s.poll().is_none());
            assert!(s.poll().is_none());
            assert_eq!(s.ack(7, ACK_OK, 0), unhex("0700820700000000001d14e09f"));
            assert_eq!(incoming(&mut s).batch.seq, 8);
        }
    }

    #[test]
    fn nothing_more_is_read_until_a_nack_is_acked() {
        for mut s in [daemon(), gateway()] {
            s.receive(&[corrupt(batch(3, 1)), encode_message(MSG_PING, b"")].concat());
            assert_eq!(nack(&mut s), (3, ACK_CRC));
            assert!(s.poll().is_none());
            s.ack(3, ACK_CRC, 0);
            assert!(matches!(s.poll(), Some(Action::Reply(_))));
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ACK for seq 4")]
    fn acking_a_seq_that_is_not_owed_is_a_caller_error() {
        let mut s = accepted(daemon());
        s.receive(&batch(3, 1));
        incoming(&mut s);
        s.ack(4, ACK_OK, 0);
    }

    #[test]
    fn a_session_fed_a_byte_at_a_time_reads_as_one_fed_whole() {
        let stream = [
            encode_message(MSG_PING, b""),
            hello(),
            batch(1, 3),
            encode_message(MSG_PING, b""),
        ]
        .concat();
        let mut s = daemon();
        let mut actions = Vec::new();
        for byte in &stream {
            s.receive(std::slice::from_ref(byte));
            while let Some(action) = s.poll() {
                match &action {
                    Action::Hello(_) => drop(s.answer_hello(HELLO_OK, 0, &[]).unwrap()),
                    Action::Batch(b) => drop(s.ack(b.batch.seq, ACK_OK, 0)),
                    _ => {}
                }
                actions.push(action);
            }
        }
        assert!(matches!(
            actions.as_slice(),
            [
                Action::Reply(_),
                Action::Hello(_),
                Action::Batch(IncomingBatch { batch, .. }),
                Action::Reply(_),
            ] if batch.records.len() == 3
        ));
    }

    #[test]
    fn time_relative_and_the_parser_follow_the_latest_accepted_hello() {
        let mut s = with_versions(1..=3);
        s.receive(&hello_v(1, true));
        assert!(matches!(s.poll(), Some(Action::Hello(_))));
        s.answer_hello(HELLO_OK, 0, &[]).unwrap();
        s.receive(&v1_batch(1));
        let b = incoming(&mut s);
        assert_eq!((b.time_relative, b.version), (true, 1));
        assert_eq!(b.batch.records[0].payload, [0xAA]);
        s.ack(1, ACK_OK, 0);

        s.receive(&hello_v(2, false));
        let Some(Action::Hello(_)) = s.poll() else {
            panic!("no re-HELLO")
        };
        assert_eq!(s.version(), Some(1), "a repeat of a v1 session");
        s.answer_hello(HELLO_OK, 0, &[]).unwrap();
        assert_eq!(s.version(), Some(2));
        s.receive(&batch(2, 1));
        let b = incoming(&mut s);
        assert_eq!((b.time_relative, b.version), (false, 2));
    }

    #[test]
    fn a_hundred_thousand_frames_fed_whole_are_all_read() {
        let ping = encode_message(MSG_PING, b"");
        let mut s = daemon();
        s.receive(&ping.repeat(100_000));
        let replies = std::iter::from_fn(|| s.poll()).count();
        assert_eq!(replies, 100_000);
    }

    #[test]
    #[ignore = "timing; run with --release -- --ignored --nocapture"]
    fn bench_a_40_mb_body() {
        let mut body = hello();
        let mut batches = 0;
        while body.len() < 40 << 20 {
            batches += 1;
            body.extend_from_slice(&batch(batches, 4));
        }
        let started = std::time::Instant::now();
        let mut s = daemon();
        let mut seen = 0;
        for chunk in body.chunks(256 << 10) {
            s.receive(chunk);
            while let Some(action) = s.poll() {
                match action {
                    Action::Hello(_) => drop(s.answer_hello(HELLO_OK, 0, &[]).unwrap()),
                    Action::Batch(b) => {
                        seen += 1;
                        drop(s.ack(b.batch.seq, ACK_OK, 0));
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(seen, batches);
        let session = started.elapsed();

        let started = std::time::Instant::now();
        let (mut read, mut frames) = (0, 0);
        while let Some((_, consumed)) = parse_frame(&body[read..]).unwrap() {
            read += consumed;
            frames += 1;
        }
        assert_eq!(frames, batches + 1);
        println!(
            "{} MB, {batches} batches: session in 256 KiB chunks {session:?}, offset loop {:?}",
            body.len() >> 20,
            started.elapsed()
        );
    }

    fn hello_v3() -> Vec<u8> {
        encode_hello(&Hello {
            version: 3,
            time_relative: false,
            token: b"k".to_vec(),
            database: String::new(),
            daemon_id: "bench".into(),
            devices: vec![Device {
                bus: 0,
                name: "can0".into(),
            }],
        })
        .unwrap()
    }

    fn accepted_v3(mut s: ServerSession) -> ServerSession {
        s.receive(&hello_v3());
        assert!(matches!(s.poll(), Some(Action::Hello(_))));
        s.answer_hello(HELLO_OK, 0, &[]).unwrap();
        s
    }

    const ASSIGNED: [Assignment; 1] = [Assignment {
        bus: 0,
        blob_sha: [0x11; 20],
    }];

    fn get(offset: u32) -> CatalogGet {
        CatalogGet {
            blob_sha: [0x11; 20],
            offset,
        }
    }

    fn catalog_get(s: &mut ServerSession) -> CatalogGet {
        match s.poll() {
            Some(Action::CatalogGet(get)) => get,
            other => panic!("expected a CATALOG_GET, got {other:?}"),
        }
    }

    fn raw_serial_batch(seq: u32) -> Vec<u8> {
        let mut body = Vec::new();
        encode_record_into(&mut body, 0, 0, RecordKind::RawSerial, 0, 1, 7, b"x");
        encode_batch(seq, 0, 1, &body)
    }

    #[test]
    fn a_v3_hello_is_answered_with_its_assignments_and_names_its_devices() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello_v3());
            let Some(Action::Hello(h)) = s.poll() else {
                panic!("no HELLO")
            };
            assert_eq!((h.version, h.daemon_id.as_str()), (3, "bench"));
            assert_eq!(s.hello(), None, "not accepted yet");
            assert_eq!(
                s.answer_hello(HELLO_OK, 42, &ASSIGNED).unwrap(),
                encode_hello_ack(HELLO_OK, 3, 42, &ASSIGNED).unwrap()
            );
            assert_eq!(s.hello(), Some(&h));
            assert_eq!(s.hello().unwrap().devices[0].name, "can0");
        }
    }

    #[test]
    fn a_refused_v3_hello_is_answered_in_the_10_byte_v2_shape() {
        let mut s = gateway();
        s.receive(&hello_v3());
        assert!(matches!(s.poll(), Some(Action::Hello(_))));
        assert_eq!(
            s.answer_hello(HELLO_BAD_AUTH, 42, &ASSIGNED).unwrap(),
            encode_message(
                MSG_HELLO_ACK,
                &[&[HELLO_BAD_AUTH, 3][..], &42u64.to_le_bytes()].concat()
            )
        );
        assert_eq!(closed(&mut s), CloseReason::Refused(HELLO_BAD_AUTH));
    }

    #[test]
    fn a_v1_or_v2_client_refused_by_a_v3_session_gets_the_10_byte_v2_shape() {
        let v2_shape = encode_message(
            MSG_HELLO_ACK,
            &[&[HELLO_BAD_VERSION, 3][..], &42u64.to_le_bytes()].concat(),
        );
        for (mut s, hello) in [
            (daemon(), hello_v(1, false)),
            (with_versions(3..=3), hello_v(2, false)),
        ] {
            s.receive(&hello);
            assert!(matches!(
                s.poll(),
                Some(Action::HelloRefused(HELLO_BAD_VERSION))
            ));
            assert_eq!(
                s.answer_hello(HELLO_BAD_VERSION, 42, &ASSIGNED).unwrap(),
                v2_shape
            );
        }
    }

    #[test]
    fn too_many_assignments_leave_the_verdict_owed() {
        let mut s = gateway();
        s.receive(&hello_v3());
        assert!(matches!(s.poll(), Some(Action::Hello(_))));
        assert!(s.answer_hello(HELLO_OK, 0, &[ASSIGNED[0]; 256]).is_err());
        assert!(s.poll().is_none(), "still owed");
        assert_eq!(s.version(), None);
        s.answer_hello(HELLO_OK, 0, &ASSIGNED).unwrap();
        assert_eq!(s.version(), Some(3));
    }

    #[test]
    #[should_panic(expected = "must be non-empty")]
    fn an_empty_version_range_is_a_config_error() {
        #[allow(clippy::reversed_empty_ranges)]
        with_versions(3..=2);
    }

    #[test]
    #[should_panic(expected = "end at most at 3")]
    fn a_version_past_the_protocol_is_a_config_error() {
        with_versions(2..=4);
    }

    #[test]
    fn a_v2_client_gets_a_v2_hello_ack_and_no_raw_serial() {
        for mut s in [daemon(), gateway()] {
            s.receive(&hello());
            assert!(matches!(s.poll(), Some(Action::Hello(_))));
            assert_eq!(
                s.answer_hello(HELLO_OK, BASE, &ASSIGNED).unwrap(),
                unhex("0b0081000200401e18240a0600dda3c4aa")
            );
            s.receive(&raw_serial_batch(5));
            assert_eq!(nack(&mut s), (5, ACK_MALFORMED));
        }
    }

    #[test]
    fn a_v3_client_takes_raw_serial() {
        let mut s = accepted_v3(daemon());
        s.receive(&raw_serial_batch(5));
        let b = incoming(&mut s);
        assert_eq!(
            (b.version, b.batch.records[0].kind),
            (3, RecordKind::RawSerial)
        );
    }

    #[test]
    fn a_v3_client_is_refused_by_a_v2_only_config_with_status_2() {
        let mut s = with_versions(2..=2);
        s.receive(&hello_v3());
        assert!(matches!(
            s.poll(),
            Some(Action::HelloRefused(HELLO_BAD_VERSION))
        ));
        let ack = s.answer_hello(HELLO_BAD_VERSION, 42, &[]).unwrap();
        assert_eq!(ack, unhex("0b008102022a0000000000000096dd5d9f"));
        let ack = parse_hello_ack(&parse_frame(&ack).unwrap().unwrap().0.body).unwrap();
        assert_eq!((ack.status, ack.accepted_version), (HELLO_BAD_VERSION, 2));
        assert_eq!(closed(&mut s), CloseReason::Refused(HELLO_BAD_VERSION));
    }

    #[test]
    fn a_malformed_v3_hello_closes_without_an_answer() {
        let mut body = parse_frame(&hello_v3()).unwrap().unwrap().0.body;
        assert_eq!(&body[9..15], b"\x05bench");
        body[10] = b'B';
        let mut s = daemon();
        s.receive(&encode_message(MSG_HELLO, &body));
        assert_eq!(closed(&mut s), CloseReason::BadHello);
    }

    #[test]
    fn a_catalog_get_is_answered_in_turn_between_batches() {
        for s in [daemon(), gateway()] {
            let mut s = accepted_v3(s);
            s.receive(&[batch(1, 1), encode_catalog_get(&get(3)), batch(2, 1)].concat());
            assert_eq!(incoming(&mut s).batch.seq, 1);
            assert!(s.poll().is_none());
            s.ack(1, ACK_OK, 0);
            assert_eq!(catalog_get(&mut s), get(3));
            assert!(s.poll().is_none(), "the CATALOG is owed");
            assert_eq!(
                s.answer_catalog(Ok(b"abcdef")),
                encode_catalog(&get(3), Ok(b"abcdef"))
            );
            assert_eq!(incoming(&mut s).batch.seq, 2);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ACK for seq 0")]
    fn acking_a_catalog_get_is_a_caller_error() {
        let mut s = accepted_v3(daemon());
        s.receive(&encode_catalog_get(&get(0)));
        catalog_get(&mut s);
        s.ack(0, ACK_OK, 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "no CATALOG is owed")]
    fn answering_a_batch_with_a_catalog_is_a_caller_error() {
        let mut s = accepted_v3(daemon());
        s.receive(&batch(0, 1));
        incoming(&mut s);
        s.answer_catalog(Err(CATALOG_UNKNOWN));
    }

    #[test]
    fn a_catalog_get_before_hello_closes() {
        for mut s in [daemon(), gateway()] {
            s.receive(&encode_catalog_get(&get(0)));
            assert_eq!(closed(&mut s), CloseReason::CatalogGetBeforeHello);
        }
    }

    #[test]
    fn a_catalog_get_is_ignored_by_an_older_session() {
        let mut s = accepted(daemon());
        s.receive(&encode_catalog_get(&get(0)));
        s.receive(&encode_message(MSG_PING, b""));
        assert!(matches!(s.poll(), Some(Action::Reply(_))));
    }

    #[test]
    fn a_short_catalog_get_closes() {
        let mut s = accepted_v3(gateway());
        s.receive(&encode_message(MSG_CATALOG_GET, &[0; 23]));
        assert_eq!(closed(&mut s), CloseReason::BadCatalogGet);
    }

    fn status() -> CatalogStatus {
        CatalogStatus {
            entries: vec![CatalogStatusEntry {
                bus: 0,
                active: ActiveCatalog::Assigned([0x11; 20]),
                refused: None,
            }],
        }
    }

    #[test]
    fn a_catalog_status_owes_nothing_and_the_session_reads_on() {
        for s in [daemon(), gateway()] {
            let mut s = accepted_v3(s);
            s.receive(&[encode_catalog_status(&status()).unwrap(), batch(1, 1)].concat());
            assert!(matches!(s.poll(), Some(Action::CatalogStatus(got)) if got == status()));
            assert_eq!(incoming(&mut s).batch.seq, 1);
        }
    }

    #[test]
    fn a_catalog_status_before_hello_closes() {
        for mut s in [daemon(), gateway()] {
            s.receive(&encode_catalog_status(&status()).unwrap());
            assert_eq!(closed(&mut s), CloseReason::CatalogStatusBeforeHello);
        }
    }

    #[test]
    fn a_catalog_status_is_ignored_by_an_older_session() {
        let mut s = accepted(daemon());
        s.receive(&encode_catalog_status(&status()).unwrap());
        s.receive(&encode_message(MSG_PING, b""));
        assert!(matches!(s.poll(), Some(Action::Reply(_))));
    }

    #[test]
    fn a_malformed_catalog_status_closes() {
        let mut s = accepted_v3(gateway());
        s.receive(&encode_message(MSG_CATALOG_STATUS, &[1; 43]));
        assert_eq!(closed(&mut s), CloseReason::BadCatalogStatus);
    }

    #[test]
    fn a_reassigned_session_closes_once_its_owed_reply_is_written() {
        let mut s = accepted_v3(gateway());
        s.receive(&[batch(1, 1), batch(2, 1)].concat());
        assert_eq!(incoming(&mut s).batch.seq, 1);
        s.close_reassigned();
        assert!(s.poll().is_none(), "the ACK is owed");
        s.ack(1, ACK_OK, 0);
        assert_eq!(closed(&mut s), CloseReason::Reassigned);
        assert!(s.poll().is_none());
    }

    #[test]
    fn the_idle_limit_is_the_configured_one() {
        assert_eq!(daemon().idle_limit(), Some(Duration::from_secs(90)));
        assert_eq!(gateway().idle_limit(), None);
    }
}
