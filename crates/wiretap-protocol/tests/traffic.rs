//! A simulated bus, run through every codec in this crate.
//!
//! The unit tests beside each module assert the bytes of a frame someone
//! thought of. This asserts the property those cases exist to protect: that a
//! session's worth of mixed traffic survives a round trip, arriving in order
//! and unchanged, whatever the reads happen to be cut into.
//!
//! It lives in `tests/` rather than inline because it uses the crate the way a
//! consumer does — through its public API only, with no access to a decoder's
//! internals — and because it spans every module rather than belonging to one.
//!
//! Deterministic: the generator is seeded and dependency-free, so a failure is
//! reproducible from the seed printed in the assertion.

use wiretap_protocol::can::{CanFrame, Direction};
use wiretap_protocol::{
    candump, dlc_to_len, gs_usb, gvret, payload_dlc, slcan, socketcan, testpattern,
};

// ---------------------------------------------------------------------------
// A bus
// ---------------------------------------------------------------------------

/// xorshift64*. Not a good random number generator; a perfectly good source of
/// awkward frame sizes and read boundaries, which is all this needs.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// One frame as it was on the bus, before any protocol saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    arb_id: u32,
    extended: bool,
    fd: bool,
    brs: bool,
    rtr: bool,
    bus: u8,
    data: Vec<u8>,
}

impl Sample {
    /// The payload once the frame's length code has rounded it up. CAN FD has
    /// no 9, 10 or 11 byte length, so a transmitter pads and a receiver sees
    /// the padding — every codec here that writes a fixed-width payload region
    /// or a full line of hex agrees about that.
    fn padded(&self) -> Vec<u8> {
        let mut d = self.data.clone();
        d.resize(dlc_to_len(payload_dlc(d.len(), self.fd), self.fd), 0);
        d
    }
}

/// A plausible-looking mix: mostly short classic frames, some extended, some
/// CAN FD across every length code, and the occasional remote request.
fn bus_traffic(seed: u64, count: usize) -> Vec<Sample> {
    let mut rng = Rng::new(seed);
    (0..count)
        .map(|_| {
            let extended = rng.below(4) == 0;
            let fd = rng.below(3) == 0;
            let rtr = !fd && rng.below(16) == 0;
            Sample {
                arb_id: if extended {
                    rng.next() as u32 & 0x1FFF_FFFF
                } else {
                    rng.next() as u32 & 0x7FF
                },
                extended,
                fd,
                brs: fd && rng.below(2) == 0,
                rtr,
                bus: rng.below(4) as u8,
                data: if rtr {
                    Vec::new()
                } else {
                    let n = if fd { rng.below(65) } else { rng.below(9) };
                    rng.bytes(n)
                },
            }
        })
        .collect()
}

/// Feed `bytes` to `decode` in chunks of awkward sizes — including single
/// bytes — and collect everything that came back.
///
/// The point of an incremental decoder is that where the reads fall makes no
/// difference, and the way to be sure is to put a boundary everywhere.
fn in_chunks<T>(seed: u64, bytes: &[u8], mut decode: impl FnMut(&[u8]) -> Vec<T>) -> Vec<T> {
    let mut rng = Rng::new(seed);
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let take = (1 + rng.below(40)).min(bytes.len() - at);
        out.extend(decode(&bytes[at..at + take]));
        at += take;
    }
    out
}

/// The same sample as an SLCAN line's frame.
fn as_slcan(s: &Sample) -> slcan::Frame {
    if s.rtr {
        slcan::Frame::remote(s.arb_id, s.extended, s.data.len() as u8)
    } else {
        slcan::Frame::data(s.arb_id, s.extended, s.fd, s.brs, s.data.clone())
    }
}

/// The same sample as a gs_usb host frame this host is transmitting.
fn as_gs_usb(s: &Sample) -> gs_usb::HostFrame {
    gs_usb::HostFrame::transmit(
        s.arb_id,
        s.extended,
        s.rtr && !s.fd,
        s.fd,
        s.brs,
        s.bus,
        s.data.clone(),
    )
}

const SEEDS: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];
const FRAMES: usize = 200;

// ---------------------------------------------------------------------------
// GVRET
// ---------------------------------------------------------------------------

/// A device streaming a busy bus, read in arbitrary chunks. GVRET carries no
/// FD flag and no BRS, so what survives is the id, the bus, the length code and
/// the payload.
#[test]
fn a_gvret_device_stream_survives_any_read_boundary() {
    for seed in SEEDS {
        let traffic: Vec<Sample> = bus_traffic(seed, FRAMES)
            .into_iter()
            .filter(|s| !s.rtr) // GVRET has no remote frame
            .collect();

        let mut wire = Vec::new();
        for (i, s) in traffic.iter().enumerate() {
            gvret::encode_frame_into(
                &mut wire, i as u32, s.arb_id, s.extended, s.bus, &s.data, s.fd,
            );
            // Real devices interleave their replies with the traffic.
            match i % 37 {
                7 => wire.extend(gvret::encode_keepalive()),
                19 => wire.extend(gvret::encode_timebase(i as u32)),
                29 => wire.extend(gvret::encode_num_buses(2)),
                _ => {}
            }
        }

        let mut decoder = gvret::DeviceDecoder::new();
        let frames: Vec<_> = in_chunks(seed, &wire, |c| decoder.feed(c))
            .into_iter()
            .filter_map(|m| match m {
                gvret::DeviceMessage::Frame {
                    ts_us,
                    bus,
                    arb_id,
                    extended,
                    dlc,
                    data,
                } => Some((ts_us, bus, arb_id, extended, dlc, data)),
                _ => None,
            })
            .collect();

        assert_eq!(frames.len(), traffic.len(), "seed {seed}: frame count");
        for (i, (s, got)) in traffic.iter().zip(&frames).enumerate() {
            assert_eq!(
                *got,
                (
                    i as u32,
                    s.bus,
                    s.arb_id,
                    s.extended,
                    payload_dlc(s.data.len(), s.fd),
                    // Padded to the length code, because the code is the only
                    // framing this protocol has: a frame carrying fewer bytes
                    // than it claims eats the head of the next one.
                    s.padded(),
                ),
                "seed {seed}, frame {i}"
            );
        }
    }
}

/// The host end transmitting, decoded by the device end. Both live in this
/// crate now, so the pair can be asserted rather than assumed.
#[test]
fn a_gvret_transmit_stream_is_read_by_the_device_end() {
    for seed in SEEDS {
        // The transmit format carries a byte count, and the device end clamps
        // the payload it keeps to 8 — see below. Classic frames only, which is
        // what the format actually describes.
        let traffic: Vec<Sample> = bus_traffic(seed, FRAMES)
            .into_iter()
            .filter(|s| !s.fd && !s.rtr)
            .collect();

        let mut wire = gvret::SYNC.to_vec();
        for s in &traffic {
            gvret::encode_transmit_into(&mut wire, s.arb_id, s.extended, s.bus, &s.data);
        }

        let mut decoder = gvret::Decoder::new();
        let got = in_chunks(seed, &wire, |c| decoder.feed(c));

        assert_eq!(got.len(), traffic.len(), "seed {seed}");
        for (i, (s, cmd)) in traffic.iter().zip(&got).enumerate() {
            assert_eq!(
                *cmd,
                gvret::ClientCommand::Transmit {
                    bus: s.bus,
                    arb_id: s.arb_id,
                    extended: s.extended,
                    declared: s.data.len() as u8,
                    data: s.data.clone(),
                },
                "seed {seed}, frame {i}"
            );
        }
    }
}

/// The dialect note, asserted: a host may transmit a CAN FD payload, and the
/// device end keeps only the first eight bytes of it while consuming all of
/// them. Stated here because it is a real asymmetry between the two ends, not
/// because it is right.
#[test]
fn a_gvret_transmit_longer_than_a_classic_frame_is_truncated_not_desynchronised() {
    let mut wire = gvret::SYNC.to_vec();
    gvret::encode_transmit_into(&mut wire, 0x123, false, 0, &[0xAB; 12]);
    gvret::encode_transmit_into(&mut wire, 0x124, false, 0, &[0xCD; 2]);

    let got = gvret::Decoder::new().feed(&wire);
    assert_eq!(
        got,
        vec![
            gvret::ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x123,
                extended: false,
                declared: 12,
                data: vec![0xAB; 8],
            },
            gvret::ClientCommand::Transmit {
                bus: 0,
                arb_id: 0x124,
                extended: false,
                declared: 2,
                data: vec![0xCD; 2],
            },
        ],
        "the payload is clamped, but the stream is not lost"
    );
}

// ---------------------------------------------------------------------------
// SLCAN
// ---------------------------------------------------------------------------

/// A device streaming lines, read in arbitrary chunks, with its replies and its
/// error bells mixed in.
#[test]
fn an_slcan_line_stream_survives_any_read_boundary() {
    for seed in SEEDS {
        let traffic = bus_traffic(seed, FRAMES);

        let mut wire = Vec::new();
        for (i, s) in traffic.iter().enumerate() {
            slcan::encode_frame_into(&mut wire, &as_slcan(s));
            // A bare `\r` is a command acknowledgement; a bell is a command
            // error. Neither is a frame, and neither may disturb one.
            match i % 23 {
                5 => wire.push(b'\r'),
                11 => wire.push(slcan::BELL),
                17 => wire.extend(b"V1013\r"),
                _ => {}
            }
        }

        let mut decoder = slcan::LineDecoder::new();
        let frames: Vec<_> = in_chunks(seed, &wire, |c| decoder.feed(c))
            .into_iter()
            .filter_map(|l| match l {
                slcan::Line::Frame(f) => Some(f),
                slcan::Line::Reply(_) => None,
            })
            .collect();

        assert_eq!(frames.len(), traffic.len(), "seed {seed}: frame count");
        for (i, (s, got)) in traffic.iter().zip(&frames).enumerate() {
            assert_eq!(
                (got.arb_id, got.extended, got.fd, got.brs, got.rtr),
                (s.arb_id, s.extended, s.fd, s.brs, s.rtr),
                "seed {seed}, frame {i}"
            );
            // A line must carry every byte its code names, so an inexact FD
            // payload arrives padded.
            let want = if s.rtr { Vec::new() } else { s.padded() };
            assert_eq!(got.data, want, "seed {seed}, frame {i}");
        }
    }
}

// ---------------------------------------------------------------------------
// gs_usb and SocketCAN
// ---------------------------------------------------------------------------

/// gs_usb frames are fixed-size records rather than a stream, so what matters
/// is that a whole session round-trips — including the length code that is not
/// a byte count.
#[test]
fn a_gs_usb_session_round_trips() {
    for seed in SEEDS {
        for (i, s) in bus_traffic(seed, FRAMES).iter().enumerate() {
            let rtr = s.rtr && !s.fd;
            let wire = gs_usb::encode_host_frame(&as_gs_usb(s));
            assert_eq!(
                wire.len(),
                if s.fd {
                    gs_usb::FD_FRAME_BYTES
                } else {
                    gs_usb::CLASSIC_FRAME_BYTES
                },
                "seed {seed}, frame {i}"
            );

            let got = gs_usb::parse_host_frame(&wire).expect("a frame");
            assert_eq!(
                (
                    got.arb_id,
                    got.extended,
                    got.rtr,
                    got.fd,
                    got.brs,
                    got.channel
                ),
                (s.arb_id, s.extended, rtr, s.fd, s.brs, s.bus),
                "seed {seed}, frame {i}"
            );
            assert_eq!(got.dlc, payload_dlc(s.data.len(), s.fd));
            assert_eq!(got.data, s.padded(), "seed {seed}, frame {i}");
            assert!(!got.is_rx(), "a transmit is not a received frame");
        }
    }
}

/// Several gs_usb frames arrive in one bulk transfer, and a reader strides
/// through them. A frame whose size the stride got wrong would decode as
/// rubbish from the second one on.
#[test]
fn a_bulk_transfer_of_gs_usb_frames_strides_correctly() {
    for seed in SEEDS {
        // One transfer carries frames of one size, so the stride is fixed.
        for fd in [false, true] {
            let traffic: Vec<Sample> = bus_traffic(seed, 32)
                .into_iter()
                .map(|mut s| {
                    s.fd = fd;
                    s.rtr = s.rtr && !fd;
                    s.data.truncate(if fd { 64 } else { 8 });
                    s
                })
                .collect();

            let mut transfer = Vec::new();
            for s in &traffic {
                gs_usb::encode_host_frame_into(&mut transfer, &as_gs_usb(s));
            }

            let stride = if fd {
                gs_usb::FD_FRAME_BYTES
            } else {
                gs_usb::CLASSIC_FRAME_BYTES
            };
            assert_eq!(transfer.len(), stride * traffic.len());
            for (i, s) in traffic.iter().enumerate() {
                let got = gs_usb::parse_host_frame(&transfer[i * stride..(i + 1) * stride])
                    .expect("a frame");
                assert_eq!(got.arb_id, s.arb_id, "seed {seed}, fd {fd}, frame {i}");
                assert_eq!(got.data, s.padded(), "seed {seed}, fd {fd}, frame {i}");
            }
        }
    }
}

/// SocketCAN carries a payload length rather than a code, so nothing is padded
/// and what goes in is exactly what comes out.
#[test]
fn a_socketcan_session_round_trips() {
    for seed in SEEDS {
        for (i, s) in bus_traffic(seed, FRAMES).iter().enumerate() {
            let sent = socketcan::Frame::new(
                s.arb_id,
                s.extended,
                s.rtr && !s.fd,
                s.fd,
                s.brs,
                s.data.clone(),
            );
            let wire = socketcan::encode_frame(&sent);
            assert_eq!(wire.len(), sent.wire_len(), "seed {seed}, frame {i}");
            assert_eq!(
                socketcan::parse_frame(&wire),
                Some(sent),
                "seed {seed}, frame {i}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Across protocols
// ---------------------------------------------------------------------------

/// The same bus, bridged from one protocol to another and back, which is what
/// every one of these codecs exists to let a capture tool do.
///
/// SLCAN and gs_usb both pad to a length code, so a bridge between them is
/// lossless; GVRET does not pad, so it is the odd one out and is compared
/// against the padded form the others agree on.
#[test]
fn a_bus_bridged_between_protocols_arrives_intact() {
    for seed in SEEDS {
        for s in bus_traffic(seed, 64).iter().filter(|s| !s.rtr) {
            let via_slcan = slcan::parse_frame(
                std::str::from_utf8(&slcan::encode_frame(&slcan::Frame::data(
                    s.arb_id,
                    s.extended,
                    s.fd,
                    s.brs,
                    s.data.clone(),
                )))
                .expect("ascii")
                .trim_end_matches('\r'),
            )
            .expect("an slcan frame");

            let via_gs_usb =
                gs_usb::parse_host_frame(&gs_usb::encode_host_frame(&gs_usb::HostFrame::transmit(
                    s.arb_id,
                    s.extended,
                    false,
                    s.fd,
                    s.brs,
                    s.bus,
                    s.data.clone(),
                )))
                .expect("a gs_usb frame");

            assert_eq!(
                (via_slcan.arb_id, via_slcan.dlc, &via_slcan.data),
                (via_gs_usb.arb_id, via_gs_usb.dlc, &via_gs_usb.data),
                "seed {seed}: slcan and gs_usb disagree about {:#x}",
                s.arb_id
            );

            let gvret_wire = gvret::encode_frame(0, s.arb_id, s.extended, s.bus, &s.data, s.fd);
            match &gvret::DeviceDecoder::new().feed(&gvret_wire)[0] {
                gvret::DeviceMessage::Frame { arb_id, dlc, .. } => {
                    assert_eq!((*arb_id, *dlc), (via_slcan.arb_id, via_slcan.dlc));
                }
                other => panic!("expected a frame, got {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// candump
// ---------------------------------------------------------------------------

/// A log of a busy bus, written and read back. The text carries every flag and
/// keeps the length as written, so nothing is padded and nothing is lost, at
/// either end of the time range.
#[test]
fn a_candump_log_round_trips_every_flag_and_length() {
    for seed in SEEDS {
        let frames: Vec<CanFrame> = bus_traffic(seed, FRAMES)
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut frame = if s.rtr {
                    CanFrame::remote(0, s.arb_id, s.extended, (i % 9) as u8)
                } else {
                    CanFrame::data(0, s.arb_id, s.extended, s.fd, s.brs, s.data.clone())
                };
                frame.esi = s.fd && i % 5 == 0;
                frame
            })
            .collect();

        for start in [0, u64::MAX - FRAMES as u64] {
            let mut log = String::new();
            for (i, frame) in frames.iter().enumerate() {
                let direction = [None, Some(Direction::Rx), Some(Direction::Tx)][i % 3];
                candump::encode_line_into(&mut log, start + i as u64, "can0", frame, direction);
                log.push('\n');
            }
            let parsed: Vec<_> = candump::lines(log.lines())
                .map(|line| line.unwrap_or_else(|e| panic!("seed {seed}: {e}")))
                .collect();
            assert_eq!(parsed.len(), frames.len(), "seed {seed}: line count");
            for (i, (line, frame)) in parsed.iter().zip(&frames).enumerate() {
                assert_eq!(line.ts_us, start + i as u64, "seed {seed}");
                assert_eq!(&line.frame, frame, "seed {seed}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test Pattern
// ---------------------------------------------------------------------------

use testpattern::{capability, Command, Flags, Message, Responder};

/// Drive a responder the way a run does, and prove a sweep comes back whole at
/// every length code.
///
/// This is the exchange that validates a real link. A codec that confuses a
/// payload length for a data length code passes at 8 bytes and fails here,
/// which is exactly the fault a fixed-payload protocol could not see.
#[test]
fn a_sweep_round_trips_at_every_length_code() {
    for fd in [false, true] {
        let mut r = Responder::new(if fd { capability::FD } else { 0 }, 0);
        let flags = Flags::new(0, 3);
        r.on_frame(
            testpattern::ID_CONTROL,
            false,
            false,
            &testpattern::encode(Message::Control(Command::Start { mode: 0, run: 3 }), flags),
            0,
        );

        for code in testpattern::sweep_codes(fd) {
            let sent = testpattern::sweep_payload(code, fd);
            let out = r.on_frame(
                testpattern::SWEEP_REQUEST_BASE + u32::from(code),
                false,
                fd,
                &sent,
                0,
            );
            assert_eq!(out.len(), 1, "fd {fd} code {code}");
            assert_eq!(
                testpattern::sweep_code(out[0].arb_id),
                Some((code, true)),
                "fd {fd} code {code}: echoed under the wrong id"
            );
            assert!(
                testpattern::sweep_echo_matches(code, fd, &out[0].data),
                "fd {fd} code {code}: {} bytes back, {} expected",
                out[0].data.len(),
                dlc_to_len(code, fd)
            );
        }
    }
}

/// A whole run, as an initiator drives it: find a peer, start it, exchange
/// traffic, ask what it saw, stop it.
#[test]
fn a_run_is_driven_end_to_end_by_its_control_messages() {
    let run = 6;
    let flags = Flags::new(1, run);
    let mut r = Responder::new(capability::FD, 2);
    let control = |m: Message| (testpattern::ID_CONTROL, testpattern::encode(m, flags));

    // Nobody has said hello yet, so nothing is answered.
    let ping = Message::PingRequest { seq: 0 };
    assert!(r
        .on_frame(
            ping.arb_id(),
            false,
            false,
            &testpattern::encode(ping, flags),
            0
        )
        .is_empty());

    // Discovery.
    let (id, wire) = control(Message::Control(Command::Hello));
    let hello = r.on_frame(id, false, false, &wire, 0);
    assert_eq!(
        testpattern::decode(&hello[0].data).unwrap().0,
        Message::Control(Command::HelloReply {
            capabilities: capability::FD,
            bus: 2
        })
    );

    // Start, then a stream with one frame missing from it.
    let (id, wire) = control(Message::Control(Command::Start { mode: 1, run }));
    r.on_frame(id, false, false, &wire, 0);
    for seq in [0u16, 1, 2, 4, 5] {
        let m = Message::PingRequest { seq };
        let out = r.on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0);
        assert_eq!(
            testpattern::decode(&out[0].data).unwrap().0,
            Message::PingReply { seq }
        );
    }

    // What did it see?
    let (id, wire) = control(Message::Control(Command::RequestStatus));
    let status = r.on_frame(id, false, false, &wire, 1_000_000);
    let value = |field: u8| {
        status
            .iter()
            .find_map(|f| match testpattern::decode(&f.data).unwrap().0 {
                Message::Status { field: g, value } if g == field => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no field {field:#x} in the status reply"))
    };
    assert_eq!(value(testpattern::status_field::RX_COUNT), 5);
    assert_eq!(value(testpattern::status_field::DROPS), 1, "seq 3");
    assert_eq!(value(testpattern::status_field::FPS), 5, "5 frames in 1 s");

    // Stop, and it goes quiet again.
    let (id, wire) = control(Message::Control(Command::Stop));
    r.on_frame(id, false, false, &wire, 0);
    let m = Message::PingRequest { seq: 6 };
    assert!(r
        .on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0)
        .is_empty());
}

/// Two initiators sharing a bus. Without the run tag their sequence numbers
/// interleave into one tracker and both report drops that never happened.
#[test]
fn two_runs_on_one_bus_do_not_contaminate_each_other() {
    let (mine, theirs) = (Flags::new(0, 1), Flags::new(0, 2));
    let mut r = Responder::new(0, 0);
    r.on_frame(
        testpattern::ID_CONTROL,
        false,
        false,
        &testpattern::encode(Message::Control(Command::Start { mode: 0, run: 1 }), mine),
        0,
    );

    let mut answered = 0;
    for seq in 0..10u16 {
        // The other run's frames are interleaved with ours, seq for seq.
        for flags in [mine, theirs] {
            let m = Message::PingRequest { seq };
            answered += r
                .on_frame(m.arb_id(), false, false, &testpattern::encode(m, flags), 0)
                .len();
        }
    }

    assert_eq!(answered, 10, "only our run is answered");
    assert_eq!(r.sequence.rx_count, 10, "and only our run is counted");
    assert_eq!(r.sequence.drops, 0, "the other run's traffic is not a gap");
    assert_eq!(r.sequence.duplicates, 0);
}
