//! SLCAN (Lawicel serial line CAN), the ASCII protocol most USB-CAN adapters
//! speak, plus the CAN FD extension the CANable 2.5 firmware added to it.
//!
//! Protocol reference: <http://www.can232.com/docs/can232_v3.pdf>, and
//! `docs/slcan.md` for the full command surface.
//! CAN FD extension: <https://github.com/Elmue/CANable-2.5-firmware-Slcan-and-Candlelight>
//!
//! Everything is a carriage-return-terminated ASCII line, in both directions,
//! so [`LineDecoder`] does the framing and [`parse_frame`] reads one line. A
//! device answers a command with a bare `\r` or with a bell (`0x07`); neither
//! is a line this module has anything to say about, and the bell discards
//! whatever was being accumulated.
//!
//! # CAN FD is a firmware extension, not the standard
//!
//! Prefixes `d`, `D`, `b` and `B`, and the `Y`/`y` data-phase bitrate commands,
//! are not in the Lawicel specification. They are the Elmue CANable 2.5
//! firmware's, and [`parse_version`] is how a caller finds out whether the
//! device in front of it has them.

use crate::dlc::{dlc_to_len, payload_dlc};
use crate::{ARB_MASK_EXT, ARB_MASK_STD};

/// A device's "that command was an error". It ends whatever line was being
/// accumulated; it does not end the connection.
pub const BELL: u8 = 0x07;

/// Longest line this decoder will accumulate before giving up on it.
///
/// A 64-byte FD frame is ~139 characters and an Elmue version reply is ~200, so
/// this is loose rather than tight: it exists to stop a device that never sends
/// a terminator from growing a buffer forever.
pub const MAX_LINE_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
//
// Every constant and every returned command below includes its terminator, so
// what a caller writes to the port is exactly what it was given.

/// Close the channel. Also resets the bitrate settings, so it is what a caller
/// sends before configuring as well as when it is finished.
pub const CLOSE: &str = "C\r";
/// Open the channel. Frames flow after this and not before.
pub const OPEN: &str = "O\r";
/// Normal mode: ACKs frames and participates in arbitration.
pub const MODE_NORMAL: &str = "M0\r";
/// Silent mode: no ACK, no transmit, passive observation only.
pub const MODE_SILENT: &str = "M1\r";
/// Ask for the firmware version. See [`parse_version`] for the two shapes of
/// answer.
pub const QUERY_VERSION: &str = "V\r";
/// Ask for the hardware version. Optional; many devices ignore it.
pub const QUERY_HW_VERSION: &str = "v\r";
/// Ask for the serial number. Optional.
pub const QUERY_SERIAL: &str = "N\r";

/// The nominal (arbitration) bitrates SLCAN can name, and the command for each.
///
/// The protocol has no way to ask for a rate that is not in this table; the
/// custom-timing `s` command exists but nothing here builds one.
pub const NOMINAL_BITRATES: [(u32, &str); 9] = [
    (10_000, "S0\r"),
    (20_000, "S1\r"),
    (50_000, "S2\r"),
    (100_000, "S3\r"),
    (125_000, "S4\r"),
    (250_000, "S5\r"),
    (500_000, "S6\r"),
    (750_000, "S7\r"),
    (1_000_000, "S8\r"),
];

/// The CAN FD data-phase bitrates the Elmue firmware can name. Sending one of
/// these implicitly puts the device into FD mode.
pub const DATA_BITRATES: [(u32, &str); 6] = [
    (500_000, "Y0\r"),
    (1_000_000, "Y1\r"),
    (2_000_000, "Y2\r"),
    (4_000_000, "Y4\r"),
    (5_000_000, "Y5\r"),
    (8_000_000, "Y8\r"),
];

/// The `S` command for a nominal bitrate, or `None` if the protocol cannot name
/// it. A caller reporting the failure can list [`NOMINAL_BITRATES`].
pub fn bitrate_command(bps: u32) -> Option<&'static str> {
    lookup(&NOMINAL_BITRATES, bps)
}

/// The `Y` command for a CAN FD data-phase bitrate, or `None`.
pub fn data_bitrate_command(bps: u32) -> Option<&'static str> {
    lookup(&DATA_BITRATES, bps)
}

fn lookup(table: &[(u32, &'static str)], bps: u32) -> Option<&'static str> {
    table.iter().find(|(rate, _)| *rate == bps).map(|(_, c)| *c)
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// One CAN frame as an SLCAN line carries it.
///
/// Named here rather than passed as loose scalars — unlike [`crate::gvret`]'s
/// encoders — because this format packs five independent flags into its prefix
/// character, and an encoder taking six positional booleans is a defect
/// waiting to happen.
///
/// `dlc` is the **data length code**, which above 8 bytes on CAN FD is not the
/// payload length. It is carried separately because a remote-transmission
/// request has a code and no payload at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    pub fd: bool,
    /// Bit rate switch — the FD data phase runs at the `Y` rate. Meaningless
    /// unless `fd`.
    pub brs: bool,
    pub dlc: u8,
    pub data: Vec<u8>,
}

impl Frame {
    /// A data frame, with the smallest length code that can carry `data`.
    pub fn data(arb_id: u32, extended: bool, fd: bool, brs: bool, data: Vec<u8>) -> Self {
        Self {
            arb_id,
            extended,
            rtr: false,
            fd,
            brs,
            dlc: payload_dlc(data.len(), fd),
            data,
        }
    }

    /// A remote-transmission request: a length code and no payload. CAN FD has
    /// no RTR, so this is always a classic frame.
    pub fn remote(arb_id: u32, extended: bool, dlc: u8) -> Self {
        Self {
            arb_id,
            extended,
            rtr: true,
            fd: false,
            brs: false,
            dlc: dlc.min(8),
            data: Vec::new(),
        }
    }

    /// The line's prefix character, which is where all four flags live.
    fn prefix(&self) -> u8 {
        let c = match (self.rtr, self.fd, self.brs) {
            (true, _, _) => b'r',
            (false, true, true) => b'b',
            (false, true, false) => b'd',
            (false, false, _) => b't',
        };
        if self.extended {
            c.to_ascii_uppercase()
        } else {
            c
        }
    }
}

/// Longest line [`encode_frame_into`] emits: prefix + 8 id + 1 code +
/// 128 payload characters + terminator.
pub const MAX_FRAME_BYTES: usize = 139;

/// Parse one line as a frame, or `None` if it is not one.
///
/// `None` covers a command reply, a truncated line and a malformed one alike:
/// there is nothing useful a caller can do differently between them, and this
/// crate has no error type. The line must not include its terminator.
pub fn parse_frame(line: &str) -> Option<Frame> {
    let b = line.as_bytes();
    let (extended, rtr, fd, brs) = match *b.first()? {
        b't' => (false, false, false, false),
        b'T' => (true, false, false, false),
        b'r' => (false, true, false, false),
        b'R' => (true, true, false, false),
        b'd' => (false, false, true, false),
        b'D' => (true, false, true, false),
        b'b' => (false, false, true, true),
        b'B' => (true, false, true, true),
        _ => return None,
    };

    let id_len = if extended { 8 } else { 3 };
    let id_end = 1 + id_len;
    let arb_id = u32::from_str_radix(std::str::from_utf8(b.get(1..id_end)?).ok()?, 16).ok()?;

    let dlc = (*b.get(id_end)? as char).to_digit(16)? as u8;
    // Classic CAN has no codes above 8. A device sending one is not speaking
    // this protocol, and guessing a length for it would desynchronise nothing
    // (lines are self-delimiting) but would invent a frame.
    if !fd && dlc > 8 {
        return None;
    }

    let mut data = Vec::new();
    if !rtr {
        let len = dlc_to_len(dlc, fd);
        let hex = b.get(id_end + 1..id_end + 1 + len * 2)?;
        data.reserve_exact(len);
        for pair in hex.as_chunks::<2>().0 {
            data.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
        }
    }

    Some(Frame {
        arb_id,
        extended,
        rtr,
        fd,
        brs,
        dlc,
        data,
    })
}

/// Append `frame` as an SLCAN line, terminator included.
///
/// The payload is zero-padded up to what `dlc` claims. CAN FD has no length
/// code for 9, 10 or 11 bytes, so a payload of one of those sizes must go out
/// as the next size up — and a line whose hex ran out early would be rejected
/// by the device. This is the opposite of [`crate::gvret::encode_frame_into`],
/// which never pads: that one describes a frame that was seen on a bus, where
/// inventing bytes would be a lie, while this one is putting one on a bus,
/// where the hardware pads regardless.
pub fn encode_frame_into(out: &mut Vec<u8>, frame: &Frame) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let len = if frame.rtr {
        0
    } else {
        dlc_to_len(frame.dlc, frame.fd)
    };

    out.reserve(2 + if frame.extended { 8 } else { 3 } + len * 2 + 1);
    out.push(frame.prefix());

    let (id, digits) = if frame.extended {
        (frame.arb_id & ARB_MASK_EXT, 8)
    } else {
        (frame.arb_id & ARB_MASK_STD, 3)
    };
    for shift in (0..digits).rev() {
        out.push(HEX[(id >> (shift * 4)) as usize & 0x0F]);
    }
    out.push(HEX[(frame.dlc & 0x0F) as usize]);

    for i in 0..len {
        let byte = frame.data.get(i).copied().unwrap_or(0);
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0x0F) as usize]);
    }
    out.push(b'\r');
}

/// [`encode_frame_into`] into a fresh buffer.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAX_FRAME_BYTES);
    encode_frame_into(&mut v, frame);
    v
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// One complete line from a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Frame(Frame),
    /// A line that is not a frame: a version or serial reply, or anything else
    /// the device chose to say. Returned rather than dropped so a caller
    /// probing a device and a caller streaming from one can share this decoder.
    Reply(String),
}

/// Splits a device's byte stream into lines.
///
/// The same shape as [`crate::gvret::DeviceDecoder`]: feed it whatever a read
/// returned, take whatever that completed, leave the rest buffered.
#[derive(Debug, Default)]
pub struct LineDecoder {
    buf: String,
}

impl LineDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed received bytes, returning every complete line they produced.
    ///
    /// A bell discards the line in progress, non-ASCII and control bytes are
    /// dropped, and a line that grows past [`MAX_LINE_BYTES`] without a
    /// terminator is abandoned.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<Line> {
        let mut out = Vec::new();
        for &byte in chunk {
            match byte {
                b'\r' | b'\n' => {
                    if !self.buf.is_empty() {
                        out.push(match parse_frame(&self.buf) {
                            Some(f) => Line::Frame(f),
                            None => Line::Reply(std::mem::take(&mut self.buf)),
                        });
                        self.buf.clear();
                    }
                }
                BELL => self.buf.clear(),
                b if b.is_ascii() && !b.is_ascii_control() => {
                    self.buf.push(b as char);
                    if self.buf.len() > MAX_LINE_BYTES {
                        self.buf.clear();
                    }
                }
                _ => {}
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Version replies
// ---------------------------------------------------------------------------

/// What a `V` reply said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Version {
    /// Firmware version, formatted for display: a bare four-digit CANable
    /// version like `1013` becomes `1.0.13`, and anything else is passed
    /// through.
    pub firmware: Option<String>,
    /// Board name, from an Elmue reply only.
    pub board: Option<String>,
    /// MCU part number, from an Elmue reply only.
    pub mcu: Option<String>,
    /// Whether this is the Elmue CANable 2.5 firmware, which is the only thing
    /// that identifies a device as CAN FD capable — the protocol has no
    /// capability query.
    pub elmue: bool,
}

/// Read a `V` reply, in either of the two shapes devices send.
///
/// Standard firmware answers with a short string: `V1013`. The Elmue firmware
/// answers with labelled fields run together without separators:
///
/// ```text
/// V+Board: MultiboardMCU: STM32G431DevID: 1128Firmware: 2490643Slcan: 100Clock: 160Limits: 512,...
/// ```
///
/// Which is why each field below is read up to the next label rather than to
/// any kind of delimiter: there isn't one.
pub fn parse_version(reply: &str) -> Version {
    let s = reply.trim();
    let Some(fw_at) = s.find("Firmware:") else {
        // Standard firmware. The leading V is the echo of the command.
        let raw = s.strip_prefix(['V', 'v']).unwrap_or(s);
        return Version {
            firmware: Some(format_version(raw)),
            ..Version::default()
        };
    };

    let digits: String = s[fw_at + "Firmware:".len()..]
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(char::is_ascii_digit)
        .collect();

    let board = s.find("Board:").map(|at| {
        let rest = &s[at + "Board:".len()..];
        let end = rest.find("MCU:").unwrap_or(rest.len());
        rest[..end]
            .trim()
            .trim_start_matches('+')
            .trim()
            .to_string()
    });
    let mcu = s.find("MCU:").map(|at| {
        let rest = &s[at + "MCU:".len()..];
        let end = rest.find("DevID:").unwrap_or(rest.len());
        rest[..end].trim().to_string()
    });

    Version {
        firmware: (!digits.is_empty()).then(|| format_version(&digits)),
        board: board.filter(|b| !b.is_empty()),
        mcu: mcu.filter(|m| !m.is_empty()),
        elmue: true,
    }
}

/// `1013` → `1.0.13`, the CANable convention. Anything else is passed through:
/// the field is free text and only this one shape is known.
fn format_version(s: &str) -> String {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() == 4 && b.iter().all(u8::is_ascii_digit) {
        format!("{}.{}.{}", &s[0..1], &s[1..2], &s[2..4])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(f: &Frame) -> String {
        String::from_utf8(encode_frame(f)).unwrap()
    }

    // --- frames ------------------------------------------------------------

    #[test]
    fn a_standard_data_frame_decodes() {
        let f = parse_frame("t1234AABBCCDD").expect("a frame");
        assert_eq!(f.arb_id, 0x123);
        assert_eq!(f.dlc, 4);
        assert_eq!(f.data, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(!f.extended && !f.rtr && !f.fd && !f.brs);
    }

    #[test]
    fn an_extended_data_frame_decodes() {
        let f = parse_frame("T123456782AABB").expect("a frame");
        assert_eq!(f.arb_id, 0x1234_5678);
        assert!(f.extended);
        assert_eq!(f.data, [0xAA, 0xBB]);
    }

    #[test]
    fn a_remote_frame_has_a_code_and_no_payload() {
        for (l, ext, id) in [
            ("r1234", false, 0x123u32),
            ("R123456784", true, 0x1234_5678),
        ] {
            let f = parse_frame(l).expect("a frame");
            assert!(f.rtr, "{l}");
            assert_eq!((f.extended, f.arb_id, f.dlc), (ext, id, 4), "{l}");
            assert!(f.data.is_empty(), "{l}");
        }
    }

    /// The four FD prefixes, and the BRS bit that only the prefix carries.
    #[test]
    fn the_four_fd_prefixes_decode() {
        for (prefix, ext, brs) in [
            ('d', false, false),
            ('D', true, false),
            ('b', false, true),
            ('B', true, true),
        ] {
            let id = if ext { "12345678" } else { "7E0" };
            let l = format!("{prefix}{id}9{}", "11".repeat(12));
            let f = parse_frame(&l).expect("a frame");
            assert!(f.fd, "{l}");
            assert_eq!((f.extended, f.brs), (ext, brs), "{l}");
            assert_eq!(f.dlc, 9, "{l}");
            assert_eq!(f.data.len(), 12, "code 9 is twelve bytes: {l}");
        }
    }

    /// The trap, from the decode side: an FD code above 8 is not a byte count.
    #[test]
    fn an_fd_code_above_eight_is_not_a_byte_count() {
        let f = parse_frame(&format!("d100F{}", "AB".repeat(64))).expect("a frame");
        assert_eq!(f.dlc, 15);
        assert_eq!(f.data.len(), 64);
    }

    #[test]
    fn a_classic_frame_may_not_carry_an_fd_code() {
        assert!(parse_frame(&format!("t100F{}", "AB".repeat(64))).is_none());
    }

    #[test]
    fn a_line_that_is_not_a_frame_is_not_one() {
        for l in ["", "V1013", "z", "x1234AABB", "t12"] {
            assert!(parse_frame(l).is_none(), "{l:?}");
        }
    }

    #[test]
    fn a_truncated_payload_is_rejected_rather_than_padded() {
        assert!(parse_frame("t1234AABB").is_none(), "claims 4, carries 2");
    }

    #[test]
    fn frames_round_trip_through_a_line() {
        let cases = [
            Frame::data(0x123, false, false, false, vec![1, 2, 3, 4]),
            Frame::data(0x1234_5678, true, false, false, vec![0xAA]),
            Frame::data(0x7E0, false, true, false, (0..12).collect()),
            Frame::data(0x7E0, false, true, true, vec![0xFF; 64]),
            Frame::data(0x1234_5678, true, true, true, vec![0x5A; 24]),
            Frame::data(0x100, false, false, false, vec![]),
            Frame::remote(0x123, false, 4),
            Frame::remote(0x1234_5678, true, 0),
        ];
        for f in cases {
            let encoded = line(&f);
            let decoded = parse_frame(encoded.trim_end_matches('\r')).expect(&encoded);
            assert_eq!(decoded, f, "{encoded}");
        }
    }

    #[test]
    fn encoded_lines_look_like_the_specification() {
        assert_eq!(
            line(&Frame::data(0x123, false, false, false, vec![0xAA, 0xBB])),
            "t1232AABB\r"
        );
        assert_eq!(
            line(&Frame::data(0x1234_5678, true, false, false, vec![0x11])),
            "T12345678111\r"
        );
        assert_eq!(line(&Frame::remote(0x123, false, 4)), "r1234\r");
        assert_eq!(
            line(&Frame::data(0x7E0, false, true, true, vec![0x22; 16])),
            format!("b7E0A{}\r", "22".repeat(16))
        );
    }

    /// A 64-byte payload is the longest line this protocol has.
    #[test]
    fn the_longest_line_is_the_advertised_length() {
        let f = Frame::data(0x1234_5678, true, true, true, vec![0; 64]);
        assert_eq!(encode_frame(&f).len(), MAX_FRAME_BYTES);
    }

    /// CAN FD has no 9-byte length, so a 9-byte payload goes out as code 9 —
    /// twelve bytes — and the line has to carry twelve. Emitting nine would
    /// produce a line the device rejects.
    #[test]
    fn an_inexact_fd_payload_is_padded_to_its_code() {
        let f = Frame::data(0x100, false, true, false, vec![0xAB; 9]);
        assert_eq!(f.dlc, 9);
        assert_eq!(
            line(&f),
            format!("d1009{}{}\r", "AB".repeat(9), "00".repeat(3))
        );
    }

    #[test]
    fn an_out_of_range_id_is_masked_rather_than_widening_the_line() {
        assert_eq!(
            line(&Frame::data(0xFFFF, false, false, false, vec![])),
            "t7FF0\r"
        );
    }

    // --- framing -----------------------------------------------------------

    #[test]
    fn lines_are_split_on_the_terminator() {
        let got = LineDecoder::new().feed(b"t1231AA\rV1013\rt1240\r");
        assert_eq!(got.len(), 3);
        assert!(matches!(got[0], Line::Frame(_)));
        assert_eq!(got[1], Line::Reply("V1013".into()));
        assert!(matches!(got[2], Line::Frame(_)));
    }

    #[test]
    fn a_line_split_across_reads_is_reassembled() {
        let mut d = LineDecoder::new();
        assert!(d.feed(b"t123").is_empty());
        assert!(d.feed(b"1A").is_empty());
        let got = d.feed(b"A\r");
        assert_eq!(got.len(), 1);
        assert!(matches!(&got[0], Line::Frame(f) if f.data == [0xAA]));
    }

    /// A bare `\r` is how a device says "that command was fine". It is not an
    /// empty line, and it must not produce one.
    #[test]
    fn an_empty_line_produces_nothing() {
        assert!(LineDecoder::new().feed(b"\r\r\n").is_empty());
    }

    #[test]
    fn a_bell_discards_the_line_in_progress() {
        let mut d = LineDecoder::new();
        let got = d.feed(b"t1231A\x07t1241BB\r");
        assert_eq!(got.len(), 1, "the interrupted line is gone");
        assert!(matches!(&got[0], Line::Frame(f) if f.arb_id == 0x124));
    }

    #[test]
    fn an_unterminated_line_is_abandoned_past_the_bound() {
        let mut d = LineDecoder::new();
        assert!(d.feed(&vec![b'A'; MAX_LINE_BYTES + 1]).is_empty());
        assert!(d.buf.is_empty());
        // And the decoder still works afterwards.
        assert_eq!(d.feed(b"t1231AA\r").len(), 1);
    }

    // --- commands ----------------------------------------------------------

    #[test]
    fn bitrate_commands_carry_their_terminator() {
        assert_eq!(bitrate_command(500_000), Some("S6\r"));
        assert_eq!(bitrate_command(10_000), Some("S0\r"));
        assert_eq!(bitrate_command(1_000_000), Some("S8\r"));
        assert_eq!(bitrate_command(300_000), None);
        assert_eq!(data_bitrate_command(2_000_000), Some("Y2\r"));
        assert_eq!(data_bitrate_command(3_000_000), None);
    }

    /// The tables are sorted and unique, so a caller can list them to a user as
    /// the valid choices without sorting them first.
    #[test]
    fn the_bitrate_tables_are_ordered_and_unique() {
        for table in [&NOMINAL_BITRATES[..], &DATA_BITRATES[..]] {
            assert!(table.windows(2).all(|w| w[0].0 < w[1].0));
        }
    }

    // --- version replies ---------------------------------------------------

    #[test]
    fn a_standard_version_reply_is_formatted_for_display() {
        let v = parse_version("V1013");
        assert_eq!(v.firmware.as_deref(), Some("1.0.13"));
        assert!(!v.elmue, "standard firmware has no CAN FD");
        assert_eq!(v.board, None);
    }

    #[test]
    fn a_version_that_is_not_four_digits_is_passed_through() {
        assert_eq!(parse_version("V2.1a").firmware.as_deref(), Some("2.1a"));
    }

    /// The Elmue reply, which is the only way to learn a device speaks CAN FD.
    #[test]
    fn an_elmue_version_reply_yields_its_fields() {
        let v = parse_version(
            "V+Board: MultiboardMCU: STM32G431DevID: 1128Firmware: 2490643Slcan: 100Clock: 160Limits: 512,256",
        );
        assert!(v.elmue);
        assert_eq!(v.firmware.as_deref(), Some("2490643"));
        assert_eq!(v.board.as_deref(), Some("Multiboard"));
        assert_eq!(v.mcu.as_deref(), Some("STM32G431"));
    }

    /// The fields run together with no separator, so the MCU has to end at the
    /// next label. Ending it at the first `D` happens to work for STM32 parts
    /// and would silently truncate anything else.
    #[test]
    fn the_mcu_ends_at_the_next_label_not_at_a_letter() {
        let v = parse_version("V+Board: XMCU: ADSP21489DevID: 9Firmware: 1000");
        assert_eq!(v.mcu.as_deref(), Some("ADSP21489"));
    }
}
