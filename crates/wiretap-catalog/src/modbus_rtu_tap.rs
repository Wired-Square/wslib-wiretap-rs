//! Modbus RTU messages off a serial line, each stamped with when it arrived.
//!
//! A message is stamped by the read that delivered its last byte: that read's
//! clock, less the wire time of the bytes after it in the read. Byte `i` of an
//! `n`-byte read at `at` arrived at `at − wire_time(n − 1 − i)`, so a message's
//! first byte arrived at `at − wire_time(raw.len() − 1)`. No stamp is earlier
//! than the clock of a read the tap has let go of, or than a stamp it has
//! already handed out, and none is earlier than the Unix epoch: a stamp can be
//! late, but it never goes backwards. The clock is the caller's.

use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::modbus_rtu_stream::{ModbusRtuMessage, ModbusRtuOptions, ModbusRtuStream};

/// A serial line's parity bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

impl Parity {
    fn letter(self) -> char {
        match self {
            Parity::None => 'N',
            Parity::Even => 'E',
            Parity::Odd => 'O',
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("parity must be none, even or odd, got {0:?}")]
pub struct UnknownParity(pub String);

/// `none`, `even` or `odd`, in any case.
impl FromStr for Parity {
    type Err = UnknownParity;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Parity::None),
            "even" => Ok(Parity::Even),
            "odd" => Ok(Parity::Odd),
            _ => Err(UnknownParity(s.to_owned())),
        }
    }
}

impl fmt::Display for Parity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Parity::None => "none",
            Parity::Even => "even",
            Parity::Odd => "odd",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidLineSettings {
    #[error("data_bits must be 5 to 8, got {0}")]
    DataBits(u8),
    #[error("stop_bits must be 1 or 2, got {0}")]
    StopBits(u8),
}

/// Why [`LineSettings::parse`] refused a line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineSettingsError {
    #[error(transparent)]
    Parity(#[from] UnknownParity),
    #[error(transparent)]
    Line(#[from] InvalidLineSettings),
}

/// A serial line's rate and character framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineSettings {
    pub baud: u32,
    /// 5 to 8.
    pub data_bits: u8,
    pub parity: Parity,
    /// 1 or 2.
    pub stop_bits: u8,
}

impl LineSettings {
    /// Start, data, parity and stop bits at the baud rate, in whole microseconds.
    pub fn wire_time(&self, bytes: u64) -> Duration {
        let bits = 1
            + u64::from(self.data_bits)
            + u64::from(self.parity != Parity::None)
            + u64::from(self.stop_bits);
        let micros = bytes
            .saturating_mul(bits * 1_000_000)
            .checked_div(u64::from(self.baud));
        Duration::from_micros(micros.unwrap_or(0))
    }

    /// An absent field reads as 8N1's, and so does an empty parity; a present
    /// one must be valid.
    pub fn parse(
        baud: u32,
        data_bits: Option<u8>,
        stop_bits: Option<u8>,
        parity: Option<&str>,
    ) -> Result<Self, LineSettingsError> {
        let parity = parity
            .filter(|p| !p.is_empty())
            .map_or(Ok(Parity::None), str::parse)?;
        let line = Self {
            baud,
            data_bits: data_bits.unwrap_or(8),
            parity,
            stop_bits: stop_bits.unwrap_or(1),
        };
        line.validate()?;
        Ok(line)
    }

    pub fn validate(&self) -> Result<(), InvalidLineSettings> {
        if !(5..=8).contains(&self.data_bits) {
            Err(InvalidLineSettings::DataBits(self.data_bits))
        } else if !matches!(self.stop_bits, 1 | 2) {
            Err(InvalidLineSettings::StopBits(self.stop_bits))
        } else {
            Ok(())
        }
    }
}

/// `9600 8N1`.
impl fmt::Display for LineSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}{}{}",
            self.baud,
            self.data_bits,
            self.parity.letter(),
            self.stop_bits
        )
    }
}

/// A message off the line, stamped when its last byte arrived.
#[derive(Debug, Clone, PartialEq)]
pub struct TappedMessage {
    pub at: SystemTime,
    pub message: ModbusRtuMessage,
}

/// One read: the stream cursor after it, and its clock.
#[derive(Debug, Clone, Copy)]
struct ReadEnd {
    end: u64,
    at: SystemTime,
}

/// One serial line's RTU framer, and the reads that fed it.
#[derive(Debug)]
pub struct RtuTap {
    options: ModbusRtuOptions,
    line: LineSettings,
    stream: ModbusRtuStream,
    /// The reads that could still deliver a message's last byte, oldest first.
    reads: VecDeque<ReadEnd>,
    floor: SystemTime,
}

impl RtuTap {
    /// A tap on one line, framing it with `options`.
    pub fn new(options: &ModbusRtuOptions, line: LineSettings) -> Self {
        Self {
            options: options.clone(),
            line,
            stream: options.stream(),
            reads: VecDeque::new(),
            floor: UNIX_EPOCH,
        }
    }

    /// One read's bytes, and the wall clock when that read returned.
    pub fn push(&mut self, bytes: &[u8], read_at: SystemTime) -> Vec<TappedMessage> {
        let messages = self.stream.push_bytes(bytes);
        self.reads.push_back(ReadEnd {
            end: self.stream.bytes_fed(),
            at: read_at,
        });
        self.stamp_all(messages)
    }

    /// A gap: the line was lost or reopened. Forgets the half message and keeps the floor.
    pub fn reset(&mut self) {
        self.release_through(u64::MAX);
        self.stream = self.options.stream();
    }

    /// End of stream: what the buffer still yields, then the residue.
    pub fn finish(&mut self) -> (Vec<TappedMessage>, Vec<u8>) {
        let (messages, residue) = self.stream.finish();
        (self.stamp_all(messages), residue)
    }

    /// Bytes pushed since the tap was made or last reset, including a finished residue.
    pub fn bytes_fed(&self) -> u64 {
        self.stream.bytes_fed()
    }

    fn stamp_all(&mut self, messages: Vec<ModbusRtuMessage>) -> Vec<TappedMessage> {
        let tapped = messages
            .into_iter()
            .map(|message| TappedMessage {
                at: self.stamp(message.end_offset),
                message,
            })
            .collect();
        self.release_through(self.stream.buffer_start());
        tapped
    }

    /// Messages come out in stream order, so the reads that ended before this
    /// one's last byte are done with.
    fn stamp(&mut self, end_offset: u64) -> SystemTime {
        self.release_through(end_offset.saturating_sub(1));
        let read = self.reads[0];
        let at = read
            .at
            .checked_sub(self.line.wire_time(read.end.saturating_sub(end_offset)))
            .unwrap_or(UNIX_EPOCH)
            .max(self.floor);
        self.floor = at;
        at
    }

    /// Lets go of every read that ended at or before `offset`, raising the floor
    /// to their clocks.
    fn release_through(&mut self, offset: u64) {
        while let Some(read) = self.reads.front().copied().filter(|r| r.end <= offset) {
            self.floor = self.floor.max(read.at);
            self.reads.pop_front();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::framing_detect::{detect, Framing};
    use crate::modbus::MAX_RTU_LEN;
    use crate::{Catalog, CrcPolicy};
    use wiretap_checksum::algorithms::crc16_modbus_checksum;

    fn with_crc(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend(crc16_modbus_checksum(body).to_le_bytes());
        out
    }

    fn at(us: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(us)
    }

    fn us(t: SystemTime) -> u64 {
        t.duration_since(UNIX_EPOCH).unwrap().as_micros() as u64
    }

    /// 10 bits a byte, 1 041.67 µs each.
    const LINE_9600_8N1: LineSettings = LineSettings {
        baud: 9600,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    fn tap_on_9600_8n1() -> RtuTap {
        RtuTap::new(&ModbusRtuOptions::tapped(), LINE_9600_8N1)
    }

    fn keys(messages: &[TappedMessage]) -> Vec<(u8, u8, usize)> {
        messages
            .iter()
            .map(|m| {
                (
                    m.message.device_address,
                    m.message.function,
                    m.message.raw.len(),
                )
            })
            .collect()
    }

    fn stamps(messages: &[TappedMessage]) -> Vec<u64> {
        messages.iter().map(|m| us(m.at)).collect()
    }

    fn increasing(stamps: &[u64]) -> bool {
        stamps.windows(2).all(|w| w[0] < w[1])
    }

    fn one_register_read() -> Vec<u8> {
        with_crc(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01])
    }

    #[test]
    fn wire_time_counts_start_parity_and_stop_bits() {
        let line = |parity, stop_bits| LineSettings {
            parity,
            stop_bits,
            ..LINE_9600_8N1
        };
        let micros = |line: LineSettings, bytes| line.wire_time(bytes).as_micros();
        assert_eq!(micros(line(Parity::None, 1), 1), 1_041, "10 bits");
        assert_eq!(micros(line(Parity::None, 1), 96), 100_000);
        assert_eq!(micros(line(Parity::Even, 2), 1), 1_250, "12 bits");
        assert_eq!(micros(line(Parity::None, 1), 0), 0);
    }

    #[test]
    fn parity_parses_any_case_and_displays_lowercase() {
        for parity in [Parity::None, Parity::Even, Parity::Odd] {
            assert_eq!(parity.to_string().parse(), Ok(parity));
            assert_eq!(parity.to_string().to_uppercase().parse(), Ok(parity));
        }
        assert_eq!("Even".parse(), Ok(Parity::Even));
        assert_eq!("e".parse::<Parity>(), Err(UnknownParity("e".into())));
        assert_eq!("".parse::<Parity>(), Err(UnknownParity(String::new())));
    }

    #[test]
    fn line_settings_display_as_baud_and_framing() {
        assert_eq!(LINE_9600_8N1.to_string(), "9600 8N1");
        let line = LineSettings {
            baud: 19200,
            data_bits: 7,
            parity: Parity::Even,
            stop_bits: 2,
        };
        assert_eq!(line.to_string(), "19200 7E2");
        let odd = LineSettings {
            parity: Parity::Odd,
            ..LINE_9600_8N1
        };
        assert_eq!(odd.to_string(), "9600 8O1");
    }

    #[test]
    fn five_to_eight_data_bits_and_one_or_two_stop_bits_validate() {
        let line = |data_bits, stop_bits| LineSettings {
            data_bits,
            stop_bits,
            ..LINE_9600_8N1
        };
        for data_bits in 5..=8 {
            for stop_bits in 1..=2 {
                assert_eq!(line(data_bits, stop_bits).validate(), Ok(()));
            }
        }
        assert_eq!(line(4, 1).validate(), Err(InvalidLineSettings::DataBits(4)));
        assert_eq!(line(9, 1).validate(), Err(InvalidLineSettings::DataBits(9)));
        assert_eq!(line(8, 0).validate(), Err(InvalidLineSettings::StopBits(0)));
        assert_eq!(line(8, 3).validate(), Err(InvalidLineSettings::StopBits(3)));
        assert_eq!(line(9, 3).validate(), Err(InvalidLineSettings::DataBits(9)));
    }

    #[test]
    fn an_absent_line_field_reads_as_8n1() {
        let parsed = |baud, data_bits, stop_bits, parity| {
            LineSettings::parse(baud, data_bits, stop_bits, parity)
                .unwrap()
                .to_string()
        };
        assert_eq!(parsed(9600, None, None, None), "9600 8N1");
        assert_eq!(parsed(9600, None, None, Some("")), "9600 8N1");
        assert_eq!(parsed(19200, Some(7), Some(2), Some("Even")), "19200 7E2");
    }

    #[test]
    fn a_present_but_invalid_line_field_is_refused() {
        assert_eq!(
            LineSettings::parse(9600, Some(9), None, None),
            Err(InvalidLineSettings::DataBits(9).into())
        );
        assert_eq!(
            LineSettings::parse(9600, None, Some(0), None),
            Err(InvalidLineSettings::StopBits(0).into())
        );
        let mark = LineSettings::parse(9600, None, None, Some("mark")).unwrap_err();
        assert_eq!(
            mark.to_string(),
            "parity must be none, even or odd, got \"mark\""
        );
    }

    #[test]
    fn a_request_and_response_become_two_messages() {
        let mut tap = tap_on_9600_8n1();
        let request = with_crc(&[0x01, 0x03, 0x1E, 0x87, 0x00, 0x02]);
        let response = with_crc(&[0x01, 0x03, 0x04, 0x00, 0x00, 0x12, 0x34]);
        let line = [&request[..], &response[..]].concat();

        let got = tap.push(&line, at(1_700_000_000_000_000));
        assert_eq!(keys(&got), [(1, 3, 8), (1, 3, 9)]);
        assert_eq!(got[0].message.raw, request);
        assert_eq!(got[1].message.raw, response);
        assert!(got.iter().all(|m| m.message.crc_valid));
        assert_eq!(us(got[1].at), 1_700_000_000_000_000, "the read's time");
    }

    /// The Sungrow line's traffic: a vendor code the length table does not
    /// model, and a broadcast. Neither is declared anywhere; both are framed.
    #[test]
    fn an_undeclared_vendor_code_is_framed() {
        let mut tap = tap_on_9600_8n1();
        let battery = with_crc(&[0x01, 0x20, 0x01, 0xC8, 0x03, 0x11, 0x1A, 0x00, 0x02]);
        let dispatch = with_crc(&[
            0x00, 0x60, 0x00, 0x00, 0x00, 0x05, 0x0A, 0x00, 0x04, 0x01, 0xBB,
        ]);
        let line = [&battery[..], &dispatch[..]].concat();

        let mut got = Vec::new();
        for (i, b) in line.iter().enumerate() {
            got.extend(tap.push(std::slice::from_ref(b), at(i as u64)));
        }
        assert_eq!(keys(&got), [(1, 0x20, 11), (0, 0x60, 13)]);
        assert_eq!(got[0].message.raw, battery);
        assert_eq!(got[1].message.raw, dispatch);
        assert_eq!(us(got[0].at), 10, "stamped when its last byte arrived");
    }

    /// A long FC03 response whose interior happens to CRC-validate at a
    /// shorter length is still framed by the length table, whole.
    #[test]
    fn a_standard_code_keeps_its_length_rule_beside_the_search() {
        // A 125-register read response, 255 bytes, from a seed found by
        // searching: its 108-byte prefix carries a valid CRC of its own.
        let mut body = vec![0x01, 0x03, 250];
        let mut x = 138u32.wrapping_mul(2_654_435_761);
        for _ in 0..250 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            body.push(x as u8);
        }
        let response = with_crc(&body);
        assert!(
            (4..response.len()).any(|n| with_crc(&response[..n - 2]) == response[..n]),
            "the seed no longer yields a spurious inner CRC"
        );

        let got = tap_on_9600_8n1().push(&response, at(0));
        assert_eq!(keys(&got), [(1, 3, 255)]);
        assert_eq!(got[0].message.raw, response);
    }

    /// Joined across a gap, half a message leaves the framer lost, holding
    /// the next message until the search gives the false head up.
    #[test]
    fn a_reset_forgets_the_half_message() {
        let request = one_register_read();

        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(0)).is_empty());
        tap.reset();
        assert_eq!(
            keys(&tap.push(&request, at(1))),
            [(1, 3, 8)],
            "framed at once"
        );

        let mut joined = tap_on_9600_8n1();
        assert!(joined.push(&request[..5], at(0)).is_empty());
        assert!(joined.push(&request, at(1)).is_empty(), "lost, and holding");
    }

    /// A line opened mid-message: every message buffered behind the false
    /// head comes out of one read, and each carries the clock of the read
    /// that delivered its last byte.
    #[test]
    fn a_sync_burst_is_stamped_by_the_read_each_message_arrived_in() {
        let request = one_register_read();
        let line = [&request[..5], &request.repeat(40)[..]].concat();

        // One byte a read, a millisecond apart.
        let mut tap = tap_on_9600_8n1();
        let mut released = Vec::new();
        for (i, b) in line.iter().enumerate() {
            let batch = tap.push(std::slice::from_ref(b), at(i as u64 * 1000));
            if !batch.is_empty() {
                released.push(batch);
            }
        }

        assert!(
            released[0].len() > 1,
            "the sync released {} message(s)",
            released[0].len()
        );
        let got = stamps(&released.concat());
        assert_eq!(got.len(), 40, "every message framed");
        // Message k's last byte is at line offset 5 + 8k + 7, in the read of
        // that index.
        let expected: Vec<u64> = (0..40).map(|k| (12 + 8 * k) * 1000).collect();
        assert_eq!(got, expected);
    }

    /// The last message carries the read's clock; each earlier one sits
    /// 8 bytes, 8.3 ms at 9600 8N1, before the next.
    #[test]
    fn messages_in_one_read_are_spread_by_wire_time() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert_eq!(tap.push(&request, at(1_000_000)).len(), 1);

        let stamps = stamps(&tap.push(&request.repeat(10), at(1_100_000)));
        assert_eq!(stamps.len(), 10);
        assert_eq!(stamps[9], 1_100_000, "the last byte is the read's");
        assert_eq!(
            stamps[8],
            1_100_000 - 8_333,
            "one message of wire time earlier"
        );
        assert_eq!(stamps[0], 1_100_000 - 75_000, "72 bytes of wire time");
        assert!(increasing(&stamps));
    }

    /// Wire time cannot reach back past a read the tap has seen return,
    /// whether it completed a message, completed nothing, or was discarded
    /// by a reopen, nor past a stamp already handed out.
    #[test]
    fn a_stamp_never_reaches_behind_a_read_the_tap_has_seen() {
        let request = one_register_read();
        let ten = request.repeat(10);

        // Half a message at t, the rest and nine more half a millisecond
        // later: 75 ms of wire time, floored at t.
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(1_000_000)).is_empty());
        let got = stamps(&tap.push(&ten[5..], at(1_000_500)));
        assert_eq!(&got[..9], &[1_000_000; 9]);
        assert_eq!(got[9], 1_000_500);

        // A read that completed nothing, then a reopen.
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(2_000_000)).is_empty());
        tap.reset();
        assert_eq!(stamps(&tap.push(&ten, at(2_000_500)))[0], 2_000_000);

        // The clock steps back between reads.
        let mut tap = tap_on_9600_8n1();
        assert_eq!(us(tap.push(&request, at(2_000_000))[0].at), 2_000_000);
        assert_eq!(us(tap.push(&request, at(1_000_000))[0].at), 2_000_000);
        tap.reset();
        assert_eq!(us(tap.push(&request, at(1_500_000))[0].at), 2_000_000);
        assert_eq!(us(tap.push(&request, at(2_500_000))[0].at), 2_500_000);
    }

    #[test]
    fn a_clock_stepping_back_mid_message_holds_the_earlier_reads_clock() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..5], at(3_000_000)).is_empty());
        assert_eq!(stamps(&tap.push(&request[5..], at(1_000_000))), [3_000_000]);
    }

    /// Every read a reset lets go of raises the floor, not only the newest.
    #[test]
    fn a_reset_keeps_the_newest_clock_of_every_read_it_lets_go_of() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        assert!(tap.push(&request[..3], at(3_000_000)).is_empty());
        assert!(tap.push(&request[3..5], at(1_000_000)).is_empty());
        tap.reset();
        assert_eq!(stamps(&tap.push(&request, at(2_000_000))), [3_000_000]);
    }

    #[test]
    fn a_pre_epoch_clock_stamps_the_epoch() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        let got = tap.push(&request, UNIX_EPOCH - Duration::from_secs(60));
        assert_eq!(got[0].at, UNIX_EPOCH);
        let got = tap.push(&request.repeat(2), at(1_000));
        assert_eq!(got[0].at, UNIX_EPOCH, "wire time reaching before the epoch");
        assert_eq!(us(got[1].at), 1_000);
    }

    /// Reads paced at the line rate, so byte `p` arrives at `p` byte times:
    /// however the line is chunked, a message's stamp less its own wire time
    /// is when its first byte arrived.
    #[test]
    fn the_first_byte_is_the_stamp_less_the_messages_wire_time() {
        // 12 bits a byte: exactly 1 250 µs, so no rounding hides a mismatch.
        let line = LineSettings {
            parity: Parity::Even,
            stop_bits: 2,
            ..LINE_9600_8N1
        };
        let byte_us = 1_250;
        let traffic = [
            one_register_read(),
            with_crc(&[0x00, 0x60, 0x00, 0x00, 0x00, 0x05, 0x0A]),
            with_crc(&[0x01, 0x03, 0x02, 0x12, 0x34]),
        ]
        .concat();
        let t0 = 1_700_000_000_000_000;

        for chunk in [1, 3, 64] {
            let mut tap = RtuTap::new(&ModbusRtuOptions::tapped(), line);
            let mut got = Vec::new();
            for (i, c) in traffic.chunks(chunk).enumerate() {
                let last_byte = (i * chunk + c.len() - 1) as u64;
                got.extend(tap.push(c, at(t0 + last_byte * byte_us)));
            }
            assert_eq!(got.len(), 3, "{chunk}-byte reads");
            for m in &got {
                let len = m.message.raw.len() as u64;
                let first_byte = m.message.end_offset - len;
                let derived = m.at - line.wire_time(len - 1);
                assert_eq!(us(derived), t0 + first_byte * byte_us, "{chunk}-byte reads");
            }
        }
    }

    #[test]
    fn the_ring_holds_only_reads_that_could_still_end_a_message() {
        let request = one_register_read();
        let mut tap = tap_on_9600_8n1();
        for (i, b) in request.iter().enumerate() {
            tap.push(std::slice::from_ref(b), at(i as u64));
        }
        assert!(tap.reads.is_empty(), "nothing buffered, nothing kept");

        tap.push(&request[..3], at(10));
        tap.push(&request[3..5], at(11));
        assert_eq!(tap.reads.len(), 2, "the reads under the half message");

        // A long line of noise and traffic, a byte a read.
        let mut x = 0x2545_F491u32;
        let mut most = 0;
        for i in 0..3_000u64 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let bytes = if i % 7 == 0 {
                request.clone()
            } else {
                vec![x as u8]
            };
            tap.push(&bytes, at(100 + i));
            most = most.max(tap.reads.len());
        }
        assert!(most <= 2 * MAX_RTU_LEN, "{most} reads kept");
    }

    #[test]
    fn finish_stamps_what_the_buffer_still_yields_by_its_own_read() {
        // CRC-invalid, and its third byte reads as a byte count, so a longer
        // candidate earns the wait until the end of the stream.
        let mut withheld = with_crc(&[0x01, 0x03, 0x04, 0x00, 0x00, 0x02]);
        withheld[7] ^= 0xFF;
        let options = ModbusRtuOptions {
            crc: CrcPolicy::Lenient,
            ..Default::default()
        };
        let mut tap = RtuTap::new(&options, LINE_9600_8N1);
        assert!(tap.push(&withheld[..4], at(1_000_000)).is_empty());
        assert!(tap.push(&withheld[4..], at(2_000_000)).is_empty());

        let (got, residue) = tap.finish();
        assert_eq!(stamps(&got), [2_000_000]);
        assert_eq!(got[0].message.raw, withheld);
        assert!(residue.is_empty());
        assert!(tap.reads.is_empty());

        let half = one_register_read()[..5].to_vec();
        assert!(tap.push(&half, at(3_000_000)).is_empty());
        assert_eq!(tap.finish(), (Vec::new(), half));
    }

    #[test]
    fn bytes_fed_counts_every_byte_pushed() {
        let mut tap = tap_on_9600_8n1();
        let request = one_register_read();
        tap.push(&request, at(0));
        tap.push(&request[..3], at(1));
        assert_eq!(tap.bytes_fed(), 11);
    }

    #[test]
    fn bytes_fed_after_finish_is_the_residues_end() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read(), at(0));
        tap.push(&[0x01, 0x03, 0x00], at(1));
        let (_, residue) = tap.finish();
        assert_eq!(residue, [0x01, 0x03, 0x00]);
        assert_eq!(tap.bytes_fed(), 11);
    }

    #[test]
    fn a_reset_zeroes_bytes_fed() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read()[..5], at(0));
        tap.reset();
        assert_eq!(tap.bytes_fed(), 0);
    }

    /// The desktop's flush, then its outage keeping the tap.
    #[test]
    fn bytes_fed_counts_up_from_zero_after_a_finish_and_reset() {
        let mut tap = tap_on_9600_8n1();
        tap.push(&one_register_read()[..5], at(0));
        tap.finish();
        tap.reset();

        let got = tap.push(&one_register_read(), at(1));
        assert_eq!(got[0].message.end_offset, 8);
        assert_eq!(tap.bytes_fed(), 8);
    }

    /// The real line, replayed. `WIRETAP_RS485_RAW` names a capture taken on
    /// the trial box: the bytes off the adapter exactly as `read` returned
    /// them, in order, with no timestamps, delimiters or headers.
    #[test]
    #[ignore = "needs a capture: WIRETAP_RS485_RAW=<path to rs485.raw>"]
    fn the_sungrow_capture_frames_at_the_measured_coverage() {
        let path = std::env::var("WIRETAP_RS485_RAW").expect("WIRETAP_RS485_RAW names the capture");
        let bytes = std::fs::read(&path).expect("the capture");
        for chunk in [64usize, 4096] {
            let mut tap = tap_on_9600_8n1();
            let mut got = Vec::new();
            let mut burst = 0;
            for (i, c) in bytes.chunks(chunk).enumerate() {
                // Read as fast as the line can deliver a chunk.
                let read_at = UNIX_EPOCH + LINE_9600_8N1.wire_time(((i + 1) * chunk) as u64);
                let batch = tap.push(c, read_at);
                if burst == 0 {
                    burst = batch.len();
                }
                got.extend(batch);
            }
            assert!(
                increasing(&stamps(&got)),
                "{chunk}-byte reads: stamps not increasing"
            );
            eprintln!("{chunk}-byte reads: the sync released {burst} messages");
            let framed: usize = got.iter().map(|m| m.message.raw.len()).sum();
            let coverage = framed as f64 / bytes.len() as f64;
            eprintln!(
                "{chunk}-byte reads: {} messages, {framed} of {} bytes ({:.4}%)",
                got.len(),
                bytes.len(),
                coverage * 100.0
            );
            assert!(
                coverage >= 0.995,
                "{chunk}-byte reads: {framed} of {} bytes framed ({coverage:.4})",
                bytes.len()
            );
            for func in [0x20, 0x60, 0x65] {
                assert!(
                    got.iter().any(|m| m.message.function == func),
                    "{chunk}-byte reads: no {func:#04x} message"
                );
            }
            assert!(got.iter().all(|m| m.message.crc_valid));
        }
    }

    fn frame_capture(options: &ModbusRtuOptions, bytes: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        let mut tap = RtuTap::new(options, LINE_9600_8N1);
        let mut got: Vec<_> = bytes
            .chunks(chunk)
            .flat_map(|c| tap.push(c, UNIX_EPOCH))
            .collect();
        got.extend(tap.finish().0);
        got.into_iter().map(|m| m.message.raw).collect()
    }

    fn report(label: &str, raws: &[Vec<u8>], total: usize) -> usize {
        let framed: usize = raws.iter().map(Vec::len).sum();
        eprintln!(
            "{label}: {} messages, {framed} of {total} bytes ({:.4}%)",
            raws.len(),
            framed as f64 / total as f64 * 100.0
        );
        for func in [0x20, 0x60, 0x65] {
            let mut lengths = std::collections::BTreeMap::<usize, usize>::new();
            for raw in raws.iter().filter(|r| r[1] == func) {
                *lengths.entry(raw.len()).or_default() += 1;
            }
            eprintln!("{label}: {func:#04x} lengths {lengths:?}");
        }
        framed
    }

    /// The Sungrow logger's vendor codes, as a catalogue that declares nothing
    /// else.
    pub(crate) const SUNGROW_FUNCTION_CODES: &str = r#"
[meta]
name = "Sungrow logger RS-485"

[meta.modbus.function_code.0x60]
lengths = [{ len = { count_at = 6, overhead = 9 } }]

# A response's first 11 bytes can also pass CRC, so its counted layout is
# tried before the request that shares its selector.
[meta.modbus.function_code.0x20]
lengths = [
  { when = { offset = 4, value = 0x03 }, len = { fixed = 11 } },
  { when = { offset = 4, value = 0x04 }, len = { count_at = 5, overhead = 8 } },
  { when = { offset = 4, value = 0x04 }, len = { fixed = 11 } },
]

[meta.modbus.function_code.0x65]
lengths = [{ len = { count_at = 4, overhead = 7 } }]
"#;

    fn sungrow_tap() -> ModbusRtuOptions {
        Catalog::parse(SUNGROW_FUNCTION_CODES)
            .unwrap()
            .rtu_options()
            .allow_broadcast()
            .frame_any_function()
    }

    #[test]
    fn a_catalogue_of_only_function_codes_configures_a_tap() {
        assert!(crate::validate::validate(SUNGROW_FUNCTION_CODES).is_empty());
        let options = sungrow_tap();
        assert_eq!(options.vendor_functions, [0x20, 0x60, 0x65]);
        assert_eq!(options.vendor_lengths.len(), 5);
        assert!(options.allow_broadcast && options.any_function);
    }

    /// The same capture with the Sungrow codes' lengths declared: no message
    /// archived short, and no fewer bytes framed than the search alone managed.
    #[test]
    #[ignore = "needs a capture: WIRETAP_RS485_RAW=<path to rs485.raw>"]
    fn declared_lengths_frame_the_sungrow_capture_whole() {
        let Ok(path) = std::env::var("WIRETAP_RS485_RAW") else {
            return;
        };
        let bytes = std::fs::read(&path).expect("the capture");
        let searched = ModbusRtuOptions::tapped();
        let declared = sungrow_tap();

        report(
            "search only",
            &frame_capture(&searched, &bytes, 4096),
            bytes.len(),
        );
        let got = frame_capture(&declared, &bytes, 64);
        let framed = report("declared", &got, bytes.len());
        for chunk in [4096, 1 << 16] {
            assert!(
                frame_capture(&declared, &bytes, chunk) == got,
                "{chunk}-byte reads frame differently from 64-byte reads"
            );
        }

        let short = |raw: &Vec<u8>| match raw[1] {
            0x60 => matches!(raw.len(), 18 | 26),
            // An 11-byte request reads with the same selector as a response.
            0x20 => {
                raw.get(4) == Some(&0x04)
                    && raw.len() != 11
                    && raw.get(5).map(|&n| 8 + n as usize) != Some(raw.len())
            }
            0x65 => raw.get(4).map(|&n| 7 + n as usize) != Some(raw.len()),
            _ => false,
        };
        assert_eq!(got.iter().filter(|r| short(r)).count(), 0);
        assert!(framed >= 34_029_275, "{framed} bytes framed");
    }

    /// Detection over the capture's tail, sampled as the desktop samples it:
    /// the codes named undeclared, and the catalogue's rules explaining the line.
    #[test]
    #[ignore = "needs a capture: WIRETAP_RS485_RAW=<path to rs485.raw>"]
    fn detection_names_the_sungrow_codes_and_their_rules_frame_the_capture() {
        let path = std::env::var("WIRETAP_RS485_RAW").expect("WIRETAP_RS485_RAW names the capture");
        let bytes = std::fs::read(&path).expect("the capture");
        let sample = &bytes[bytes.len().saturating_sub(100_000)..];
        let rules = Catalog::parse(SUNGROW_FUNCTION_CODES)
            .unwrap()
            .rtu_options()
            .allow_broadcast();

        let stock = detect(sample, &ModbusRtuOptions::default());
        let declared = detect(sample, &rules);
        for (label, detection) in [("stock", &stock), ("rules", &declared)] {
            let rank = detection
                .candidates
                .iter()
                .position(|c| c.framing == Framing::ModbusRtu);
            let frames = rank.map(|i| detection.candidates[i].frames.count);
            eprintln!(
                "{label}: RTU ranked {rank:?} with {frames:?} frames; {:?}",
                detection.unframed
            );
        }

        for func in [0x20, 0x60, 0x65] {
            assert!(stock.unframed.functions.contains(&func), "{func:#04x}");
            assert!(!declared.unframed.functions.contains(&func), "{func:#04x}");
        }
        assert!(stock.unframed.broadcasts >= 3);
        assert_eq!(declared.candidates[0].framing, Framing::ModbusRtu);
        assert_eq!(declared.unframed.broadcasts, 0);
        assert!(declared.unframed.rejected.is_empty());
    }
}
