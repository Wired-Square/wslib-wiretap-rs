//! Which framing a raw serial byte stream is using.
//!
//! SLIP and Modbus RTU are scored by running the framer that would read them —
//! [`SlipDecoder`] and the [`ModbusRtuStream`] the options build — so the tool
//! that says what a line is and the framer that reads it cannot disagree. The
//! delimiters are scored by counting positions. Detection reports facts as
//! [`Evidence`]; the wording is the caller's.
//!
//! What RTU could not frame is reported too, since declaring it is what makes a
//! vendor line readable: [`Unframed`].

use std::collections::{BTreeMap, BTreeSet};

use wiretap_checksum::algorithms::crc16_modbus_valid;
use wiretap_protocol::slip::{self, SlipDecoder};

use crate::modbus::{MAX_RTU_LEN, MIN_RTU_LEN};
use crate::modbus_rtu_stream::{ModbusRtuMessage, ModbusRtuOptions, ModbusRtuStream};

/// Delimiters worth testing, likeliest first.
const DELIMITERS: [(&[u8], &str); 6] = [
    (&[0x0D, 0x0A], "CRLF"),
    (&[0x0A], "LF"),
    (&[0x0D], "CR"),
    (&[0x00], "NUL"),
    (&[0x03], "ETX"),
    (&[0x04], "EOT"),
];

/// What [`detect`] made of a byte stream.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Detection {
    pub byte_count: usize,
    /// Highest confidence first; ties keep SLIP, RTU, then delimiter order.
    pub candidates: Vec<Candidate>,
    pub unframed: Unframed,
}

/// One framing that could explain the stream.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Candidate {
    pub framing: Framing,
    /// 0–100.
    pub confidence: u8,
    pub frames: FrameStats,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Framing {
    Slip,
    ModbusRtu,
    /// `name` is `"CRLF"`, `"LF"`, `"CR"`, `"NUL"`, `"ETX"` or `"EOT"`.
    Delimiter {
        delimiter: &'static [u8],
        name: &'static str,
    },
}

/// Frame lengths under one framing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameStats {
    pub count: usize,
    pub avg: f64,
    pub min: usize,
    pub max: usize,
}

/// What RTU couldn't frame. Codes are commonest first, at most four, each seen
/// at least three times; broadcasts count only from three upwards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unframed {
    /// Undeclared codes found by CRC in the bytes the stream skipped.
    pub functions: Vec<u8>,
    /// Address-0 messages found there while broadcast is not allowed.
    pub broadcasts: usize,
    /// Declared codes whose length rules selected a message and gave no length
    /// that CRC-validated.
    pub rejected: Vec<u8>,
}

/// One fact behind a candidate's confidence.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Evidence {
    SlipEscapes(usize),
    /// `END` turns up more often than the frames account for.
    SlipEndsInData,
    SlipFrames(usize),
    ConsistentSizes,
    /// The fraction of bytes in CRC-valid frames, from 0.8 up.
    CrcCoverage(f64),
    /// Distinct device addresses, when three or fewer.
    DeviceAddresses(usize),
    CrcFrames(usize),
    UnframedFunctions(Vec<u8>),
    UnframedBroadcasts(usize),
    RejectedFunctions(Vec<u8>),
    AsciiText,
    DelimiterFrames(usize),
}

impl FrameStats {
    fn of(lengths: &[usize]) -> Option<Self> {
        let (&min, &max) = lengths.iter().min().zip(lengths.iter().max())?;
        Some(FrameStats {
            count: lengths.len(),
            avg: lengths.iter().sum::<usize>() as f64 / lengths.len() as f64,
            min,
            max,
        })
    }

    /// True where frame sizes barely vary, which suggests a structured protocol.
    fn consistent(&self) -> bool {
        ((self.max - self.min) as f64) < self.avg * 0.5
    }
}

fn candidate(
    framing: Framing,
    confidence: i32,
    frames: FrameStats,
    evidence: Vec<Evidence>,
) -> Candidate {
    Candidate {
        framing,
        confidence: confidence.clamp(0, 100) as u8,
        frames,
        evidence,
    }
}

fn test_slip(bytes: &[u8]) -> Option<Candidate> {
    let end_count = bytes.iter().filter(|&&b| b == slip::END).count();
    let esc_count = bytes.iter().filter(|&&b| b == slip::ESC).count();
    if end_count < 2 {
        return None;
    }

    let lengths: Vec<usize> = SlipDecoder::new()
        .feed(bytes)
        .iter()
        .map(|f| f.bytes.len())
        .collect();
    let stats = FrameStats::of(&lengths)?;

    let mut evidence = Vec::new();
    let mut confidence = match stats.count {
        50.. => 50,
        10..=49 => 40,
        3..=9 => 25,
        _ => 10,
    };
    if esc_count > 0 {
        evidence.push(Evidence::SlipEscapes(esc_count));
        confidence += 25;
    }
    if (4.0..=256.0).contains(&stats.avg) {
        confidence += 15;
    }
    if stats.consistent() {
        confidence += 10;
        evidence.push(Evidence::ConsistentSizes);
    }
    // SLIP spends one or two END markers per frame. Many more than that and
    // 0xC0 is probably data rather than a delimiter.
    let end_ratio = end_count as f64 / (stats.count * 2) as f64;
    if end_ratio > 2.0 {
        confidence -= 20;
        evidence.push(Evidence::SlipEndsInData);
    } else if end_ratio <= 1.5 {
        confidence += 15;
    }
    evidence.push(Evidence::SlipFrames(stats.count));

    (confidence >= 20).then(|| candidate(Framing::Slip, confidence, stats, evidence))
}

fn test_modbus_rtu(
    bytes: &[u8],
    messages: &[ModbusRtuMessage],
    unframed: &Unframed,
) -> Option<Candidate> {
    let lengths: Vec<usize> = messages.iter().map(|m| m.raw.len()).collect();
    let stats = FrameStats::of(&lengths).filter(|s| s.count >= 2)?;

    let mut evidence = Vec::new();
    let mut confidence = match stats.count {
        10.. => 50,
        5..=9 => 35,
        _ => 20,
    };
    let covered: usize = lengths.iter().sum();
    let coverage = covered as f64 / bytes.len() as f64;
    if coverage >= 0.8 {
        confidence += 30;
        evidence.push(Evidence::CrcCoverage(coverage));
    } else if coverage >= 0.5 {
        confidence += 15;
    }
    let addresses: BTreeSet<u8> = messages.iter().map(|m| m.device_address).collect();
    if addresses.len() <= 3 {
        confidence += 10;
        evidence.push(Evidence::DeviceAddresses(addresses.len()));
    }
    evidence.push(Evidence::CrcFrames(stats.count));
    if !unframed.functions.is_empty() {
        evidence.push(Evidence::UnframedFunctions(unframed.functions.clone()));
    }
    if unframed.broadcasts > 0 {
        evidence.push(Evidence::UnframedBroadcasts(unframed.broadcasts));
    }
    if !unframed.rejected.is_empty() {
        evidence.push(Evidence::RejectedFunctions(unframed.rejected.clone()));
    }

    (confidence >= 30).then(|| candidate(Framing::ModbusRtu, confidence, stats, evidence))
}

/// Codes commonest first, at most four, each seen at least three times.
fn ranked(tally: &BTreeMap<u8, usize>) -> Vec<u8> {
    let mut ranked: Vec<(u8, usize)> = tally
        .iter()
        .map(|(&f, &n)| (f, n))
        .filter(|&(_, n)| n >= 3)
        .collect();
    ranked.sort_by_key(|&(func, n)| (std::cmp::Reverse(n), func));
    ranked.into_iter().take(4).map(|(f, _)| f).collect()
}

/// What the stream could not frame, searched for in the runs it skipped.
///
/// There by CRC alone, shortest match first, as the stream's own vendor search
/// does. An unbounded search of that kind is what the stream refuses to do,
/// because roughly one resync in 260 validates by chance; here it only ranks a
/// suggestion, and the threshold in [`ranked`] separates a stray hit from a
/// real code.
///
/// The search admits address 0 whatever the options say: a hint that cannot see
/// a broadcast can never say to allow one. Codes the stream frames are not
/// reported — an undeclared broadcast swallows the messages behind it, declared
/// or not.
fn unframed(
    bytes: &[u8],
    messages: &[ModbusRtuMessage],
    options: &ModbusRtuOptions,
    stream: &ModbusRtuStream,
) -> Unframed {
    let rejected = ranked(stream.rule_rejections());
    // Nothing framed means this is not a Modbus line, and the RTU candidate is
    // discarded either way: searching every byte of it for a coincidental CRC
    // would be the whole cost of the sample spent on a suggestion nobody sees.
    if messages.len() < 2 {
        return Unframed {
            rejected,
            ..Unframed::default()
        };
    }

    /// Two compares reject most of a stream before any CRC work.
    fn opens_message(head: &[u8], device_address: Option<u8>) -> bool {
        let Some(&[address, function]) = head.get(..2) else {
            return false;
        };
        let addressed = match device_address {
            Some(want) => address == want || address == 0,
            None => (0..=247).contains(&address),
        };
        addressed && function & 0x80 == 0
    }

    let mut tally = BTreeMap::new();
    let mut broadcasts = 0usize;
    let mut search_gap = |gap: &[u8]| {
        let mut i = 0usize;
        while i + MIN_RTU_LEN <= gap.len() {
            if !opens_message(&gap[i..], options.device_address) {
                i += 1;
                continue;
            }
            let limit = (gap.len() - i).min(MAX_RTU_LEN);
            match (MIN_RTU_LEN..=limit).find(|&n| crc16_modbus_valid(&gap[i..i + n])) {
                Some(n) => {
                    let (address, func) = (gap[i], gap[i + 1]);
                    if address == 0 && !options.allow_broadcast {
                        broadcasts += 1;
                    }
                    if !stream.frames_function(func) {
                        *tally.entry(func).or_default() += 1;
                    }
                    i += n;
                }
                None => i += 1,
            }
        }
    };
    let mut cursor = 0usize;
    for msg in messages {
        let end = msg.end_offset as usize;
        search_gap(&bytes[cursor..end - msg.raw.len()]);
        cursor = end;
    }
    search_gap(&bytes[cursor..]);

    Unframed {
        functions: ranked(&tally),
        broadcasts: if broadcasts >= 3 { broadcasts } else { 0 },
        rejected,
    }
}

fn test_delimiter(bytes: &[u8], delimiter: &'static [u8], name: &'static str) -> Option<Candidate> {
    let positions: Vec<usize> = bytes
        .windows(delimiter.len())
        .enumerate()
        .filter(|(_, w)| *w == delimiter)
        .map(|(i, _)| i)
        .collect();
    if positions.len() < 2 {
        return None;
    }

    let lengths: Vec<usize> = positions
        .windows(2)
        .map(|p| p[1] - (p[0] + delimiter.len()))
        .filter(|&n| n > 0)
        .collect();
    let stats = FrameStats::of(&lengths)?;

    let mut evidence = Vec::new();
    let mut confidence = match stats.count {
        10.. => 35,
        3..=9 => 20,
        _ => 10,
    };
    if (4.0..=256.0).contains(&stats.avg) {
        confidence += 20;
    } else if (1.0..=1024.0).contains(&stats.avg) {
        confidence += 10;
    }
    if stats.count >= 3 && stats.consistent() {
        confidence += 15;
        evidence.push(Evidence::ConsistentSizes);
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b))
        .count();
    if printable as f64 / bytes.len() as f64 > 0.7 && matches!(name, "CRLF" | "LF" | "CR") {
        confidence += 15;
        evidence.push(Evidence::AsciiText);
    }
    // A delimiter turning up far more often than the frame count implies is
    // more likely to be data.
    if positions.len() as f64 > (bytes.len() as f64 / stats.avg).floor() * 2.0 {
        confidence -= 10;
    }
    evidence.push(Evidence::DelimiterFrames(stats.count));

    let framing = Framing::Delimiter { delimiter, name };
    (confidence >= 25).then(|| candidate(framing, confidence, stats, evidence))
}

/// Rank the framings that could explain `bytes`, framing RTU as `rtu` would.
pub fn detect(bytes: &[u8], rtu: &ModbusRtuOptions) -> Detection {
    if bytes.is_empty() {
        return Detection {
            byte_count: 0,
            candidates: Vec::new(),
            unframed: Unframed::default(),
        };
    }

    let mut stream = rtu.stream();
    let mut messages = stream.push_bytes(bytes);
    messages.extend(stream.finish().0);
    let unframed = unframed(bytes, &messages, rtu, &stream);

    let mut candidates: Vec<Candidate> = test_slip(bytes)
        .into_iter()
        .chain(test_modbus_rtu(bytes, &messages, &unframed))
        .chain(
            DELIMITERS
                .iter()
                .filter_map(|&(d, name)| test_delimiter(bytes, d, name)),
        )
        .collect();
    candidates.sort_by_key(|c| std::cmp::Reverse(c.confidence));

    Detection {
        byte_count: bytes.len(),
        candidates,
        unframed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiretap_checksum::algorithms::crc16_modbus_checksum;
    use wiretap_decode::hex::parse_bytes;

    /// A Modbus RTU message: the body, with its CRC appended.
    fn msg(body: &str) -> Vec<u8> {
        let mut out = parse_bytes(body).unwrap();
        out.extend(crc16_modbus_checksum(&out).to_le_bytes());
        out
    }

    fn stock() -> ModbusRtuOptions {
        ModbusRtuOptions::default()
    }

    fn sungrow() -> ModbusRtuOptions {
        ModbusRtuOptions::default()
            .with_vendor_functions(&[0x20, 0x60, 0x65])
            .allow_broadcast()
    }

    /// A read request and the response answering it, repeated.
    fn polling(pairs: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..pairs {
            out.extend(msg("01044DE20002"));
            out.extend(msg("010404CAFEF00D"));
        }
        out
    }

    fn best(bytes: &[u8], options: &ModbusRtuOptions) -> Option<Framing> {
        detect(bytes, options)
            .candidates
            .into_iter()
            .next()
            .map(|c| c.framing)
    }

    fn rtu(detection: &Detection) -> Option<&Candidate> {
        detection
            .candidates
            .iter()
            .find(|c| c.framing == Framing::ModbusRtu)
    }

    fn framed(bytes: &[u8], options: &ModbusRtuOptions) -> usize {
        rtu(&detect(bytes, options)).map_or(0, |c| c.frames.count)
    }

    #[test]
    fn an_empty_stream_detects_nothing() {
        let out = detect(&[], &stock());
        assert_eq!(out.byte_count, 0);
        assert!(out.candidates.is_empty());
        assert_eq!(out.unframed, Unframed::default());
    }

    #[test]
    fn a_modbus_line_is_recognised_by_its_crcs() {
        let bytes = polling(8);
        assert_eq!(best(&bytes, &stock()), Some(Framing::ModbusRtu));
        assert_eq!(framed(&bytes, &stock()), 16);
    }

    #[test]
    fn a_slip_stream_is_recognised() {
        // 0xC0-delimited frames, one carrying an escape.
        let mut bytes = Vec::new();
        for i in 0..12u8 {
            bytes.push(0xC0);
            bytes.extend([0x01, 0x02, i, 0xDB, 0xDC]);
        }
        bytes.push(0xC0);
        assert_eq!(best(&bytes, &stock()), Some(Framing::Slip));
    }

    #[test]
    fn a_crlf_text_stream_is_recognised_as_a_delimiter() {
        let bytes: Vec<u8> = std::iter::repeat_n(b"STATUS,OK,1234\r\n".as_slice(), 20)
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            best(&bytes, &stock()),
            Some(Framing::Delimiter {
                delimiter: b"\r\n",
                name: "CRLF"
            })
        );
    }

    #[test]
    fn an_exception_response_is_framed() {
        // Five bytes, shorter than its own function code's length rule.
        let mut bytes = polling(3);
        bytes.extend(msg("018402"));
        let out = detect(&bytes, &stock());
        let frames = rtu(&out).unwrap().frames;
        assert_eq!(frames.count, 7);
        assert_eq!(frames.min, 5);
    }

    #[test]
    fn a_vendor_line_is_unreadable_until_its_codes_are_declared() {
        // What a Sungrow logger's RS-485 line looks like: vendor codes and a
        // broadcasting master, with a little standard polling mixed in.
        let mut bytes = polling(2);
        for _ in 0..6 {
            bytes.extend(msg("012001C803111A0002"));
            bytes.extend(msg("0060000000050A000401BB03E808"));
            bytes.extend(msg("0165000200"));
        }
        assert_eq!(
            framed(&bytes, &stock()),
            4,
            "only the standard polling should frame"
        );
        assert_eq!(framed(&bytes, &sungrow()), 22);
    }

    #[test]
    fn the_codes_it_could_not_frame_are_reported() {
        // The whole point of the hint: you should not have to already know them.
        let mut bytes = polling(2);
        for _ in 0..6 {
            bytes.extend(msg("012001C803111A0002"));
            bytes.extend(msg("0165000200"));
        }
        let functions = detect(&bytes, &stock()).unframed.functions;
        assert!(functions.contains(&0x20), "{functions:?}");
        assert!(functions.contains(&0x65), "{functions:?}");

        // Declared, they are framed rather than reported.
        assert!(detect(&bytes, &sungrow()).unframed.functions.is_empty());
    }

    #[test]
    fn a_broadcast_needs_declaring_too() {
        let mut bytes = polling(2);
        for _ in 0..6 {
            bytes.extend(msg("0060000000050A000401BB03E808"));
        }
        let with_vendor = ModbusRtuOptions::default().with_vendor_functions(&[0x60]);
        assert_eq!(
            framed(&bytes, &with_vendor),
            4,
            "address 0 cannot start a message"
        );
        assert_eq!(framed(&bytes, &sungrow()), 10);

        // The hint has to say so, or the line stays unreadable with every code
        // declared. Allowed, the broadcasts frame and the hint goes quiet.
        let hint = detect(&bytes, &with_vendor).unframed;
        assert_eq!(hint.broadcasts, 6);
        assert!(hint.functions.is_empty(), "{:?}", hint.functions);
        assert_eq!(detect(&bytes, &sungrow()).unframed.broadcasts, 0);
    }

    #[test]
    fn a_split_message_is_not_resynced_through() {
        // A message straddling the end of the sample must not have its head
        // eaten byte by byte.
        let mut bytes = polling(4);
        let tail = msg("01044DE20002");
        bytes.extend(&tail[..tail.len() - 1]);
        assert_eq!(framed(&bytes, &stock()), 8);
    }
}

#[cfg(test)]
mod feeder_check {
    use super::*;
    use crate::modbus_rtu_tap::tests::SUNGROW_FUNCTION_CODES;
    use crate::{Catalog, VendorLen, VendorLength};
    use wiretap_decode::hex::parse_bytes;

    /// `scripts/modbus_rtu_feeder.py --start 8 --cycles 4` (the desktop's),
    /// verbatim. Four cycles so the vendor codes clear the hint's occurrence
    /// threshold as they would on any real line, starting at 8 so one of them
    /// carries an exception response.
    const VENDOR_LINE: &str = "01044de20002c69101040401340000bbb602030010000185fc02030200027d8501010000000abc0d0101022a02275d0105001aff00adfd012001c803111a0000650b0060000000050a000401bb03e80832e8016500020807aa01044de20002c69101040401350000ea7602030010000185fc0203020003bc4501010000000abc0d010102d50266ad0105001a0000ec0d012001c803111a0001a4cb0060000000050a000401bb03e80832e80165000209c66a01044de20002c691010404013600001a7602030010000185fc0203020004fd8701010000000abc0d0101022a02275d0105001aff00adfd012001c803111a0002e4ca0060000000050a000401bb03e80832e8016500020a866b018402c2c101044de20002c691010404013700004bb602030010000185fc02030200053c4701010000000abc0d010102d50266ad0105001aff00adfd012001c803111a0003250a0060000000050a000401bb03e80832e8016500020b47ab";

    /// The same line with `--stock`: its 29 spec-defined messages, no vendor
    /// codes and no broadcast.
    const STOCK_LINE: &str = "01044de20002c69101040401340000bbb602030010000185fc02030200027d8501010000000abc0d0101022a02275d0105001aff00adfd01044de20002c69101040401350000ea7602030010000185fc0203020003bc4501010000000abc0d010102d50266ad0105001a0000ec0d01044de20002c691010404013600001a7602030010000185fc0203020004fd8701010000000abc0d0101022a02275d0105001aff00adfd018402c2c101044de20002c691010404013700004bb602030010000185fc02030200053c4701010000000abc0d010102d50266ad0105001aff00adfd";

    /// `VENDOR_LINE` with its vendor messages laid out as the Sungrow rules
    /// read them: `0x60`'s count byte is the 7 data bytes it carries, and `0x65`
    /// carries a one-byte block counted at `b[4]`. `0x20` already fits. What
    /// the feeder's `--rules --start 8 --cycles 4` emits.
    const RULES_LINE: &str = concat!(
        "01044de20002c69101040401340000bbb602030010000185fc02030200027d8501010000000abc0d0101022a02275d0105001aff00adfd",
        "012001c803111a0000650b",
        "00600000000507000401bb03e808f371",
        "016500020108ec54",
        "01044de20002c69101040401350000ea7602030010000185fc0203020003bc4501010000000abc0d010102d50266ad0105001a0000ec0d",
        "012001c803111a0001a4cb",
        "00600000000507000401bb03e808f371",
        "0165000201092d94",
        "01044de20002c691010404013600001a7602030010000185fc0203020004fd8701010000000abc0d0101022a02275d0105001aff00adfd",
        "012001c803111a0002e4ca",
        "00600000000507000401bb03e808f371",
        "01650002010a6d95",
        "018402c2c1",
        "01044de20002c691010404013700004bb602030010000185fc02030200053c4701010000000abc0d010102d50266ad0105001aff00adfd",
        "012001c803111a0003250a",
        "00600000000507000401bb03e808f371",
        "01650002010bac55",
    );

    fn bytes(line: &str) -> Vec<u8> {
        parse_bytes(line).unwrap()
    }

    fn framed(line: &str, options: &ModbusRtuOptions) -> usize {
        detect(&bytes(line), options)
            .candidates
            .iter()
            .find(|c| c.framing == Framing::ModbusRtu)
            .map_or(0, |c| c.frames.count)
    }

    fn sungrow_rules() -> ModbusRtuOptions {
        Catalog::parse(SUNGROW_FUNCTION_CODES)
            .unwrap()
            .rtu_options()
    }

    #[test]
    fn the_feeders_stream_frames_as_advertised() {
        let stock = ModbusRtuOptions::default();
        let declared = ModbusRtuOptions::default()
            .with_vendor_functions(&[0x20, 0x60, 0x65])
            .allow_broadcast();

        // 41 messages on the wire, 29 of them spec-defined. Undeclared, the 12
        // vendor ones fail to frame.
        assert_eq!(framed(VENDOR_LINE, &stock), 29);
        assert_eq!(framed(VENDOR_LINE, &declared), 41);

        // And the tool names everything standing in the way, first time —
        // including the broadcast it cannot itself frame — and, once the user has
        // declared what it said, does not name those again.
        let hint = detect(&bytes(VENDOR_LINE), &stock).unframed;
        assert_eq!(hint.functions, [0x20, 0x60, 0x65]);
        assert_eq!(hint.broadcasts, 4);
        let partial = ModbusRtuOptions::default().with_vendor_functions(&[0x20, 0x65]);
        assert_eq!(framed(VENDOR_LINE, &partial), 37);
        let hint = detect(&bytes(VENDOR_LINE), &partial).unframed;
        assert_eq!(hint.functions, [0x60]);
        assert_eq!(hint.broadcasts, 4);
    }

    #[test]
    fn a_stock_line_frames_whole_with_nothing_declared() {
        let stock = ModbusRtuOptions::default();
        let report = detect(&bytes(STOCK_LINE), &stock);
        assert_eq!(report.candidates[0].framing, Framing::ModbusRtu);
        assert_eq!(framed(STOCK_LINE, &stock), 29);
        assert_eq!(report.unframed, Unframed::default());
    }

    #[test]
    fn a_catalogues_length_rules_frame_a_line_laid_out_by_them() {
        let rules = sungrow_rules();
        let hint = detect(&bytes(RULES_LINE), &rules).unframed;
        assert_eq!(framed(RULES_LINE, &rules), 37);
        assert_eq!(
            hint,
            Unframed {
                broadcasts: 4,
                ..Unframed::default()
            }
        );

        let rules = rules.allow_broadcast();
        assert_eq!(framed(RULES_LINE, &rules), 41);
        assert_eq!(
            detect(&bytes(RULES_LINE), &rules).unframed,
            Unframed::default()
        );
    }

    #[test]
    fn a_code_declared_only_by_a_length_rule_is_not_reported_unframed() {
        let telemetry = VendorLength {
            function: 0x65,
            when: None,
            len: VendorLen::Counted {
                count_at: 4,
                overhead: 7,
            },
        };
        let options = ModbusRtuOptions::default()
            .with_vendor_functions(&[0x20])
            .with_vendor_lengths(&[telemetry]);
        assert_eq!(framed(RULES_LINE, &options), 37);

        let unframed = detect(&bytes(VENDOR_LINE), &options).unframed;
        assert_eq!(unframed.functions, [0x60]);
        assert_eq!(unframed.rejected, [0x65]);
    }

    /// The failure `rejected` exists for: the codes are declared, so the hint
    /// is silent about them, and their rules drop every one.
    #[test]
    fn declared_codes_their_rules_reject_are_named() {
        let out = detect(&bytes(VENDOR_LINE), &sungrow_rules().allow_broadcast());
        assert_eq!(
            out.unframed,
            Unframed {
                rejected: vec![0x60, 0x65],
                ..Unframed::default()
            }
        );
        assert_eq!(out.candidates[0].frames.count, 34);
    }
}
