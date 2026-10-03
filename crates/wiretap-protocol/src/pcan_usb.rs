//! PCAN-USB, PEAK-System's classic SJA1000 adapter (PID `0x000C`) — not the
//! PCAN-USB FD or Pro family, which speak another protocol.
//!
//! Reference: the kernel driver, `drivers/net/can/usb/peak_usb/pcan_usb.c`,
//! and `docs/pcan_usb.md`.
//!
//! In one bulk-IN message only the first timestamped record carries the whole
//! 16-bit tick count; each later one carries its low byte, and a low byte below
//! the previous one carries into the high byte. So records decode in order,
//! never one alone.
//!
//! A frame whose id flags carry SRR is the adapter handing back one this host
//! sent, and is followed by one client byte. On transmit that byte is written
//! whenever SRR is, remote frames included, as the kernel writes it.

use crate::{
    bittiming::{calculate, Constraints, Timing},
    ARB_MASK_EXT, ARB_MASK_STD,
};

pub const VID: u16 = 0x0c72;
pub const PID: u16 = 0x000c;

pub const EP_COMMAND_OUT: u8 = 0x01;
pub const EP_COMMAND_IN: u8 = 0x81;
pub const EP_MESSAGE_OUT: u8 = 0x02;
pub const EP_MESSAGE_IN: u8 = 0x82;

/// Every bulk message, both ways.
pub const MESSAGE_BYTES: usize = 64;

/// `bcdDevice >> 8`, the revision the features below are keyed on.
pub fn device_rev(bcd_device: u16) -> u8 {
    (bcd_device >> 8) as u8
}

pub const SILENT_MODE_FROM_REV: u8 = 4;
/// Self-reception (SRR) and one-shot.
pub const SELF_RECEPTION_FROM_REV: u8 = 41;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub const COMMAND_BYTES: usize = 16;
pub const ARGS_BYTES: usize = 14;

pub mod function {
    pub const BITRATE: u8 = 1;
    pub const SET_BUS: u8 = 3;
    pub const DEVID: u8 = 4;
    pub const SN: u8 = 6;
    pub const REGISTER: u8 = 9;
    pub const EXT_VCC: u8 = 10;
    pub const ERR_FR: u8 = 11;
    pub const LED: u8 = 12;
}

pub mod number {
    pub const GET: u8 = 1;
    pub const SET: u8 = 2;
    /// `SET_BUS`'s: the transceiver, bus on or off.
    pub const XCVER: u8 = 2;
    pub const SILENT_MODE: u8 = 3;
}

/// `ERR_FR`'s mask: report the rx and tx error counters on every change.
pub const BERR_MASK: u8 = 0x06;

/// One command on the command endpoints, or a reply to a `GET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    pub function: u8,
    pub number: u8,
    pub args: [u8; ARGS_BYTES],
}

impl Command {
    pub fn get(function: u8) -> Self {
        Self {
            function,
            number: number::GET,
            args: [0; ARGS_BYTES],
        }
    }

    fn with(function: u8, number: u8, args: &[u8]) -> Self {
        let mut command = Self {
            function,
            number,
            args: [0; ARGS_BYTES],
        };
        command.args[..args.len()].copy_from_slice(args);
        command
    }

    /// The transceiver on or off.
    pub fn set_bus(on: bool) -> Self {
        Self::with(function::SET_BUS, number::XCVER, &[on.into()])
    }

    pub fn set_silent(on: bool) -> Self {
        Self::with(function::SET_BUS, number::SILENT_MODE, &[on.into()])
    }

    /// The SJA1000 into reset (init) mode, or out of it.
    pub fn set_sja1000_init(init: bool) -> Self {
        Self::with(function::REGISTER, number::SET, &[0, init.into()])
    }

    pub fn set_bitrate(btr: Btr) -> Self {
        Self::with(function::BITRATE, number::SET, &[btr.btr1, btr.btr0])
    }

    pub fn set_error_frames(mask: u8) -> Self {
        Self::with(function::ERR_FR, number::SET, &[mask])
    }

    pub fn set_ext_vcc(on: bool) -> Self {
        Self::with(function::EXT_VCC, number::SET, &[on.into()])
    }

    pub fn to_bytes(&self) -> [u8; COMMAND_BYTES] {
        let mut b = [0u8; COMMAND_BYTES];
        b[0] = self.function;
        b[1] = self.number;
        b[2..].copy_from_slice(&self.args);
        b
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let data = data.get(..COMMAND_BYTES)?;
        Some(Self::with(data[0], data[1], &data[2..]))
    }
}

/// A `GET SN` reply's serial number, or `None` where none was ever programmed
/// (an erased `0xFFFFFFFF`).
pub fn serial_number(args: &[u8; ARGS_BYTES]) -> Option<u32> {
    let sn = u32::from_le_bytes([args[0], args[1], args[2], args[3]]);
    (sn != u32::MAX).then_some(sn)
}

// ---------------------------------------------------------------------------
// Bit timing
// ---------------------------------------------------------------------------

/// The SJA1000's clock: half the 16 MHz crystal.
pub const CLOCK_HZ: u32 = 8_000_000;
pub const BITTIMING: Constraints = Constraints {
    tseg1_min: 1,
    tseg1_max: 16,
    tseg2_min: 1,
    tseg2_max: 8,
    sjw_max: 4,
    brp_min: 1,
    brp_max: 64,
    brp_inc: 1,
};

/// The SJA1000's two bus timing registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Btr {
    pub btr0: u8,
    pub btr1: u8,
}

impl Btr {
    pub fn brp(self) -> u32 {
        u32::from(self.btr0 & 0x3f) + 1
    }

    pub fn sjw(self) -> u32 {
        u32::from(self.btr0 >> 6) + 1
    }

    /// `prop_seg + phase_seg1`.
    pub fn tseg1(self) -> u32 {
        u32::from(self.btr1 & 0x0f) + 1
    }

    pub fn tseg2(self) -> u32 {
        u32::from((self.btr1 >> 4) & 0x07) + 1
    }

    pub fn triple_sampling(self) -> bool {
        self.btr1 & 0x80 != 0
    }

    fn timing(self) -> Timing {
        Timing {
            brp: self.brp(),
            prop_seg: 0,
            phase_seg1: self.tseg1(),
            phase_seg2: self.tseg2(),
            sjw: self.sjw(),
        }
    }

    pub fn bitrate(self) -> u32 {
        self.timing().bitrate(CLOCK_HZ)
    }

    /// Percent.
    pub fn sample_point(self) -> f32 {
        self.timing().sample_point()
    }
}

impl From<Timing> for Btr {
    fn from(t: Timing) -> Self {
        Self {
            btr0: ((t.brp - 1) & 0x3f) as u8 | (((t.sjw - 1) & 0x03) << 6) as u8,
            btr1: ((t.tseg1() - 1) & 0x0f) as u8 | (((t.phase_seg2 - 1) & 0x07) << 4) as u8,
        }
    }
}

/// The kernel's `can_calc_bittiming` for this controller: `None` where no
/// timing lands within 5% of `bitrate`. `sample_point` is in percent.
pub fn btr_for_bitrate(bitrate: u32, sample_point: Option<f32>) -> Option<Btr> {
    calculate(CLOCK_HZ, bitrate, sample_point, &BITTIMING).map(Btr::from)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// µs = ticks × `TICK_SCALE` >> `TICK_SHIFT`: a tick is 42.666 µs.
pub const TICK_SCALE: u64 = 44_739_243;
pub const TICK_SHIFT: u32 = 20;

pub fn ticks_to_us(ticks: u64) -> u64 {
    ((u128::from(ticks) * u128::from(TICK_SCALE)) >> TICK_SHIFT) as u64
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A record's first byte.
pub mod status_len {
    pub const TIMESTAMP: u8 = 1 << 7;
    pub const INTERNAL: u8 = 1 << 6;
    pub const EXT_ID: u8 = 1 << 5;
    pub const RTR: u8 = 1 << 4;
    pub const DLC: u8 = 0x0f;
}

/// Flags in the low bits of a data record's id.
pub mod id_flags {
    pub const SRR: u32 = 0x01;
    pub const AT: u32 = 0x02;
}

/// A status record's function.
pub mod record {
    pub const ERROR: u8 = 1;
    pub const ANALOG: u8 = 2;
    pub const BUSLOAD: u8 = 3;
    pub const TS: u8 = 4;
    pub const BUSEVT: u8 = 5;
}

/// An `ERROR` record's number.
pub mod error_flags {
    pub const TXFULL: u8 = 0x01;
    pub const RXQOVR: u8 = 0x02;
    pub const BUS_LIGHT: u8 = 0x04;
    pub const BUS_HEAVY: u8 = 0x08;
    pub const BUS_OFF: u8 = 0x10;
    pub const RXQEMPTY: u8 = 0x20;
    pub const QOVR: u8 = 0x40;
    pub const TXQFULL: u8 = 0x80;
}

const HEADER_BYTES: usize = 2;
const MSG_TX_CAN: u8 = 2;
const CLIENT_ID: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    /// The raw nibble: up to 15 on a classic frame, whose payload stops at 8.
    pub dlc: u8,
    pub data: Vec<u8>,
    /// Self-reception: on a received frame, this host's own send handed back.
    pub srr: bool,
}

/// One record of a bulk-IN message. Analog, bus-load and unknown records are
/// skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Frame {
        frame: Frame,
        ticks: u16,
    },
    Error {
        flags: u8,
        ticks: Option<u16>,
    },
    /// The device's periodic sync.
    Timestamp(u16),
    BusEvent {
        rxerr: u8,
        txerr: u8,
        ticks: Option<u16>,
    },
}

/// A bulk-IN message's records, up to the first one that doesn't fit.
pub fn decode_message(message: &[u8]) -> Vec<Record> {
    let mut records = Vec::new();
    if message.len() <= HEADER_BYTES {
        return records;
    }
    let mut reader = Reader {
        message,
        at: HEADER_BYTES,
        ts16: 0,
        prev_ts8: 0,
        stamped: false,
    };
    for _ in 0..message[1] {
        match reader.record() {
            Some(Some(record)) => records.push(record),
            Some(None) => {}
            None => break,
        }
    }
    records
}

struct Reader<'a> {
    message: &'a [u8],
    at: usize,
    ts16: u16,
    prev_ts8: u8,
    stamped: bool,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let bytes = self.message.get(self.at..self.at + n)?;
        self.at += n;
        Some(bytes)
    }

    fn peek(&self, n: usize) -> Option<&'a [u8]> {
        self.message.get(self.at..self.at + n)
    }

    fn le16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn timestamp(&mut self) -> Option<u16> {
        if self.stamped {
            let ts8 = self.take(1)?[0];
            if ts8 < self.prev_ts8 {
                self.ts16 = self.ts16.wrapping_add(0x100);
            }
            self.ts16 = (self.ts16 & 0xff00) | u16::from(ts8);
            self.prev_ts8 = ts8;
        } else {
            self.ts16 = self.le16()?;
            self.prev_ts8 = self.ts16 as u8;
            self.stamped = true;
        }
        Some(self.ts16)
    }

    fn record(&mut self) -> Option<Option<Record>> {
        let status = self.take(1)?[0];
        if status & status_len::INTERNAL != 0 {
            self.status(status)
        } else {
            self.frame(status).map(Some)
        }
    }

    fn frame(&mut self, status: u8) -> Option<Record> {
        let extended = status & status_len::EXT_ID != 0;
        let (arb_id, flags) = if extended {
            let b = self.take(4)?;
            let raw = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            (raw >> 3, raw)
        } else {
            let raw = u32::from(self.le16()?);
            (raw >> 5, raw)
        };
        let dlc = status & status_len::DLC;
        let ticks = self.timestamp()?;
        let rtr = status & status_len::RTR != 0;
        let srr = flags & id_flags::SRR != 0;
        let data = if rtr {
            Vec::new()
        } else {
            let data = self.take(dlc.into())?[..usize::from(dlc.min(8))].to_vec();
            if srr {
                self.at += 1;
            }
            data
        };
        Some(Record::Frame {
            frame: Frame {
                arb_id,
                extended,
                rtr,
                dlc,
                data,
                srr,
            },
            ticks,
        })
    }

    fn status(&mut self, status: u8) -> Option<Option<Record>> {
        let head = self.take(2)?;
        let (function, number) = (head[0], head[1]);
        let ticks = if status & status_len::TIMESTAMP != 0 {
            Some(self.timestamp()?)
        } else {
            None
        };
        let mut len = usize::from(status & status_len::DLC);
        let record = match function {
            record::ERROR => Some(Record::Error {
                flags: number,
                ticks,
            }),
            record::ANALOG => {
                len = 2;
                None
            }
            record::BUSLOAD => {
                len = 1;
                None
            }
            record::TS => {
                let b = self.peek(2)?;
                self.ts16 = u16::from_le_bytes([b[0], b[1]]);
                Some(Record::Timestamp(self.ts16))
            }
            record::BUSEVT if number == 0x00 || number == 0x80 => {
                let b = self.peek(3)?;
                Some(Record::BusEvent {
                    rxerr: b[1],
                    txerr: b[2],
                    ticks,
                })
            }
            _ => None,
        };
        self.take(len)?;
        Some(record)
    }
}

/// The bulk-OUT message sending `frame`, with `sequence` in its last byte.
pub fn encode_transmit(frame: &Frame, sequence: u8) -> [u8; MESSAGE_BYTES] {
    let mut out = [0u8; MESSAGE_BYTES];
    out[0] = MSG_TX_CAN;
    out[1] = 1;
    out[2] = (frame.dlc & status_len::DLC)
        | if frame.rtr { status_len::RTR } else { 0 }
        | if frame.extended {
            status_len::EXT_ID
        } else {
            0
        };
    let srr = if frame.srr { id_flags::SRR } else { 0 };
    let mut at = if frame.extended {
        let raw = ((frame.arb_id & ARB_MASK_EXT) << 3) | srr;
        out[3..7].copy_from_slice(&raw.to_le_bytes());
        7
    } else {
        let raw = (((frame.arb_id & ARB_MASK_STD) << 5) | srr) as u16;
        out[3..5].copy_from_slice(&raw.to_le_bytes());
        5
    };
    if !frame.rtr {
        let len = frame.data.len().min(8);
        out[at..at + len].copy_from_slice(&frame.data[..len]);
        at += len;
    }
    if frame.srr {
        out[at] = CLIENT_ID;
    }
    out[MESSAGE_BYTES - 1] = sequence;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bittiming::cia_sample_point;

    fn command(bytes: &[u8]) -> [u8; COMMAND_BYTES] {
        let mut b = [0u8; COMMAND_BYTES];
        b[..bytes.len()].copy_from_slice(bytes);
        b
    }

    fn frame(arb_id: u32, extended: bool, rtr: bool, dlc: u8, data: &[u8], srr: bool) -> Frame {
        Frame {
            arb_id,
            extended,
            rtr,
            dlc,
            data: data.to_vec(),
            srr,
        }
    }

    fn message(records: &[&[u8]]) -> Vec<u8> {
        let mut m = vec![0x00, records.len() as u8];
        m.extend(records.concat());
        m
    }

    // --- commands ----------------------------------------------------------

    #[test]
    fn each_command_is_the_kernels_sixteen_bytes() {
        for (sent, wire) in [
            (Command::get(function::SN), command(&[6, 1])),
            (Command::get(function::DEVID), command(&[4, 1])),
            (Command::set_bus(false), command(&[3, 2, 0])),
            (Command::set_bus(true), command(&[3, 2, 1])),
            (Command::set_silent(true), command(&[3, 3, 1])),
            (Command::set_sja1000_init(true), command(&[9, 2, 0, 1])),
            (Command::set_sja1000_init(false), command(&[9, 2, 0, 0])),
            (
                Command::set_bitrate(Btr {
                    btr0: 0x01,
                    btr1: 0x1c,
                }),
                command(&[1, 2, 0x1c, 0x01]),
            ),
            (
                Command::set_error_frames(BERR_MASK),
                command(&[11, 2, 0x06]),
            ),
            (Command::set_ext_vcc(false), command(&[10, 2, 0])),
        ] {
            assert_eq!(sent.to_bytes(), wire, "{sent:?}");
            assert_eq!(Command::from_bytes(&wire), Some(sent));
        }
        assert_eq!(Command::from_bytes(&[6, 1, 0]), None);
    }

    #[test]
    fn a_reply_carries_the_serial_in_its_args_and_an_erased_one_is_none() {
        let reply = Command::from_bytes(&command(&[6, 1, 0x78, 0x56, 0x34, 0x12])).unwrap();
        assert_eq!(serial_number(&reply.args), Some(0x1234_5678));
        let erased = Command::from_bytes(&command(&[6, 1, 0xff, 0xff, 0xff, 0xff])).unwrap();
        assert_eq!(serial_number(&erased.args), None);
    }

    #[test]
    fn the_revision_is_bcd_devices_high_byte() {
        assert_eq!(device_rev(0x54ff), 84);
    }

    // --- bit timing --------------------------------------------------------

    /// PEAK's own published register values.
    #[test]
    fn the_standard_rates_time_to_peaks_constants() {
        for (bitrate, btr0, btr1) in [
            (1_000_000, 0x00, 0x14),
            (800_000, 0x00, 0x16),
            (500_000, 0x00, 0x1c),
            (250_000, 0x01, 0x1c),
            (125_000, 0x03, 0x1c),
        ] {
            let btr = btr_for_bitrate(bitrate, None).unwrap();
            assert_eq!(btr, Btr { btr0, btr1 }, "{bitrate}");
            assert_eq!(btr.bitrate(), bitrate);
            assert_eq!(btr.sample_point(), cia_sample_point(bitrate));
        }
    }

    #[test]
    fn a_given_sample_point_is_honoured() {
        let btr = btr_for_bitrate(500_000, Some(75.0)).unwrap();
        assert_eq!((btr.bitrate(), btr.sample_point()), (500_000, 75.0));
        assert!(!btr.triple_sampling());
        assert_eq!(btr_for_bitrate(500_000, Some(100.0)), None);
    }

    #[test]
    fn the_slowest_rate_takes_the_largest_prescaler() {
        let btr = btr_for_bitrate(5_000, None).unwrap();
        assert_eq!((btr.brp(), btr.bitrate()), (64, 5_000));
        assert_eq!((btr.tseg1(), btr.tseg2(), btr.sjw()), (16, 8, 4));
    }

    /// Four quanta at the undivided clock: the kernel's search allows it.
    #[test]
    fn two_megabits_is_timeable_as_the_kernel_times_it() {
        let btr = btr_for_bitrate(2_000_000, None).unwrap();
        assert_eq!(
            btr,
            Btr {
                btr0: 0x00,
                btr1: 0x01
            }
        );
        assert_eq!((btr.bitrate(), btr.sample_point()), (2_000_000, 75.0));
    }

    #[test]
    fn a_rate_the_clock_cant_divide_to_is_none() {
        assert_eq!(btr_for_bitrate(0, None), None);
        assert_eq!(btr_for_bitrate(3_000_000, None), None);
        assert_eq!(btr_for_bitrate(u32::MAX, None), None);
        assert_eq!(btr_for_bitrate(1_000, None), None);
    }

    #[test]
    fn ticks_convert_by_the_kernels_scale() {
        assert_eq!(ticks_to_us(1_000), 42_666);
        assert_eq!(ticks_to_us(65_535), 2_796_160);
        assert_eq!(ticks_to_us(1 << 16), 2_796_202);
    }

    // --- messages ----------------------------------------------------------

    #[test]
    fn only_the_first_stamp_is_a_word_and_a_lower_byte_carries() {
        let m = message(&[
            &[0x02, 0x60, 0x24, 0xf0, 0x12, 0xaa, 0xbb],
            &[0x01, 0xe0, 0xff, 0x05, 0xcc],
            &[0x00, 0x20, 0x00, 0x06],
        ]);
        assert_eq!(
            decode_message(&m),
            [
                Record::Frame {
                    frame: frame(0x123, false, false, 2, &[0xaa, 0xbb], false),
                    ticks: 0x12f0,
                },
                Record::Frame {
                    frame: frame(0x7ff, false, false, 1, &[0xcc], false),
                    ticks: 0x1305,
                },
                Record::Frame {
                    frame: frame(0x001, false, false, 0, &[], false),
                    ticks: 0x1306,
                },
            ]
        );
    }

    #[test]
    fn an_extended_frame_and_a_remote_frame() {
        let m = message(&[
            &[
                0x28, 0x80, 0x88, 0xd7, 0xc6, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8,
            ],
            &[0x14, 0x60, 0x24, 0x11],
        ]);
        assert_eq!(
            decode_message(&m),
            [
                Record::Frame {
                    frame: frame(
                        0x18da_f110,
                        true,
                        false,
                        8,
                        &[1, 2, 3, 4, 5, 6, 7, 8],
                        false
                    ),
                    ticks: 0x1000,
                },
                Record::Frame {
                    frame: frame(0x123, false, true, 4, &[], false),
                    ticks: 0x1011,
                },
            ]
        );
    }

    #[test]
    fn a_length_code_above_eight_carries_eight_bytes_but_consumes_all() {
        let mut data = vec![0x0a, 0x60, 0x24, 0x00, 0x00];
        data.extend([0x55; 10]);
        let m = message(&[&data, &[0x40, 1, 0x02]]);
        let records = decode_message(&m);
        let Record::Frame { frame: f, .. } = &records[0] else {
            panic!("a frame");
        };
        assert_eq!((f.dlc, f.data.len()), (10, 8));
        assert_eq!(
            records[1],
            Record::Error {
                flags: error_flags::RXQOVR,
                ticks: None
            }
        );
    }

    #[test]
    fn an_srr_echo_skips_its_client_byte() {
        let m = message(&[
            &[0x01, 0x01, 0x20, 0x34, 0x12, 0x11, 0x80],
            &[0x40, 1, 0x02],
        ]);
        assert_eq!(
            decode_message(&m),
            [
                Record::Frame {
                    frame: frame(0x100, false, false, 1, &[0x11], true),
                    ticks: 0x1234,
                },
                Record::Error {
                    flags: error_flags::RXQOVR,
                    ticks: None
                },
            ]
        );
    }

    #[test]
    fn a_status_record_is_stamped_only_with_bit_seven() {
        let m = message(&[
            &[0xc0, 1, error_flags::BUS_OFF, 0x34, 0x12],
            &[0x40, 1, error_flags::BUS_HEAVY],
            &[0xc0, 1, error_flags::BUS_LIGHT, 0x40],
        ]);
        assert_eq!(
            decode_message(&m),
            [
                Record::Error {
                    flags: error_flags::BUS_OFF,
                    ticks: Some(0x1234)
                },
                Record::Error {
                    flags: error_flags::BUS_HEAVY,
                    ticks: None
                },
                Record::Error {
                    flags: error_flags::BUS_LIGHT,
                    ticks: Some(0x1240)
                },
            ]
        );
    }

    /// The kernel re-bases on a sync's word but keeps the previous low byte to
    /// compare against, so the next byte can carry past the sync.
    #[test]
    fn a_sync_record_re_bases_the_next_stamp() {
        let m = message(&[
            &[0x00, 0x20, 0x00, 0xf0, 0x00],
            &[0x42, 4, 0, 0x34, 0x12],
            &[0x00, 0x20, 0x00, 0x40],
        ]);
        let records = decode_message(&m);
        assert_eq!(records[1], Record::Timestamp(0x1234));
        assert!(matches!(records[2], Record::Frame { ticks: 0x1340, .. }));
    }

    #[test]
    fn a_bus_event_reads_its_counters_and_analog_and_bus_load_are_skipped() {
        let m = message(&[
            &[0x43, 5, 0x80, 0, 7, 9],
            &[0x40, 2, 0, 0xaa, 0xbb],
            &[0x40, 3, 0, 0xcc],
            &[0x40, 9, 0],
            &[0x43, 5, 0x01, 0, 1, 2],
            &[0x40, 1, error_flags::TXFULL],
        ]);
        assert_eq!(
            decode_message(&m),
            [
                Record::BusEvent {
                    rxerr: 7,
                    txerr: 9,
                    ticks: None
                },
                Record::Error {
                    flags: error_flags::TXFULL,
                    ticks: None
                },
            ]
        );
    }

    #[test]
    fn a_message_that_ends_mid_record_keeps_the_records_before_it() {
        let m = message(&[
            &[0x02, 0x60, 0x24, 0xf0, 0x12, 0xaa, 0xbb],
            &[0x08, 0x60, 0x24, 0x01, 1, 2],
        ]);
        assert_eq!(decode_message(&m).len(), 1);
        assert_eq!(decode_message(&m[..6]).len(), 0);
        let mut counted_short = m.clone();
        counted_short[1] = 1;
        assert_eq!(decode_message(&counted_short).len(), 1);
        assert!(decode_message(&[0x00, 0x01]).is_empty());
        assert!(decode_message(&[]).is_empty());
    }

    // --- transmit ----------------------------------------------------------

    fn transmit(head: &[u8], sequence: u8) -> [u8; MESSAGE_BYTES] {
        let mut out = [0u8; MESSAGE_BYTES];
        out[..head.len()].copy_from_slice(head);
        out[MESSAGE_BYTES - 1] = sequence;
        out
    }

    #[test]
    fn a_send_is_one_record_with_the_sequence_in_the_last_byte() {
        for (sent, sequence, wire) in [
            (
                frame(0x123, false, false, 3, &[1, 2, 3], false),
                7,
                transmit(&[2, 1, 0x03, 0x60, 0x24, 1, 2, 3], 7),
            ),
            (
                frame(0x18da_f110, true, false, 1, &[0xaa], false),
                0,
                transmit(&[2, 1, 0x21, 0x80, 0x88, 0xd7, 0xc6, 0xaa], 0),
            ),
            (
                frame(0x123, false, true, 5, &[], false),
                255,
                transmit(&[2, 1, 0x15, 0x60, 0x24], 255),
            ),
            (
                frame(0x100, false, false, 1, &[0x11], true),
                1,
                transmit(&[2, 1, 0x01, 0x01, 0x20, 0x11, 0x80], 1),
            ),
            (
                frame(0x100, true, true, 2, &[], true),
                2,
                transmit(&[2, 1, 0x32, 0x01, 0x08, 0x00, 0x00, 0x80], 2),
            ),
        ] {
            assert_eq!(encode_transmit(&sent, sequence), wire, "{sent:?}");
        }
    }
}
