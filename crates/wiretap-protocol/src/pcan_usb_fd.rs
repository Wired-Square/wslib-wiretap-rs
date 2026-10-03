//! PEAK-System's uCAN adapters over USB: PCAN-USB FD, PCAN-Chip USB, PCAN-USB
//! Pro FD and PCAN-USB X6. **Untested: no device of this family has met this
//! code.** Every byte of it is read from the kernel source, none from a wire.
//!
//! Reference: the kernel driver, `drivers/net/can/usb/peak_usb/pcan_usb_fd.c`,
//! with `include/linux/can/dev/peak_canfd.h` for the uCAN layouts and
//! `pcan_usb_pro.c` for the vendor requests, and `docs/pcan_usb_fd.md`.
//!
//! Commands go out as one list of 8-byte records. A list with room left for
//! another record ends with an end-of-collection record; one that fills the
//! 512-byte buffer does not. Off a high-speed link the firmware can't
//! reassemble more than 64 bytes, so there the list goes out 64 at a time.
//!
//! A received buffer is a run of records, each giving its own size. A zero size
//! ends the run; so does a record that is short for its type, runs past the
//! buffer or names a channel past the second, the records before it standing.

use crate::{
    bittiming::{Constraints, Timing},
    dlc_to_len, len_to_dlc, ARB_MASK_EXT, ARB_MASK_STD,
};

pub use crate::pcan_usb::VID;

pub const PID_USB_PRO_FD: u16 = 0x0011;
pub const PID_USB_FD: u16 = 0x0012;
pub const PID_CHIP_USB: u16 = 0x0013;
pub const PID_USB_X6: u16 = 0x0014;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    pub pid: u16,
    pub name: &'static str,
    /// Per USB device: the kernel binds an X6 as several of two each.
    pub channels: u8,
}

pub const PRODUCTS: [Product; 4] = [
    Product {
        pid: PID_USB_FD,
        name: "PCAN-USB FD",
        channels: 1,
    },
    Product {
        pid: PID_CHIP_USB,
        name: "PCAN-Chip USB",
        channels: 1,
    },
    Product {
        pid: PID_USB_PRO_FD,
        name: "PCAN-USB Pro FD",
        channels: 2,
    },
    Product {
        pid: PID_USB_X6,
        name: "PCAN-USB X6",
        channels: 2,
    },
];

pub fn product(pid: u16) -> Option<Product> {
    PRODUCTS.into_iter().find(|p| p.pid == pid)
}

/// The kernel's interface probe: the PCAN-USB FD's CAN interface is 0, and the
/// others' is one whose endpoints all lie in the default layout.
pub fn is_can_interface(pid: u16, interface: u8, endpoints: &[u8]) -> bool {
    if pid == PID_USB_FD {
        return interface == 0;
    }
    endpoints.iter().all(|ep| PRO_LAYOUT.contains(ep))
}

/// PCAN-USB Pro's endpoints, `0x83` unused among them.
const PRO_LAYOUT: [u8; 6] = [0x01, 0x81, 0x02, 0x82, 0x03, 0x83];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    pub command_out: u8,
    /// Named by the firmware info, but nothing is read from it.
    pub command_in: u8,
    /// One per channel.
    pub data_out: [u8; 2],
    /// Shared by both channels.
    pub data_in: u8,
}

impl Endpoints {
    /// PCAN-USB Pro's, used where the firmware info doesn't name its own.
    pub const DEFAULT: Self = Self {
        command_out: 0x01,
        command_in: 0x81,
        data_out: [0x02, 0x03],
        data_in: 0x82,
    };
}

// ---------------------------------------------------------------------------
// Vendor requests
// ---------------------------------------------------------------------------

/// `bRequest`s on the default control pipe: vendor type, recipient other,
/// `wIndex` 0.
pub mod request {
    pub const INFO: u8 = 0;
    pub const FCT: u8 = 2;
}

/// `INFO`'s `wValue` for the [`FirmwareInfo`], read IN.
pub const INFO_FW: u16 = 1;
/// `FCT`'s `wValue` telling the device a driver is or isn't loaded, written OUT.
pub const FCT_DRVLD: u16 = 5;
pub const DRVLD_BYTES: usize = 16;

pub fn driver_loaded(loaded: bool) -> [u8; DRVLD_BYTES] {
    let mut b = [0u8; DRVLD_BYTES];
    b[1] = loaded.into();
    b
}

/// The reply to `INFO` `INFO_FW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareInfo {
    pub size_of: u16,
    /// 2 and up carries the endpoints.
    pub kind: u16,
    pub hw_type: u8,
    pub bl_version: [u8; 3],
    pub hw_version: u8,
    pub fw_version: [u8; 3],
    /// A user-set id per channel.
    pub dev_id: [u32; 2],
    pub ser_no: u32,
    pub flags: u32,
    pub endpoints: Option<Endpoints>,
}

impl FirmwareInfo {
    pub const SIZE: usize = 36;
    const BASE_SIZE: usize = 28;
    const WITH_ENDPOINTS: u16 = 2;

    /// `None` when short for its `kind`.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::BASE_SIZE {
            return None;
        }
        let kind = le16(b, 2);
        let endpoints = if kind >= Self::WITH_ENDPOINTS {
            let e = b.get(28..33)?;
            Some(Endpoints {
                command_out: e[0],
                command_in: e[1],
                data_out: [e[2], e[3]],
                data_in: e[4],
            })
        } else {
            None
        };
        Some(Self {
            size_of: le16(b, 0),
            kind,
            hw_type: b[4],
            bl_version: [b[5], b[6], b[7]],
            hw_version: b[8],
            fw_version: [b[9], b[10], b[11]],
            dev_id: [le32(b, 12), le32(b, 16)],
            ser_no: le32(b, 20),
            flags: le32(b, 24),
            endpoints,
        })
    }

    pub fn endpoints(&self) -> Endpoints {
        self.endpoints.unwrap_or(Endpoints::DEFAULT)
    }

    /// `None` where none was ever programmed (an erased `0xFFFFFFFF`).
    pub fn serial_number(&self) -> Option<u32> {
        (self.ser_no != u32::MAX).then_some(self.ser_no)
    }

    /// Firmware from 2.0 can be told ISO or non-ISO CAN FD; before it, it is
    /// non-ISO and fixed.
    pub fn iso_switchable(&self) -> bool {
        self.fw_version[0] >= 2
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub const COMMAND_BYTES: usize = 8;
pub const COMMAND_BUFFER_BYTES: usize = 512;
/// The most a device off a high-speed link takes in one command transfer.
pub const FULL_SPEED_PACKET_BYTES: usize = 64;

pub type Command = [u8; COMMAND_BYTES];

/// The low 10 bits of a command's first word.
pub mod opcode {
    pub const NOP: u16 = 0x000;
    pub const RESET_MODE: u16 = 0x001;
    pub const NORMAL_MODE: u16 = 0x002;
    pub const LISTEN_ONLY_MODE: u16 = 0x003;
    pub const TIMING_SLOW: u16 = 0x004;
    pub const TIMING_FAST: u16 = 0x005;
    pub const SET_STD_FILTER: u16 = 0x006;
    pub const FILTER_STD: u16 = 0x008;
    pub const TX_ABORT: u16 = 0x009;
    pub const WR_ERR_CNT: u16 = 0x00a;
    pub const SET_EN_OPTION: u16 = 0x00b;
    pub const CLR_DIS_OPTION: u16 = 0x00c;
    pub const RX_BARRIER: u16 = 0x010;
    pub const END_OF_COLLECTION: u16 = 0x3ff;
    pub const CLK_SET: u16 = 0x080;
    pub const DEVID_SET: u16 = 0x081;
    pub const LED_SET: u16 = 0x086;
}

pub fn opcode_channel(channel: u8, opcode: u16) -> u16 {
    (u16::from(channel) << 12) | (opcode & 0x3ff)
}

fn command(channel: u8, opcode: u16, args: [u8; 6]) -> Command {
    let mut c = [0u8; COMMAND_BYTES];
    c[..2].copy_from_slice(&opcode_channel(channel, opcode).to_le_bytes());
    c[2..].copy_from_slice(&args);
    c
}

pub const END_OF_COLLECTION: Command = [0xff; COMMAND_BYTES];

pub fn reset_mode(channel: u8) -> Command {
    command(channel, opcode::RESET_MODE, [0; 6])
}

pub fn normal_mode(channel: u8) -> Command {
    command(channel, opcode::NORMAL_MODE, [0; 6])
}

pub fn listen_only_mode(channel: u8) -> Command {
    command(channel, opcode::LISTEN_ONLY_MODE, [0; 6])
}

/// The clock every channel is timed from, once `clock_set(CLOCK_80MHZ)`.
pub const CLOCK_HZ: u32 = 80_000_000;
pub const CLOCK_80MHZ: u8 = 0;

pub fn clock_set(channel: u8, mode: u8) -> Command {
    command(channel, opcode::CLK_SET, [mode, 0, 0, 0, 0, 0])
}

/// The LED as the device drives it.
pub const LED_DEVICE: u8 = 0;

pub fn led_set(channel: u8, mode: u8) -> Command {
    command(channel, opcode::LED_SET, [mode, 0, 0, 0, 0, 0])
}

pub const NOMINAL_BITTIMING: Constraints = Constraints {
    tseg1_min: 1,
    tseg1_max: 256,
    tseg2_min: 1,
    tseg2_max: 128,
    sjw_max: 128,
    brp_min: 1,
    brp_max: 1024,
    brp_inc: 1,
};

pub const DATA_BITTIMING: Constraints = Constraints {
    tseg1_min: 1,
    tseg1_max: 32,
    tseg2_min: 1,
    tseg2_max: 16,
    sjw_max: 16,
    brp_min: 1,
    brp_max: 1024,
    brp_inc: 1,
};

/// The error warning limit the kernel sends.
pub const EWL: u8 = 96;

/// The nominal (arbitration) phase, triple sampling off.
pub fn timing_slow(channel: u8, t: Timing) -> Command {
    let brp = (((t.brp - 1) & 0x3ff) as u16).to_le_bytes();
    command(
        channel,
        opcode::TIMING_SLOW,
        [
            EWL,
            ((t.sjw - 1) & 0x7f) as u8,
            ((t.phase_seg2 - 1) & 0x7f) as u8,
            ((t.tseg1() - 1) & 0xff) as u8,
            brp[0],
            brp[1],
        ],
    )
}

/// The CAN FD data phase.
pub fn timing_fast(channel: u8, t: Timing) -> Command {
    let brp = (((t.brp - 1) & 0x3ff) as u16).to_le_bytes();
    command(
        channel,
        opcode::TIMING_FAST,
        [
            0,
            ((t.sjw - 1) & 0x0f) as u8,
            ((t.phase_seg2 - 1) & 0x0f) as u8,
            ((t.tseg1() - 1) & 0x1f) as u8,
            brp[0],
            brp[1],
        ],
    )
}

/// Row `row` of the 64 × 32-bit standard-id filter: bit `j` passes id
/// `row × 32 + j`.
pub fn filter_std(channel: u8, row: u16, mask: u32) -> Command {
    let [r0, r1] = row.to_le_bytes();
    let [m0, m1, m2, m3] = mask.to_le_bytes();
    command(channel, opcode::FILTER_STD, [r0, r1, m0, m1, m2, m3])
}

pub const FILTER_ROWS: u16 = 64;

/// Every row open, as the kernel opens a channel.
pub fn accept_all(channel: u8) -> Vec<Command> {
    (0..FILTER_ROWS)
        .map(|row| filter_std(channel, row, u32::MAX))
        .collect()
}

/// Both error counters written back to zero.
pub fn reset_error_counters(channel: u8) -> Command {
    const TE: u16 = 0x4000;
    const RE: u16 = 0x8000;
    let [s0, s1] = (TE | RE).to_le_bytes();
    command(channel, opcode::WR_ERR_CNT, [s0, s1, 0, 0, 0, 0])
}

/// uCAN option bits, for [`set_options`] and [`set_iso`].
pub mod option {
    pub const ERROR: u16 = 0x0001;
    pub const BUSLOAD: u16 = 0x0002;
    pub const CANFD_ISO: u16 = 0x0004;
}

/// The USB option bit asking for [`Message::Calibration`] records.
pub const USB_CALIBRATION: u16 = 0x8000;

/// `SET_EN_OPTION` or `CLR_DIS_OPTION` with the USB adapter's extra mask.
pub fn set_options(channel: u8, enable: bool, ucan: u16, usb: u16) -> Command {
    let [u0, u1] = ucan.to_le_bytes();
    let [b0, b1] = usb.to_le_bytes();
    command(channel, option_opcode(enable), [u0, u1, 0, 0, b0, b1])
}

/// ISO CAN FD, or non-ISO; only for firmware that is [`FirmwareInfo::iso_switchable`].
pub fn set_iso(channel: u8, iso: bool) -> Command {
    let [o0, o1] = option::CANFD_ISO.to_le_bytes();
    command(channel, option_opcode(iso), [o0, o1, 0, 0, 0, 0])
}

fn option_opcode(enable: bool) -> u16 {
    if enable {
        opcode::SET_EN_OPTION
    } else {
        opcode::CLR_DIS_OPTION
    }
}

/// The kernel's `pcan_usb_fd_build_restart_cmd`: the error counters cleared,
/// the ISO choice where the firmware takes one, and the mode.
pub fn bus_on(channel: u8, listen_only: bool, iso: Option<bool>) -> Vec<Command> {
    let mode = if listen_only {
        listen_only_mode(channel)
    } else {
        normal_mode(channel)
    };
    [reset_error_counters(channel)]
        .into_iter()
        .chain(iso.map(|iso| set_iso(channel, iso)))
        .chain([mode])
        .collect()
}

/// The bytes one command write carries, ended where there is room.
pub fn command_list(commands: &[Command]) -> Vec<u8> {
    let mut list = commands.concat();
    if list.len() <= COMMAND_BUFFER_BYTES - COMMAND_BYTES {
        list.extend(END_OF_COLLECTION);
    }
    list
}

/// A command list as its bulk transfers.
pub fn transfers(list: &[u8], high_speed: bool) -> core::slice::Chunks<'_, u8> {
    list.chunks(if high_speed {
        list.len().max(1)
    } else {
        FULL_SPEED_PACKET_BYTES
    })
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

pub const RX_BUFFER_BYTES: usize = 2048;
pub const TX_BUFFER_BYTES: usize = 512;
/// The kernel's `PCAN_USB_MAX_CHANNEL`: a record naming another ends the buffer.
pub const MAX_CHANNELS: u8 = 2;

/// A record's type.
pub mod message {
    pub const CAN_RX: u16 = 0x0001;
    pub const ERROR: u16 = 0x0002;
    pub const STATUS: u16 = 0x0003;
    pub const BUSLOAD: u16 = 0x0004;
    pub const CALIBRATION: u16 = 0x0100;
    pub const OVERRUN: u16 = 0x0101;
    pub const CAN_TX: u16 = 0x1000;
}

/// A frame record's flags.
pub mod flags {
    pub const SELF_RECEIVE: u16 = 0x80;
    pub const ESI: u16 = 0x40;
    pub const BRS: u16 = 0x20;
    /// CAN FD.
    pub const EXT_DATA_LEN: u16 = 0x10;
    pub const SINGLE_SHOT: u16 = 0x08;
    pub const LOOPED_BACK: u16 = 0x04;
    pub const EXT_ID: u16 = 0x02;
    pub const RTR: u16 = 0x01;
}

/// A status record's bits, above its channel.
pub mod status {
    pub const RX_BARRIER: u8 = 0x10;
    pub const PASSIVE: u8 = 0x20;
    pub const WARNING: u8 = 0x40;
    pub const BUSOFF: u8 = 0x80;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: u8,
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    pub fd: bool,
    pub brs: bool,
    pub esi: bool,
    /// The raw code: up to 15 on a classic frame, whose payload stops at 8.
    pub dlc: u8,
    pub data: Vec<u8>,
}

/// One received record, stamped in µs by the device's 64-bit clock. Bus-load
/// and unknown records are skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    CanRx {
        frame: Frame,
        ts_us: u64,
    },
    /// The controller's error counters.
    Error {
        channel: u8,
        tx_err_cnt: u8,
        rx_err_cnt: u8,
        ts_us: u64,
    },
    /// `flags` are [`status`] bits.
    Status {
        channel: u8,
        flags: u8,
        ts_us: u64,
    },
    Overrun {
        channel: u8,
        ts_us: u64,
    },
    Calibration {
        usb_frame_index: u16,
        ts_us: u64,
    },
}

const HEAD_BYTES: usize = 12;
const CAN_RX_HEAD_BYTES: usize = 28;
const TX_HEAD_BYTES: usize = 20;

fn min_size(kind: u16) -> usize {
    match kind {
        message::CAN_RX => CAN_RX_HEAD_BYTES,
        message::ERROR | message::STATUS | message::CALIBRATION | message::OVERRUN => 16,
        _ => HEAD_BYTES,
    }
}

/// A data-IN buffer's records, up to the first that ends it.
pub fn decode_messages(buffer: &[u8]) -> Vec<Message> {
    let mut messages = Vec::new();
    let mut rest = buffer;
    while rest.len() >= HEAD_BYTES {
        let size = usize::from(le16(rest, 0));
        let kind = le16(rest, 2);
        if size == 0 || size > rest.len() || size < min_size(kind) {
            break;
        }
        let (record, next) = rest.split_at(size);
        match decode(kind, record) {
            Some(Some(message)) => messages.push(message),
            Some(None) => {}
            None => break,
        }
        rest = next;
    }
    messages
}

fn decode(kind: u16, r: &[u8]) -> Option<Option<Message>> {
    let ts_us = (u64::from(le32(r, 8)) << 32) | u64::from(le32(r, 4));
    let channel = || Some(r[12] & 0x0f).filter(|c| *c < MAX_CHANNELS);
    let message = match kind {
        message::CAN_RX => Message::CanRx {
            frame: can_rx(r)?,
            ts_us,
        },
        message::ERROR => Message::Error {
            channel: channel()?,
            tx_err_cnt: r[14],
            rx_err_cnt: r[15],
            ts_us,
        },
        message::STATUS => Message::Status {
            channel: channel()?,
            flags: r[12] & 0xf0,
            ts_us,
        },
        message::OVERRUN => Message::Overrun {
            channel: channel()?,
            ts_us,
        },
        message::CALIBRATION => Message::Calibration {
            usb_frame_index: le16(r, 12),
            ts_us,
        },
        _ => return Some(None),
    };
    Some(Some(message))
}

fn can_rx(r: &[u8]) -> Option<Frame> {
    let channel = r[20] & 0x0f;
    if channel >= MAX_CHANNELS {
        return None;
    }
    let dlc = r[20] >> 4;
    let flags = le16(r, 22);
    let has = |flag| flags & flag != 0;
    let (fd, rtr, extended) = (
        has(flags::EXT_DATA_LEN),
        has(flags::RTR),
        has(flags::EXT_ID),
    );
    let data = if rtr {
        Vec::new()
    } else {
        let len = dlc_to_len(dlc, fd);
        r.get(CAN_RX_HEAD_BYTES..CAN_RX_HEAD_BYTES + len)?.to_vec()
    };
    let id_mask = if extended { ARB_MASK_EXT } else { ARB_MASK_STD };
    Some(Frame {
        channel,
        arb_id: le32(r, 24) & id_mask,
        extended,
        rtr,
        fd,
        brs: fd && has(flags::BRS),
        esi: fd && has(flags::ESI),
        dlc,
        data,
    })
}

/// The data-OUT transfer sending `frame` on its channel: one record, its
/// payload zero-padded to its length code's, then a zero size ending the list.
/// A CAN FD frame's code is its payload's; a classic frame's is `dlc`.
pub fn encode_transmit(frame: &Frame) -> Vec<u8> {
    let dlc = if frame.fd {
        len_to_dlc(frame.data.len())
    } else {
        frame.dlc & 0x0f
    };
    let len = dlc_to_len(dlc, frame.fd);
    let size = (TX_HEAD_BYTES + len).next_multiple_of(4);
    let mut flags = 0;
    if frame.extended {
        flags |= flags::EXT_ID;
    }
    if frame.fd {
        flags |= flags::EXT_DATA_LEN;
        if frame.brs {
            flags |= flags::BRS;
        }
        if frame.esi {
            flags |= flags::ESI;
        }
    } else if frame.rtr {
        flags |= flags::RTR;
    }
    let id_mask = if frame.extended {
        ARB_MASK_EXT
    } else {
        ARB_MASK_STD
    };

    let mut out = vec![0u8; size + 4];
    out[0..2].copy_from_slice(&(size as u16).to_le_bytes());
    out[2..4].copy_from_slice(&message::CAN_TX.to_le_bytes());
    out[12] = (frame.channel & 0x0f) | (dlc << 4);
    out[14..16].copy_from_slice(&flags.to_le_bytes());
    out[16..20].copy_from_slice(&(frame.arb_id & id_mask).to_le_bytes());
    let copied = frame.data.len().min(len);
    out[TX_HEAD_BYTES..TX_HEAD_BYTES + copied].copy_from_slice(&frame.data[..copied]);
    out
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bittiming::calculate;

    // --- identity ----------------------------------------------------------

    #[test]
    fn each_pid_is_its_model_with_its_channels() {
        let seen: Vec<_> = [0x0011, 0x0012, 0x0013, 0x0014, 0x000c]
            .into_iter()
            .map(|pid| product(pid).map(|p| (p.name, p.channels)))
            .collect();
        assert_eq!(
            seen,
            [
                Some(("PCAN-USB Pro FD", 2)),
                Some(("PCAN-USB FD", 1)),
                Some(("PCAN-Chip USB", 1)),
                Some(("PCAN-USB X6", 2)),
                None,
            ]
        );
        assert_eq!(VID, 0x0c72);
    }

    #[test]
    fn the_usb_fd_takes_interface_zero_and_the_others_the_default_layout() {
        assert!(is_can_interface(PID_USB_FD, 0, &[0x05, 0x85]));
        assert!(!is_can_interface(PID_USB_FD, 1, &[0x01, 0x81]));
        let pro = [0x01, 0x81, 0x02, 0x82, 0x03, 0x83];
        assert!(is_can_interface(PID_USB_PRO_FD, 1, &pro));
        assert!(!is_can_interface(PID_USB_X6, 0, &[0x01, 0x84]));
    }

    // --- vendor requests ---------------------------------------------------

    fn firmware_info(kind: u16, fw_major: u8, ser_no: u32) -> Vec<u8> {
        let mut b = vec![0u8; FirmwareInfo::SIZE];
        b[0..2].copy_from_slice(&36u16.to_le_bytes());
        b[2..4].copy_from_slice(&kind.to_le_bytes());
        b[4] = 3;
        b[5..8].copy_from_slice(&[1, 2, 3]);
        b[8] = 7;
        b[9..12].copy_from_slice(&[fw_major, 5, 6]);
        b[12..16].copy_from_slice(&0x1111_1111u32.to_le_bytes());
        b[16..20].copy_from_slice(&0x2222_2222u32.to_le_bytes());
        b[20..24].copy_from_slice(&ser_no.to_le_bytes());
        b[24..28].copy_from_slice(&0x10u32.to_le_bytes());
        b[28..33].copy_from_slice(&[0x04, 0x84, 0x05, 0x06, 0x87]);
        b
    }

    #[test]
    fn firmware_info_carries_its_endpoints_from_type_two() {
        let info = FirmwareInfo::from_bytes(&firmware_info(2, 3, 0x00AB_CDEF)).unwrap();
        assert_eq!(
            info,
            FirmwareInfo {
                size_of: 36,
                kind: 2,
                hw_type: 3,
                bl_version: [1, 2, 3],
                hw_version: 7,
                fw_version: [3, 5, 6],
                dev_id: [0x1111_1111, 0x2222_2222],
                ser_no: 0x00AB_CDEF,
                flags: 0x10,
                endpoints: Some(Endpoints {
                    command_out: 0x04,
                    command_in: 0x84,
                    data_out: [0x05, 0x06],
                    data_in: 0x87,
                }),
            }
        );
        assert_eq!(info.serial_number(), Some(0x00AB_CDEF));
        assert!(info.iso_switchable());
        assert!(FirmwareInfo::from_bytes(&firmware_info(2, 3, 0)[..32]).is_none());
    }

    #[test]
    fn before_type_two_the_endpoints_are_the_default_layout() {
        let bytes = firmware_info(1, 1, u32::MAX);
        for b in [&bytes[..], &bytes[..28]] {
            let info = FirmwareInfo::from_bytes(b).unwrap();
            assert_eq!(info.endpoints, None);
            assert_eq!(info.endpoints(), Endpoints::DEFAULT);
            assert_eq!(info.serial_number(), None);
            assert!(!info.iso_switchable());
        }
        assert!(FirmwareInfo::from_bytes(&bytes[..27]).is_none());
    }

    #[test]
    fn drvld_is_sixteen_bytes_with_the_flag_second() {
        let mut on = [0u8; 16];
        on[1] = 1;
        assert_eq!(driver_loaded(true), on);
        assert_eq!(driver_loaded(false), [0u8; 16]);
    }

    // --- commands ----------------------------------------------------------

    #[test]
    fn each_command_is_the_kernels_eight_bytes() {
        let t = Timing {
            brp: 2,
            prop_seg: 5,
            phase_seg1: 6,
            phase_seg2: 4,
            sjw: 3,
        };
        for (sent, wire) in [
            (reset_mode(0), [0x01, 0x00, 0, 0, 0, 0, 0, 0]),
            (reset_mode(1), [0x01, 0x10, 0, 0, 0, 0, 0, 0]),
            (normal_mode(0), [0x02, 0x00, 0, 0, 0, 0, 0, 0]),
            (listen_only_mode(1), [0x03, 0x10, 0, 0, 0, 0, 0, 0]),
            (timing_slow(0, t), [0x04, 0x00, 96, 2, 3, 10, 1, 0]),
            (timing_fast(1, t), [0x05, 0x10, 0, 2, 3, 10, 1, 0]),
            (
                filter_std(0, 63, 0xffff_ffff),
                [0x08, 0x00, 63, 0, 0xff, 0xff, 0xff, 0xff],
            ),
            (
                reset_error_counters(0),
                [0x0a, 0x00, 0x00, 0xc0, 0, 0, 0, 0],
            ),
            (
                set_options(0, true, option::ERROR, USB_CALIBRATION),
                [0x0b, 0x00, 0x01, 0x00, 0, 0, 0x00, 0x80],
            ),
            (
                set_options(1, false, option::ERROR, USB_CALIBRATION),
                [0x0c, 0x10, 0x01, 0x00, 0, 0, 0x00, 0x80],
            ),
            (set_iso(0, true), [0x0b, 0x00, 0x04, 0x00, 0, 0, 0, 0]),
            (set_iso(0, false), [0x0c, 0x00, 0x04, 0x00, 0, 0, 0, 0]),
            (clock_set(0, CLOCK_80MHZ), [0x80, 0x00, 0, 0, 0, 0, 0, 0]),
            (led_set(1, LED_DEVICE), [0x86, 0x10, 0, 0, 0, 0, 0, 0]),
        ] {
            assert_eq!(sent, wire);
        }
        assert_eq!(opcode_channel(1, opcode::END_OF_COLLECTION), 0x13ff);
    }

    #[test]
    fn the_timing_fields_are_masked_to_their_widths() {
        let wide = Timing {
            brp: 1025,
            prop_seg: 100,
            phase_seg1: 200,
            phase_seg2: 129,
            sjw: 129,
        };
        assert_eq!(timing_slow(0, wide)[2..], [96, 0, 0, 43, 0, 0]);
        assert_eq!(timing_fast(0, wide)[2..], [0, 0, 0, 11, 0, 0]);
    }

    /// Pinned from `calculate` and decoded back from the bytes.
    #[test]
    fn five_hundred_k_nominal_and_two_meg_data_at_eighty_mhz() {
        let nominal = calculate(CLOCK_HZ, 500_000, None, &NOMINAL_BITTIMING).unwrap();
        let slow = timing_slow(0, nominal);
        assert_eq!(slow, [0x04, 0x00, 96, 9, 19, 138, 0, 0]);
        let data = calculate(CLOCK_HZ, 2_000_000, None, &DATA_BITTIMING).unwrap();
        let fast = timing_fast(0, data);
        assert_eq!(fast, [0x05, 0x00, 0, 4, 9, 28, 0, 0]);

        for (command, bitrate, sample_point) in [(slow, 500_000, 87.5), (fast, 2_000_000, 75.0)] {
            let brp = u32::from(le16(&command, 6)) + 1;
            let (tseg1, tseg2) = (u32::from(command[5]) + 1, u32::from(command[4]) + 1);
            let quanta = 1 + tseg1 + tseg2;
            assert_eq!(CLOCK_HZ / (brp * quanta), bitrate);
            assert_eq!(100.0 * (1 + tseg1) as f32 / quanta as f32, sample_point);
        }
    }

    #[test]
    fn bus_on_clears_the_counters_then_sets_iso_where_it_can_then_the_mode() {
        assert_eq!(
            bus_on(1, true, Some(true)),
            [
                reset_error_counters(1),
                set_iso(1, true),
                listen_only_mode(1)
            ]
        );
        assert_eq!(
            bus_on(0, false, None),
            [reset_error_counters(0), normal_mode(0)]
        );
    }

    #[test]
    fn a_list_ends_with_end_of_collection_unless_it_fills_the_buffer() {
        let one = command_list(&[reset_mode(0)]);
        assert_eq!(one.len(), 16);
        assert_eq!(one[8..], END_OF_COLLECTION);

        let filters = command_list(&accept_all(1));
        assert_eq!(filters.len(), COMMAND_BUFFER_BYTES);
        assert_eq!(filters[..8], filter_std(1, 0, u32::MAX));
        assert_eq!(filters[504..], filter_std(1, 63, u32::MAX));

        let almost = command_list(&accept_all(0)[..63]);
        assert_eq!(almost.len(), COMMAND_BUFFER_BYTES);
        assert_eq!(almost[504..], END_OF_COLLECTION);
    }

    #[test]
    fn off_high_speed_a_list_goes_out_sixty_four_bytes_at_a_time() {
        let list = command_list(&accept_all(0));
        let full: Vec<usize> = transfers(&list, false).map(<[u8]>::len).collect();
        assert_eq!(full, [64; 8]);
        let high: Vec<usize> = transfers(&list, true).map(<[u8]>::len).collect();
        assert_eq!(high, [512]);

        let short = command_list(&[reset_mode(0); 9]);
        let full: Vec<usize> = transfers(&short, false).map(<[u8]>::len).collect();
        assert_eq!(full, [64, 16]);
    }

    // --- messages ----------------------------------------------------------

    fn record(kind: u16, ts: u64, body: &[u8], size: Option<u16>) -> Vec<u8> {
        let size = size.unwrap_or((HEAD_BYTES + body.len()) as u16);
        let mut r = Vec::new();
        r.extend(size.to_le_bytes());
        r.extend(kind.to_le_bytes());
        r.extend((ts as u32).to_le_bytes());
        r.extend(((ts >> 32) as u32).to_le_bytes());
        r.extend(body);
        r
    }

    fn can_rx_record(ts: u64, channel_dlc: u8, flags: u16, id: u32, data: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body.extend([channel_dlc, 0]);
        body.extend(flags.to_le_bytes());
        body.extend(id.to_le_bytes());
        body.extend(data);
        body.resize(body.len().next_multiple_of(4), 0);
        record(message::CAN_RX, ts, &body, None)
    }

    fn frame(channel: u8, arb_id: u32, dlc: u8, data: &[u8]) -> Frame {
        Frame {
            channel,
            arb_id,
            extended: false,
            rtr: false,
            fd: false,
            brs: false,
            esi: false,
            dlc,
            data: data.to_vec(),
        }
    }

    #[test]
    fn classic_fd_extended_and_remote_frames_with_the_whole_64_bit_stamp() {
        let fd_data: Vec<u8> = (0..12).collect();
        let buffer = [
            can_rx_record(0x1234_5678, 0x30, 0, 0x123, &[1, 2, 3]),
            can_rx_record(
                0x0000_0002_0000_0010,
                0x91,
                flags::EXT_DATA_LEN | flags::BRS | flags::ESI,
                0x7ff,
                &fd_data,
            ),
            can_rx_record(3, 0x20, flags::EXT_ID, 0x18da_f110, &[0xaa, 0xbb]),
            can_rx_record(4, 0x40, flags::RTR, 0x100, &[]),
            can_rx_record(5, 0xa0, 0, 0x101, &[9; 8]),
        ]
        .concat();
        let messages = decode_messages(&buffer);
        assert_eq!(
            messages,
            [
                Message::CanRx {
                    frame: frame(0, 0x123, 3, &[1, 2, 3]),
                    ts_us: 0x1234_5678,
                },
                Message::CanRx {
                    frame: Frame {
                        fd: true,
                        brs: true,
                        esi: true,
                        ..frame(1, 0x7ff, 9, &fd_data)
                    },
                    ts_us: 0x2_0000_0010,
                },
                Message::CanRx {
                    frame: Frame {
                        extended: true,
                        ..frame(0, 0x18da_f110, 2, &[0xaa, 0xbb])
                    },
                    ts_us: 3,
                },
                Message::CanRx {
                    frame: Frame {
                        rtr: true,
                        ..frame(0, 0x100, 4, &[])
                    },
                    ts_us: 4,
                },
                Message::CanRx {
                    frame: frame(0, 0x101, 10, &[9; 8]),
                    ts_us: 5,
                },
            ]
        );
    }

    #[test]
    fn the_other_records_decode_and_bus_load_and_unknown_are_skipped_by_size() {
        let buffer = [
            record(message::ERROR, 1, &[0x21, 0x07, 5, 6], None),
            record(message::BUSLOAD, 2, &[0; 8], None),
            record(
                message::STATUS,
                3,
                &[0x01 | status::BUSOFF | status::PASSIVE, 0, 0, 0],
                None,
            ),
            record(0x0777, 4, &[0xee; 20], None),
            record(message::OVERRUN, 5, &[0x01, 0, 0, 0], None),
            record(message::CALIBRATION, 6, &[0x34, 0x12, 0, 0], None),
            can_rx_record(7, 0x10, 0, 0x1, &[0x55]),
        ]
        .concat();
        assert_eq!(
            decode_messages(&buffer),
            [
                Message::Error {
                    channel: 1,
                    tx_err_cnt: 5,
                    rx_err_cnt: 6,
                    ts_us: 1,
                },
                Message::Status {
                    channel: 1,
                    flags: status::BUSOFF | status::PASSIVE,
                    ts_us: 3,
                },
                Message::Overrun {
                    channel: 1,
                    ts_us: 5,
                },
                Message::Calibration {
                    usb_frame_index: 0x1234,
                    ts_us: 6,
                },
                Message::CanRx {
                    frame: frame(0, 0x1, 1, &[0x55]),
                    ts_us: 7,
                },
            ]
        );
    }

    #[test]
    fn a_zero_size_ends_the_run() {
        let buffer = [
            can_rx_record(1, 0x10, 0, 0x1, &[0x55]),
            vec![0u8; 16],
            can_rx_record(2, 0x10, 0, 0x2, &[0x66]),
        ]
        .concat();
        assert_eq!(decode_messages(&buffer).len(), 1);
    }

    #[test]
    fn a_bad_record_ends_the_run_keeping_what_came_before() {
        let good = can_rx_record(1, 0x10, 0, 0x1, &[0x55]);
        let short_payload = can_rx_record(2, 0x80, 0, 0x2, &[1, 2, 3, 4]);
        let short_for_type = record(message::STATUS, 3, &[0], None);
        let third_channel = can_rx_record(4, 0x12, 0, 0x3, &[0x77]);
        let status_on_a_third_channel = record(message::STATUS, 5, &[0x02, 0, 0, 0], None);
        for bad in [
            short_payload,
            short_for_type,
            third_channel,
            status_on_a_third_channel,
        ] {
            let buffer = [good.clone(), bad, good.clone()].concat();
            assert_eq!(decode_messages(&buffer).len(), 1);
        }

        let mut overrunning = good.clone();
        overrunning[0] = 0xff;
        assert!(decode_messages(&overrunning).is_empty());
        assert_eq!(
            decode_messages(&[good.clone(), vec![0; 11]].concat()).len(),
            1
        );
        assert!(decode_messages(&[]).is_empty());
    }

    // --- transmit ----------------------------------------------------------

    fn transmit(size: u16, channel_dlc: u8, flags: u16, id: u32, data: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend(size.to_le_bytes());
        t.extend(message::CAN_TX.to_le_bytes());
        t.extend([0u8; 8]);
        t.extend([channel_dlc, 0]);
        t.extend(flags.to_le_bytes());
        t.extend(id.to_le_bytes());
        t.extend(data);
        t.resize(usize::from(size) + 4, 0);
        t
    }

    #[test]
    fn a_send_is_one_record_padded_to_four_then_a_zero_size() {
        let fd_data: Vec<u8> = (1..=9).collect();
        for (sent, wire) in [
            (
                frame(0, 0x123, 3, &[1, 2, 3]),
                transmit(24, 0x30, 0, 0x123, &[1, 2, 3]),
            ),
            (
                Frame {
                    fd: true,
                    brs: true,
                    ..frame(1, 0x7ff, 9, &fd_data)
                },
                transmit(32, 0x91, flags::EXT_DATA_LEN | flags::BRS, 0x7ff, &fd_data),
            ),
            (
                Frame {
                    extended: true,
                    ..frame(0, 0xffff_ffff, 8, &[0xaa; 8])
                },
                transmit(28, 0x80, flags::EXT_ID, 0x1fff_ffff, &[0xaa; 8]),
            ),
            (
                Frame {
                    rtr: true,
                    ..frame(0, 0x100, 4, &[])
                },
                transmit(24, 0x40, flags::RTR, 0x100, &[]),
            ),
        ] {
            let bytes = encode_transmit(&sent);
            assert_eq!(bytes, wire, "{sent:?}");
            assert_eq!(bytes[bytes.len() - 4..], [0; 4]);
        }
    }
}
