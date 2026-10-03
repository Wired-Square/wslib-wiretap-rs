//! gs_usb, the protocol candleLight firmware speaks — CANable, CANable Pro,
//! Geschwister Schneider adapters, and whatever else the Linux kernel's
//! `gs_usb` driver binds to.
//!
//! Reference: the kernel driver, `drivers/net/can/usb/gs_usb.c`, and
//! `docs/gs_usb.md`.
//!
//! Everything on this wire is little-endian and the device is told so: a host
//! opens by writing [`HOST_FORMAT`] as a `u32`, and the device reads the byte
//! order off it. So every layout here serialises explicitly rather than casting
//! a struct, which is also what stops a host with a different alignment or byte
//! order from sending something the device cannot read.
//!
//! On Linux this protocol is the kernel's business and an application sees
//! SocketCAN instead. It is here for the platforms with no such driver, where
//! an application drives the USB endpoints itself.
//!
//! # The data length code, again
//!
//! `can_dlc` on a host frame is a byte count on a classic frame and a **data
//! length code** on an FD one — the kernel calls `can_fd_len2dlc` on the way
//! out and `can_fd_dlc2len` on the way back. Below 9 bytes they are the same
//! number, which is why getting it wrong is invisible until someone sends a
//! 12-byte frame. [`HostFrame::transmit`] derives it with
//! [`crate::dlc::payload_dlc`].

use crate::dlc::{dlc_to_len, payload_dlc};
use crate::{ARB_MASK_EXT, ARB_MASK_STD};

// ---------------------------------------------------------------------------
// USB identity
// ---------------------------------------------------------------------------

/// The (vendor, product) pairs the kernel driver binds, at interface 0.
pub const DEVICES: &[(u16, u16)] = &[
    (0x1d50, 0x606f), // Geschwister Schneider USB/CAN, candleLight
    (0x1209, 0x2323), // candleLight, pid.codes
    (0x1cd2, 0x606f), // CES CANext FD
    (0x16d0, 0x10b8), // ABE CANdebugger FD
    (0x16d0, 0x0f30), // Xylanta SAINT3
    (0x1209, 0xca01), // CANnectivity
];

/// The byte-order negotiation value a host writes first. A device that reads it
/// byte-swapped knows to swap everything else.
pub const HOST_FORMAT: u32 = 0x0000_beef;

/// The echo id that marks a frame as received rather than as the device
/// echoing back something this host transmitted.
pub const ECHO_ID_RX: u32 = 0xFFFF_FFFF;

/// Vendor control requests.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breq {
    HostFormat = 0,
    Bittiming = 1,
    Mode = 2,
    Berr = 3,
    BtConst = 4,
    DeviceConfig = 5,
    Timestamp = 6,
    Identify = 7,
    GetUserId = 8,
    SetUserId = 9,
    DataBittiming = 10,
    BtConstExt = 11,
    SetTermination = 12,
    GetTermination = 13,
    GetState = 14,
}

/// What a channel is being asked to do, in [`Mode::flags`].
pub mod can_mode {
    pub const NORMAL: u32 = 0;
    pub const LISTEN_ONLY: u32 = 1 << 0;
    pub const LOOP_BACK: u32 = 1 << 1;
    pub const TRIPLE_SAMPLE: u32 = 1 << 2;
    pub const ONE_SHOT: u32 = 1 << 3;
    pub const HW_TIMESTAMP: u32 = 1 << 4;
    pub const PAD_PKTS_TO_MAX_PKT_SIZE: u32 = 1 << 7;
    pub const FD: u32 = 1 << 8;
    pub const BERR_REPORTING: u32 = 1 << 12;
}

/// What a device says it can do, in [`BtConst::feature`].
pub mod can_feature {
    pub const LISTEN_ONLY: u32 = 1 << 0;
    pub const LOOP_BACK: u32 = 1 << 1;
    pub const TRIPLE_SAMPLE: u32 = 1 << 2;
    pub const ONE_SHOT: u32 = 1 << 3;
    pub const HW_TIMESTAMP: u32 = 1 << 4;
    pub const IDENTIFY: u32 = 1 << 5;
    pub const USER_ID: u32 = 1 << 6;
    pub const PAD_PKTS_TO_MAX_PKT_SIZE: u32 = 1 << 7;
    pub const FD: u32 = 1 << 8;
    pub const REQ_USB_QUIRK_LPC546XX: u32 = 1 << 9;
    pub const BT_CONST_EXT: u32 = 1 << 10;
    pub const TERMINATION: u32 = 1 << 11;
    pub const BERR_REPORTING: u32 = 1 << 12;
    pub const GET_STATE: u32 = 1 << 13;
}

/// Per-frame flags, in a host frame's `flags` byte: the kernel's `GS_CAN_FLAG_*`.
pub mod fd_flags {
    pub const OVERFLOW: u8 = 0x01;
    pub const FD: u8 = 0x02;
    pub const BRS: u8 = 0x04;
    pub const ESI: u8 = 0x08;
}

/// Flags packed alongside the arbitration id. The extended bit sits where
/// SocketCAN's does, because this protocol carries a SocketCAN id verbatim.
pub mod id_flags {
    pub const EXTENDED: u32 = 0x8000_0000;
    pub const RTR: u32 = 0x4000_0000;
    pub const ERR: u32 = 0x2000_0000;
    pub const ARB_MASK: u32 = crate::ARB_MASK_EXT;
}

// ---------------------------------------------------------------------------
// Host frames
// ---------------------------------------------------------------------------

/// Echo id, id word, length code, channel, flags and a reserved byte.
pub const HEADER_BYTES: usize = 12;
/// A classic host frame: the header and a fixed 8-byte payload.
pub const CLASSIC_FRAME_BYTES: usize = 20;
/// A CAN FD host frame: the same header and a fixed 64-byte payload.
pub const FD_FRAME_BYTES: usize = 76;
/// The device's µs counter, after the frame, once `can_mode::HW_TIMESTAMP` is on.
pub const TIMESTAMP_BYTES: usize = 4;

/// One frame in either direction. The device sends these on the bulk IN
/// endpoint and reads them from the bulk OUT one; the layout is the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFrame {
    /// [`ECHO_ID_RX`] on a frame off the bus; on an echo, whatever the host
    /// put there when it transmitted.
    pub echo_id: u32,
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    /// An error frame rather than a data one. Its payload is a SocketCAN error
    /// class, which this module does not interpret.
    pub error: bool,
    pub channel: u8,
    pub fd: bool,
    /// Bit rate switch.
    pub brs: bool,
    /// Error state indicator.
    pub esi: bool,
    /// The device dropped frames before this one.
    pub overflow: bool,
    /// The data length code. See this module's header for when that is not the
    /// payload length.
    pub dlc: u8,
    pub data: Vec<u8>,
}

impl HostFrame {
    /// A frame for this host to transmit, with the length code its payload
    /// needs and an `echo_id` of 0.
    pub fn transmit(
        arb_id: u32,
        extended: bool,
        rtr: bool,
        fd: bool,
        brs: bool,
        channel: u8,
        data: Vec<u8>,
    ) -> Self {
        Self {
            echo_id: 0,
            arb_id,
            extended,
            rtr,
            error: false,
            channel,
            fd,
            brs,
            esi: false,
            overflow: false,
            dlc: payload_dlc(data.len(), fd),
            data,
        }
    }

    /// Did this come off the bus, rather than being an echo of a transmit?
    pub fn is_rx(&self) -> bool {
        self.echo_id == ECHO_ID_RX
    }

    /// How many bytes this frame occupies on the wire.
    pub fn wire_len(&self) -> usize {
        if self.fd {
            FD_FRAME_BYTES
        } else {
            CLASSIC_FRAME_BYTES
        }
    }
}

/// Read a host frame, or `None` if `data` stops before the header or the bytes
/// its length code implies: the kernel's rule, which takes a frame shorter than
/// its 20 or 76 bytes. The `FD` flag alone decides the layout; a classic frame
/// with a code above 8 keeps the code and 8 bytes of data.
pub fn parse_host_frame(data: &[u8]) -> Option<HostFrame> {
    if data.len() < HEADER_BYTES {
        return None;
    }
    let flags = data[10];
    let dlc = data[8];
    let fd = flags & fd_flags::FD != 0;
    let payload = data.get(HEADER_BYTES..HEADER_BYTES + dlc_to_len(dlc, fd))?;

    let raw_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let extended = raw_id & id_flags::EXTENDED != 0;

    Some(HostFrame {
        echo_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        arb_id: raw_id & if extended { ARB_MASK_EXT } else { ARB_MASK_STD },
        extended,
        rtr: raw_id & id_flags::RTR != 0,
        error: raw_id & id_flags::ERR != 0,
        channel: data[9],
        fd,
        brs: fd && flags & fd_flags::BRS != 0,
        esi: fd && flags & fd_flags::ESI != 0,
        overflow: flags & fd_flags::OVERFLOW != 0,
        dlc,
        data: payload.to_vec(),
    })
}

/// The hardware timestamp after a host frame read with `fd` as
/// [`parse_host_frame`] read it, or `None` if `data` stops before it.
pub fn host_frame_timestamp(data: &[u8], fd: bool) -> Option<u32> {
    let at = if fd {
        FD_FRAME_BYTES
    } else {
        CLASSIC_FRAME_BYTES
    };
    let bytes = data.get(at..at + TIMESTAMP_BYTES)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Append `frame` as a host frame — 20 bytes or 76, per [`HostFrame::wire_len`].
///
/// The payload region is fixed-width and zero-filled, so a payload shorter than
/// its length code claims is padded, which is what CAN FD does on the wire
/// anyway.
pub fn encode_host_frame_into(out: &mut Vec<u8>, frame: &HostFrame) {
    let wire = frame.wire_len();
    let at = out.len();
    out.resize(at + wire, 0);
    let buf = &mut out[at..];

    let mut raw_id = frame.arb_id & ARB_MASK_EXT;
    if frame.extended {
        raw_id |= id_flags::EXTENDED;
    }
    if frame.rtr {
        raw_id |= id_flags::RTR;
    }
    if frame.error {
        raw_id |= id_flags::ERR;
    }

    buf[0..4].copy_from_slice(&frame.echo_id.to_le_bytes());
    buf[4..8].copy_from_slice(&raw_id.to_le_bytes());
    buf[8] = frame.dlc & 0x0F;
    buf[9] = frame.channel;
    buf[10] = if frame.fd {
        fd_flags::FD
            | if frame.brs { fd_flags::BRS } else { 0 }
            | if frame.esi { fd_flags::ESI } else { 0 }
    } else {
        0
    };
    if frame.overflow {
        buf[10] |= fd_flags::OVERFLOW;
    }

    let len = frame.data.len().min(wire - HEADER_BYTES);
    buf[HEADER_BYTES..HEADER_BYTES + len].copy_from_slice(&frame.data[..len]);
}

/// [`encode_host_frame_into`] into a fresh buffer.
pub fn encode_host_frame(frame: &HostFrame) -> Vec<u8> {
    let mut v = Vec::with_capacity(frame.wire_len());
    encode_host_frame_into(&mut v, frame);
    v
}

// ---------------------------------------------------------------------------
// Control transfers
// ---------------------------------------------------------------------------

/// Read `n` little-endian `u32`s from the front of `data`, or `None` if there
/// are not that many. Every structure below is a run of them.
fn words<const N: usize>(data: &[u8]) -> Option<[u32; N]> {
    if data.len() < N * 4 {
        return None;
    }
    let mut out = [0u32; N];
    for (i, w) in out.iter_mut().enumerate() {
        let b = &data[i * 4..];
        *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    }
    Some(out)
}

/// The `DEVICE_CONFIG` reply: how many channels, and what versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Channel count **minus one**, as the protocol reports it.
    pub icount: u8,
    pub sw_version: u32,
    pub hw_version: u32,
}

impl DeviceConfig {
    pub const SIZE: usize = 12;

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let [_, sw, hw] = words::<3>(data)?;
        Some(Self {
            icount: data[3],
            sw_version: sw,
            hw_version: hw,
        })
    }

    /// How many CAN channels the device actually has.
    pub fn channels(&self) -> u8 {
        self.icount.saturating_add(1)
    }
}

/// The `BT_CONST` reply: what the device can do, and the bit timing it will
/// accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtConst {
    pub feature: u32,
    pub fclk_can: u32,
    pub nominal: BittimingConstraints,
}

impl BtConst {
    pub const SIZE: usize = 40;

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let w = words::<10>(data)?;
        Some(Self {
            feature: w[0],
            fclk_can: w[1],
            nominal: BittimingConstraints::from_words(&w[2..10]),
        })
    }

    /// Does the device claim CAN FD?
    pub fn supports_fd(&self) -> bool {
        self.feature & can_feature::FD != 0
    }
}

/// The `BT_CONST_EXT` reply: [`BtConst`] plus the data-phase constraints, which
/// on an FD device are usually much tighter than the nominal ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtConstExtended {
    pub feature: u32,
    pub fclk_can: u32,
    pub nominal: BittimingConstraints,
    pub data: BittimingConstraints,
}

impl BtConstExtended {
    pub const SIZE: usize = 72;

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let w = words::<18>(data)?;
        Some(Self {
            feature: w[0],
            fclk_can: w[1],
            nominal: BittimingConstraints::from_words(&w[2..10]),
            data: BittimingConstraints::from_words(&w[10..18]),
        })
    }
}

/// The bit timing values a device will accept for one phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BittimingConstraints {
    pub tseg1_min: u32,
    pub tseg1_max: u32,
    pub tseg2_min: u32,
    pub tseg2_max: u32,
    pub sjw_max: u32,
    pub brp_min: u32,
    pub brp_max: u32,
    /// The step the prescaler moves in. Reported as 0 by firmware that means 1,
    /// and normalised here so no caller has to remember that.
    pub brp_inc: u32,
}

impl BittimingConstraints {
    fn from_words(w: &[u32]) -> Self {
        Self {
            tseg1_min: w[0],
            tseg1_max: w[1],
            tseg2_min: w[2],
            tseg2_max: w[3],
            sjw_max: w[4],
            brp_min: w[5],
            brp_max: w[6],
            brp_inc: if w[7] == 0 { 1 } else { w[7] },
        }
    }
}

/// A bit timing to send, for either phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bittiming {
    pub prop_seg: u32,
    pub phase_seg1: u32,
    pub phase_seg2: u32,
    pub sjw: u32,
    pub brp: u32,
}

impl Bittiming {
    pub const SIZE: usize = 20;

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        for (i, w) in [
            self.prop_seg,
            self.phase_seg1,
            self.phase_seg2,
            self.sjw,
            self.brp,
        ]
        .iter()
        .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}

/// A channel mode to send: start or stop, and the [`can_mode`] flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    /// 0 to reset the channel, 1 to start it.
    pub mode: u32,
    pub flags: u32,
}

impl Mode {
    pub const SIZE: usize = 8;
    /// Stop the channel.
    pub const RESET: Self = Self { mode: 0, flags: 0 };

    /// Start the channel with `flags`.
    pub fn start(flags: u32) -> Self {
        Self { mode: 1, flags }
    }

    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut b = [0u8; Self::SIZE];
        b[0..4].copy_from_slice(&self.mode.to_le_bytes());
        b[4..8].copy_from_slice(&self.flags.to_le_bytes());
        b
    }
}

// ---------------------------------------------------------------------------
// Bit timing
// ---------------------------------------------------------------------------

/// The clock the fallback table below assumes, and the CANable's: an STM32F042
/// running its CAN peripheral at 48 MHz.
const FALLBACK_FCLK: u32 = 48_000_000;
/// Time quanta per bit in that table. With `phase_seg1` 13 and `phase_seg2` 2
/// the sample point lands at 87.5%.
const FALLBACK_TQ: u32 = 16;

/// The bitrates [`bittiming_for_bitrate`] will answer for.
///
/// A last resort: it is only right for a device whose CAN clock is 48 MHz, and
/// it exists for firmware that will not say what its clock is.
pub const COMMON_BITRATES: [u32; 9] = [
    10_000, 20_000, 50_000, 100_000, 125_000, 250_000, 500_000, 750_000, 1_000_000,
];

/// Bit timing for one of [`COMMON_BITRATES`] at 48 MHz, or `None`.
pub fn bittiming_for_bitrate(bitrate: u32) -> Option<Bittiming> {
    COMMON_BITRATES.contains(&bitrate).then(|| Bittiming {
        prop_seg: 0,
        phase_seg1: 13,
        phase_seg2: 2,
        sjw: 1,
        brp: FALLBACK_FCLK / (bitrate * FALLBACK_TQ),
    })
}

/// Bit timing for a clock, a bitrate and a sample point, within whatever the
/// device says it will accept.
///
/// The sample point is where in the bit the level is read, as a percentage:
/// `(1 + prop_seg + phase_seg1) / total quanta`. 87.5% is the usual nominal
/// choice; an FD data phase wants something lower, often 75%.
///
/// Every arrangement inside `c` is scored and the closest wins — on bitrate
/// error first, then on how near the sample point lands. Taking the first that
/// merely fits makes the answer depend on the order the quanta counts happen to
/// be written in, and that order was already the difference between an exact
/// 125 kbit/s and one 1% out.
///
/// Returns `None` when nothing lands within 1% of the requested bitrate and
/// inside `c` — which is the answer, not a failure to try: a bitrate the
/// hardware cannot divide down to is not one it can be asked for.
pub fn calculate_bittiming(
    fclk_can: u32,
    bitrate: u32,
    sample_point: f32,
    c: &BittimingConstraints,
) -> Option<Bittiming> {
    if bitrate == 0 || fclk_can == 0 {
        return None;
    }

    let mut best: Option<(u32, f32, Bittiming)> = None;
    // The small counts at the end are what a high-speed FD data phase needs;
    // the large ones place the sample point most precisely.
    for tq in [25u32, 20, 16, 12, 10, 8, 6, 5, 4] {
        let brp = fclk_can / (bitrate * tq);
        if brp < c.brp_min.max(1) || brp > c.brp_max {
            continue;
        }
        if c.brp_inc > 1 && !(brp - c.brp_min).is_multiple_of(c.brp_inc) {
            continue;
        }

        // Exact rather than a percentage rounded to an integer, which admitted
        // anything under 2% while claiming to admit 1%.
        let error = (fclk_can / (brp * tq)).abs_diff(bitrate);
        if u64::from(error) * 100 > u64::from(bitrate) {
            continue;
        }

        let seg1 = ((sample_point / 100.0) * tq as f32).round() as u32;
        let seg1 = seg1.saturating_sub(1);
        let seg2 = tq.saturating_sub(1).saturating_sub(seg1);
        if seg1 < c.tseg1_min || seg1 > c.tseg1_max || seg2 < c.tseg2_min || seg2 > c.tseg2_max {
            continue;
        }

        let sjw = seg1.min(seg2).min(c.sjw_max);
        if sjw < 1 {
            continue;
        }

        let drift = (100.0 * (1 + seg1) as f32 / tq as f32 - sample_point).abs();
        if best
            .as_ref()
            .is_some_and(|(e, d, _)| (*e, *d) <= (error, drift))
        {
            continue;
        }
        best = Some((
            error,
            drift,
            Bittiming {
                prop_seg: 0,
                phase_seg1: seg1,
                phase_seg2: seg2,
                sjw,
                brp,
            },
        ));
    }
    best.map(|(_, _, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only what is physically true of a CAN controller, so a test constrains
    /// the search and not the device.
    const PERMISSIVE_CONSTRAINTS: BittimingConstraints = BittimingConstraints {
        tseg1_min: 1,
        tseg1_max: 256,
        tseg2_min: 1,
        tseg2_max: 128,
        sjw_max: 128,
        brp_min: 1,
        brp_max: 1024,
        brp_inc: 1,
    };

    // --- host frames -------------------------------------------------------

    #[test]
    fn a_classic_frame_round_trips() {
        let f = HostFrame::transmit(0x123, false, false, false, false, 1, vec![1, 2, 3, 4]);
        let wire = encode_host_frame(&f);
        assert_eq!(wire.len(), CLASSIC_FRAME_BYTES);
        assert_eq!(&wire[4..8], &[0x23, 0x01, 0x00, 0x00], "no flags set");
        assert_eq!(wire[8], 4);
        assert_eq!(wire[9], 1, "channel");
        assert_eq!(parse_host_frame(&wire), Some(f));
    }

    #[test]
    fn an_extended_frame_sets_the_socketcan_bit() {
        let f = HostFrame::transmit(0x18DA_F110, true, false, false, false, 0, vec![0xAA]);
        let wire = encode_host_frame(&f);
        assert_eq!(&wire[4..8], &[0x10, 0xF1, 0xDA, 0x98]);
        assert_eq!(parse_host_frame(&wire), Some(f));
    }

    #[test]
    fn a_remote_frame_round_trips() {
        let f = HostFrame::transmit(0x123, false, true, false, false, 0, vec![]);
        let back = parse_host_frame(&encode_host_frame(&f)).expect("a frame");
        assert!(back.rtr && !back.extended);
        assert_eq!(back.arb_id, 0x123);
    }

    /// The one that is easy to get wrong: `can_dlc` on an FD frame is a code.
    /// Writing 12 there would have the device transmit 24 bytes.
    #[test]
    fn an_fd_frame_carries_a_code_not_a_byte_count() {
        let f = HostFrame::transmit(0x100, false, false, true, true, 0, vec![0xAB; 12]);
        assert_eq!(f.dlc, 9, "12 bytes is code 9");
        let wire = encode_host_frame(&f);
        assert_eq!(wire.len(), FD_FRAME_BYTES);
        assert_eq!(wire[8], 9);
        assert_eq!(wire[10], 0x06, "FD | BRS");
        assert_eq!(parse_host_frame(&wire), Some(f));
    }

    #[test]
    fn a_short_fd_frame_is_read_by_its_flag() {
        let mut wire = vec![0u8; FD_FRAME_BYTES];
        wire[0..4].copy_from_slice(&ECHO_ID_RX.to_le_bytes());
        wire[8] = 8;
        wire[10] = 0x06;
        let f = parse_host_frame(&wire).expect("a frame");
        assert!(f.fd && f.brs && !f.esi);
        wire[10] = 0x0A;
        let f = parse_host_frame(&wire).expect("a frame");
        assert!(f.fd && !f.brs && f.esi);
    }

    #[test]
    fn an_overflowed_classic_frame_says_so_and_is_not_fd() {
        let mut wire = vec![0u8; FD_FRAME_BYTES];
        wire[0..4].copy_from_slice(&ECHO_ID_RX.to_le_bytes());
        wire[8] = 8;
        wire[10] = 0x01;
        let f = parse_host_frame(&wire).expect("a frame");
        assert!(f.overflow && !f.fd);
    }

    #[test]
    fn an_overflow_round_trips_beside_the_fd_flags() {
        for (fd, brs, flags) in [(false, false, 0x01), (true, true, 0x07)] {
            let f = HostFrame {
                overflow: true,
                ..HostFrame::transmit(0x100, false, false, fd, brs, 0, vec![0; 8])
            };
            let wire = encode_host_frame(&f);
            assert_eq!(wire[10], flags);
            assert_eq!(parse_host_frame(&wire), Some(f));
        }
    }

    #[test]
    fn an_fd_frame_without_brs_carries_only_the_fd_bit() {
        let f = HostFrame::transmit(0x100, false, false, true, false, 0, vec![0; 8]);
        assert_eq!(encode_host_frame(&f)[10], 0x02);
    }

    #[test]
    fn a_full_fd_payload_round_trips() {
        let f = HostFrame::transmit(0x7FF, false, false, true, false, 2, vec![0x5A; 64]);
        assert_eq!(f.dlc, 15);
        let back = parse_host_frame(&encode_host_frame(&f)).expect("a frame");
        assert_eq!(back.data.len(), 64);
        assert_eq!(back, f);
    }

    /// An inexact FD payload rounds its code up; the wire region is fixed and
    /// zero-filled, so what comes back is the padded frame the device sees.
    #[test]
    fn an_inexact_fd_payload_is_padded_to_its_code() {
        let f = HostFrame::transmit(0x100, false, false, true, false, 0, vec![0xAB; 9]);
        assert_eq!(f.dlc, 9);
        let back = parse_host_frame(&encode_host_frame(&f)).expect("a frame");
        assert_eq!(back.data.len(), 12);
        assert_eq!(&back.data[..9], &[0xAB; 9]);
        assert_eq!(&back.data[9..], &[0, 0, 0]);
    }

    /// A classic frame may carry a raw code of 9–15 (the kernel's
    /// `CAN_CTRLMODE_CC_LEN8_DLC`); it is still 8 bytes on the wire.
    #[test]
    fn the_fd_flag_alone_decides_the_layout() {
        let mut wire = vec![0u8; FD_FRAME_BYTES];
        wire[0..4].copy_from_slice(&ECHO_ID_RX.to_le_bytes());
        wire[8] = 9;
        let f = parse_host_frame(&wire).expect("a frame");
        assert!(!f.fd && f.is_rx());
        assert_eq!((f.dlc, f.data.len()), (9, 8));

        wire[10] = fd_flags::FD;
        let f = parse_host_frame(&wire).expect("a frame");
        assert!(f.fd);
        assert_eq!((f.dlc, f.data.len()), (9, 12));
    }

    #[test]
    fn a_frame_needs_its_header_and_the_bytes_its_code_implies() {
        let mut wire = vec![0u8; CLASSIC_FRAME_BYTES];
        wire[8] = 3;
        wire[HEADER_BYTES..].fill(0xAB);
        assert_eq!(parse_host_frame(&wire[..15]).unwrap().data, [0xAB; 3]);
        assert!(parse_host_frame(&wire[..14]).is_none());
        assert!(parse_host_frame(&wire[..HEADER_BYTES - 1]).is_none());

        wire[8] = 15;
        wire[10] = fd_flags::FD;
        assert!(
            parse_host_frame(&wire).is_none(),
            "a truncated FD frame is nothing, never a classic one"
        );
        wire[8] = 9;
        wire.resize(HEADER_BYTES + 12, 0xAB);
        assert_eq!(parse_host_frame(&wire).unwrap().data.len(), 12);
    }

    #[test]
    fn a_standard_id_is_masked_to_eleven_bits() {
        let mut wire = vec![0u8; CLASSIC_FRAME_BYTES];
        wire[4..8].copy_from_slice(&[0x23, 0x19, 0x00, 0x00]);
        assert_eq!(parse_host_frame(&wire).unwrap().arb_id, 0x123);
        wire[4..8].copy_from_slice(&[0x23, 0x19, 0x00, 0x80]);
        assert_eq!(parse_host_frame(&wire).unwrap().arb_id, 0x1923);
    }

    #[test]
    fn the_hardware_timestamp_follows_the_frame() {
        let mut classic = vec![0u8; CLASSIC_FRAME_BYTES];
        classic.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(host_frame_timestamp(&classic, false), Some(0x1234_5678));
        assert_eq!(host_frame_timestamp(&classic[..23], false), None);

        let mut fd = vec![0u8; FD_FRAME_BYTES];
        fd.extend_from_slice(&[0x01, 0x00, 0x00, 0x80]);
        assert_eq!(host_frame_timestamp(&fd, true), Some(0x8000_0001));
        assert_eq!(host_frame_timestamp(&fd, false), Some(0));
        assert_eq!(host_frame_timestamp(&fd[..79], true), None);
    }

    #[test]
    fn an_echo_is_told_apart_from_a_received_frame() {
        let mut wire = encode_host_frame(&HostFrame::transmit(
            0x1,
            false,
            false,
            false,
            false,
            0,
            vec![],
        ));
        assert!(!parse_host_frame(&wire).unwrap().is_rx(), "echo_id 0");
        wire[0..4].copy_from_slice(&ECHO_ID_RX.to_le_bytes());
        assert!(parse_host_frame(&wire).unwrap().is_rx());
    }

    // --- control transfers -------------------------------------------------

    #[test]
    fn a_device_config_reply_reports_its_channels() {
        let mut b = vec![0u8; DeviceConfig::SIZE];
        b[3] = 1; // icount: two channels
        b[4..8].copy_from_slice(&2u32.to_le_bytes());
        b[8..12].copy_from_slice(&3u32.to_le_bytes());
        let c = DeviceConfig::from_bytes(&b).expect("a config");
        assert_eq!(c.channels(), 2, "icount is one less than the count");
        assert_eq!((c.sw_version, c.hw_version), (2, 3));
        assert!(DeviceConfig::from_bytes(&b[..11]).is_none());
    }

    #[test]
    fn bt_const_and_its_extended_form_agree_about_the_nominal_phase() {
        let mut b = vec![0u8; BtConstExtended::SIZE];
        for (i, v) in [
            can_feature::FD | can_feature::BT_CONST_EXT,
            80_000_000, // fclk
            1,
            256,
            1,
            128,
            128,
            1,
            512,
            0, // nominal, brp_inc 0
            1,
            32,
            1,
            16,
            16,
            1,
            32,
            2, // data
        ]
        .iter()
        .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }

        let short = BtConst::from_bytes(&b).expect("a bt_const");
        let long = BtConstExtended::from_bytes(&b).expect("an extended bt_const");
        assert!(short.supports_fd());
        assert_eq!(short.fclk_can, 80_000_000);
        assert_eq!(short.nominal, long.nominal, "the same forty leading bytes");
        assert_eq!(short.nominal.brp_inc, 1, "a reported 0 means 1");
        assert_eq!(long.data.brp_inc, 2);
        assert_eq!(long.data.tseg1_max, 32);
        assert!(BtConstExtended::from_bytes(&b[..71]).is_none());
    }

    #[test]
    fn a_bittiming_serialises_as_five_little_endian_words() {
        let t = Bittiming {
            prop_seg: 0,
            phase_seg1: 13,
            phase_seg2: 2,
            sjw: 1,
            brp: 6,
        };
        let b = t.to_bytes();
        assert_eq!(b.len(), Bittiming::SIZE);
        assert_eq!(&b[4..8], &[13, 0, 0, 0]);
        assert_eq!(&b[16..20], &[6, 0, 0, 0]);
    }

    #[test]
    fn a_mode_serialises_as_two_little_endian_words() {
        assert_eq!(Mode::RESET.to_bytes(), [0u8; 8]);
        let b = Mode::start(can_mode::LISTEN_ONLY | can_mode::FD).to_bytes();
        assert_eq!(&b[0..4], &[1, 0, 0, 0]);
        assert_eq!(&b[4..8], &[0x01, 0x01, 0, 0]);
    }

    // --- bit timing --------------------------------------------------------

    /// The fallback table's whole content is one formula, and it has to keep
    /// producing the bitrate it is asked for.
    #[test]
    fn the_fallback_table_produces_the_bitrate_it_names() {
        for rate in COMMON_BITRATES {
            let t = bittiming_for_bitrate(rate).expect("a timing");
            let tq = 1 + t.prop_seg + t.phase_seg1 + t.phase_seg2;
            assert_eq!(48_000_000 / (t.brp * tq), rate, "{rate}");
        }
        assert_eq!(bittiming_for_bitrate(300_000), None);
        assert_eq!(bittiming_for_bitrate(0), None);
    }

    #[test]
    fn a_calculated_timing_lands_on_its_bitrate_and_sample_point() {
        for (fclk, rate, point) in [
            (48_000_000u32, 500_000u32, 87.5f32),
            (48_000_000, 125_000, 87.5),
            (80_000_000, 500_000, 87.5),
            (80_000_000, 2_000_000, 75.0),
            (160_000_000, 1_000_000, 80.0),
        ] {
            let t = calculate_bittiming(fclk, rate, point, &PERMISSIVE_CONSTRAINTS)
                .unwrap_or_else(|| panic!("{fclk}/{rate}@{point}"));
            let tq = 1 + t.prop_seg + t.phase_seg1 + t.phase_seg2;
            assert_eq!(fclk / (t.brp * tq), rate, "{fclk}/{rate}");

            let actual = 100.0 * (1 + t.phase_seg1) as f32 / tq as f32;
            assert!(
                (actual - point).abs() <= 100.0 / tq as f32,
                "{fclk}/{rate}: sample point {actual} not near {point}"
            );
        }
    }

    /// The constraints are the point of passing them: a device that will not
    /// take a prescaler that large must not be sent one.
    #[test]
    fn device_constraints_rule_out_a_timing_that_would_otherwise_fit() {
        let tight = BittimingConstraints {
            brp_max: 2,
            ..PERMISSIVE_CONSTRAINTS
        };
        assert!(calculate_bittiming(48_000_000, 500_000, 87.5, &PERMISSIVE_CONSTRAINTS).is_some());
        assert!(calculate_bittiming(48_000_000, 500_000, 87.5, &tight).is_none());
    }

    #[test]
    fn an_unreachable_bitrate_is_none_rather_than_a_wrong_answer() {
        assert!(calculate_bittiming(48_000_000, 0, 87.5, &PERMISSIVE_CONSTRAINTS).is_none());
        assert!(
            calculate_bittiming(48_000_000, 7_000_000, 87.5, &PERMISSIVE_CONSTRAINTS).is_none()
        );
    }
}
