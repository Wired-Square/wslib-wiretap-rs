//! SocketCAN's `struct can_frame` and `struct canfd_frame`, and the flags Linux
//! packs alongside an arbitration id.
//!
//! Reference: `include/uapi/linux/can.h`, and `docs/socketcan.md`.
//!
//! # This is a kernel ABI, not a wire format
//!
//! Everything else in this crate describes bytes that cross a link between two
//! machines. These bytes never leave one: they are what a `read` on a CAN
//! socket returns and what a `write` takes, so the id is **native**-endian and
//! the layouts carry the padding a C compiler put there. Reading them as
//! little-endian works by accident on every machine anyone runs this on, and
//! would be wrong on the one where it mattered.
//!
//! It is here because an application that talks to a raw CAN socket has to
//! spell these layouts somewhere, and spelling them once next to the data
//! length code table is better than spelling them inline at each `write`. A
//! binding that hands out typed frames should use that instead.
//!
//! The extended-id bit is at the same position as [`crate::gvret`]'s. That is a
//! coincidence and not a contract, so it is written out here rather than
//! shared.

use crate::{ARB_MASK_EXT, ARB_MASK_STD};

/// `struct can_frame`: id, length, three bytes of padding, eight of payload.
pub const CLASSIC_FRAME_BYTES: usize = 16;
/// `struct canfd_frame`: id, length, flags, two reserved bytes, 64 of payload.
pub const FD_FRAME_BYTES: usize = 72;

/// The id is 29-bit rather than 11-bit.
pub const CAN_EFF_FLAG: u32 = 0x8000_0000;
/// A remote transmission request.
pub const CAN_RTR_FLAG: u32 = 0x4000_0000;
/// An error frame; the payload is an error class rather than bus data.
pub const CAN_ERR_FLAG: u32 = 0x2000_0000;
/// What is left of the id word once the three flags are masked off.
pub const CAN_EFF_MASK: u32 = ARB_MASK_EXT;
/// The 11 bits an id has when [`CAN_EFF_FLAG`] is clear.
pub const CAN_SFF_MASK: u32 = ARB_MASK_STD;

/// Per-frame CAN FD flags, in a `canfd_frame`'s `flags` byte.
pub mod fd_flags {
    /// Bit rate switch.
    pub const BRS: u8 = 0x01;
    /// Error state indicator.
    pub const ESI: u8 = 0x02;
}

/// Split an id word into its arbitration id and the three flags.
///
/// A standard id is masked to 11 bits rather than 29: a sender that left rubbish
/// in the unused bits is not describing a 29-bit id, and passing it on would
/// make one up.
pub fn split_can_id(raw: u32) -> (u32, bool, bool, bool) {
    let extended = raw & CAN_EFF_FLAG != 0;
    (
        raw & if extended { CAN_EFF_MASK } else { CAN_SFF_MASK },
        extended,
        raw & CAN_RTR_FLAG != 0,
        raw & CAN_ERR_FLAG != 0,
    )
}

/// The inverse of [`split_can_id`].
pub fn make_can_id(arb_id: u32, extended: bool, rtr: bool) -> u32 {
    let mut raw = if extended {
        (arb_id & CAN_EFF_MASK) | CAN_EFF_FLAG
    } else {
        arb_id & CAN_SFF_MASK
    };
    if rtr {
        raw |= CAN_RTR_FLAG;
    }
    raw
}

/// One frame in either layout.
///
/// Both carry a payload **length**, not a data length code — SocketCAN converts
/// at its own edge, so nothing here needs [`crate::dlc`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    pub error: bool,
    pub fd: bool,
    pub brs: bool,
    pub esi: bool,
    pub data: Vec<u8>,
}

impl Frame {
    /// A frame to send. A remote request carries no payload, and a payload is
    /// clamped to what its kind can hold.
    pub fn new(
        arb_id: u32,
        extended: bool,
        rtr: bool,
        fd: bool,
        brs: bool,
        mut data: Vec<u8>,
    ) -> Self {
        data.truncate(match (rtr, fd) {
            (true, _) => 0,
            (false, true) => 64,
            (false, false) => 8,
        });
        Self {
            arb_id,
            extended,
            rtr,
            error: false,
            fd,
            brs,
            esi: false,
            data,
        }
    }

    /// How many bytes this frame occupies.
    pub fn wire_len(&self) -> usize {
        if self.fd {
            FD_FRAME_BYTES
        } else {
            CLASSIC_FRAME_BYTES
        }
    }
}

/// Read a frame from a socket buffer, taking its length as the kind: a read
/// that returned a whole `canfd_frame` is one, and anything shorter is classic.
///
/// `None` if there is not even a classic frame there.
pub fn parse_frame(bytes: &[u8]) -> Option<Frame> {
    if bytes.len() < CLASSIC_FRAME_BYTES {
        return None;
    }
    let fd = bytes.len() >= FD_FRAME_BYTES;
    let (arb_id, extended, rtr, error) =
        split_can_id(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));

    let flags = if fd { bytes[5] } else { 0 };
    let len = (bytes[4] as usize).min(if fd { 64 } else { 8 });

    Some(Frame {
        arb_id,
        extended,
        rtr,
        error,
        fd,
        brs: flags & fd_flags::BRS != 0,
        esi: flags & fd_flags::ESI != 0,
        data: bytes[8..8 + len].to_vec(),
    })
}

/// Append `frame` in its layout — 16 bytes or 72, per [`Frame::wire_len`].
///
/// The payload region is fixed-width and zero-filled, which is what the kernel
/// expects: a `canfd_frame` is always 72 bytes however few of them mean
/// anything.
pub fn encode_frame_into(out: &mut Vec<u8>, frame: &Frame) {
    let wire = frame.wire_len();
    let at = out.len();
    out.resize(at + wire, 0);
    let buf = &mut out[at..];

    let raw = make_can_id(frame.arb_id, frame.extended, frame.rtr)
        | if frame.error { CAN_ERR_FLAG } else { 0 };
    buf[0..4].copy_from_slice(&raw.to_ne_bytes());

    let len = frame.data.len().min(wire - 8);
    buf[4] = len as u8;
    if frame.fd {
        buf[5] =
            if frame.brs { fd_flags::BRS } else { 0 } | if frame.esi { fd_flags::ESI } else { 0 };
    }
    buf[8..8 + len].copy_from_slice(&frame.data[..len]);
}

/// [`encode_frame_into`] into a fresh buffer.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut v = Vec::with_capacity(frame.wire_len());
    encode_frame_into(&mut v, frame);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_with_their_flags() {
        for (arb, ext, rtr) in [
            (0x123u32, false, false),
            (0x7FF, false, true),
            (0x18DA_F110, true, false),
            (0x1FFF_FFFF, true, true),
        ] {
            let (back, back_ext, back_rtr, err) = split_can_id(make_can_id(arb, ext, rtr));
            assert_eq!((back, back_ext, back_rtr), (arb, ext, rtr), "{arb:#x}");
            assert!(!err);
        }
    }

    /// A standard id is eleven bits. Carrying whatever a sender left in bits
    /// 11 to 28 would report an id the bus never saw.
    #[test]
    fn a_standard_id_is_masked_to_eleven_bits() {
        assert_eq!(split_can_id(0x0000_FFFF).0, 0x7FF);
    }

    #[test]
    fn an_error_flag_is_reported_and_not_taken_for_id_bits() {
        let (arb, _, _, error) = split_can_id(CAN_ERR_FLAG | 0x123);
        assert!(error);
        assert_eq!(arb, 0x123);
    }

    #[test]
    fn a_classic_frame_round_trips() {
        let f = Frame::new(0x123, false, false, false, false, vec![1, 2, 3, 4]);
        let wire = encode_frame(&f);
        assert_eq!(wire.len(), CLASSIC_FRAME_BYTES);
        assert_eq!(wire[4], 4);
        assert_eq!(&wire[5..8], &[0, 0, 0], "the padding stays padding");
        assert_eq!(parse_frame(&wire), Some(f));
    }

    #[test]
    fn an_fd_frame_round_trips_with_its_flags() {
        let f = Frame::new(0x18DA_F110, true, false, true, true, vec![0xAB; 48]);
        let wire = encode_frame(&f);
        assert_eq!(wire.len(), FD_FRAME_BYTES);
        assert_eq!(wire[4], 48, "a length, not a code");
        assert_eq!(wire[5], fd_flags::BRS);
        assert_eq!(parse_frame(&wire), Some(f));
    }

    #[test]
    fn payloads_are_clamped_to_the_kind_of_frame() {
        let len = |rtr, fd| {
            Frame::new(0x1, false, rtr, fd, false, vec![0xFF; 80])
                .data
                .len()
        };
        assert_eq!(len(false, false), 8, "classic");
        assert_eq!(len(false, true), 64, "fd");
        assert_eq!(len(true, false), 0, "a remote request has no payload");
    }

    /// The kernel says how long a frame is by how much it gave you. A 16-byte
    /// read is never an FD frame, whatever its length byte claims.
    #[test]
    fn the_length_of_the_read_decides_the_kind() {
        let mut wire = vec![0u8; CLASSIC_FRAME_BYTES];
        wire[4] = 64;
        let f = parse_frame(&wire).expect("a frame");
        assert!(!f.fd);
        assert_eq!(f.data.len(), 8);
        assert!(parse_frame(&wire[..15]).is_none());
    }

    /// Native, not little: these bytes never leave the machine that made them.
    #[test]
    fn the_id_is_native_endian() {
        let wire = encode_frame(&Frame::new(0x123, false, false, false, false, vec![]));
        assert_eq!(&wire[0..4], &0x123u32.to_ne_bytes());
    }
}
