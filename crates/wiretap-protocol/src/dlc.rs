//! The CAN data length code table, and the two directions across it.
//!
//! The wire carries a *code*; a database column stores a *length*; above 8
//! bytes on CAN FD the two differ. That is the trap this module exists to hold
//! in one place. The sixteen-entry table is otherwise easy to write out by
//! hand, and had been, nine times over across the consumers of this crate.
//! Every copy has to agree, and nothing makes them.

/// CAN FD data length code → byte count. Below 9 the code *is* the length.
pub const FD_DLC_LEN: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64];

/// Data length code → payload length in bytes.
#[inline]
pub fn dlc_to_len(dlc: u8, is_fd: bool) -> usize {
    let dlc = (dlc & 0x0F) as usize;
    if dlc <= 8 {
        dlc
    } else if is_fd {
        FD_DLC_LEN[dlc]
    } else {
        // Classic CAN caps at 8 bytes however the code is encoded.
        8
    }
}

/// Payload length → the smallest data length code that can carry it.
#[inline]
pub fn len_to_dlc(len: usize) -> u8 {
    if len <= 8 {
        return len as u8;
    }
    FD_DLC_LEN.iter().position(|&l| l >= len).unwrap_or(15) as u8
}

/// The code for a payload of `len` bytes, clamped to what the frame type can
/// actually carry.
#[inline]
pub fn payload_dlc(len: usize, is_fd: bool) -> u8 {
    len_to_dlc(len.min(if is_fd { 64 } else { 8 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_dlc_round_trips_above_eight() {
        // The pairs that actually differ between code and length.
        for (dlc, len) in [
            (9u8, 12usize),
            (10, 16),
            (11, 20),
            (12, 24),
            (13, 32),
            (14, 48),
            (15, 64),
        ] {
            assert_eq!(dlc_to_len(dlc, true), len, "dlc {dlc}");
            assert_eq!(len_to_dlc(len), dlc, "len {len}");
        }
    }

    #[test]
    fn classic_can_never_exceeds_eight_bytes() {
        // A classic frame carrying a DLC above 8 is legal on the wire and
        // means 8 bytes; reading it as an FD length would over-read.
        for dlc in 9u8..=15 {
            assert_eq!(dlc_to_len(dlc, false), 8);
        }
    }

    #[test]
    fn len_to_dlc_rounds_up_to_the_next_code() {
        // 9 bytes does not exist as an FD length; it must pad to 12 (code 9).
        assert_eq!(len_to_dlc(9), 9);
        assert_eq!(len_to_dlc(13), 10);
        assert_eq!(len_to_dlc(0), 0);
        assert_eq!(len_to_dlc(8), 8);
    }

    #[test]
    fn payload_dlc_clamps_by_frame_type() {
        assert_eq!(payload_dlc(20, false), 8, "classic clamps to 8");
        assert_eq!(payload_dlc(20, true), 11, "fd keeps 20 as code 11");
        assert_eq!(payload_dlc(100, true), 15, "fd clamps to 64, code 15");
        assert_eq!(payload_dlc(3, false), 3);
        assert_eq!(payload_dlc(3, true), 3);
    }

    /// The code a payload is given must round-trip back to a length that can
    /// hold it — the property the hand-written copies had to preserve
    /// individually.
    #[test]
    fn payload_dlc_round_trips_through_dlc_to_len() {
        for is_fd in [false, true] {
            for len in 0..=70usize {
                let dlc = payload_dlc(len, is_fd);
                let back = dlc_to_len(dlc, is_fd);
                let cap = if is_fd { 64 } else { 8 };
                assert!(
                    back >= len.min(cap),
                    "len {len} fd {is_fd}: {back} < {}",
                    len.min(cap)
                );
            }
        }
    }
}
