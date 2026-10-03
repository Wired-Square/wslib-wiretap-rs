//! The CAN frame as it is on the bus, shared by every CAN codec and transport
//! that takes a whole frame rather than scalars, and the SocketCAN error frame's
//! report on the controller.
//!
//! Reference for the error frame: `include/uapi/linux/can/error.h`.

use crate::payload_dlc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanFrame {
    /// The device's own bus or channel number; mapping it is the consumer's.
    pub bus: u8,
    /// Flags stripped, and on a read masked to 11 or 29 bits.
    pub arb_id: u32,
    pub extended: bool,
    pub rtr: bool,
    pub fd: bool,
    /// Meaningless unless `fd`.
    pub brs: bool,
    pub esi: bool,
    /// The payload: a length, not a length code.
    pub data: Vec<u8>,
    remote_dlc: u8,
}

impl CanFrame {
    pub fn data(bus: u8, arb_id: u32, extended: bool, fd: bool, brs: bool, data: Vec<u8>) -> Self {
        Self {
            bus,
            arb_id,
            extended,
            rtr: false,
            fd,
            brs,
            esi: false,
            data,
            remote_dlc: 0,
        }
    }

    pub fn remote(bus: u8, arb_id: u32, extended: bool, dlc: u8) -> Self {
        Self {
            rtr: true,
            remote_dlc: dlc,
            ..Self::data(bus, arb_id, extended, false, false, Vec::new())
        }
    }

    /// [`payload_dlc`], or the code an RTR carries.
    pub fn dlc(&self) -> u8 {
        if self.rtr {
            self.remote_dlc
        } else {
            payload_dlc(self.data.len(), self.fd)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Rx,
    /// Sent by this end, as the device or kernel handed it back.
    Tx,
}

/// The controller's fault confinement, with the warning level controllers
/// report on the way to passive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorState {
    Active,
    Warning,
    Passive,
    BusOff,
}

/// What a SocketCAN error frame says about the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorFrame {
    /// The controller gave up on a transmission and flushed its queue.
    pub tx_timeout: bool,
    /// A transmission went unacknowledged.
    pub no_ack: bool,
    /// `None` where the frame doesn't say.
    pub state: Option<ErrorState>,
    pub tx_errors: Option<u8>,
    pub rx_errors: Option<u8>,
}

mod class {
    pub const TX_TIMEOUT: u32 = 0x001;
    pub const CRTL: u32 = 0x004;
    pub const ACK: u32 = 0x020;
    pub const BUSOFF: u32 = 0x040;
    pub const RESTARTED: u32 = 0x100;
}

mod crtl {
    pub const RX_WARNING: u8 = 0x04;
    pub const TX_WARNING: u8 = 0x08;
    pub const RX_PASSIVE: u8 = 0x10;
    pub const TX_PASSIVE: u8 = 0x20;
    pub const ACTIVE: u8 = 0x40;
}

impl ErrorFrame {
    /// `class` is the id with its flags stripped. The counters are read
    /// wherever the payload reaches them, `CNT` or not: candleLight fills them
    /// without it.
    pub fn decode(class: u32, data: &[u8]) -> Self {
        let status = data.get(1).copied().unwrap_or(0);
        let crtl = class & class::CRTL != 0;
        let state = if class & class::BUSOFF != 0 {
            Some(ErrorState::BusOff)
        } else if crtl && status & (crtl::TX_PASSIVE | crtl::RX_PASSIVE) != 0 {
            Some(ErrorState::Passive)
        } else if crtl && status & (crtl::TX_WARNING | crtl::RX_WARNING) != 0 {
            Some(ErrorState::Warning)
        } else if (crtl && status & crtl::ACTIVE != 0) || class & class::RESTARTED != 0 {
            Some(ErrorState::Active)
        } else {
            None
        };
        Self {
            tx_timeout: class & class::TX_TIMEOUT != 0,
            no_ack: class & class::ACK != 0,
            state,
            tx_errors: data.get(6).copied(),
            rx_errors: data.get(7).copied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_frame_gives_its_length_code_and_a_remote_frame_its_own() {
        assert_eq!(
            CanFrame::data(0, 1, false, false, false, vec![0; 8]).dlc(),
            8
        );
        assert_eq!(
            CanFrame::data(0, 1, false, true, true, vec![0; 12]).dlc(),
            9
        );
        assert_eq!(
            CanFrame::data(0, 1, false, true, false, vec![0; 13]).dlc(),
            10
        );
        let remote = CanFrame::remote(0, 1, false, 5);
        assert!(remote.rtr && remote.data.is_empty());
        assert_eq!(remote.dlc(), 5);
    }

    #[test]
    fn candlelights_tx_timeout_is_passive_unacked_with_its_counters() {
        let report = ErrorFrame::decode(0x25, &[0, 0x20, 0, 0, 0, 0x10, 0x80, 0]);
        assert_eq!(
            report,
            ErrorFrame {
                tx_timeout: true,
                no_ack: true,
                state: Some(ErrorState::Passive),
                tx_errors: Some(128),
                rx_errors: Some(0),
            }
        );
        let repeat = ErrorFrame::decode(0x24, &[0, 0x20, 0, 0, 0, 0, 0x80, 0]);
        assert!(!repeat.tx_timeout && repeat.no_ack);
        assert_eq!(repeat.state, Some(ErrorState::Passive));
    }

    #[test]
    fn a_frame_with_no_class_carries_only_its_counters() {
        let report = ErrorFrame::decode(0, &[0, 0, 0, 0, 0, 0, 8, 0]);
        assert_eq!(
            report,
            ErrorFrame {
                tx_timeout: false,
                no_ack: false,
                state: None,
                tx_errors: Some(8),
                rx_errors: Some(0),
            }
        );
    }

    #[test]
    fn the_state_is_the_worst_the_frame_reports() {
        let state = |class, status| ErrorFrame::decode(class, &[0, status]).state;
        assert_eq!(state(0x40 | 0x04, 0x20), Some(ErrorState::BusOff));
        assert_eq!(state(0x04, 0x08 | 0x10), Some(ErrorState::Passive));
        assert_eq!(state(0x04, 0x04), Some(ErrorState::Warning));
        assert_eq!(state(0x04, 0x40), Some(ErrorState::Active));
        assert_eq!(state(0x100, 0), Some(ErrorState::Active));
        assert_eq!(state(0x04, 0x01), None, "an overflow alone says nothing");
        assert_eq!(state(0x00, 0x20), None, "status counts only under CRTL");
    }

    #[test]
    fn a_short_payload_has_no_counters() {
        let report = ErrorFrame::decode(0x20, &[]);
        assert!(report.no_ack);
        assert_eq!((report.tx_errors, report.rx_errors), (None, None));
    }
}
