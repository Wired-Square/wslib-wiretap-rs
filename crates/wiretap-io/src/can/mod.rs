//! CAN devices: one frame type across every transport, and one task shape, which
//! opens the device, emits what it reads and serves sends between reads, as the
//! serial task does.
//!
//! The transports each sit behind their own `can-*` feature; `can` alone
//! brings the types every one of them shares.

use std::{io, time::Duration, time::SystemTime};

mod clock;
#[cfg(all(
    feature = "can-gsusb",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub mod gsusb;
#[cfg(feature = "can-gvret")]
pub mod gvret;
#[cfg(all(
    feature = "can-pcan",
    any(test, target_os = "macos", target_os = "windows")
))]
pub mod pcan;
#[cfg(all(
    any(feature = "can-gvret-serial", feature = "can-slcan"),
    not(target_os = "ios")
))]
mod port;
#[cfg(all(feature = "can-slcan", not(target_os = "ios")))]
pub mod slcan;
#[cfg(all(feature = "can-socketcan", target_os = "linux"))]
pub mod socketcan;
mod task;
#[cfg(any(
    all(
        feature = "can-gsusb",
        any(test, target_os = "macos", target_os = "windows", target_os = "linux")
    ),
    all(
        feature = "can-pcan",
        any(test, target_os = "macos", target_os = "windows")
    )
))]
mod usb;
mod writer;

#[cfg(feature = "can-gvret")]
pub use crate::net::{tcp_endpoint, ResolveError, TransportError};
pub use task::CanTask;
pub use wiretap_protocol::can::{CanFrame, Direction, ErrorState};
pub use writer::{CanWriter, SendRefused, Unsupported};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanRead {
    pub frame: CanFrame,
    pub direction: Direction,
    /// Whole microseconds, and never earlier than a stamp this task has
    /// already handed out, except a kernel's, which is passed through.
    pub at: SystemTime,
    /// The device's own clock, unwrapped, where it has one.
    pub device_us: Option<u64>,
    /// The device dropped frames before this one; only gs_usb reports it, and
    /// the other transports leave it false.
    pub overflow: bool,
}

impl CanRead {
    /// No device stamp and no overflow; set either afterwards.
    pub fn new(frame: CanFrame, direction: Direction, at: SystemTime) -> Self {
        Self {
            frame,
            direction,
            at,
            device_us: None,
            overflow: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeMapping {
    /// The device clock mapped onto the wall clock by the lower envelope of
    /// its offset over `window` of device time.
    Mapped { window: Duration },
    /// Every frame stamped with its read's time.
    Host,
}

impl Default for TimeMapping {
    fn default() -> Self {
        Self::Mapped {
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CanOptions {
    /// The task never transmits, and every send is refused. The device is told
    /// as well where it can enforce it.
    pub listen_only: bool,
    /// Emit what the device or kernel hands back as sent, as `Tx` reads.
    pub own_frames: bool,
    pub time: TimeMapping,
    /// The wait before each reopen after a loss; `None` ends the task on the
    /// first loss.
    pub reopen: Option<Duration>,
    /// A device that isn't there at open is waited for, as after a loss,
    /// rather than returned; needs `reopen`.
    pub wait_for_device: bool,
    /// The event queue's bound. When it is full the task waits for the
    /// consumer, and still serves sends.
    pub events: usize,
    pub writes: usize,
}

impl Default for CanOptions {
    fn default() -> Self {
        Self {
            listen_only: false,
            own_frames: false,
            time: TimeMapping::default(),
            reopen: Some(Duration::from_secs(1)),
            wait_for_device: false,
            events: 64,
            writes: 32,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceInfo {
    /// `None` if the device didn't say.
    pub buses: Option<u8>,
    pub fd: bool,
    pub firmware: Option<String>,
    pub serial: Option<String>,
    /// The device answered a keepalive, so going unanswered is a loss.
    pub keepalive: bool,
    /// gs_usb's `hw_version`; SLCAN's `v` reply, or Elmue's board and MCU.
    pub hardware: Option<String>,
    /// gs_usb's `fclk_can`.
    pub clock_hz: Option<u32>,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CanEvent {
    /// The first event once the device is open, and the first after every
    /// reopen.
    Connected(DeviceInfo),
    /// One read's frames, in order, never empty.
    Read(Vec<CanRead>),
    /// `consecutive` counts failures since the last `Connected` or the start,
    /// the loss that ended it included. With `retry_in: None` this is the last
    /// event.
    Disconnected {
        error: CanError,
        consecutive: u32,
        retry_in: Option<Duration>,
    },
    /// gs_usb and PEAK only, on a change of `state`. gs_usb fills every field, also
    /// reports on a change of `no_ack` and every transmit timeout, and 5 s with
    /// no report clears it; PEAK fills `state` and the counters, and restarts a
    /// bus-off channel after 1 s.
    Bus(BusState),
}

/// The whole of a bus's current state, never a change to it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BusState {
    /// As `CanFrame::bus`.
    pub bus: u8,
    pub state: ErrorState,
    /// The controller is seeing its sends go unacknowledged.
    pub no_ack: bool,
    /// Sends known lost to a transmit timeout in this event. A floor: up to
    /// three echoed just before it may be lost too.
    pub tx_dropped: u32,
    pub tx_errors: Option<u8>,
    pub rx_errors: Option<u8>,
}

impl BusState {
    /// Active and acknowledged, with no counters.
    pub fn active(bus: u8) -> Self {
        Self {
            bus,
            state: ErrorState::Active,
            no_ack: false,
            tx_dropped: 0,
            tx_errors: None,
            rx_errors: None,
        }
    }
}

/// Each reason is short and single-line, as `TransportError`'s are.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CanError {
    /// `device` is the path, interface, `host:port` or USB selector.
    #[error("cannot open {device}: {source}")]
    Open { device: String, source: io::Error },
    #[cfg(feature = "can-gvret")]
    #[error(transparent)]
    Connect(TransportError),
    /// The device didn't answer as its protocol says.
    #[error("handshake failed: {0}")]
    Handshake(&'static str),
    /// A setting the device can't take; the valid ones are in the text.
    #[error("{0}")]
    Config(String),
    /// A zero-byte read, the socket's end, or the USB device gone.
    #[error("device closed")]
    Closed,
    #[error("device stopped answering")]
    Unresponsive,
    #[error("read failed: {0}")]
    Read(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_the_specs() {
        let options = CanOptions::default();
        assert!(!options.listen_only);
        assert!(!options.own_frames);
        assert_eq!(
            options.time,
            TimeMapping::Mapped {
                window: Duration::from_secs(60)
            }
        );
        assert_eq!(options.reopen, Some(Duration::from_secs(1)));
        assert!(!options.wait_for_device);
        assert_eq!(options.events, 64);
        assert_eq!(options.writes, 32);
    }

    #[test]
    fn a_new_read_has_no_device_stamp_and_no_overflow() {
        let frame = CanFrame::remote(0, 1, false, 5);
        let read = CanRead::new(frame, Direction::Rx, SystemTime::UNIX_EPOCH);
        assert_eq!((read.device_us, read.overflow), (None, false));
    }
}
