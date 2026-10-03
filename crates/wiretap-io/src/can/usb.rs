//! What the nusb transports share.

#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(
        dead_code,
        reason = "only the tests and the Linux listing build it here"
    )
)]

use std::io;

use super::CanError;

/// A request the device didn't take: its going away is `Closed`, anything else
/// names the request.
pub(super) fn refused(request: &'static str) -> impl Fn(io::Error) -> CanError {
    move |e| match e.kind() {
        io::ErrorKind::ConnectionAborted => CanError::Closed,
        kind => CanError::Read(io::Error::new(kind, format!("{request}: {e}"))),
    }
}

/// The desktop's reading, so the bus it has stored still matches.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn bus(found: &nusb::DeviceInfo) -> u8 {
    found.bus_id().parse().unwrap_or(0)
}
