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

/// The service Windows has bound to the device; elsewhere `None`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(super) fn bound_driver(found: &nusb::DeviceInfo) -> Option<&str> {
    #[cfg(target_os = "windows")]
    return found.driver();
    #[cfg(not(target_os = "windows"))]
    {
        let _ = found;
        None
    }
}

/// nusb's refusal of a device bound to a driver other than WinUSB, which names
/// neither the driver nor what would work.
pub(super) fn foreign_driver(error: io::Error, driver: Option<&str>, remedy: &str) -> io::Error {
    match driver {
        Some(driver) if error.kind() == io::ErrorKind::Unsupported => io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the adapter is bound to the {driver} driver, not WinUSB: {remedy}"),
        ),
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_bound_driver_and_the_remedy_and_nothing_else_changes() {
        let unsupported = || io::Error::new(io::ErrorKind::Unsupported, "incompatible driver");
        let named = foreign_driver(unsupported(), Some("libusbK"), "bind WinUSB to it");
        assert_eq!(named.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            named.to_string(),
            "the adapter is bound to the libusbK driver, not WinUSB: bind WinUSB to it"
        );
        let unbound = foreign_driver(unsupported(), None, "bind WinUSB to it");
        assert_eq!(unbound.to_string(), "incompatible driver");
        let other = foreign_driver(io::ErrorKind::NotFound.into(), Some("WinUSB"), "");
        assert_eq!(other.kind(), io::ErrorKind::NotFound);
    }
}
