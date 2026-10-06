//! Device I/O for WireTAP: the transports, each behind its own feature, so an
//! app compiles only the ones it uses.
//!
//! Nothing here builds a runtime, and nothing spawns a task without
//! `modbus-task`, `testing`, `serial` or a `can-*` transport. Every method is an `async fn` that runs on the
//! caller's task.
//!
//! - `modbus-tcp` — `modbus::ModbusTcp`: reads and device identification;
//!   `modbus::Poller`: a schedule read over it.
//! - `modbus-write` — its write methods. Strictly additive: no other feature
//!   turns it on, but Cargo unions features across a build graph, so a consumer
//!   that must stay read-only checks `cargo tree -e features -i wiretap-io`.
//! - `modbus-task` — `modbus::spawn`: a task that owns a connection and a
//!   poller, on the ambient tokio runtime.
//! - `testing` — `modbus::testing::device`: a fake Modbus TCP device on
//!   loopback, for a consumer's tests.
//! - `serial` — `serial::open`: a read-only serial port, read by a task on the
//!   ambient tokio runtime that reopens the line when it goes away.
//! - `serial-ports` — `serial::ports`: the ports the OS lists, with their USB
//!   identity.
//! - `serial-write` — `Access::ReadWrite` and `serial::SerialWriter`, whose
//!   writes that task serves between reads. Strictly additive, as
//!   `modbus-write` is.
//! - `can` — `can::CanFrame`, the events, `can::CanWriter` and the task
//!   every CAN transport runs; implied by each `can-*` feature.
//! - `can-gvret` — `can::gvret::{open, probe}`: a GVRET device over TCP.
//! - `can-gvret-serial` — `gvret::Link::Serial`: the same device over a serial
//!   port. Implies `can-gvret` and `serial-write`.
//! - `can-slcan` — `can::slcan::{open, probe}`: an SLCAN adapter on a serial port.
//!   Implies `can` and `serial-write`.
//! - `can-gsusb` — `can::gsusb::{devices, open, probe}`: a gs_usb (candleLight)
//!   adapter over USB. On Linux only `devices`, which names each channel's
//!   SocketCAN interface. Implies `can`.
//! - `can-pcan` — `can::pcan::{devices, open, probe}`: a PEAK-System adapter
//!   over USB, the classic PCAN-USB or the CAN FD PCAN-USB FD, PCAN-Chip USB,
//!   PCAN-USB Pro FD and PCAN-USB X6; the four FD models are untested. On
//!   Windows, one bound to PEAK's own driver goes through `PCANBasic.dll`,
//!   classic only. Implies `can`.
//! - `can-socketcan` — `can::socketcan::{open, bitrates}`: a SocketCAN
//!   interface. Implies `can`.
//!
//! Modbus, `can` and `can-gvret` build only for Windows, macOS, Linux and iOS,
//! serial, `can-gvret-serial` and `can-slcan` only for Windows, macOS and
//! Linux, `can-gsusb` only for Windows and macOS (bar its Linux `devices`),
//! `can-pcan` only for Windows and macOS, and `can-socketcan` only for Linux.

#[cfg(all(
    feature = "modbus-tcp",
    any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "ios"
    )
))]
pub mod modbus;

#[cfg(all(
    any(feature = "modbus-tcp", feature = "can-gvret"),
    any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "ios"
    )
))]
mod net;

#[cfg(all(
    feature = "serial",
    any(target_os = "windows", target_os = "macos", target_os = "linux")
))]
pub mod serial;

#[cfg(all(
    feature = "can",
    any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "ios"
    )
))]
pub mod can;
