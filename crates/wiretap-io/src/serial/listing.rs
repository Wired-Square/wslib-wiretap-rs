//! The ports the OS lists, through serialport, with the USB identity a picker
//! shows. Nothing is filtered.

use std::{io, path::Path};

use serialport::{SerialPortInfo, SerialPortType};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PortInfo {
    /// What `serial::open`, `SlcanOptions::path` and `Link::Serial` take.
    pub path: String,
    pub kind: PortKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortKind {
    Usb(UsbPort),
    Pci,
    Bluetooth,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UsbPort {
    pub vid: u16,
    pub pid: u16,
    pub serial: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
}

/// Every port the OS lists, `tty.*` and `cu.*` alike on macOS.
pub fn ports() -> io::Result<Vec<PortInfo>> {
    listed(cfg!(target_os = "linux").then_some(Path::new("/sys/class/tty")))
}

/// Without libudev, serialport's scan of `/sys/class/tty` panics where it is
/// missing, as in a minimal container.
fn listed(sysfs: Option<&Path>) -> io::Result<Vec<PortInfo>> {
    if sysfs.is_some_and(|dir| !dir.is_dir()) {
        return Ok(Vec::new());
    }
    Ok(serialport::available_ports()?
        .into_iter()
        .map(port_info)
        .collect())
}

fn port_info(port: SerialPortInfo) -> PortInfo {
    PortInfo {
        path: port.port_name,
        kind: match port.port_type {
            SerialPortType::UsbPort(usb) => PortKind::Usb(UsbPort {
                vid: usb.vid,
                pid: usb.pid,
                serial: usb.serial_number,
                manufacturer: usb.manufacturer,
                product: usb.product,
            }),
            SerialPortType::PciPort => PortKind::Pci,
            SerialPortType::BluetoothPort => PortKind::Bluetooth,
            SerialPortType::Unknown => PortKind::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use serialport::UsbPortInfo;

    use super::*;

    fn usb(serial: Option<&str>) -> UsbPortInfo {
        UsbPortInfo {
            vid: 0x1D50,
            pid: 0x606F,
            serial_number: serial.map(str::to_owned),
            manufacturer: Some("Wired Square".into()),
            product: Some("candleLight".into()),
        }
    }

    #[test]
    fn each_port_type_maps_field_for_field() {
        let usb_port = |serial: Option<&str>| {
            PortKind::Usb(UsbPort {
                vid: 0x1D50,
                pid: 0x606F,
                serial: serial.map(str::to_owned),
                manufacturer: Some("Wired Square".into()),
                product: Some("candleLight".into()),
            })
        };
        let cases = [
            (
                SerialPortType::UsbPort(usb(Some("0042"))),
                usb_port(Some("0042")),
            ),
            (SerialPortType::UsbPort(usb(None)), usb_port(None)),
            (SerialPortType::PciPort, PortKind::Pci),
            (SerialPortType::BluetoothPort, PortKind::Bluetooth),
            (SerialPortType::Unknown, PortKind::Unknown),
        ];
        for (port_type, kind) in cases {
            let port = SerialPortInfo {
                port_name: "/dev/cu.usbmodem1".into(),
                port_type,
            };
            assert_eq!(
                port_info(port),
                PortInfo {
                    path: "/dev/cu.usbmodem1".into(),
                    kind
                }
            );
        }
    }

    #[test]
    fn a_missing_sysfs_lists_nothing_rather_than_panicking() {
        let missing = Path::new("/nonexistent/wiretap-sys-class-tty");
        assert_eq!(listed(Some(missing)).unwrap(), []);
    }
}
