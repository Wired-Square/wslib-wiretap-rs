use std::{
    fs::{self, DirEntry},
    io,
    path::Path,
};

use wiretap_protocol::gs_usb::DEVICES;

use super::GsUsbDevice;

/// A gs_usb adapter on Linux, where the kernel driver makes each of its
/// channels a SocketCAN interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxGsUsbDevice {
    pub device: GsUsbDevice,
    /// `can0`, or `None` until the driver binds the adapter.
    pub interface: Option<String>,
    /// From the interface's `operstate`, where it can be read.
    pub up: Option<bool>,
}

/// One entry per `can*` interface on a gs_usb adapter, then one per adapter
/// plugged in with none yet, read from sysfs.
pub fn devices() -> io::Result<Vec<LinuxGsUsbDevice>> {
    scan(Path::new("/sys"))
}

fn scan(sys: &Path) -> io::Result<Vec<LinuxGsUsbDevice>> {
    let mut found = Vec::new();
    for entry in entries(&sys.join("class/net"))? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("can") {
            continue;
        }
        let Ok(path) = fs::canonicalize(entry.path().join("device")) else {
            continue;
        };
        if let Some(device) = path.ancestors().skip(1).find_map(usb_device) {
            found.push(LinuxGsUsbDevice {
                device,
                up: read(&entry.path(), "operstate").map(|state| state == "up"),
                interface: Some(name),
            });
        }
    }
    for entry in entries(&sys.join("bus/usb/devices")).unwrap_or_default() {
        if entry.file_name().to_string_lossy().contains(':') {
            continue;
        }
        let Some(device) = usb_device(&entry.path()) else {
            continue;
        };
        let listed =
            |d: &LinuxGsUsbDevice| d.device.bus == device.bus && d.device.address == device.address;
        if !found.iter().any(listed) {
            found.push(LinuxGsUsbDevice {
                device,
                interface: None,
                up: None,
            });
        }
    }
    Ok(found)
}

/// A directory that isn't there is empty.
fn entries(dir: &Path) -> io::Result<Vec<DirEntry>> {
    match fs::read_dir(dir) {
        Ok(entries) => Ok(entries.flatten().collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn read(dir: &Path, attribute: &str) -> Option<String> {
    fs::read_to_string(dir.join(attribute))
        .ok()
        .map(|value| value.trim().to_owned())
}

fn usb_device(dir: &Path) -> Option<GsUsbDevice> {
    let id = |attribute| u16::from_str_radix(&read(dir, attribute)?, 16).ok();
    if !DEVICES.contains(&(id("idVendor")?, id("idProduct")?)) {
        return None;
    }
    let number = |attribute| {
        read(dir, attribute)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    Some(GsUsbDevice {
        serial: read(dir, "serial"),
        bus: number("busnum"),
        address: number("devnum"),
        product: read(dir, "product").unwrap_or_else(|| "candleLight".to_owned()),
    })
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::symlink, path::PathBuf};

    use super::*;

    struct Sysfs(PathBuf);

    impl Sysfs {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("wiretap-io-sysfs-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("class/net")).unwrap();
            fs::create_dir_all(root.join("bus/usb/devices")).unwrap();
            Self(root)
        }

        fn write(&self, dir: &Path, attributes: &[(&str, &str)]) {
            fs::create_dir_all(dir).unwrap();
            for (attribute, value) in attributes {
                fs::write(dir.join(attribute), format!("{value}\n")).unwrap();
            }
        }

        /// A USB device at `port` on bus 1, with `port` as its serial, listed in
        /// `bus/usb/devices`.
        fn usb(&self, port: &str, vid: u16, pid: u16, devnum: u8) -> PathBuf {
            let dir = self.0.join("devices/usb1").join(port);
            self.write(
                &dir,
                &[
                    ("idVendor", &format!("{vid:04x}")),
                    ("idProduct", &format!("{pid:04x}")),
                    ("busnum", "1"),
                    ("devnum", &devnum.to_string()),
                    ("serial", port),
                ],
            );
            symlink(&dir, self.0.join("bus/usb/devices").join(port)).unwrap();
            dir
        }

        /// A net interface on `usb`'s interface 0, as the kernel links it.
        fn interface(&self, usb: &Path, name: &str, operstate: &str) {
            let usb_interface = usb.join(format!(
                "{}:1.0",
                usb.file_name().unwrap().to_string_lossy()
            ));
            let net = usb_interface.join("net").join(name);
            self.write(&net, &[("operstate", operstate)]);
            symlink(&usb_interface, net.join("device")).unwrap();
            symlink(&net, self.0.join("class/net").join(name)).unwrap();
        }
    }

    impl Drop for Sysfs {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn each_bound_channel_is_listed_with_its_interface_then_each_unbound_adapter() {
        let sys = Sysfs::new("bound");
        let (vid, pid) = DEVICES[0];
        let two_channels = sys.usb("1-1", vid, pid, 4);
        sys.interface(&two_channels, "can0", "up");
        sys.interface(&two_channels, "can1", "down");
        sys.usb("1-2", vid, pid, 5);
        let other = sys.usb("1-3", 0x0483, 0x5740, 6);
        sys.interface(&other, "can2", "up");

        let mut listed: Vec<_> = scan(&sys.0)
            .unwrap()
            .into_iter()
            .map(|d| (d.device.serial.unwrap(), d.interface, d.up))
            .collect();
        listed.sort();
        assert_eq!(
            listed,
            [
                ("1-1".into(), Some("can0".into()), Some(true)),
                ("1-1".into(), Some("can1".into()), Some(false)),
                ("1-2".into(), None, None),
            ]
        );
    }

    #[test]
    fn every_kernel_pair_is_an_adapter_and_a_vendors_other_products_are_not() {
        let sys = Sysfs::new("table");
        for (i, (vid, pid)) in DEVICES.iter().enumerate() {
            sys.usb(&format!("1-{i}"), *vid, *pid, i as u8);
        }
        sys.usb("1-8", 0x1d50, 0x0000, 8);
        sys.usb("1-9", 0x1209, 0x0000, 9);

        let mut listed: Vec<_> = scan(&sys.0)
            .unwrap()
            .into_iter()
            .map(|d| d.device.address)
            .collect();
        listed.sort();
        assert_eq!(listed, (0..DEVICES.len() as u8).collect::<Vec<_>>());
    }

    #[test]
    fn a_missing_attribute_falls_back_to_a_default() {
        let sys = Sysfs::new("fallback");
        let dir = sys.0.join("devices/usb1/1-1");
        let (vid, pid) = DEVICES[0];
        sys.write(
            &dir,
            &[
                ("idVendor", &format!("{vid:04x}")),
                ("idProduct", &format!("{pid:04x}")),
            ],
        );
        symlink(&dir, sys.0.join("bus/usb/devices/1-1")).unwrap();

        let device = &scan(&sys.0).unwrap()[0].device;
        assert_eq!((device.bus, device.address), (0, 0));
        assert_eq!(device.product, "candleLight");
        assert_eq!(device.serial, None);
    }

    #[test]
    fn a_host_without_sysfs_lists_nothing() {
        assert!(scan(Path::new("/nonexistent-sysfs")).unwrap().is_empty());
        if !Path::new("/sys").exists() {
            assert!(devices().unwrap().is_empty());
        }
    }
}
