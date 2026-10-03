use std::time::{Duration, SystemTime};

use wiretap_catalog::modbus::{ModbusFrame, ModbusManifest, PollItem, RegisterType};

/// One read: FC01/02/03/04 by bank, protocol-addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadRequest {
    pub register_type: RegisterType,
    pub start: u16,
    pub count: u16,
    /// Overrides [`TcpOptions::unit_id`](super::TcpOptions::unit_id) for this
    /// request only.
    pub unit: Option<u8>,
}

/// Addressed to the item's `device_address` (1 unless the catalogue says
/// otherwise). Set `unit` to `None` to use the connection's unit instead.
impl<T> From<&PollItem<T>> for ReadRequest {
    fn from(item: &PollItem<T>) -> Self {
        Self {
            register_type: item.register_type,
            start: item.start,
            count: item.count,
            unit: Some(item.device_address),
        }
    }
}

impl ReadRequest {
    /// Protocol-addressed (`manifest.protocol_address`), so 40026 goes out as 25.
    /// Addressed to the frame's `device_address`, as `From<&PollItem>` is.
    pub fn for_frame(manifest: &ModbusManifest, frame: &ModbusFrame) -> Self {
        Self {
            register_type: frame.register_type,
            start: manifest.protocol_address(frame),
            count: frame.length,
            unit: Some(frame.device_address),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    pub data: ReadData,
    /// Request sent to response parsed.
    pub latency: Duration,
    /// Wall clock at completion.
    pub at: SystemTime,
}

/// The words or bits as received: a short reply stays short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadData {
    Registers(Vec<u16>),
    Coils(Vec<bool>),
}

/// The FC43/14 read device id code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdCode {
    Basic,
    Regular,
    Extended,
    Specific,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentification {
    pub conformity_level: u8,
    /// `(object id, value)`, in the order the device sent them.
    pub objects: Vec<(u8, Vec<u8>)>,
    /// Stream access continues from `next_object_id` while this is set.
    pub more_follows: bool,
    pub next_object_id: u8,
}

impl DeviceIdentification {
    /// Object `id` as text, the last one sent where the device repeats it;
    /// `None` when it is absent or not UTF-8.
    pub fn text(&self, id: u8) -> Option<&str> {
        let (_, value) = self
            .objects
            .iter()
            .rev()
            .find(|(object, _)| *object == id)?;
        std::str::from_utf8(value).ok()
    }

    /// `VendorName`, object 0x00.
    pub fn vendor(&self) -> Option<&str> {
        self.text(0x00)
    }

    /// `ProductCode`, object 0x01.
    pub fn product_code(&self) -> Option<&str> {
        self.text(0x01)
    }

    /// `MajorMinorRevision`, object 0x02.
    pub fn revision(&self) -> Option<&str> {
        self.text(0x02)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_reads_from_its_protocol_address_on_its_own_unit() {
        let manifest = ModbusManifest::parse(
            r#"
[meta.modbus]
register_base = 1

[frame.modbus.cfg]
register_number = 40026
register_type = "holding"
length = 2
node_address = 5

[[frame.modbus.cfg.signals]]
name = "X"
start_bit = 0
bit_length = 32
"#,
        )
        .unwrap();
        let request = ReadRequest::for_frame(&manifest, &manifest.frames[0]);
        assert_eq!(
            request,
            ReadRequest {
                register_type: RegisterType::Holding,
                start: 25,
                count: 2,
                unit: Some(5),
            }
        );
    }

    #[test]
    fn a_poll_item_reads_what_it_names() {
        let item = PollItem {
            register_type: RegisterType::Coil,
            start: 100,
            count: 40,
            interval: Duration::from_secs(1),
            device_address: 3,
            tag: (),
        };
        assert_eq!(
            ReadRequest::from(&item),
            ReadRequest {
                register_type: RegisterType::Coil,
                start: 100,
                count: 40,
                unit: Some(3),
            }
        );
    }

    #[test]
    fn the_basic_objects_read_as_text_the_last_one_sent_winning() {
        let identification = DeviceIdentification {
            conformity_level: 0x01,
            objects: vec![
                (0x00, b"Acme".to_vec()),
                (0x02, b"v1".to_vec()),
                (0x02, vec![0xFF]),
                (0x01, b"old".to_vec()),
                (0x01, b"X-1".to_vec()),
            ],
            more_follows: false,
            next_object_id: 0,
        };
        assert_eq!(identification.vendor(), Some("Acme"));
        assert_eq!(identification.product_code(), Some("X-1"));
        assert_eq!(identification.revision(), None);
        assert_eq!(identification.text(0x03), None);
    }
}
