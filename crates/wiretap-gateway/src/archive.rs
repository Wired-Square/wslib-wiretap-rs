//! What the archive endpoints answer: `/inventory`, `/time-bounds`, `/frames`,
//! `/payloads` and `/import`.

use serde::{Deserialize, Serialize};

#[cfg(feature = "client")]
use crate::Protocol;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub frame_id: u32,
    pub is_extended: bool,
    pub count: i64,
    pub first_us: i64,
    pub last_us: i64,
    pub max_dlc: u16,
    /// Absent from gateways before 0.1.4.
    #[serde(default)]
    pub max_len: Option<u16>,
}

#[cfg(feature = "client")]
impl InventoryEntry {
    /// The longest payload in bytes. A gateway before 0.1.4 serves only
    /// `max_dlc`, a CAN length code (above 8 only FD) or a whole message's length.
    pub fn max_len_for(&self, protocol: Protocol) -> u16 {
        self.max_len.unwrap_or_else(|| match protocol {
            Protocol::Can => wiretap_protocol::dlc_to_len(self.max_dlc as u8, true) as u16,
            Protocol::Modbus | Protocol::Serial => self.max_dlc,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryResponse {
    pub entries: Vec<InventoryEntry>,
    /// The gateway cut `entries` at the request's `limit`; absent from older gateways.
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeBounds {
    pub min_ts_us: Option<i64>,
    pub max_ts_us: Option<i64>,
}

/// `dlc` must stay directly before `len`: WireTAP-Server's smoke test greps
/// the pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameBatchRow {
    pub ts_us: i64,
    pub id: u32,
    pub extended: bool,
    pub dlc: u16,
    /// Absent from gateways before 0.1.4.
    #[serde(default)]
    pub len: Option<u16>,
    pub is_fd: bool,
    /// Absent from gateways before schema v4.
    #[serde(default)]
    pub is_rtr: bool,
    #[serde(default)]
    pub is_brs: bool,
    #[serde(default)]
    pub is_esi: bool,
    pub bus: u8,
    pub dir: String,
    pub data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameBatch {
    pub frames: Vec<FrameBatchRow>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadsResponse {
    pub payloads: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportResult {
    pub imported: u64,
    pub elapsed_ms: u64,
}
