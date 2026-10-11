use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use wiretap_decode::frame_id::format_frame_id;

/// One frame identity in a source, with its rollup.
///
/// Identity is (protocol, frame_id, is_extended): CAN `0x100` and Modbus
/// register 256 are different frames that happen to share a number, and a
/// standard id is not its extended namesake. This is the shape every source
/// reports, and the one the MCP `frame_inventory` tool serialises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct InventoryRow {
    pub protocol: String,
    pub frame_id: u32,
    pub frame_id_hex: String,
    pub is_extended: bool,
    pub count: i64,
    pub first_us: i64,
    pub last_us: i64,
    pub max_dlc: u16,
}

impl InventoryRow {
    pub fn new(
        protocol: &str,
        frame_id: u32,
        is_extended: bool,
        count: i64,
        first_us: i64,
        last_us: i64,
        max_dlc: u16,
    ) -> Self {
        Self {
            protocol: protocol.to_string(),
            frame_id,
            frame_id_hex: format_frame_id(frame_id, is_extended),
            is_extended,
            count,
            first_us,
            last_us,
            max_dlc,
        }
    }
}

/// A protocol and the frame ids selected under it.
///
/// Frame identity is (protocol, frame_id): CAN 0x100 and Modbus register 256 are
/// different frames that share a numeric id, so a bare id over-matches across
/// protocols. Grouping keeps the protocol string off every entry — a busy selection
/// is thousands of ids across at most three protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFrames {
    pub protocol: String,
    pub frame_ids: Vec<u32>,
    /// Every id of this protocol, `frame_ids` notwithstanding — a protocol tab
    /// wants its whole protocol, ids seen or not.
    #[serde(default)]
    pub all_ids: bool,
}

impl ProtocolFrames {
    pub fn ids(protocol: impl Into<String>, frame_ids: Vec<u32>) -> Self {
        Self {
            protocol: protocol.into(),
            frame_ids,
            all_ids: false,
        }
    }

    pub fn whole(protocol: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            frame_ids: Vec::new(),
            all_ids: true,
        }
    }
}

/// A normalised frame selection: empty groups dropped, ids deduplicated, and the
/// protocols selected whole — which absorb any ids listed under them.
///
/// Every consumer reads empty as "select everything", so a group carrying no ids must
/// not leave the selection looking non-empty — that would turn "select nothing" into
/// "select everything".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameSelection {
    ids: HashMap<String, HashSet<u32>>,
    whole: HashSet<String>,
}

impl FrameSelection {
    pub fn from_groups(groups: Vec<ProtocolFrames>) -> Self {
        let mut selection = Self::default();
        for group in groups {
            if group.all_ids {
                selection.whole.insert(group.protocol);
            } else if !group.frame_ids.is_empty() {
                selection
                    .ids
                    .entry(group.protocol)
                    .or_default()
                    .extend(group.frame_ids);
            }
        }
        let whole = &selection.whole;
        selection
            .ids
            .retain(|protocol, _| !whole.contains(protocol));
        selection
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.whole.is_empty()
    }

    /// True when every frame seen, as each protocol's ids, is selected, so the
    /// filter can be skipped entirely.
    pub fn covers<'a, I>(&self, seen: impl IntoIterator<Item = (&'a str, I)>) -> bool
    where
        I: IntoIterator<Item = &'a u32>,
    {
        seen.into_iter().all(|(protocol, ids)| {
            self.whole.contains(protocol)
                || self
                    .ids
                    .get(protocol)
                    .is_some_and(|selected| ids.into_iter().all(|id| selected.contains(id)))
        })
    }

    /// Whether one frame is selected, matched on the identity pair.
    pub fn contains(&self, protocol: &str, frame_id: u32) -> bool {
        self.whole.contains(protocol)
            || self
                .ids
                .get(protocol)
                .is_some_and(|ids| ids.contains(&frame_id))
    }

    /// (frame_id, protocol) pairs, sorted so the JSON payload is stable across calls.
    /// A protocol selected whole contributes none: it is matched by `protocols`.
    pub fn pairs(&self) -> Vec<(u32, &str)> {
        let mut pairs: Vec<(u32, &str)> = self
            .ids
            .iter()
            .flat_map(|(protocol, ids)| ids.iter().map(move |id| (*id, protocol.as_str())))
            .collect();
        pairs.sort_unstable();
        pairs
    }

    /// The protocols selected whole, sorted.
    pub fn protocols(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.whole.iter().map(String::as_str).collect();
        out.sort_unstable();
        out
    }
}
