//! A catalogue summarised across every protocol: its counts, the defaults
//! decode applies, and one row per frame with what it resolves to. Structure
//! only; the wording and layout are the consumer's.

use serde::{Deserialize, Serialize};
use toml::Value;

use crate::model::{
    Catalog, Confidence, EffectiveDefaults, Endianness, Frame, Mux, Protocol, Signal,
};
use crate::mux_case::{compare_mux_case_keys, mux_case_values, CaseRange};
use crate::parse::{parse_id, CatalogError};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSummary {
    pub name: String,
    pub version: u32,
    pub defaults: EffectiveDefaults,
    pub counts: SummaryCounts,
    /// By protocol (CAN, Modbus, serial, as the editor's tree), then numeric id,
    /// then key.
    pub frames: Vec<FrameRow>,
}

/// Counts of what the catalogue defines: a mirror's inherited signals and mux
/// are its source's, counted there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryCounts {
    pub frames: ProtocolCounts,
    pub mux_frames: usize,
    /// Every mux case's included, at any depth.
    pub signals: usize,
    pub enum_signals: usize,
    pub confidence: ConfidenceCounts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolCounts {
    pub can: usize,
    pub modbus: usize,
    pub serial: usize,
}

/// A signal with no confidence counts as `none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfidenceCounts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub none: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameRow {
    pub protocol: Protocol,
    pub key: String,
    /// `None` for a serial frame keyed by a name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<Interval>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// [`Frame::inherited_fields`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_fields: Vec<String>,
    pub signals: Vec<SignalRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interval {
    pub ms: u64,
    /// Taken from the protocol's default rather than the frame or the frame it
    /// copies.
    pub default: bool,
}

/// A signal as the model holds it, with the byte order it decodes in: its own
/// (`signal.endianness`, from `byte_order` or `endianness`) or its protocol's default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalRow {
    pub byte_order: Endianness,
    pub signal: Signal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxRow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// In [`compare_mux_case_keys`] order.
    pub cases: Vec<CaseRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseRow {
    pub key: String,
    /// Empty only for a value wider than 64 bits.
    pub values: Vec<CaseRange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    pub signals: Vec<SignalRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Box<MuxRow>>,
}

impl CatalogSummary {
    pub fn of(catalog: &Catalog) -> Self {
        let defaults = catalog.derived_defaults();
        let mut frames: Vec<&Frame> = catalog.frames.iter().collect();
        frames.sort_by_key(|&f| (protocol_rank(f.protocol), f.frame_id, f.key.as_str()));
        let mut counts = SummaryCounts::default();
        for frame in &frames {
            counts.add(frame);
        }
        Self {
            name: catalog.meta.name.clone(),
            version: catalog.meta.version,
            defaults,
            counts,
            frames: frames
                .into_iter()
                .map(|f| frame_row(catalog, &defaults, f))
                .collect(),
        }
    }

    /// The summary of a catalogue's text, reading a legacy `[id]` table as
    /// `[frame.can]` when there is none.
    pub fn from_text(text: &str) -> Result<Self, CatalogError> {
        let mut root: Value = toml::from_str(text)?;
        promote_legacy_ids(&mut root);
        Ok(Self::of(&Catalog::parse_root(&root, text)))
    }
}

fn promote_legacy_ids(root: &mut Value) {
    let Some(table) = root.as_table_mut() else {
        return;
    };
    if table.get("frame").and_then(|f| f.get("can")).is_some() {
        return;
    }
    let Some(ids) = table.remove("id") else {
        return;
    };
    if let Some(frame) = table
        .entry("frame")
        .or_insert_with(|| Value::Table(Default::default()))
        .as_table_mut()
    {
        frame.insert("can".into(), ids);
    }
}

fn protocol_rank(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Can => 0,
        Protocol::Modbus => 1,
        Protocol::Serial => 2,
    }
}

fn inherits(frame: &Frame, field: &str) -> bool {
    frame.inherited_fields.iter().any(|f| f == field)
}

impl SummaryCounts {
    fn add(&mut self, frame: &Frame) {
        *match frame.protocol {
            Protocol::Can => &mut self.frames.can,
            Protocol::Modbus => &mut self.frames.modbus,
            Protocol::Serial => &mut self.frames.serial,
        } += 1;
        if frame.mux.is_some() && !inherits(frame, "mux") {
            self.mux_frames += 1;
        }
        for signal in frame.own_signals() {
            self.signals += 1;
            if signal.enum_map.is_some() {
                self.enum_signals += 1;
            }
            *match signal.confidence.unwrap_or(Confidence::None) {
                Confidence::High => &mut self.confidence.high,
                Confidence::Medium => &mut self.confidence.medium,
                Confidence::Low => &mut self.confidence.low,
                Confidence::None => &mut self.confidence.none,
            } += 1;
        }
    }
}

fn frame_row(catalog: &Catalog, defaults: &EffectiveDefaults, frame: &Frame) -> FrameRow {
    let byte_order = match frame.protocol {
        Protocol::Can => defaults.can_byte_order,
        Protocol::Modbus => defaults.modbus_byte_order,
        Protocol::Serial => defaults.serial_byte_order,
    };
    FrameRow {
        protocol: frame.protocol,
        key: frame.key.clone(),
        frame_id: (!frame.is_keyed_by_name()).then_some(frame.frame_id),
        name: frame.name.clone(),
        length: frame.length,
        transmitter: frame.transmitter.clone(),
        bus: frame.bus,
        interval: frame.interval.map(|ms| Interval {
            ms,
            default: inherits(frame, "interval") && !copied_interval(catalog, frame),
        }),
        notes: frame.notes.clone(),
        inherited_fields: frame.inherited_fields.clone(),
        signals: signal_rows(&frame.signals, byte_order),
        mux: frame.mux.as_ref().map(|m| mux_row(m, byte_order)),
    }
}

/// Whether the frame's interval is one its copy or mirror source sets (the
/// copy's, when it has both).
fn copied_interval(catalog: &Catalog, frame: &Frame) -> bool {
    let Some(source) = frame.copy_from.as_deref().or(frame.mirror_of.as_deref()) else {
        return false;
    };
    let id = parse_id(source);
    catalog.frames.iter().any(|s| {
        s.protocol == frame.protocol
            && Some(s.frame_id) == id
            && s.interval.is_some()
            && !inherits(s, "interval")
    })
}

fn signal_rows(signals: &[Signal], default: Endianness) -> Vec<SignalRow> {
    signals
        .iter()
        .map(|s| SignalRow {
            byte_order: s.endianness.unwrap_or(default),
            signal: s.clone(),
        })
        .collect()
}

fn mux_row(mux: &Mux, byte_order: Endianness) -> MuxRow {
    let mut cases: Vec<_> = mux.cases.iter().collect();
    cases.sort_by(|(a, _), (b, _)| compare_mux_case_keys(a, b));
    MuxRow {
        name: mux.name.clone(),
        start_bit: mux.start_bit,
        bit_length: mux.bit_length,
        default: mux.default.clone(),
        notes: mux.notes.clone(),
        cases: cases
            .into_iter()
            .map(|(key, case)| CaseRow {
                key: key.clone(),
                values: mux_case_values(key).unwrap_or_default(),
                notes: case.notes.clone(),
                signals: signal_rows(&case.signals, byte_order),
                mux: case.mux.as_ref().map(|m| Box::new(mux_row(m, byte_order))),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(toml: &str) -> CatalogSummary {
        CatalogSummary::from_text(toml).unwrap()
    }

    fn row<'a>(s: &'a CatalogSummary, key: &str) -> &'a FrameRow {
        s.frames.iter().find(|f| f.key == key).unwrap()
    }

    #[test]
    fn an_interval_is_the_default_only_when_neither_the_frame_nor_its_source_sets_one() {
        let s = summary(
            r#"
[meta]
name = "x"
[meta.can]
default_interval = 100
[frame.can.0x100]
interval_ms = 50
[frame.can.0x101]
copy = "0x100"
[frame.can.0x102]
[frame.can.0x103]
mirror_of = "0x102"
"#,
        );
        let interval = |key| row(&s, key).interval.map(|i| (i.ms, i.default));
        assert_eq!(interval("0x100"), Some((50, false)));
        assert_eq!(interval("0x101"), Some((50, false)));
        assert_eq!(interval("0x102"), Some((100, true)));
        assert_eq!(interval("0x103"), Some((100, true)));
    }

    #[test]
    fn rows_run_by_protocol_then_id_then_key_and_a_named_frame_has_no_id() {
        let s = summary(
            r#"
[meta]
name = "x"
[frame.serial.heartbeat]
[frame.serial."0x20"]
[frame.modbus.b]
register_number = 7
[frame.modbus.a]
register_number = 7
[frame.can."0x200"]
[frame.can."0x100"]
"#,
        );
        let order: Vec<_> = s
            .frames
            .iter()
            .map(|f| (f.key.as_str(), f.frame_id))
            .collect();
        assert_eq!(
            order,
            [
                ("0x100", Some(0x100)),
                ("0x200", Some(0x200)),
                ("a", Some(7)),
                ("b", Some(7)),
                ("0x20", Some(0x20)),
                ("heartbeat", None),
            ]
        );
        let f = s.counts.frames;
        assert_eq!((f.can, f.modbus, f.serial), (2, 2, 2));
    }

    #[test]
    fn a_summary_round_trips_through_json() {
        let toml = include_str!("../tests/fixtures/desktop/report-edges.toml");
        let s = summary(toml);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["frames"][0]["signals"][0]["byteOrder"], "big");
        assert_eq!(json["counts"]["frames"]["can"], 3);
        assert_eq!(serde_json::from_value::<CatalogSummary>(json).unwrap(), s);
    }

    #[test]
    fn a_legacy_id_table_is_read_only_when_there_is_no_frame_can() {
        let legacy = "[id.\"0x10\"]\nlength = 4\n";
        assert_eq!(summary(legacy).frames[0].key, "0x10");
        let both = format!("{legacy}[frame.can.\"0x20\"]\n");
        let keys: Vec<_> = summary(&both).frames.into_iter().map(|f| f.key).collect();
        assert_eq!(keys, ["0x20"]);
    }

    #[test]
    fn a_signal_decodes_in_its_own_byte_order_else_its_protocols_default() {
        let s = summary(
            r#"
[meta]
name = "x"
[frame.can.0x100]
[[frame.can.0x100.signals]]
name = "own"
byte_order = "big"
[[frame.can.0x100.signals]]
name = "default"
"#,
        );
        let orders: Vec<_> = row(&s, "0x100")
            .signals
            .iter()
            .map(|r| (r.byte_order, r.signal.endianness))
            .collect();
        assert_eq!(
            orders,
            [
                (Endianness::Big, Some(Endianness::Big)),
                (Endianness::Little, None)
            ]
        );
    }
}
