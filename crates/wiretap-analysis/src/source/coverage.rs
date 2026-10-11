use std::collections::{HashMap, HashSet};

use serde::Serialize;
use wiretap_catalog::model::{Confidence, Frame};
use wiretap_catalog::Catalog;
use wiretap_decode::frame_id::format_frame_id;

use super::{InventoryRow, PayloadQuery, PayloadSource, Sampling};
use crate::roles::{profile_bytes, ByteProfile};

/// A catalogue signal's confidence as coverage reports it: `unset` both where
/// the catalogue says `none` and where it says nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageConfidence {
    Low,
    Medium,
    High,
    Unset,
}

impl From<Option<Confidence>> for CoverageConfidence {
    fn from(confidence: Option<Confidence>) -> Self {
        match confidence {
            Some(Confidence::Low) => Self::Low,
            Some(Confidence::Medium) => Self::Medium,
            Some(Confidence::High) => Self::High,
            Some(Confidence::None) | None => Self::Unset,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ConfidenceTally {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unset: usize,
}

impl ConfidenceTally {
    fn add(&mut self, confidence: CoverageConfidence) {
        match confidence {
            CoverageConfidence::High => self.high += 1,
            CoverageConfidence::Medium => self.medium += 1,
            CoverageConfidence::Low => self.low += 1,
            CoverageConfidence::Unset => self.unset += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignalCoverage {
    pub name: String,
    pub confidence: CoverageConfidence,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PresentFrame {
    pub frame_id: u32,
    pub frame_id_hex: String,
    pub name: Option<String>,
    pub count: i64,
    pub first_us: i64,
    pub last_us: i64,
    pub signals: Vec<SignalCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_roles: Option<ByteProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingFrame {
    pub frame_id: u32,
    pub frame_id_hex: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UncataloguedFrame {
    /// The id to add to the catalogue — masked, when the catalogue is.
    pub frame_id: u32,
    pub frame_id_hex: String,
    pub is_extended: bool,
    pub count: i64,
    /// A raw id this was actually seen as, when that differs from `frame_id`.
    /// Absent without a `frame_id_mask`, so an ordinary report is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_as_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CoverageReport {
    pub catalog: String,
    pub catalog_frames: usize,
    /// Distinct frames in the data, counted the way the catalogue counts them:
    /// under a `frame_id_mask`, fewer than the ids on the wire.
    pub data_frames: usize,
    pub present: Vec<PresentFrame>,
    pub missing: Vec<MissingFrame>,
    pub uncatalogued: Vec<UncataloguedFrame>,
    /// Over the catalogue's directly-defined signals, not mirror or copy
    /// duplicates.
    pub confidence: ConfidenceTally,
}

/// A frame's catalogue name, falling back to the transmitter.
fn frame_label(f: &Frame) -> Option<String> {
    f.name.clone().or_else(|| f.transmitter.clone())
}

/// The data side of one catalogue frame: every inventory row whose id maps onto
/// it, rolled up.
struct DataFrame<'a> {
    /// The most-seen contributing row. Decides how the id renders, and is the
    /// raw id payloads are sampled by: a masked catalogue id never appears in
    /// the data.
    top: &'a InventoryRow,
    count: i64,
    first_us: i64,
    last_us: i64,
}

impl<'a> DataFrame<'a> {
    fn new(row: &'a InventoryRow) -> Self {
        Self {
            top: row,
            count: row.count,
            first_us: row.first_us,
            last_us: row.last_us,
        }
    }

    fn merge(&mut self, row: &'a InventoryRow) {
        self.count += row.count;
        self.first_us = self.first_us.min(row.first_us);
        self.last_us = self.last_us.max(row.last_us);
        if row.count > self.top.count {
            self.top = row;
        }
    }
}

/// The inventory rolled up onto the ids the catalogue is keyed by. `mask` is the
/// catalogue's `frame_id_mask`, or `u32::MAX` for none, when the only merge is a
/// std/extended pair.
fn roll_up(inventory: &[InventoryRow], mask: u32) -> HashMap<u32, DataFrame<'_>> {
    let mut by_id: HashMap<u32, DataFrame> = HashMap::new();
    for row in inventory {
        by_id
            .entry(row.frame_id & mask)
            .and_modify(|d| d.merge(row))
            .or_insert_with(|| DataFrame::new(row));
    }
    by_id
}

/// `catalog`, reported under `catalog_name`, diffed against a source keyed the
/// way the catalogue is, its `frame_id_mask` applied.
///
/// Only the inventory's error is returned. A frame whose payloads fail to read
/// is profiled over none, so one unreadable frame costs its byte roles and not
/// the report.
pub async fn catalog_coverage<S: PayloadSource>(
    source: &S,
    catalog_name: &str,
    catalog: &Catalog,
    include_byte_roles: bool,
    sample_limit: u32,
    start_us: Option<i64>,
    end_us: Option<i64>,
) -> Result<CoverageReport, S::Error> {
    let mask = wiretap_catalog::decode::frame_id_mask(catalog).unwrap_or(u32::MAX);
    let inventory = source.inventory(start_us, end_us).await?;
    let data_by_id = roll_up(&inventory, mask);

    let mut confidence = ConfidenceTally::default();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let catalog_ids: HashSet<u32> = catalog.frames.iter().map(|f| f.frame_id).collect();

    for frame in &catalog.frames {
        let sigs = frame.own_signals();
        for s in &sigs {
            confidence.add(s.confidence.into());
        }

        match data_by_id.get(&frame.frame_id) {
            Some(data) => {
                let byte_roles = if include_byte_roles {
                    // Any protocol, and the sampled row's own width: the
                    // masked rollup is not authoritative about either.
                    let payloads = source
                        .payloads(PayloadQuery {
                            protocol: None,
                            frame_id: data.top.frame_id,
                            is_extended: Some(data.top.is_extended),
                            limit: sample_limit,
                            sampling: Sampling::Recent,
                        })
                        .await
                        .unwrap_or_default();
                    Some(profile_bytes(&payloads))
                } else {
                    None
                };
                present.push(PresentFrame {
                    frame_id: frame.frame_id,
                    frame_id_hex: format_frame_id(frame.frame_id, data.top.is_extended),
                    name: frame_label(frame),
                    count: data.count,
                    first_us: data.first_us,
                    last_us: data.last_us,
                    signals: sigs
                        .iter()
                        .filter_map(|s| {
                            s.name.clone().map(|name| SignalCoverage {
                                name,
                                confidence: s.confidence.into(),
                            })
                        })
                        .collect(),
                    byte_roles,
                });
            }
            None => missing.push(MissingFrame {
                frame_id: frame.frame_id,
                frame_id_hex: format_frame_id(frame.frame_id, frame.is_extended.unwrap_or(false)),
                name: frame_label(frame),
            }),
        }
    }

    // Reported by the id to add to the catalogue, so under a mask one unknown
    // message from five nodes is one frame; the raw id rides along.
    let mut uncatalogued: Vec<UncataloguedFrame> = data_by_id
        .iter()
        .filter(|(id, _)| !catalog_ids.contains(id))
        .map(|(id, d)| UncataloguedFrame {
            frame_id: *id,
            frame_id_hex: format_frame_id(*id, d.top.is_extended),
            is_extended: d.top.is_extended,
            count: d.count,
            seen_as_hex: (d.top.frame_id != *id)
                .then(|| format_frame_id(d.top.frame_id, d.top.is_extended)),
        })
        .collect();
    uncatalogued.sort_by_key(|f| f.frame_id);

    Ok(CoverageReport {
        catalog: catalog_name.to_owned(),
        catalog_frames: catalog.frames.len(),
        data_frames: data_by_id.len(),
        present,
        missing,
        uncatalogued,
        confidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(frame_id: u32, count: i64, first_us: i64, last_us: i64) -> InventoryRow {
        InventoryRow::new("can", frame_id, true, count, first_us, last_us, 8)
    }

    /// A J1939 mask strips the source address, so several ids on the wire are
    /// one catalogue frame. Diffing raw ids reported `present=0` on a bus the
    /// catalogue decoded in full.
    #[test]
    fn a_masked_catalogue_frame_rolls_up_every_id_that_maps_onto_it() {
        let inventory = [
            row(0x1802_FF01, 10, 500, 900),
            row(0x1802_FF02, 30, 100, 700),
            row(0x1802_FF03, 5, 300, 3000),
        ];
        let rolled = roll_up(&inventory, 0x1FFF_FF00);

        assert_eq!(
            rolled.len(),
            1,
            "three source addresses, one catalogue frame"
        );
        let data = &rolled[&0x1802_FF00];
        assert_eq!(data.count, 45, "counts sum across contributing ids");
        assert_eq!(data.first_us, 100, "the window starts at the earliest");
        assert_eq!(data.last_us, 3000, "and ends at the latest");
        assert_eq!(
            data.top.frame_id, 0x1802_FF02,
            "payloads sample by the most-seen raw id — the masked id is not on the wire"
        );
    }

    /// `u32::MAX` is what a catalogue declaring no mask resolves to, and must
    /// leave every id in its own bucket.
    #[test]
    fn no_mask_keeps_every_id_apart() {
        let inventory = [row(0x1802_FF01, 10, 0, 1), row(0x1802_FF02, 30, 0, 1)];
        assert_eq!(roll_up(&inventory, u32::MAX).len(), 2);
    }

    /// Without a mask the only merge is a std/extended pair, and the bigger row
    /// still decides how the id renders.
    #[test]
    fn an_unmasked_frame_keeps_the_bigger_rows_identity() {
        let inventory = [
            InventoryRow::new("can", 0x100, false, 3, 10, 20, 8),
            InventoryRow::new("can", 0x100, true, 90, 5, 50, 8),
        ];
        let rolled = roll_up(&inventory, u32::MAX);
        let data = &rolled[&0x100];

        assert!(
            data.top.is_extended,
            "the most-seen row decides how the id renders"
        );
        assert_eq!(data.count, 93);
        assert_eq!(data.first_us, 5);
        assert_eq!(data.last_us, 50);
    }
}
