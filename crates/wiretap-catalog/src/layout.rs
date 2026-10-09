//! What a bit-layout preview of one item in a frame shows: the frame's byte
//! length and the ranges around the item, the item itself flagged.
//!
//! An item is addressed by the editor tree's path below `["frame", protocol,
//! key]`: `[]` is the frame, `["signals", i]` and `["checksum", i]` its own
//! signal and checksum, `["mux"]` its multiplexer, `["mux", case]` a case, and a
//! case continues the same way (`["mux", case, "signals", i]`,
//! `["mux", case, "mux", inner]`). The ranges are those of every container on
//! the path, the frame then each case in turn: its signals and its selector, and
//! the frame's checksums.

use serde::{Deserialize, Serialize};
use wiretap_checksum::resolve_byte_index;

use crate::model::{Catalog, Mux, Protocol, Signal};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameLayout {
    /// The model's [`Frame::length`](crate::model::Frame::length): a Modbus
    /// frame's by its register type.
    pub byte_length: u32,
    pub ranges: Vec<LayoutRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
    pub kind: RangeKind,
    /// The item the path addresses.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub edited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RangeKind {
    Signal,
    Selector,
    Checksum,
}

/// The layout around the item at `path` in the frame `(protocol, key)`, or
/// `None` when there is no such frame or item.
pub fn frame_layout<S: AsRef<str>>(
    catalog: &Catalog,
    protocol: Protocol,
    key: &str,
    path: &[S],
) -> Option<FrameLayout> {
    let frame = catalog.frame_by_key(protocol, key)?;
    let mut ranges: Vec<LayoutRange> = frame
        .checksums
        .iter()
        .map(|c| LayoutRange {
            name: c.name.clone(),
            start_bit: resolve_byte_index(c.start_byte, frame.length as usize) as u32 * 8,
            bit_length: c.byte_length * 8,
            kind: RangeKind::Checksum,
            edited: false,
        })
        .collect();
    let (mut signals, mut mux) = (&frame.signals, frame.mux.as_ref());
    let segments: Vec<&str> = path.iter().map(AsRef::as_ref).collect();
    let mut rest = segments.as_slice();
    let edited = loop {
        let at_frame = rest.len() == segments.len();
        let first_signal = ranges.len();
        ranges.extend(signals.iter().map(signal_range));
        ranges.extend(mux.map(selector_range));
        match rest {
            [] => break None,
            ["signals", i] => break Some(first_signal + index_below(i, signals.len())?),
            ["checksum", i] if at_frame => break Some(index_below(i, frame.checksums.len())?),
            ["mux"] => {
                mux?;
                break Some(ranges.len() - 1);
            }
            ["mux", case, tail @ ..] => {
                let case = mux?.cases.get(*case)?;
                (signals, mux) = (&case.signals, case.mux.as_deref());
                rest = tail;
            }
            _ => return None,
        }
    };
    if let Some(i) = edited {
        ranges[i].edited = true;
    }
    Some(FrameLayout {
        byte_length: frame.length,
        ranges,
    })
}

fn index_below(segment: &str, len: usize) -> Option<usize> {
    segment.parse().ok().filter(|&i| i < len)
}

fn signal_range(signal: &Signal) -> LayoutRange {
    LayoutRange {
        name: signal.name.clone(),
        start_bit: signal.start_bit.unwrap_or(0),
        bit_length: signal.bit_length.unwrap_or(0),
        kind: RangeKind::Signal,
        edited: false,
    }
}

fn selector_range(mux: &Mux) -> LayoutRange {
    LayoutRange {
        name: mux.name.clone(),
        start_bit: mux.start_bit,
        bit_length: mux.bit_length,
        kind: RangeKind::Selector,
        edited: false,
    }
}
