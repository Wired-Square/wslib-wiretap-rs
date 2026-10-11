//! A serial byte stream cut into frames: SLIP and delimiter from
//! [`wiretap_protocol`], Modbus RTU from [`ModbusRtuStream`], behind one enum.

use std::fmt;

use serde::{Deserialize, Serialize};
use wiretap_decode::frame_id::{extract_frame_id, FrameIdField, FrameIdWidth};
use wiretap_decode::Endianness;
pub use wiretap_protocol::framing::DelimiterOptions;
use wiretap_protocol::framing::{DelimiterFramer, Framed};
use wiretap_protocol::slip::SlipDecoder;

use crate::modbus_rtu_stream::{ModbusRtuMessage, ModbusRtuOptions, ModbusRtuStream, RtuSettings};
use crate::Catalog;

/// How a serial byte stream is cut into frames, in every path that frames one:
/// the port, a live framing change and re-framing a capture. `Raw` is no
/// framing, the bytes as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum FramingMode {
    #[default]
    Raw,
    Slip,
    Delimiter,
    ModbusRtu,
}

/// The serde spelling: `raw`, `slip`, `delimiter` or `modbus_rtu`.
impl fmt::Display for FramingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FramingMode::Raw => "raw",
            FramingMode::Slip => "slip",
            FramingMode::Delimiter => "delimiter",
            FramingMode::ModbusRtu => "modbus_rtu",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FramingEncoding {
    Delimiter(DelimiterOptions),
    /// SLIP (RFC 1055); a frame outgrowing `max_frame_len` is abandoned.
    Slip {
        max_frame_len: usize,
    },
    ModbusRtu(RtuSettings),
    /// No framing: the bytes as read.
    Raw,
}

impl Default for FramingEncoding {
    fn default() -> Self {
        FramingEncoding::Slip {
            max_frame_len: 1024,
        }
    }
}

/// A framing that would release every byte as its own frame, by the field that
/// makes it so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Serial framing: '{field}' would release every byte as its own frame")]
pub struct DegenerateFraming {
    pub field: &'static str,
}

impl FramingEncoding {
    /// `mode` with default options, for a live framing change that carries no
    /// profile context.
    pub fn from_mode(mode: FramingMode, modbus: Option<&RtuSettings>) -> Self {
        match mode {
            FramingMode::Slip => FramingEncoding::default(),
            FramingMode::ModbusRtu => {
                FramingEncoding::ModbusRtu(modbus.cloned().unwrap_or_default())
            }
            FramingMode::Delimiter => FramingEncoding::Delimiter(DelimiterOptions {
                delimiter: vec![0x0A],
                max_length: 1024,
                include_delimiter: false,
            }),
            FramingMode::Raw => FramingEncoding::Raw,
        }
    }

    pub fn checked(self) -> Result<Self, DegenerateFraming> {
        let field = match &self {
            Self::Delimiter(o) => {
                degenerate_framing_field(Some(&o.delimiter), Some(o.max_length as i64))
            }
            Self::Slip { max_frame_len } => {
                degenerate_framing_field(None, Some(*max_frame_len as i64))
            }
            Self::ModbusRtu(_) | Self::Raw => None,
        };
        field.map_or(Ok(self), |field| Err(DegenerateFraming { field }))
    }
}

/// The serial framing field, if any, whose value would release every byte as
/// its own frame.
pub fn degenerate_framing_field(
    delimiter: Option<&[u8]>,
    max_frame_length: Option<i64>,
) -> Option<&'static str> {
    if delimiter.is_some_and(<[u8]>::is_empty) {
        Some("delimiter")
    } else if max_frame_length.is_some_and(|n| n <= 0) {
        Some("max_frame_length")
    } else {
        None
    }
}

/// A complete frame extracted from the serial stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialFrame {
    pub bytes: Vec<u8>,
    /// These bytes are a leftover rather than a message: the stream ended
    /// before a delimiter.
    pub incomplete: bool,
    /// For Modbus RTU, whether the message's CRC matched. `None` where the
    /// question does not apply: another encoding, or a residue that is not a
    /// message at all.
    pub crc_valid: Option<bool>,
    /// Bytes fed through this frame's last byte. A Modbus RTU message buffered
    /// before the framer synced is released by a later byte.
    pub end_offset: u64,
}

impl SerialFrame {
    /// The trailing bytes at end of stream, when there are any: not a message,
    /// and marked as such.
    pub fn residue(bytes: Vec<u8>, end_offset: u64) -> Option<Self> {
        (!bytes.is_empty()).then_some(Self {
            bytes,
            incomplete: true,
            crc_valid: None,
            end_offset,
        })
    }

    fn complete(framed: Framed) -> Self {
        Self {
            bytes: framed.bytes,
            incomplete: false,
            crc_valid: None,
            end_offset: framed.end_offset,
        }
    }
}

/// The CRC verdict rides along: under a lenient policy it is the only thing
/// telling a recovered message from a guessed one.
impl From<ModbusRtuMessage> for SerialFrame {
    fn from(msg: ModbusRtuMessage) -> Self {
        Self {
            bytes: msg.raw,
            incomplete: false,
            crc_valid: Some(msg.crc_valid),
            end_offset: msg.end_offset,
        }
    }
}

/// Configuration for extracting frame ID from frame bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct FrameIdConfig {
    /// Start byte index (negative = from end)
    pub start_byte: i32,
    /// Number of bytes for frame ID (1 or 2)
    pub num_bytes: u8,
    /// Whether to interpret as big-endian
    pub big_endian: bool,
}

impl Default for FrameIdConfig {
    fn default() -> Self {
        FrameIdConfig {
            start_byte: 0,
            num_bytes: 1,
            big_endian: false,
        }
    }
}

impl FrameIdConfig {
    /// `None` for a width other than 1 or 2, which extracts nothing.
    pub fn field(&self) -> Option<FrameIdField> {
        let width = match self.num_bytes {
            1 => FrameIdWidth::One,
            2 => FrameIdWidth::Two(if self.big_endian {
                Endianness::Big
            } else {
                Endianness::Little
            }),
            _ => return None,
        };
        Some(FrameIdField {
            start_byte: self.start_byte,
            width,
        })
    }

    pub fn extract(&self, frame: &[u8]) -> Option<u32> {
        extract_frame_id(frame, &self.field()?)
    }
}

/// A stateful serial framer. Modbus RTU goes through [`ModbusRtuStream`], the
/// reassembler the CAN tunnel path uses.
#[derive(Debug)]
pub enum SerialFramer {
    Delimiter(DelimiterFramer),
    Slip(SlipDecoder),
    Rtu(ModbusRtuStream),
}

impl SerialFramer {
    /// `None` for [`FramingEncoding::Raw`], which is unframed.
    pub fn new(encoding: FramingEncoding) -> Option<Self> {
        Self::with_catalog(encoding, None)
    }

    /// Modbus RTU framing takes `catalog`'s declared function codes too.
    pub fn with_catalog(encoding: FramingEncoding, catalog: Option<&Catalog>) -> Option<Self> {
        Some(match encoding {
            FramingEncoding::Delimiter(options) => Self::Delimiter(DelimiterFramer::new(options)),
            FramingEncoding::Slip { max_frame_len } => {
                Self::Slip(SlipDecoder::with_max_frame_len(max_frame_len))
            }
            FramingEncoding::ModbusRtu(settings) => {
                Self::Rtu(ModbusRtuOptions::from_settings(&settings, catalog).stream())
            }
            FramingEncoding::Raw => return None,
        })
    }

    pub fn feed(&mut self, data: &[u8]) -> Vec<SerialFrame> {
        match self {
            Self::Delimiter(framer) => framer
                .feed(data)
                .into_iter()
                .map(SerialFrame::complete)
                .collect(),
            Self::Slip(decoder) => decoder
                .feed(data)
                .into_iter()
                .map(SerialFrame::complete)
                .collect(),
            Self::Rtu(stream) => stream
                .push_bytes(data)
                .into_iter()
                .map(SerialFrame::from)
                .collect(),
        }
    }

    pub fn bytes_fed(&self) -> u64 {
        match self {
            Self::Delimiter(framer) => framer.bytes_fed(),
            Self::Slip(decoder) => decoder.bytes_fed(),
            Self::Rtu(stream) => stream.bytes_fed(),
        }
    }

    /// SLIP frames that outgrew the frame cap without an END; zero for the
    /// other encodings.
    pub fn abandoned_frames(&self) -> u64 {
        match self {
            Self::Slip(decoder) => decoder.abandoned_frames(),
            Self::Delimiter(_) | Self::Rtu(_) => 0,
        }
    }

    /// Flush at end of stream. Modbus RTU can still recover whole messages from
    /// what it holds, so those come first and the residue last; the other
    /// encodings only ever have a residue.
    pub fn flush(&mut self) -> Vec<SerialFrame> {
        let framed = match self {
            Self::Delimiter(framer) => framer.flush(),
            Self::Slip(decoder) => decoder.flush(),
            Self::Rtu(stream) => {
                let (messages, trailing) = stream.finish();
                let end_offset = stream.bytes_fed();
                return messages
                    .into_iter()
                    .map(SerialFrame::from)
                    .chain(SerialFrame::residue(trailing, end_offset))
                    .collect();
            }
        };
        framed
            .and_then(|f| SerialFrame::residue(f.bytes, f.end_offset))
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flushed_residue_is_incomplete() {
        let mut framer = SerialFramer::new(FramingEncoding::default()).unwrap();
        assert!(framer.feed(&[0x01, 0x02, 0x03]).is_empty());

        let flushed = framer.flush();
        assert_eq!(flushed.len(), 1);
        assert!(flushed[0].incomplete);
        assert_eq!(flushed[0].bytes, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn a_slip_line_without_end_stops_growing_at_the_frame_cap() {
        let mut framer =
            SerialFramer::new(FramingEncoding::from_mode(FramingMode::Slip, None)).unwrap();
        framer.feed(&[0x55; 4096]);
        let released = framer.feed(&[wiretap_protocol::slip::END]);
        let longest = released.iter().map(|f| f.bytes.len()).max();
        assert!(
            longest.is_none_or(|len| len <= 1024),
            "released a {longest:?}-byte frame"
        );
        assert!(framer.abandoned_frames() > 0);
    }

    #[test]
    fn raw_is_unframed() {
        assert!(SerialFramer::new(FramingEncoding::from_mode(FramingMode::Raw, None)).is_none());
    }

    #[test]
    fn a_framing_that_releases_every_byte_is_refused_by_field() {
        let delimiter = |delimiter: Vec<u8>, max_length| {
            FramingEncoding::Delimiter(DelimiterOptions {
                delimiter,
                max_length,
                include_delimiter: false,
            })
            .checked()
        };
        assert_eq!(
            delimiter(vec![], 1024),
            Err(DegenerateFraming { field: "delimiter" })
        );
        assert_eq!(
            delimiter(vec![0x0A], 0),
            Err(DegenerateFraming {
                field: "max_frame_length"
            })
        );
        assert!(delimiter(vec![0x0A], 1).is_ok());
        assert_eq!(
            FramingEncoding::Slip { max_frame_len: 0 }
                .checked()
                .unwrap_err()
                .to_string(),
            "Serial framing: 'max_frame_length' would release every byte as its own frame"
        );
    }

    #[test]
    fn a_framing_mode_displays_as_it_serialises() {
        for mode in [
            FramingMode::Raw,
            FramingMode::Slip,
            FramingMode::Delimiter,
            FramingMode::ModbusRtu,
        ] {
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::json!(mode.to_string())
            );
        }
    }
}
