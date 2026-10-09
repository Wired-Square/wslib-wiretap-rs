//! The typed ops' field sets, and the rules for which keys each one writes.
//!
//! An op owns the keys it models: one it leaves unset is removed, and a key it
//! does not model is never touched. Default values are not written, and legacy
//! aliases of a modelled key are folded into it.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::de::{DeserializeOwned, Deserializer, Error as _};
use serde::Deserialize;
use toml_edit::{ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use super::{
    cmp_value, int_value, json_to_value, navigate_create, norm, op_upsert_frame, table_exists,
};
use crate::model::{
    Catalog, Confidence, DisplayHint, EffectiveDefaults, Endianness, Frame, Protocol, RegisterType,
};
use crate::parse::parse_id;

/// One signal, for [`super::EditOp::UpsertSignal`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct SignalFields {
    pub name: String,
    pub start_bit: u32,
    pub bit_length: u32,
    /// Not written when 1.
    pub factor: Option<f64>,
    /// Not written when 0.
    pub offset: Option<f64>,
    pub unit: Option<String>,
    /// Not written when false.
    pub signed: Option<bool>,
    #[serde(alias = "endianness", deserialize_with = "blank_is_none")]
    pub byte_order: Option<Endianness>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub format: Option<String>,
    #[serde(deserialize_with = "blank_is_none")]
    pub confidence: Option<Confidence>,
    #[serde(rename = "enum")]
    pub enum_map: BTreeMap<String, String>,
    #[serde(deserialize_with = "one_or_many")]
    pub notes: Vec<String>,
    pub display: Option<DisplayHint>,
}

/// A frame's own keys, for [`super::EditOp::SetFrame`]. Its signals, mux and
/// checksums are other ops'. Keys of another protocol than the op's are ignored.
/// A value the frame would inherit anyway, from its `copy` or `mirror_of` source
/// or a protocol default, is not written.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct FrameFields {
    /// Bytes, but registers (or coils) for Modbus, which must cover at least one.
    pub length: Option<u32>,
    pub transmitter: Option<String>,
    #[serde(alias = "interval")]
    pub interval_ms: Option<u64>,
    #[serde(deserialize_with = "one_or_many")]
    pub notes: Vec<String>,
    pub extended: Option<bool>,
    pub fd: Option<bool>,
    pub bus: Option<u32>,
    pub copy: Option<String>,
    pub mirror_of: Option<String>,
    pub delimiter: Vec<u8>,
    /// Not written when the key already names the register.
    pub register_number: Option<u16>,
    pub node_address: Option<u8>,
    /// Not written when `holding`.
    pub register_type: Option<RegisterType>,
}

/// A mux selector, for [`super::EditOp::SetMux`]. Its cases are kept.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct MuxFields {
    /// Blank is named by [`mux_name`].
    pub name: String,
    pub start_bit: u32,
    pub bit_length: u32,
    #[serde(deserialize_with = "one_or_many")]
    pub notes: Vec<String>,
}

/// `[meta]`, for [`super::EditOp::SetMeta`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct MetaFields {
    pub name: String,
    pub version: u32,
    #[serde(default)]
    pub default_frame: Option<Protocol>,
}

/// `[meta.can]`, for [`super::EditOp::SetCanConfig`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct CanConfigFields {
    /// Not written when it is decode's default and the file states none.
    pub default_byte_order: Option<Endianness>,
    pub default_interval: Option<u64>,
    pub default_extended: Option<bool>,
    pub default_fd: Option<bool>,
    pub frame_id_mask: Option<Mask>,
    /// A blank name or mask drops the field.
    pub fields: BTreeMap<String, HeaderFieldFields>,
}

/// `[meta.serial]`, for [`super::EditOp::SetSerialConfig`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct SerialConfigFields {
    pub encoding: Option<String>,
    pub byte_order: Option<Endianness>,
    pub frame_id_mask: Option<Mask>,
    /// Not written when 0.
    pub header_length: Option<u32>,
    /// Not written when 0.
    pub min_frame_length: Option<u32>,
    pub checksum: Option<SerialChecksumFields>,
    /// A blank name or mask drops the field.
    pub fields: BTreeMap<String, HeaderFieldFields>,
}

/// A header field of [`CanConfigFields`] or [`SerialConfigFields`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct HeaderFieldFields {
    pub mask: Mask,
    /// Not written when 0.
    pub shift: Option<u32>,
    /// Not written when `hex`.
    pub format: Option<String>,
    /// Not written when big.
    #[serde(alias = "endianness")]
    pub byte_order: Option<Endianness>,
}

/// A bit mask: a number, or hex text with or without `0x`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Mask {
    Value(u32),
    Text(String),
}

impl Default for Mask {
    fn default() -> Self {
        Mask::Text(String::new())
    }
}

impl Mask {
    /// `None` when blank; an `Err` when the text is not hex.
    pub fn value(&self) -> Result<Option<u32>, String> {
        let text = match self {
            Mask::Value(n) => return Ok(Some(*n)),
            Mask::Text(text) => text.trim(),
        };
        if text.is_empty() {
            return Ok(None);
        }
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        u32::from_str_radix(digits, 16)
            .map(Some)
            .map_err(|_| format!("mask '{text}' is not hexadecimal"))
    }
}

/// `[meta.serial.checksum]`. The camelCase names are accepted as aliases.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SerialChecksumFields {
    pub algorithm: String,
    #[serde(alias = "startByte")]
    pub start_byte: i32,
    #[serde(alias = "byteLength", default = "one")]
    pub byte_length: u32,
    #[serde(alias = "calcStartByte", default)]
    pub calc_start_byte: i32,
    #[serde(alias = "calcEndByte", default)]
    pub calc_end_byte: Option<i32>,
    /// Not written when false.
    #[serde(alias = "bigEndian", default)]
    pub big_endian: bool,
}

fn one() -> u32 {
    1
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Notes {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<Notes>::deserialize(d)? {
        None => Vec::new(),
        Some(Notes::One(one)) => vec![one],
        Some(Notes::Many(many)) => many,
    })
}

fn blank_is_none<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> Result<Option<T>, D::Error> {
    match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(v) => serde_json::from_value(v)
            .map(Some)
            .map_err(D::Error::custom),
    }
}

/// `[meta.modbus]`, for [`super::EditOp::SetModbusConfig`]. Function codes are kept.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct ModbusConfigFields {
    pub device_address: Option<u8>,
    pub register_base: Option<u8>,
    pub default_interval: Option<u64>,
    pub default_byte_order: Option<Endianness>,
    pub default_word_order: Option<Endianness>,
}

pub(super) enum Field {
    Absent,
    Value(Value),
    /// The listed keys are written and any other key is kept.
    Record(Record),
    /// Keyed by data, so a key that is not listed is removed.
    Map(Vec<(String, Field)>),
}

pub(super) type Record = Vec<(&'static str, Field)>;

fn val(v: impl Into<Value>) -> Field {
    Field::Value(v.into())
}

fn opt(v: Option<impl Into<Value>>) -> Field {
    v.map_or(Field::Absent, val)
}

fn map(entries: Vec<(String, Field)>) -> Field {
    if entries.is_empty() {
        Field::Absent
    } else {
        Field::Map(entries)
    }
}

fn uint(v: Option<impl Into<u64>>) -> Field {
    opt(v.map(|n| n.into() as i64))
}

fn hex(n: u32) -> Value {
    int_value("mask", n.into())
}

fn trimmed(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn text(v: &Option<String>) -> Field {
    opt(trimmed(v))
}

/// `v`, unless it is what the frame resolves to without it.
fn own<T: PartialEq>(v: Option<T>, inherited: Option<T>) -> Option<T> {
    v.filter(|v| inherited.as_ref() != Some(v))
}

fn order(v: Option<Endianness>) -> Field {
    opt(v.map(|e| match e {
        Endianness::Big => "big",
        Endianness::Little => "little",
    }))
}

/// Trimmed, blank ones dropped; one is a string and more an array.
pub(super) fn notes<'a>(notes: impl IntoIterator<Item = &'a str>) -> Field {
    let kept: Vec<&str> = notes
        .into_iter()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    match kept[..] {
        [] => Field::Absent,
        [one] => val(one),
        _ => val(Value::Array(kept.into_iter().collect())),
    }
}

fn note_list(list: &[String]) -> Field {
    notes(list.iter().map(String::as_str))
}

fn display(hint: &DisplayHint) -> Value {
    if hint.options.is_empty() {
        return hint.widget.as_str().into();
    }
    let mut table = InlineTable::new();
    table.insert("widget", hint.widget.as_str().into());
    for (k, v) in &hint.options {
        if let Some(v) = json_to_value(k, v) {
            table.insert(k, v);
        }
    }
    Value::InlineTable(table)
}

fn mask(mask: &Option<Mask>) -> Result<Field, String> {
    let value = mask.as_ref().map(Mask::value).transpose()?.flatten();
    Ok(opt(value.map(hex)))
}

fn header_fields(fields: &BTreeMap<String, HeaderFieldFields>) -> Result<Field, String> {
    let mut entries = Vec::new();
    for (name, f) in fields {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let Some(mask) = f.mask.value()? else {
            continue;
        };
        let field = Field::Record(vec![
            ("mask", val(hex(mask))),
            ("shift", uint(f.shift.filter(|s| *s != 0))),
            ("format", opt(f.format.as_deref().filter(|f| *f != "hex"))),
            (
                "byte_order",
                order(f.byte_order.filter(|e| *e != Endianness::Big)),
            ),
            ("endianness", Field::Absent),
        ]);
        entries.push((name.to_string(), field));
    }
    Ok(map(entries))
}

impl SignalFields {
    fn record(&self) -> Record {
        let mut labels: Vec<_> = self.enum_map.iter().collect();
        labels.sort_by_key(|(k, _)| (k.parse::<i64>().ok(), k.as_str()));
        let labels = labels
            .into_iter()
            .map(|(k, v)| (k.clone(), val(v.as_str())));
        vec![
            ("name", val(self.name.as_str())),
            ("start_bit", val(i64::from(self.start_bit))),
            ("bit_length", val(i64::from(self.bit_length))),
            ("factor", opt(self.factor.filter(|f| *f != 1.0))),
            ("offset", opt(self.offset.filter(|o| *o != 0.0))),
            ("unit", text(&self.unit)),
            ("signed", opt(self.signed.filter(|s| *s))),
            ("byte_order", order(self.byte_order)),
            ("endianness", Field::Absent),
            ("min", opt(self.min)),
            ("max", opt(self.max)),
            ("format", text(&self.format)),
            ("confidence", opt(self.confidence.map(Confidence::as_str))),
            ("enum", map(labels.collect())),
            ("notes", note_list(&self.notes)),
            ("display", opt(self.display.as_ref().map(display))),
        ]
    }
}

/// What a frame resolves to with none of its own inheritable keys.
#[derive(Default)]
struct Inherited {
    length: Option<u32>,
    transmitter: Option<String>,
    interval: Option<u64>,
    extended: Option<bool>,
    fd: Option<bool>,
}

impl Inherited {
    fn of(frame: &Frame) -> Self {
        Self {
            length: match frame.protocol {
                Protocol::Can => frame
                    .inherited_fields
                    .iter()
                    .any(|f| f == "length")
                    .then_some(frame.length),
                Protocol::Modbus => frame.modbus_register_count.map(u32::from),
                Protocol::Serial => Some(frame.length),
            },
            transmitter: frame.transmitter.clone(),
            interval: frame.interval,
            extended: frame.is_extended,
            fd: frame.is_fd,
        }
    }
}

impl FrameFields {
    fn record(
        &self,
        protocol: Protocol,
        key: &str,
        inherited: &Inherited,
    ) -> Result<Record, String> {
        if protocol == Protocol::Modbus && self.length == Some(0) {
            return Err("a Modbus frame covers at least one register".to_string());
        }
        let length = self.length.filter(|n| match protocol {
            Protocol::Can => true,
            Protocol::Serial => *n > 0,
            Protocol::Modbus => *n != 1,
        });
        let transmitter = own(trimmed(&self.transmitter), inherited.transmitter.as_deref());
        let mut record = vec![
            ("length", uint(own(length, inherited.length))),
            ("transmitter", opt(transmitter)),
            (
                "interval_ms",
                uint(own(self.interval_ms, inherited.interval)),
            ),
            ("interval", Field::Absent),
            ("tx", Field::Absent),
            ("notes", note_list(&self.notes)),
        ];
        match protocol {
            Protocol::Can => record.extend([
                ("extended", opt(own(self.extended, inherited.extended))),
                ("fd", opt(own(self.fd, inherited.fd))),
                ("bus", uint(self.bus)),
                ("copy", text(&self.copy)),
                ("mirror_of", text(&self.mirror_of)),
            ]),
            Protocol::Serial => record.push((
                "delimiter",
                opt((!self.delimiter.is_empty())
                    .then(|| Value::Array(self.delimiter.iter().map(|b| i64::from(*b)).collect()))),
            )),
            Protocol::Modbus => record.extend([
                (
                    "register_number",
                    uint(
                        self.register_number
                            .filter(|n| parse_id(key) != Some(u32::from(*n))),
                    ),
                ),
                ("node_address", uint(self.node_address)),
                (
                    "register_type",
                    opt(self
                        .register_type
                        .filter(|t| *t != RegisterType::Holding)
                        .map(RegisterType::as_str)),
                ),
            ]),
        }
        Ok(record)
    }

    fn without_inheritable(&self) -> Self {
        Self {
            length: None,
            transmitter: None,
            interval_ms: None,
            extended: None,
            fd: None,
            ..self.clone()
        }
    }

    /// One signal over the registers (16 bits each) or coils (1 bit each).
    fn modbus_seed(&self, key: &str) -> SignalFields {
        let count = self.length.unwrap_or(1);
        let bank = self
            .register_type
            .unwrap_or(RegisterType::Holding)
            .is_register_bank();
        SignalFields {
            name: key.to_string(),
            bit_length: if bank { count * 16 } else { count },
            byte_order: bank.then_some(Endianness::Big),
            ..Default::default()
        }
    }
}

impl MuxFields {
    fn record(&self, name: String) -> Record {
        vec![
            ("name", val(name)),
            ("start_bit", val(i64::from(self.start_bit))),
            ("bit_length", val(i64::from(self.bit_length))),
            ("notes", note_list(&self.notes)),
        ]
    }
}

impl MetaFields {
    pub(super) fn record(&self) -> Record {
        vec![
            ("name", val(self.name.as_str())),
            ("version", val(i64::from(self.version))),
            (
                "default_frame",
                opt(self.default_frame.map(Protocol::as_str)),
            ),
        ]
    }
}

impl CanConfigFields {
    fn record(&self, file_states_byte_order: bool) -> Result<Record, String> {
        let decode_default = EffectiveDefaults::default().can_byte_order;
        let byte_order = self
            .default_byte_order
            .filter(|o| file_states_byte_order || *o != decode_default);
        Ok(vec![
            ("default_byte_order", order(byte_order)),
            ("default_endianness", Field::Absent),
            ("default_interval", uint(self.default_interval)),
            ("default_extended", opt(self.default_extended)),
            ("default_fd", opt(self.default_fd)),
            ("frame_id_mask", mask(&self.frame_id_mask)?),
            ("fields", header_fields(&self.fields)?),
        ])
    }
}

impl SerialConfigFields {
    pub(super) fn record(&self) -> Result<Record, String> {
        let checksum = self.checksum.as_ref().map_or(Field::Absent, |c| {
            Field::Record(vec![
                ("algorithm", val(c.algorithm.as_str())),
                ("start_byte", val(i64::from(c.start_byte))),
                ("byte_length", val(i64::from(c.byte_length))),
                ("calc_start_byte", val(i64::from(c.calc_start_byte))),
                ("calc_end_byte", opt(c.calc_end_byte.map(i64::from))),
                ("big_endian", opt(c.big_endian.then_some(true))),
            ])
        });
        Ok(vec![
            ("encoding", text(&self.encoding)),
            ("byte_order", order(self.byte_order)),
            ("frame_id_mask", mask(&self.frame_id_mask)?),
            ("header_length", uint(self.header_length.filter(|n| *n > 0))),
            (
                "min_frame_length",
                uint(self.min_frame_length.filter(|n| *n > 0)),
            ),
            ("fields", header_fields(&self.fields)?),
            ("checksum", checksum),
        ])
    }
}

impl ModbusConfigFields {
    pub(super) fn record(&self) -> Record {
        vec![
            ("device_address", uint(self.device_address)),
            ("register_base", uint(self.register_base)),
            ("default_interval", uint(self.default_interval)),
            ("default_byte_order", order(self.default_byte_order)),
            ("byte_order", Field::Absent),
            ("default_word_order", order(self.default_word_order)),
        ]
    }
}

fn protocol_of(key: &str) -> Option<Protocol> {
    [Protocol::Can, Protocol::Serial, Protocol::Modbus]
        .into_iter()
        .find(|p| p.as_str() == key)
}

// ── writing ───────────────────────────────────────────────────────────────────

fn write_record(tbl: &mut dyn TableLike, record: Record) {
    for (key, field) in record {
        write_field(tbl, key, field);
    }
}

pub(super) fn write_field(tbl: &mut dyn TableLike, key: &str, field: Field) {
    match field {
        Field::Absent => {
            tbl.remove(key);
        }
        Field::Value(new) => match tbl.get_mut(key) {
            Some(Item::Value(old)) if same_value(old, &new) => {}
            Some(Item::Value(old)) => {
                let decor = old.decor().clone();
                *old = new;
                *old.decor_mut() = decor;
            }
            _ => {
                tbl.insert(key, Item::Value(new));
            }
        },
        Field::Record(record) => write_record(child_table(tbl, key), record),
        Field::Map(entries) => {
            let child = child_table(tbl, key);
            let stale: Vec<String> = child
                .iter()
                .map(|(k, _)| k.to_string())
                .filter(|k| !entries.iter().any(|(e, _)| e == k))
                .collect();
            for k in stale {
                child.remove(&k);
            }
            for (k, field) in entries {
                write_field(child, &k, field);
            }
        }
    }
}

fn child_table<'a>(tbl: &'a mut dyn TableLike, key: &str) -> &'a mut dyn TableLike {
    if !tbl.get(key).is_some_and(Item::is_table_like) {
        let mut child = Table::new();
        child.set_implicit(true);
        tbl.insert(key, Item::Table(child));
    }
    tbl.get_mut(key)
        .and_then(Item::as_table_like_mut)
        .expect("just made a table")
}

/// Equal as TOML values, whatever their formatting: an unchanged value keeps
/// its representation and its comment.
fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.value() == y.value(),
        (Value::Integer(x), Value::Integer(y)) => x.value() == y.value(),
        (Value::Float(x), Value::Float(y)) => x.value() == y.value(),
        (Value::Integer(i), Value::Float(f)) | (Value::Float(f), Value::Integer(i)) => {
            *i.value() as f64 == *f.value()
        }
        (Value::Boolean(x), Value::Boolean(y)) => x.value() == y.value(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(a, b)| same_value(a, b))
        }
        (Value::InlineTable(x), Value::InlineTable(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| same_value(v, w)))
        }
        _ => false,
    }
}

// ── the ops ───────────────────────────────────────────────────────────────────

fn signal_order(a: &dyn TableLike, b: &dyn TableLike) -> Ordering {
    ["start_bit", "bit_length", "name"]
        .into_iter()
        .map(|k| {
            cmp_value(
                a.get(k).and_then(Item::as_value),
                b.get(k).and_then(Item::as_value),
            )
        })
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

pub(super) fn upsert_signal(
    doc: &mut DocumentMut,
    owner_path: &[String],
    index: Option<usize>,
    signal: &SignalFields,
) -> Result<(), String> {
    let owner = navigate_create(doc.as_table_mut(), owner_path);
    let slot = owner
        .entry("signals")
        .or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
    match slot {
        // Rebuilt from clones, as in `upsert_aot`: each keeps its comment block.
        Item::ArrayOfTables(aot) => {
            let mut tables: Vec<Table> = aot.iter().cloned().collect();
            let mut t = match index {
                Some(i) if i < tables.len() => tables.remove(i),
                _ => {
                    let mut t = Table::new();
                    t.decor_mut().set_prefix("\n");
                    t
                }
            };
            write_record(&mut t, signal.record());
            let pos = tables
                .iter()
                .position(|e| signal_order(e, &t).is_gt())
                .unwrap_or(tables.len());
            tables.insert(pos, t);
            aot.clear();
            for t in tables {
                aot.push(t);
            }
        }
        Item::Value(Value::Array(arr)) => {
            let mut t = match index {
                Some(i) if i < arr.len() => match arr.remove(i) {
                    Value::InlineTable(t) => t,
                    _ => InlineTable::new(),
                },
                _ => InlineTable::new(),
            };
            write_record(&mut t, signal.record());
            let pos = arr
                .iter()
                .position(|v| {
                    v.as_inline_table()
                        .is_some_and(|e| signal_order(e, &t).is_gt())
                })
                .unwrap_or(arr.len());
            arr.insert(pos, Value::InlineTable(t));
        }
        _ => return Err("`signals` is not an array of tables".to_string()),
    }
    Ok(())
}

fn frame_key(key: &str) -> Result<&str, String> {
    match norm(key).trim() {
        "" => Err("a frame key is required".to_string()),
        key => Ok(key),
    }
}

fn frame_path(protocol: Protocol, key: &str) -> [String; 3] {
    ["frame", protocol.as_str(), key].map(String::from)
}

pub(super) fn set_frame(
    doc: &mut DocumentMut,
    protocol: Protocol,
    key: &str,
    rename_from: Option<&str>,
    frame: &FrameFields,
) -> Result<(), String> {
    let key = frame_key(key)?;
    op_upsert_frame(
        doc,
        protocol.as_str(),
        key,
        &Default::default(),
        &[],
        rename_from,
        &[],
    )?;
    let path = frame_path(protocol, key);
    let inherited = inherited(doc, protocol, key, frame)?;
    let record = frame.record(protocol, key, &inherited)?;
    write_record(navigate_create(doc.as_table_mut(), &path), record);
    Ok(())
}

/// Worked out by parsing the document with the frame's inheritable keys removed.
fn inherited(
    doc: &DocumentMut,
    protocol: Protocol,
    key: &str,
    frame: &FrameFields,
) -> Result<Inherited, String> {
    let mut probe = doc.clone();
    let bare = frame
        .without_inheritable()
        .record(protocol, key, &Inherited::default())?;
    write_record(
        navigate_create(probe.as_table_mut(), &frame_path(protocol, key)),
        bare,
    );
    Ok(Catalog::parse(&probe.to_string())
        .ok()
        .and_then(|c| c.frame_by_key(protocol, key).map(Inherited::of))
        .unwrap_or_default())
}

pub(super) fn add_frame(
    doc: &mut DocumentMut,
    protocol: Protocol,
    key: &str,
    frame: &FrameFields,
) -> Result<(), String> {
    let key = frame_key(key)?;
    let path = frame_path(protocol, key);
    if table_exists(doc, &path) {
        return Err(format!("frame '{key}' already exists"));
    }
    set_frame(doc, protocol, key, None, frame)?;
    if protocol == Protocol::Modbus {
        upsert_signal(doc, &path, None, &frame.modbus_seed(key))?;
    }
    Ok(())
}

/// `(key, cases)` of a frame or mux case path, `["frame", protocol, key, ("mux", case)…]`.
fn mux_owner(path: &[String]) -> Result<(&str, Vec<&str>), String> {
    let bad = || format!("'{}' is not a frame or mux case", path.join("."));
    let [frame, protocol, key, cases @ ..] = path else {
        return Err(bad());
    };
    if frame != "frame" || protocol_of(protocol).is_none() || cases.len() % 2 != 0 {
        return Err(bad());
    }
    let cases = cases
        .chunks(2)
        .map(|pair| (pair[0] == "mux").then(|| norm(&pair[1])))
        .collect::<Option<_>>()
        .ok_or_else(bad)?;
    Ok((norm(key), cases))
}

/// The name a new mux at `owner_path` gets: `mux_<frame>_<case>…_<start>_<length>`,
/// the frame by its numeric id when it has one, every part reduced to `[A-Za-z0-9_]`.
pub fn mux_name(owner_path: &[String], start_bit: u32, bit_length: u32) -> Result<String, String> {
    let (key, cases) = mux_owner(owner_path)?;
    let frame = parse_id(key).map_or_else(|| sanitise(key), |id| id.to_string());
    let parts = ["mux".to_string(), frame]
        .into_iter()
        .chain(cases.into_iter().map(sanitise))
        .chain([start_bit.to_string(), bit_length.to_string()]);
    Ok(parts.collect::<Vec<_>>().join("_"))
}

fn sanitise(part: &str) -> String {
    part.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// The frame and every mux on the path must exist; a case may be new.
pub(super) fn set_mux(
    doc: &mut DocumentMut,
    owner_path: &[String],
    mux: &MuxFields,
) -> Result<(), String> {
    mux_owner(owner_path)?;
    let missing = (2..owner_path.len())
        .filter(|i| *i == 2 || owner_path[*i] == "mux")
        .find(|i| !table_exists(doc, &owner_path[..=*i]));
    if let Some(i) = missing {
        return Err(format!("'{}' does not exist", owner_path[..=i].join(".")));
    }
    let name = match mux.name.trim() {
        "" => mux_name(owner_path, mux.start_bit, mux.bit_length)?,
        name => name.to_string(),
    };
    set_table(
        doc,
        owner_path.iter().map(String::as_str).chain(["mux"]),
        mux.record(name),
    );
    Ok(())
}

pub(super) fn set_can_config(
    doc: &mut DocumentMut,
    config: &CanConfigFields,
) -> Result<(), String> {
    let stated = doc.get("meta").and_then(|m| m.get("can")).is_some_and(|c| {
        c.get("default_byte_order")
            .or(c.get("default_endianness"))
            .is_some()
    });
    set_table(doc, ["meta", "can"], config.record(stated)?);
    Ok(())
}

pub(super) fn set_table<'a>(
    doc: &mut DocumentMut,
    path: impl IntoIterator<Item = &'a str>,
    record: Record,
) {
    let path: Vec<String> = path.into_iter().map(String::from).collect();
    write_record(navigate_create(doc.as_table_mut(), &path), record);
}

#[cfg(test)]
mod tests;
