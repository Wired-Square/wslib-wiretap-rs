//! The typed ops' field sets, and the rules for which keys each one writes.
//!
//! An op owns the keys it models: one it leaves unset is removed, and a key it
//! does not model is never touched. Default values are not written, and legacy
//! aliases of a modelled key are folded into it.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::Deserialize;
use toml_edit::{ArrayOfTables, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use super::{cmp_value, int_value, json_to_value, navigate_create, op_upsert_frame};
use crate::model::{
    ChecksumConfig, Confidence, DisplayHint, Endianness, HeaderField, Protocol, RegisterType,
};

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
    pub signed: Option<bool>,
    #[serde(alias = "endianness")]
    pub byte_order: Option<Endianness>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub format: Option<String>,
    pub confidence: Option<Confidence>,
    #[serde(rename = "enum")]
    pub enum_map: BTreeMap<String, String>,
    pub notes: Vec<String>,
    pub display: Option<DisplayHint>,
}

/// A frame's own keys, for [`super::EditOp::SetFrame`]. Its signals, mux and
/// checksums are other ops'. Keys of another protocol than the op's are ignored.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct FrameFields {
    /// Not written for a serial frame when 0, or for a Modbus frame when 1.
    pub length: Option<u32>,
    pub transmitter: Option<String>,
    pub interval_ms: Option<u64>,
    pub notes: Vec<String>,
    pub extended: Option<bool>,
    pub fd: Option<bool>,
    pub bus: Option<u32>,
    pub copy: Option<String>,
    pub mirror_of: Option<String>,
    pub delimiter: Vec<u8>,
    pub register_number: Option<u16>,
    pub node_address: Option<u8>,
    /// Not written when `holding`.
    pub register_type: Option<RegisterType>,
}

/// A mux selector, for [`super::EditOp::SetMux`]. Its cases are kept.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct MuxFields {
    pub name: String,
    pub start_bit: u32,
    pub bit_length: u32,
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
    pub default_byte_order: Option<Endianness>,
    pub default_interval: Option<u64>,
    pub default_extended: Option<bool>,
    pub default_fd: Option<bool>,
    pub frame_id_mask: Option<u32>,
    pub fields: BTreeMap<String, HeaderField>,
}

/// `[meta.serial]`, for [`super::EditOp::SetSerialConfig`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct SerialConfigFields {
    pub encoding: Option<String>,
    pub byte_order: Option<Endianness>,
    pub frame_id_mask: Option<u32>,
    /// Not written when 0.
    pub header_length: Option<u32>,
    /// Not written when 0.
    pub min_frame_length: Option<u32>,
    pub checksum: Option<ChecksumConfig>,
    pub fields: BTreeMap<String, HeaderField>,
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

fn text(v: &Option<String>) -> Field {
    opt(v.as_deref().filter(|s| !s.is_empty()))
}

fn order(v: Option<Endianness>) -> Field {
    opt(v.map(|e| match e {
        Endianness::Big => "big",
        Endianness::Little => "little",
    }))
}

fn notes(notes: &[String]) -> Field {
    match notes {
        [] => Field::Absent,
        [one] => val(one.as_str()),
        many => val(Value::Array(many.iter().map(String::as_str).collect())),
    }
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

fn header_fields(fields: &BTreeMap<String, HeaderField>) -> Field {
    map(fields
        .iter()
        .map(|(name, f)| {
            let field = Field::Record(vec![
                ("mask", val(hex(f.mask))),
                ("shift", uint(f.shift.filter(|s| *s != 0))),
                ("format", opt(f.format.as_deref().filter(|f| *f != "hex"))),
                (
                    "byte_order",
                    order(f.endianness.filter(|e| *e != Endianness::Big)),
                ),
                ("endianness", Field::Absent),
            ]);
            (name.clone(), field)
        })
        .collect())
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
            ("signed", opt(self.signed)),
            ("byte_order", order(self.byte_order)),
            ("endianness", Field::Absent),
            ("min", opt(self.min)),
            ("max", opt(self.max)),
            ("format", text(&self.format)),
            ("confidence", opt(self.confidence.map(Confidence::as_str))),
            ("enum", map(labels.collect())),
            ("notes", notes(&self.notes)),
            ("display", opt(self.display.as_ref().map(display))),
        ]
    }
}

impl FrameFields {
    fn record(&self, protocol: Protocol) -> Record {
        let length = self.length.filter(|n| match protocol {
            Protocol::Can => true,
            Protocol::Serial => *n > 0,
            Protocol::Modbus => *n != 1,
        });
        let mut record = vec![
            ("length", uint(length)),
            ("transmitter", text(&self.transmitter)),
            ("interval_ms", uint(self.interval_ms)),
            ("interval", Field::Absent),
            ("tx", Field::Absent),
            ("notes", notes(&self.notes)),
        ];
        match protocol {
            Protocol::Can => record.extend([
                ("extended", opt(self.extended)),
                ("fd", opt(self.fd)),
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
                ("register_number", uint(self.register_number)),
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
        record
    }
}

impl MuxFields {
    pub(super) fn record(&self) -> Record {
        vec![
            ("name", val(self.name.as_str())),
            ("start_bit", val(i64::from(self.start_bit))),
            ("bit_length", val(i64::from(self.bit_length))),
            ("notes", notes(&self.notes)),
        ]
    }
}

impl MetaFields {
    pub(super) fn record(&self) -> Record {
        vec![
            ("name", val(self.name.as_str())),
            ("version", val(i64::from(self.version))),
            ("default_frame", opt(self.default_frame.map(protocol_key))),
        ]
    }
}

impl CanConfigFields {
    pub(super) fn record(&self) -> Record {
        vec![
            ("default_byte_order", order(self.default_byte_order)),
            ("default_endianness", Field::Absent),
            ("default_interval", uint(self.default_interval)),
            ("default_extended", opt(self.default_extended)),
            ("default_fd", opt(self.default_fd)),
            ("frame_id_mask", opt(self.frame_id_mask.map(hex))),
            ("fields", header_fields(&self.fields)),
        ]
    }
}

impl SerialConfigFields {
    pub(super) fn record(&self) -> Record {
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
        vec![
            ("encoding", text(&self.encoding)),
            ("byte_order", order(self.byte_order)),
            ("frame_id_mask", opt(self.frame_id_mask.map(hex))),
            ("header_length", uint(self.header_length.filter(|n| *n > 0))),
            (
                "min_frame_length",
                uint(self.min_frame_length.filter(|n| *n > 0)),
            ),
            ("fields", header_fields(&self.fields)),
            ("checksum", checksum),
        ]
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

fn protocol_key(p: Protocol) -> &'static str {
    match p {
        Protocol::Can => "can",
        Protocol::Serial => "serial",
        Protocol::Modbus => "modbus",
    }
}

// ── writing ───────────────────────────────────────────────────────────────────

fn write_record(tbl: &mut dyn TableLike, record: Record) {
    for (key, field) in record {
        write_field(tbl, key, field);
    }
}

fn write_field(tbl: &mut dyn TableLike, key: &str, field: Field) {
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

pub(super) fn set_frame(
    doc: &mut DocumentMut,
    protocol: Protocol,
    key: &str,
    rename_from: Option<&str>,
    frame: &FrameFields,
) -> Result<(), String> {
    let proto = protocol_key(protocol);
    op_upsert_frame(doc, proto, key, &Default::default(), &[], rename_from, &[])?;
    let path = ["frame", proto, super::norm(key)].map(String::from);
    write_record(
        navigate_create(doc.as_table_mut(), &path),
        frame.record(protocol),
    );
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
