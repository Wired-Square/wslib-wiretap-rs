//! Comment- and formatting-preserving in-place edits over catalogue TOML.
//!
//! The catalogue editor mutates documents by issuing [`EditOp`]s rather than
//! re-serialising a parsed model — that would discard every comment and all
//! hand-authored formatting. Each op is applied to a [`toml_edit::DocumentMut`]
//! so untouched frames, signals, and their `#` comments survive byte-for-byte;
//! only the targeted entry changes. This generalises the `toml_edit` pattern
//! first used by [`crate::modbus::set_frame_disabled`].
//!
//! The ops are deliberately *document primitives* (set a table, upsert an
//! array-of-tables entry in sorted position, rename a key, …) rather than one
//! variant per editor action. The editor's TypeScript wrappers decide *which*
//! fields a given action writes (the protocol "tidiness" rules); this module
//! owns the parts that genuinely need the TOML AST: sorted insertion without
//! disturbing siblings, hex-literal rendering of masks, key/decor preservation,
//! and rename-with-reference-rewrite.
//!
//! The typed ops ([`EditOp::UpsertSignal`], [`EditOp::SetFrame`], …) carry those
//! rules here instead, for a caller that builds a catalogue rather than edits one.

use std::cmp::Ordering;

use serde::Deserialize;
use serde_json::{Map, Value as Json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::model::Protocol;

mod typed;
pub use typed::{
    CanConfigFields, FrameFields, MetaFields, ModbusConfigFields, MuxFields, SerialConfigFields,
    SignalFields,
};

type JsonMap = Map<String, Json>;

/// One comment-preserving edit. Deserialised straight from the WS `catalog.edit`
/// params (internally tagged on `op`); the extra `content` param is ignored.
#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
pub enum EditOp {
    /// Create-or-update the table at `path`, setting every key in `value`.
    /// `managed_keys` present in the table but absent from `value` are removed
    /// (so toggling a field to inherited drops it); other keys and sub-tables
    /// are left untouched. `replace_contents` first clears all existing keys
    /// (used for protocol configs, which are regenerated wholesale). Integer
    /// values under a key named `mask`/`frame_id_mask` render as hex literals.
    SetTable {
        path: Vec<String>,
        value: JsonMap,
        #[serde(default)]
        managed_keys: Vec<String>,
        #[serde(default)]
        replace_contents: bool,
        #[serde(default)]
        sort_parent_numeric: bool,
        #[serde(default)]
        skip_if_exists: bool,
        #[serde(default)]
        error_if_exists: bool,
    },
    /// Upsert a `[frame.<protocol>.<key>]` table, preserving its existing
    /// `signals`/`mux`/`checksum` sub-tables. `rename_from` moves an existing
    /// frame (carrying its sub-tables) before applying `value`. `initial_signals`
    /// are pushed only when the frame is newly created. CAN frame keys are kept
    /// numerically sorted.
    UpsertFrame {
        protocol: String,
        key: String,
        value: JsonMap,
        #[serde(default)]
        managed_keys: Vec<String>,
        #[serde(default)]
        rename_from: Option<String>,
        #[serde(default)]
        initial_signals: Vec<JsonMap>,
    },
    /// Insert (or replace at `index`) a table in the array-of-tables at
    /// `array_path`, keeping it ordered by `sort_keys`. Insertion places the new
    /// entry in sorted position so existing entries — and their comments — do
    /// not move. Works on inline `signals = [{…}]` arrays too.
    UpsertArrayItem {
        array_path: Vec<String>,
        value: JsonMap,
        #[serde(default)]
        index: Option<usize>,
        #[serde(default)]
        sort_keys: Vec<String>,
    },
    /// Remove the array entry at `index`; optionally drop the whole array when
    /// it becomes empty.
    RemoveArrayItem {
        array_path: Vec<String>,
        index: usize,
        #[serde(default)]
        remove_if_empty: bool,
    },
    /// Rename `old`→`new` within the table at `parent_path` (carrying the child's
    /// body and comments), optionally applying `set_value` to the renamed child,
    /// re-sorting the parent numerically, and rewriting CAN `transmitter`
    /// references. `error_if_exists` rejects a collision with an existing `new`.
    RenameKey {
        parent_path: Vec<String>,
        old: String,
        new: String,
        #[serde(default)]
        set_value: Option<JsonMap>,
        #[serde(default)]
        managed_keys: Vec<String>,
        #[serde(default)]
        sort_numeric: bool,
        #[serde(default)]
        update_transmitter_refs: bool,
        #[serde(default)]
        error_if_exists: bool,
    },
    /// Remove the key at `path` (no-op if absent).
    DeleteAtPath {
        path: Vec<String>,
        #[serde(default)]
        sort_parent_numeric: bool,
    },
    /// Insert (or update at `index`) a signal in the `signals` of the frame or
    /// mux case at `owner_path`, in `start_bit` order.
    UpsertSignal {
        owner_path: Vec<String>,
        #[serde(default)]
        index: Option<usize>,
        signal: SignalFields,
    },
    /// The typed [`EditOp::UpsertFrame`]: create or update a frame's own keys.
    SetFrame {
        protocol: Protocol,
        key: String,
        #[serde(default)]
        rename_from: Option<String>,
        frame: FrameFields,
    },
    /// Create or update the `mux` of the frame or mux case at `owner_path`.
    SetMux {
        owner_path: Vec<String>,
        mux: MuxFields,
    },
    SetMeta {
        meta: MetaFields,
    },
    SetCanConfig {
        config: CanConfigFields,
    },
    SetSerialConfig {
        config: SerialConfigFields,
    },
    SetModbusConfig {
        config: ModbusConfigFields,
    },
}

/// The outcome of [`bump_meta_version`]: the new text, and the pair of numbers so a
/// caller can say "3 → 4" without parsing either side again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionBump {
    pub text: String,
    pub from: u32,
    pub to: u32,
}

/// Increment `[meta].version`, changing nothing else in the file.
///
/// **Deliberately not an [`EditOp`].** Every op goes through [`DocumentMut`], and a
/// `DocumentMut` round-trip is not byte-preserving in three ways that matter here:
///
/// * `Table::insert` re-formats the key it replaces, and the parser folds the comment
///   lines *above* a key into that key's own decor — so a comment block above
///   `version` is deleted;
/// * a trailing `# note` on the version line lives in the value's suffix decor and is
///   replaced along with the value;
/// * the encoder re-emits every key-value with `writeln!`, so a CRLF document comes
///   back LF throughout.
///
/// The publish path hashes *exact bytes* to decide what is in sync, so any of the
/// three would turn a one-line bump into a whole-file diff. Splicing over the
/// integer's own span leaves the rest of the document untouched by construction
/// rather than by inspection — which is what the tests assert.
///
/// `Err` when there is no `[meta]`, when `version` is not an integer, or on overflow.
/// Callers treat that as "no bump": this is a convenience, and it must never fail the
/// operation it is decorating.
pub fn bump_meta_version(text: &str) -> Result<VersionBump, String> {
    // `ImDocument` keeps spans; `DocumentMut` discards them (it calls `despan`), and
    // the span is the whole point.
    let doc = toml_edit::ImDocument::parse(text)
        .map_err(|e| format!("catalogue is not valid TOML: {e}"))?;
    let meta = doc
        .as_table()
        .get("meta")
        .and_then(Item::as_table)
        .ok_or_else(|| "catalogue has no [meta] section".to_string())?;

    let Some(item) = meta.get("version") else {
        // Absent and `= 1` are the same claim — `Meta::version` defaults to 1 — so the
        // honest increment is 2. Refusing would silently do nothing for a valid file
        // whose author never wrote the key, having just been asked to bump it.
        return insert_meta_version(text, meta, 2);
    };
    let value = item
        .as_value()
        .and_then(Value::as_integer)
        .ok_or_else(|| "[meta].version is not an integer".to_string())?;
    let from = u32::try_from(value).map_err(|_| "[meta].version is out of range".to_string())?;
    let to = from
        .checked_add(1)
        .ok_or_else(|| "[meta].version is at its maximum".to_string())?;
    let span = item
        .span()
        .ok_or_else(|| "[meta].version has no source span".to_string())?;

    Ok(VersionBump {
        text: format!("{}{to}{}", &text[..span.start], &text[span.end..]),
        from,
        to,
    })
}

/// Write a `version` key into an existing `[meta]` that lacks one, on its own line
/// after `name` (or at the top of the table when there is no `name` either).
///
/// Splices at a line boundary for the same reason [`bump_meta_version`] splices at a
/// value span: anything that rebuilds the table rewrites the whole document.
fn insert_meta_version(text: &str, meta: &Table, to: u32) -> Result<VersionBump, String> {
    // After `name` keeps the two identity keys together, which is how every catalogue
    // in the wild is laid out; the table header is the fallback.
    let anchor = meta
        .get("name")
        .and_then(Item::span)
        .or_else(|| meta.span())
        .ok_or_else(|| "[meta] has no source span".to_string())?;
    let line_end = text[anchor.end..]
        .find('\n')
        .map(|i| anchor.end + i)
        .unwrap_or(text.len());
    // Match the document's own line ending, so a CRLF file stays CRLF here too.
    let newline = if text[..line_end].ends_with('\r') {
        "\r\n"
    } else {
        "\n"
    };
    let insert_at = if newline == "\r\n" {
        line_end - 1
    } else {
        line_end
    };
    Ok(VersionBump {
        text: format!(
            "{}{newline}version = {to}{}",
            &text[..insert_at],
            &text[insert_at..]
        ),
        from: 1,
        to,
    })
}

/// Apply one edit to the raw catalogue TOML, preserving comments and formatting.
/// `Err` carries a UI-friendly message (invalid TOML, missing target, rename
/// collision); the caller shows it and leaves the document untouched.
pub fn apply_edit(text: &str, op: EditOp) -> Result<String, String> {
    apply_edits(text, std::slice::from_ref(&op))
}

/// Apply `ops` in order, parsing and printing once. All or nothing: the first
/// failing op's `Err` is returned. A new catalogue is `apply_edits("", ops)`.
/// The output keeps the line ending of the input's first line.
pub fn apply_edits(text: &str, ops: &[EditOp]) -> Result<String, String> {
    let mut doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("catalogue is not valid TOML: {e}"))?;
    for op in ops {
        apply_op(&mut doc, op)?;
    }
    let out = doc.to_string();
    Ok(if first_line_ends_crlf(text) {
        out.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        out
    })
}

/// The encoder writes `\n` everywhere but keeps an untouched multi-line string's raw
/// line endings, hence the normalise-then-expand above.
fn first_line_ends_crlf(text: &str) -> bool {
    text.find('\n').is_some_and(|i| text[..i].ends_with('\r'))
}

fn apply_op(doc: &mut DocumentMut, op: &EditOp) -> Result<(), String> {
    match op {
        EditOp::SetTable {
            path,
            value,
            managed_keys,
            replace_contents,
            sort_parent_numeric,
            skip_if_exists,
            error_if_exists,
        } => {
            let exists = table_exists(doc, path);
            if exists && *skip_if_exists {
                return Ok(());
            }
            if exists && *error_if_exists {
                return Err(format!(
                    "'{}' already exists",
                    path.last().map_or("", |s| s)
                ));
            }
            let tbl = navigate_create(doc.as_table_mut(), path);
            if *replace_contents {
                for k in keys_of(tbl) {
                    tbl.remove(&k);
                }
            }
            apply_object(tbl, value, managed_keys);
            if *sort_parent_numeric && !path.is_empty() {
                sort_table_numeric(doc, &path[..path.len() - 1]);
            }
        }
        EditOp::UpsertFrame {
            protocol,
            key,
            value,
            managed_keys,
            rename_from,
            initial_signals,
        } => op_upsert_frame(
            doc,
            protocol,
            key,
            value,
            managed_keys,
            rename_from.as_deref(),
            initial_signals,
        )?,
        EditOp::UpsertArrayItem {
            array_path,
            value,
            index,
            sort_keys,
        } => op_upsert_array_item(doc, array_path, value, *index, sort_keys)?,
        EditOp::RemoveArrayItem {
            array_path,
            index,
            remove_if_empty,
        } => op_remove_array_item(doc, array_path, *index, *remove_if_empty),
        EditOp::RenameKey {
            parent_path,
            old,
            new,
            set_value,
            managed_keys,
            sort_numeric,
            update_transmitter_refs,
            error_if_exists,
        } => op_rename_key(
            doc,
            parent_path,
            old,
            new,
            set_value.as_ref(),
            managed_keys,
            *sort_numeric,
            *update_transmitter_refs,
            *error_if_exists,
        )?,
        EditOp::DeleteAtPath {
            path,
            sort_parent_numeric,
        } => {
            if let Some((last, parent)) = path.split_last() {
                if let Some(tbl) = navigate_existing_mut(doc, parent) {
                    tbl.remove(norm(last));
                }
                if *sort_parent_numeric {
                    sort_table_numeric(doc, parent);
                }
            }
        }
        EditOp::UpsertSignal {
            owner_path,
            index,
            signal,
        } => typed::upsert_signal(doc, owner_path, *index, signal)?,
        EditOp::SetFrame {
            protocol,
            key,
            rename_from,
            frame,
        } => typed::set_frame(doc, *protocol, key, rename_from.as_deref(), frame)?,
        EditOp::SetMux { owner_path, mux } => typed::set_table(
            doc,
            owner_path.iter().map(String::as_str).chain(["mux"]),
            mux.record(),
        ),
        EditOp::SetMeta { meta } => typed::set_table(doc, ["meta"], meta.record()),
        EditOp::SetCanConfig { config } => typed::set_table(doc, ["meta", "can"], config.record()),
        EditOp::SetSerialConfig { config } => {
            typed::set_table(doc, ["meta", "serial"], config.record())
        }
        EditOp::SetModbusConfig { config } => {
            typed::set_table(doc, ["meta", "modbus"], config.record())
        }
    }
    Ok(())
}

// ── frames ──────────────────────────────────────────────────────────────────

fn op_upsert_frame(
    doc: &mut DocumentMut,
    protocol: &str,
    key: &str,
    value: &JsonMap,
    managed_keys: &[String],
    rename_from: Option<&str>,
    initial_signals: &[JsonMap],
) -> Result<(), String> {
    let proto = norm(protocol).to_string();
    let newk = norm(key).to_string();
    let section_path = [String::from("frame"), proto.clone()];

    if let Some(old) = rename_from {
        let oldk = norm(old);
        if oldk != newk {
            let section = navigate_create(doc.as_table_mut(), &section_path);
            if let Some(item) = section.remove(oldk) {
                section.insert(&newk, item);
            }
        }
    }

    let frame_path = [section_path[0].clone(), proto.clone(), newk.clone()];
    let was_new = !table_exists(doc, &frame_path);
    let ftbl = navigate_create(doc.as_table_mut(), &frame_path);
    apply_object(ftbl, value, managed_keys);

    if was_new && !initial_signals.is_empty() && !ftbl.contains_key("signals") {
        let mut aot = ArrayOfTables::new();
        for sig in initial_signals {
            let mut t = Table::new();
            apply_object(&mut t, sig, &[]);
            aot.push(t);
        }
        ftbl.insert("signals", Item::ArrayOfTables(aot));
    }

    if proto == "can" {
        sort_table_numeric(doc, &section_path);
    }
    Ok(())
}

// ── arrays of tables (signals, checksums) ─────────────────────────────────────

fn op_upsert_array_item(
    doc: &mut DocumentMut,
    array_path: &[String],
    value: &JsonMap,
    index: Option<usize>,
    sort_keys: &[String],
) -> Result<(), String> {
    let (arr_key_raw, owner_path) = array_path
        .split_last()
        .ok_or_else(|| "empty array_path".to_string())?;
    let arr_key = norm(arr_key_raw).to_string();
    let owner = navigate_create(doc.as_table_mut(), owner_path);
    if !owner.contains_key(&arr_key) {
        owner.insert(&arr_key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    match owner.get_mut(&arr_key) {
        Some(Item::ArrayOfTables(aot)) => upsert_aot(aot, value, index, sort_keys),
        Some(Item::Value(Value::Array(arr))) => upsert_inline(arr, value, index, sort_keys),
        Some(slot) => {
            // Present but not an array (e.g. an empty placeholder) — replace it.
            let mut aot = ArrayOfTables::new();
            let mut t = Table::new();
            apply_object(&mut t, value, &[]);
            aot.push(t);
            *slot = Item::ArrayOfTables(aot);
        }
        None => unreachable!("just inserted"),
    }
    Ok(())
}

fn upsert_aot(
    aot: &mut ArrayOfTables,
    value: &JsonMap,
    index: Option<usize>,
    sort_keys: &[String],
) {
    // Rebuild from clones: toml_edit has no positional insert for an
    // array-of-tables, but each cloned `Table` carries its decor (the leading
    // `#` comment block), so re-pushing in the new order reproduces existing
    // entries verbatim.
    let mut tables: Vec<Table> = aot.iter().cloned().collect();
    match index {
        Some(i) if i < tables.len() => {
            let existing = keys_of(&tables[i]);
            apply_object(&mut tables[i], value, &existing);
            let t = tables.remove(i);
            let pos = sorted_pos(&tables, &t, sort_keys);
            tables.insert(pos, t);
        }
        _ => {
            let mut t = Table::new();
            t.decor_mut().set_prefix("\n");
            apply_object(&mut t, value, &[]);
            let pos = sorted_pos(&tables, &t, sort_keys);
            tables.insert(pos, t);
        }
    }
    aot.clear();
    for t in tables {
        aot.push(t);
    }
}

/// Inline `signals = [{…}]` fallback. Inline tables carry no comments, so a
/// straight positional insert/replace is fine.
fn upsert_inline(arr: &mut Array, value: &JsonMap, index: Option<usize>, sort_keys: &[String]) {
    let new_val = Value::InlineTable(build_inline_table(value));
    match index {
        Some(i) if i < arr.len() => {
            arr.remove(i);
            let pos = sorted_pos_inline(arr, value, sort_keys);
            arr.insert(pos, new_val);
        }
        _ => {
            let pos = sorted_pos_inline(arr, value, sort_keys);
            arr.insert(pos, new_val);
        }
    }
}

fn op_remove_array_item(
    doc: &mut DocumentMut,
    array_path: &[String],
    index: usize,
    remove_if_empty: bool,
) {
    let Some((arr_key_raw, owner_path)) = array_path.split_last() else {
        return;
    };
    let arr_key = norm(arr_key_raw).to_string();
    let Some(owner) = navigate_existing_mut(doc, owner_path) else {
        return;
    };
    let empty = match owner.get_mut(&arr_key) {
        Some(Item::ArrayOfTables(aot)) => {
            if index < aot.len() {
                aot.remove(index);
            }
            aot.is_empty()
        }
        Some(Item::Value(Value::Array(arr))) => {
            if index < arr.len() {
                arr.remove(index);
            }
            arr.is_empty()
        }
        _ => false,
    };
    if remove_if_empty && empty {
        owner.remove(&arr_key);
    }
}

// ── rename (nodes, mux cases) ─────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn op_rename_key(
    doc: &mut DocumentMut,
    parent_path: &[String],
    old: &str,
    new: &str,
    set_value: Option<&JsonMap>,
    managed_keys: &[String],
    sort_numeric: bool,
    update_transmitter_refs: bool,
    error_if_exists: bool,
) -> Result<(), String> {
    let oldk = norm(old).to_string();
    let newk = norm(new).to_string();
    {
        let parent = navigate_create(doc.as_table_mut(), parent_path);
        if !parent.contains_key(&oldk) {
            return Err(format!("'{old}' not found"));
        }
        if oldk != newk {
            if error_if_exists && parent.contains_key(&newk) {
                return Err(format!("'{new}' already exists"));
            }
            if let Some(item) = parent.remove(&oldk) {
                parent.insert(&newk, item);
            }
        }
        if let Some(sv) = set_value {
            if let Some(child) = parent.get_mut(&newk).and_then(Item::as_table_mut) {
                apply_object(child, sv, managed_keys);
            }
        }
    }
    if update_transmitter_refs && oldk != newk {
        update_transmitter_references(doc, old, new);
    }
    if sort_numeric {
        sort_table_numeric(doc, parent_path);
    }
    Ok(())
}

/// On node rename, rewrite the references that point at it: CAN frames carry the
/// node in `transmitter`, Modbus registers in `node`.
fn update_transmitter_references(doc: &mut DocumentMut, old: &str, new: &str) {
    let Some(frame) = doc
        .as_table_mut()
        .get_mut("frame")
        .and_then(Item::as_table_mut)
    else {
        return;
    };
    rewrite_ref_field(frame.get_mut("can"), "transmitter", old, new);
    rewrite_ref_field(frame.get_mut("modbus"), "node", old, new);
}

/// Rewrite `field = "old"` → `field = "new"` across every child table of a
/// `[frame.<protocol>]` section.
fn rewrite_ref_field(section: Option<&mut Item>, field: &str, old: &str, new: &str) {
    let Some(table) = section.and_then(Item::as_table_mut) else {
        return;
    };
    for (_k, item) in table.iter_mut() {
        if let Some(tbl) = item.as_table_mut() {
            if tbl.get(field).and_then(|i| i.as_str()) == Some(old) {
                tbl.insert(field, toml_edit::value(new));
            }
        }
    }
}

// ── object → table application ────────────────────────────────────────────────

/// Set every key in `value` on `tbl`; remove `managed_keys` that are absent from
/// `value`. Unchanged scalars are left in place so their inline `#` comments
/// survive.
fn apply_object(tbl: &mut Table, value: &JsonMap, managed_keys: &[String]) {
    for k in managed_keys {
        if !value.contains_key(k) {
            tbl.remove(k);
        }
    }
    for (k, v) in value {
        set_key(tbl, k, v);
    }
}

fn set_key(tbl: &mut Table, key: &str, json: &Json) {
    match json {
        Json::Object(obj) => {
            let existing = tbl
                .get(key)
                .and_then(Item::as_table)
                .map(keys_of)
                .unwrap_or_default();
            let child = get_or_create_table(tbl, key, false);
            apply_object(child, obj, &existing);
        }
        Json::Array(items) => {
            tbl.insert(key, json_array_item(items));
        }
        Json::Null => {
            tbl.remove(key);
        }
        _ => set_scalar(tbl, key, json),
    }
}

fn set_scalar(tbl: &mut Table, key: &str, json: &Json) {
    if tbl.get(key).map(|it| scalar_eq(it, json)).unwrap_or(false) {
        return; // unchanged — keep the existing key + its inline comment
    }
    tbl.insert(key, json_scalar_item(key, json));
}

fn scalar_eq(item: &Item, json: &Json) -> bool {
    let Some(v) = item.as_value() else {
        return false;
    };
    match json {
        Json::Bool(b) => v.as_bool() == Some(*b),
        Json::String(s) => v.as_str() == Some(s.as_str()),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                v.as_integer() == Some(i)
            } else if let Some(f) = n.as_f64() {
                v.as_float() == Some(f)
            } else {
                false
            }
        }
        _ => false,
    }
}

fn json_scalar_item(key: &str, json: &Json) -> Item {
    json_to_value(key, json)
        .map(Item::Value)
        .unwrap_or(Item::None)
}

fn json_array_item(items: &[Json]) -> Item {
    if items.first().is_some_and(Json::is_object) {
        let mut aot = ArrayOfTables::new();
        for v in items {
            if let Json::Object(obj) = v {
                let mut t = Table::new();
                apply_object(&mut t, obj, &[]);
                aot.push(t);
            }
        }
        return Item::ArrayOfTables(aot);
    }
    let mut arr = Array::new();
    for v in items {
        if let Some(val) = json_to_value("", v) {
            arr.push_formatted(val);
        }
    }
    Item::Value(Value::Array(arr))
}

fn json_to_value(key: &str, json: &Json) -> Option<Value> {
    match json {
        Json::Bool(b) => Some(Value::from(*b)),
        Json::String(s) => Some(Value::from(s.as_str())),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(int_value(key, i))
            } else if let Some(u) = n.as_u64() {
                Some(int_value(key, u as i64))
            } else {
                n.as_f64().map(Value::from)
            }
        }
        Json::Array(items) => {
            let mut arr = Array::new();
            for v in items {
                if let Some(val) = json_to_value("", v) {
                    arr.push_formatted(val);
                }
            }
            Some(Value::Array(arr))
        }
        Json::Object(obj) => Some(Value::InlineTable(build_inline_table(obj))),
        Json::Null => None,
    }
}

fn build_inline_table(obj: &JsonMap) -> InlineTable {
    let mut it = InlineTable::new();
    for (k, v) in obj {
        if let Some(val) = json_to_value(k, v) {
            it.insert(k, val);
        }
    }
    it
}

/// Masks are conventionally written as hex. `Repr::new_unchecked` is crate-private
/// in toml_edit, so mint the hex-formatted integer by parsing it back out of a
/// throwaway document — the parsed value keeps its `0x…` representation.
fn int_value(key: &str, n: i64) -> Value {
    if (key == "mask" || key == "frame_id_mask") && n >= 0 {
        if let Ok(doc) = format!("v = 0x{n:X}").parse::<DocumentMut>() {
            if let Some(v) = doc.as_table().get("v").and_then(Item::as_value) {
                return v.clone();
            }
        }
    }
    Value::from(n)
}

// ── navigation & ordering helpers ─────────────────────────────────────────────

/// Strip the surrounding quotes a tree path may carry on a key (e.g. `"0x700"`).
fn norm(seg: &str) -> &str {
    let b = seg.as_bytes();
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        &seg[1..seg.len() - 1]
    } else {
        seg
    }
}

fn keys_of(t: &Table) -> Vec<String> {
    t.iter().map(|(k, _)| k.to_string()).collect()
}

fn navigate_create<'a>(mut cur: &'a mut Table, path: &[String]) -> &'a mut Table {
    for (i, seg) in path.iter().enumerate() {
        let key = norm(seg);
        let last = i + 1 == path.len();
        if !cur.get(key).map(Item::is_table).unwrap_or(false) {
            let mut t = Table::new();
            t.set_implicit(!last); // intermediates implied by the leaf header
            cur.insert(key, Item::Table(t));
        }
        cur = cur.get_mut(key).unwrap().as_table_mut().unwrap();
    }
    cur
}

fn navigate_existing_mut<'a>(doc: &'a mut DocumentMut, path: &[String]) -> Option<&'a mut Table> {
    let mut cur = doc.as_table_mut();
    for seg in path {
        cur = cur.get_mut(norm(seg))?.as_table_mut()?;
    }
    Some(cur)
}

fn table_exists(doc: &DocumentMut, path: &[String]) -> bool {
    let mut cur = doc.as_table();
    for seg in path {
        match cur.get(norm(seg)).and_then(Item::as_table) {
            Some(t) => cur = t,
            None => return false,
        }
    }
    true
}

fn get_or_create_table<'a>(parent: &'a mut Table, key: &str, implicit: bool) -> &'a mut Table {
    if !parent.get(key).map(Item::is_table).unwrap_or(false) {
        let mut t = Table::new();
        t.set_implicit(implicit);
        parent.insert(key, Item::Table(t));
    }
    parent.get_mut(key).unwrap().as_table_mut().unwrap()
}

fn sort_table_numeric(doc: &mut DocumentMut, path: &[String]) {
    if let Some(tbl) = navigate_existing_mut(doc, path) {
        tbl.sort_values_by(|k1, _, k2, _| numeric_key_compare(k1.get(), k2.get()));
    }
}

fn numeric_key_compare(a: &str, b: &str) -> Ordering {
    match (parse_key_num(a), parse_key_num(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
        _ => a.cmp(b),
    }
}

fn parse_key_num(v: &str) -> Option<f64> {
    let v = norm(v);
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok().map(|n| n as f64);
    }
    v.parse::<f64>().ok()
}

fn sorted_pos(tables: &[Table], new: &Table, sort_keys: &[String]) -> usize {
    if sort_keys.is_empty() {
        return tables.len();
    }
    tables
        .iter()
        .position(|t| cmp_tables(t, new, sort_keys) == Ordering::Greater)
        .unwrap_or(tables.len())
}

fn sorted_pos_inline(arr: &Array, value: &JsonMap, sort_keys: &[String]) -> usize {
    if sort_keys.is_empty() {
        return arr.len();
    }
    arr.iter()
        .position(|v| {
            v.as_inline_table()
                .map(|it| cmp_inline(it, value, sort_keys) == Ordering::Greater)
                .unwrap_or(false)
        })
        .unwrap_or(arr.len())
}

fn cmp_tables(a: &Table, b: &Table, keys: &[String]) -> Ordering {
    for k in keys {
        let o = cmp_value(
            a.get(k).and_then(Item::as_value),
            b.get(k).and_then(Item::as_value),
        );
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn cmp_inline(a: &InlineTable, b: &JsonMap, keys: &[String]) -> Ordering {
    for k in keys {
        let bv = b.get(k).and_then(|v| json_to_value(k, v));
        let o = cmp_value(a.get(k), bv.as_ref());
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

fn cmp_value(a: Option<&Value>, b: Option<&Value>) -> Ordering {
    if let (Some(x), Some(y)) = (a.and_then(Value::as_integer), b.and_then(Value::as_integer)) {
        return x.cmp(&y);
    }
    if let (Some(x), Some(y)) = (a.and_then(Value::as_float), b.and_then(Value::as_float)) {
        return x.partial_cmp(&y).unwrap_or(Ordering::Equal);
    }
    let xs = a.and_then(Value::as_str).unwrap_or("");
    let ys = b.and_then(Value::as_str).unwrap_or("");
    xs.cmp(ys)
}

#[cfg(test)]
mod tests;
