//! Format migrations that upgrade a catalogue's *text* to the current schema,
//! preserving comments and hand-authored formatting.
//!
//! The parser ([`crate::parse`]) silently upgrades legacy shapes in memory so
//! the editor and decoder always see the current model. That's display-only —
//! the on-disk file is untouched, so the upgrade is invisible and lost on close.
//! This module produces the *upgraded TOML* for the same migrations, over a
//! [`toml_edit::DocumentMut`] (same comment-preserving approach as
//! [`crate::edit`]), so the editor can show the upgrade as a real diff against
//! the on-disk baseline and let the user save it.
//!
//! Migrations are idempotent: re-running [`migrate`] on already-upgraded text is
//! a no-op (`changed == false`). The canonical naming shared with the in-memory
//! migration lives in [`slave_node_name`] so the two cannot drift.

use toml_edit::{value, DocumentMut, Item, Table, Value};

/// The result of running every migration step over a catalogue's text.
pub struct Migration {
    /// Whether any step changed the document.
    pub changed: bool,
    /// The upgraded TOML (byte-for-byte equal to the input when `changed` is false).
    pub toml: String,
    /// Human-readable lines describing what changed, for the editor's banner.
    pub summary: Vec<String>,
}

/// Canonical slave-node name for a legacy Modbus device address. Shared with the
/// in-memory migration in [`crate::parse`] so both spell the synthesised node
/// identically.
pub fn slave_node_name(addr: u8) -> String {
    format!("Slave {addr}")
}

/// Run every migration step over `text`, returning the upgraded TOML plus a
/// summary. `Err` carries a UI-friendly message when the input is not valid TOML.
pub fn migrate(text: &str) -> Result<Migration, String> {
    let mut doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("catalogue is not valid TOML: {e}"))?;
    let mut summary = Vec::new();

    migrate_modbus_nodes(&mut doc, &mut summary);
    migrate_frame_intervals(&mut doc, &mut summary);

    let changed = !summary.is_empty();
    // Leave the input untouched when nothing fired — avoids any incidental
    // re-formatting from `to_string()` showing up as a phantom diff.
    let toml = if changed {
        doc.to_string()
    } else {
        text.to_string()
    };
    Ok(Migration {
        changed,
        toml,
        summary,
    })
}

/// Legacy Modbus catalogues carried the slave address on `[meta.modbus]`
/// `device_address` with no `[node]` tables. The current form makes each slave a
/// node that owns the address. Synthesise a `[node."Slave N"]` table, attach the
/// orphaned registers to it, and drop the now-redundant `[meta.modbus]`
/// `device_address`. Mirrors the in-memory migration in [`crate::parse`].
fn migrate_modbus_nodes(doc: &mut DocumentMut, summary: &mut Vec<String>) {
    // Real modbus registers present? (`config` is a defaults table, not a frame.)
    let has_modbus_frames = modbus_frames(doc)
        .map(|t| t.iter().any(|(k, _)| k != "config"))
        .unwrap_or(false);
    if !has_modbus_frames {
        return;
    }
    // Already node-based — nothing to migrate.
    if doc
        .get("node")
        .and_then(Item::as_table)
        .map(|t| t.iter().next().is_some())
        .unwrap_or(false)
    {
        return;
    }

    // Resolve the address the parser would: `[meta.modbus].device_address`,
    // defaulting to 1 when modbus frames exist.
    let addr = meta_modbus(doc)
        .and_then(|t| t.get("device_address"))
        .and_then(Item::as_integer)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(1);
    let name = slave_node_name(addr);

    // Attach every register that lacks an explicit slave address.
    let mut tagged = 0usize;
    if let Some(frames) = modbus_frames_mut(doc) {
        for (k, item) in frames.iter_mut() {
            if k == "config" {
                continue;
            }
            if let Some(ftbl) = item.as_table_mut() {
                if !ftbl.contains_key("node_address") {
                    ftbl.insert("node_address", value(i64::from(addr)));
                    tagged += 1;
                }
            }
        }
    }

    // Create [node."Slave N"] with the address. The `node` parent is implicit so
    // only the `[node."Slave N"]` header is emitted, matching authored files.
    let mut node_body = Table::new();
    node_body.insert("device_address", value(i64::from(addr)));
    let root = doc.as_table_mut();
    if !root.get("node").map(Item::is_table).unwrap_or(false) {
        let mut t = Table::new();
        t.set_implicit(true);
        root.insert("node", Item::Table(t));
    }
    if let Some(node_section) = root.get_mut("node").and_then(Item::as_table_mut) {
        node_section.insert(&name, Item::Table(node_body));
    }

    // Drop the now-redundant legacy address (the node owns it).
    let removed_meta = meta_modbus_mut(doc)
        .map(|t| t.remove("device_address").is_some())
        .unwrap_or(false);

    summary.push(format!(
        "Created slave node \"{name}\" (device address {addr})"
    ));
    if tagged > 0 {
        let plural = if tagged == 1 { "" } else { "s" };
        summary.push(format!("Assigned {tagged} register{plural} to \"{name}\""));
    }
    if removed_meta {
        summary.push("Removed the redundant [meta.modbus] device_address".to_string());
    }
}

/// Move every frame's legacy `[tx]` interval to the canonical top-level
/// `interval_ms`, across all protocols. The parser still reads `tx.interval_ms` /
/// `tx.interval`, but the flat form is canonical; this drops the now-empty `[tx]`.
fn migrate_frame_intervals(doc: &mut DocumentMut, summary: &mut Vec<String>) {
    let mut moved = 0usize;
    for proto in ["can", "modbus", "serial"] {
        let Some(frames) = frame_section_mut(doc, proto) else {
            continue;
        };
        for (k, item) in frames.iter_mut() {
            if k == "config" {
                continue;
            }
            let Some(ftbl) = item.as_table_mut() else {
                continue;
            };
            if let Some(ms) = take_tx_interval(ftbl) {
                // A pre-existing top-level value wins; just drop the stale `[tx]`.
                if !ftbl.contains_key("interval_ms") {
                    ftbl.insert("interval_ms", value(ms));
                }
                moved += 1;
            }
        }
    }
    if moved > 0 {
        let plural = if moved == 1 { "" } else { "s" };
        summary.push(format!(
            "Moved {moved} frame interval{plural} from [tx] to interval_ms"
        ));
    }
}

/// Remove a frame's interval from its `[tx]` sub-table (table or inline), dropping
/// `tx` when it is left empty. Returns the interval in ms, if any.
fn take_tx_interval(ftbl: &mut Table) -> Option<i64> {
    let (ms, empty) = match ftbl.get_mut("tx")? {
        Item::Table(t) => (
            t.remove("interval_ms")
                .or_else(|| t.remove("interval"))?
                .as_integer()?,
            t.is_empty(),
        ),
        Item::Value(Value::InlineTable(it)) => (
            it.remove("interval_ms")
                .or_else(|| it.remove("interval"))?
                .as_integer()?,
            it.is_empty(),
        ),
        _ => return None,
    };
    if empty {
        ftbl.remove("tx");
    }
    Some(ms)
}

// ── document navigation helpers ───────────────────────────────────────────────

fn frame_section_mut<'a>(doc: &'a mut DocumentMut, proto: &str) -> Option<&'a mut Table> {
    doc.get_mut("frame")
        .and_then(Item::as_table_mut)?
        .get_mut(proto)
        .and_then(Item::as_table_mut)
}

fn modbus_frames(doc: &DocumentMut) -> Option<&Table> {
    doc.get("frame")
        .and_then(Item::as_table)?
        .get("modbus")
        .and_then(Item::as_table)
}

fn modbus_frames_mut(doc: &mut DocumentMut) -> Option<&mut Table> {
    frame_section_mut(doc, "modbus")
}

fn meta_modbus(doc: &DocumentMut) -> Option<&Table> {
    doc.get("meta")
        .and_then(Item::as_table)?
        .get("modbus")
        .and_then(Item::as_table)
}

fn meta_modbus_mut(doc: &mut DocumentMut) -> Option<&mut Table> {
    doc.get_mut("meta")
        .and_then(Item::as_table_mut)?
        .get_mut("modbus")
        .and_then(Item::as_table_mut)
}

#[cfg(test)]
mod tests;
