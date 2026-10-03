use super::*;
use crate::Catalog;

const LEGACY: &str = r#"# A legacy modbus catalogue.
[meta]
name = "Legacy"
version = 1
default_frame = "modbus"

[meta.modbus]
device_address = 1   # slave address
register_base = 0
default_interval = 5000

[frame.modbus.version_1]
register_number = 2581
register_type = "input"
length = 22

[frame.modbus.firmware]
register_number = 4953
register_type = "input"
length = 15
"#;

#[test]
fn upgrades_legacy_modbus_to_node() {
    let m = migrate(LEGACY).unwrap();
    assert!(m.changed);
    assert!(!m.summary.is_empty());

    // A slave node owns the address, registers reference it by address.
    assert!(m.toml.contains("[node.\"Slave 1\"]"));
    assert!(m.toml.contains("device_address = 1"));
    assert_eq!(m.toml.matches("node_address = 1").count(), 2);

    // The redundant legacy address is gone, but other meta keys remain.
    assert!(!m.toml.contains("[meta.modbus]\ndevice_address"));
    let meta = m
        .toml
        .split("[meta.modbus]")
        .nth(1)
        .unwrap()
        .split("[frame")
        .next()
        .unwrap();
    assert!(!meta.contains("device_address"));
    assert!(meta.contains("register_base = 0"));
    assert!(meta.contains("default_interval = 5000"));
}

#[test]
fn preserves_comments() {
    let m = migrate(LEGACY).unwrap();
    assert!(m.toml.contains("# A legacy modbus catalogue."));
}

#[test]
fn is_idempotent() {
    let once = migrate(LEGACY).unwrap();
    assert!(once.changed);
    let twice = migrate(&once.toml).unwrap();
    assert!(!twice.changed);
    assert_eq!(twice.toml, once.toml);
}

#[test]
fn text_migration_matches_in_memory_migration() {
    // The parser migrates legacy text in memory; the document migration must
    // produce text that parses to the same frames and nodes.
    let from_legacy = Catalog::parse(LEGACY).unwrap();
    let migrated = migrate(LEGACY).unwrap();
    let from_migrated = Catalog::parse(&migrated.toml).unwrap();
    assert_eq!(from_migrated.nodes, from_legacy.nodes);
    assert_eq!(from_migrated.frames, from_legacy.frames);
}

#[test]
fn non_default_address_is_carried_to_the_node() {
    let toml = LEGACY.replace("device_address = 1", "device_address = 5");
    let m = migrate(&toml).unwrap();
    assert!(m.toml.contains("[node.\"Slave 5\"]"));
    assert_eq!(m.toml.matches("node_address = 5").count(), 2);
}

#[test]
fn already_node_based_is_a_no_op() {
    let toml = r#"
[meta]
name = "x"
[node."Slave 1"]
device_address = 1
[frame.modbus.reg]
register_number = 100
register_type = "input"
length = 1
node_address = 1
"#;
    let m = migrate(toml).unwrap();
    assert!(!m.changed);
    assert_eq!(m.toml, toml);
}

#[test]
fn can_only_catalogue_is_a_no_op() {
    let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
"#;
    let m = migrate(toml).unwrap();
    assert!(!m.changed);
    assert_eq!(m.toml, toml);
}

#[test]
fn registers_with_an_explicit_address_are_left_alone() {
    let toml = r#"
[meta]
name = "x"
[meta.modbus]
device_address = 1
[frame.modbus.a]
register_number = 1
register_type = "input"
length = 1
node_address = 9
[frame.modbus.b]
register_number = 2
register_type = "input"
length = 1
"#;
    let m = migrate(toml).unwrap();
    assert!(m.changed);
    // Only `b` gets the synthesised address; `a` keeps its explicit one.
    assert_eq!(m.toml.matches("node_address = 1").count(), 1);
    assert!(m.toml.contains("node_address = 9"));
}

// ── interval flattening (tx.interval[_ms] → top-level interval_ms) ─────────────

const TX_INTERVALS: &str = r#"
[meta]
name = "x"
[meta.can]
default_interval = 100
[frame.can.0x100]
length = 8
[frame.can.0x100.tx]
interval_ms = 500
[frame.can.0x200]
length = 8
tx = { interval = 250 }
[frame.modbus.reg]
register_number = 13
register_type = "input"
length = 1
node_address = 1
tx.interval_ms = 9000
[node."Slave 1"]
device_address = 1
"#;

#[test]
fn flattens_tx_interval_to_top_level() {
    let m = migrate(TX_INTERVALS).unwrap();
    assert!(m.changed);
    assert!(m.toml.contains("interval_ms = 500"));
    assert!(m.toml.contains("interval_ms = 250")); // tx.interval → interval_ms
    assert!(m.toml.contains("interval_ms = 9000"));
    // No frame keeps a `[tx]` table once its interval has moved out.
    assert!(!m.toml.contains("[frame.can.0x100.tx]"));
    assert!(!m.toml.contains("tx ="));
    assert!(!m.toml.contains("tx.interval"));
}

#[test]
fn interval_flatten_is_idempotent() {
    let once = migrate(TX_INTERVALS).unwrap();
    let twice = migrate(&once.toml).unwrap();
    assert!(!twice.changed);
    assert_eq!(twice.toml, once.toml);
}

#[test]
fn interval_flatten_preserves_resolved_intervals() {
    let before = Catalog::parse(TX_INTERVALS).unwrap();
    let after = Catalog::parse(&migrate(TX_INTERVALS).unwrap().toml).unwrap();
    assert_eq!(before.frames, after.frames);
    // Spot-check the resolved values survived the move.
    assert_eq!(after.frame(0x100).unwrap().interval, Some(500));
    assert_eq!(after.frame(0x200).unwrap().interval, Some(250));
    assert_eq!(after.frame(13).unwrap().interval, Some(9000));
}

#[test]
fn frames_without_tx_intervals_are_untouched() {
    let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
interval_ms = 500
"#;
    let m = migrate(toml).unwrap();
    assert!(!m.changed);
    assert_eq!(m.toml, toml);
}
