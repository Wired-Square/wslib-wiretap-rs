//! The desktop's authoring golden, `fixtures/desktop/authoring.json`, as the
//! typed ops the editor sends instead: its form values, with the library
//! deciding what is written. Each step applies the desktop's recorded ops and
//! the library's ops to the same document and compares the TOML as data. Where
//! they differ the step pins the library's TOML and the reason, by the plan's
//! decision (D#) or the facts note's item (facts #). Cases that are form state
//! with no library counterpart are listed in `FORM_STATE`.

use std::path::PathBuf;

use serde_json::{json, Value};
use wiretap_catalog::edit::{apply_edits, mux_name, EditOp};

const TOML: &str = "[meta]\nname = \"x\"\nversion = 1\n\n[frame.can.\"0x100\"]\nlength = 8\n";

const FORM_STATE: [&str; 4] = [
    "Frame keys a fresh frame falls back to, and the handlers' display ids",
    "Adding a frame: each protocol's starting form",
    "Editing a mux: notes joined, missing fields defaulted",
    "A signal read back into the form: byte_order to endianness, string bits coerced, notes joined",
];

fn read(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/desktop")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

fn golden(name: &str) -> Value {
    let cases: Value = serde_json::from_str(&read("authoring.json")).unwrap();
    cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))["expected"]
        .clone()
}

/// The ops each step of a case sent, in order.
fn desktop_steps(expected: &Value) -> Vec<Value> {
    match expected {
        Value::Array(steps) => steps.iter().map(|s| s["ops"].clone()).collect(),
        one => vec![one["ops"].clone()],
    }
}

fn apply(text: &str, ops: &Value) -> Result<String, String> {
    let ops: Vec<EditOp> = serde_json::from_value(ops.clone()).map_err(|e| e.to_string())?;
    apply_edits(text, &ops)
}

fn data(text: &str) -> toml::Table {
    text.parse().unwrap_or_else(|e| panic!("{e}\n{text}"))
}

enum Outcome {
    Same,
    Differs {
        lib: String,
        why: &'static str,
    },
    Refused {
        error: &'static str,
        why: &'static str,
    },
}
use Outcome::*;

fn differs(lib: impl Into<String>, why: &'static str) -> Outcome {
    Differs {
        lib: lib.into(),
        why,
    }
}

fn check(name: &str, base: &str, steps: Vec<(Value, Outcome)>) {
    let desktop = desktop_steps(&golden(name));
    assert_eq!(desktop.len(), steps.len(), "{name}: step count");
    let (mut ts, mut lib) = (base.to_string(), base.to_string());
    for (i, (desktop_ops, (lib_ops, outcome))) in desktop.iter().zip(steps).enumerate() {
        ts = apply(&ts, desktop_ops).unwrap_or_else(|e| panic!("{name} #{i}: desktop ops: {e}"));
        let result = apply(&lib, &lib_ops);
        let at = format!("{name} #{i}");
        match outcome {
            Same => {
                lib = result.unwrap_or_else(|e| panic!("{at}: {e}"));
                assert_eq!(data(&lib), data(&ts), "{at}\n{lib}");
            }
            Differs { lib: expected, why } => {
                lib = result.unwrap_or_else(|e| panic!("{at}: {e}"));
                assert_eq!(data(&lib), data(&expected), "{at}: {why}\n{lib}");
            }
            Refused { error, why } => {
                let e = result.expect_err(&at);
                assert!(e.contains(error), "{at}: {why}: {e}");
            }
        }
    }
}

fn with(base: &str, more: &str) -> String {
    format!("{base}\n{more}")
}

const NOT_FROM_FLAGS: &str = "facts 2, D7: inheritance is read from the document, not the caller's flags, and nothing here supplies these";

#[test]
fn legacy_can_frames() {
    check(
        "CAN frame (legacy editor): notes array of one collapses, interval goes under tx",
        TOML,
        vec![(
            json!([{ "op": "SetFrame", "protocol": "can", "key": "0x123",
                "frame": { "length": 8, "transmitter": "BMS", "interval": 100, "notes": ["one"] } }]),
            differs(
                with(TOML, "[frame.can.0x123]\nlength = 8\ntransmitter = \"BMS\"\ninterval_ms = 100\nnotes = \"one\"\n"),
                "the interval is written as interval_ms, never under tx",
            ),
        )],
    );
    check(
        "CAN frame (legacy editor): inherited length, transmitter and interval are omitted, a rename names the old key",
        TOML,
        vec![(
            json!([{ "op": "SetFrame", "protocol": "can", "key": "0x101", "rename_from": "0x100",
                "frame": { "length": 8, "transmitter": "BMS", "interval": 100, "notes": [] } }]),
            differs(
                "[meta]\nname = \"x\"\nversion = 1\n\n[frame.can.0x101]\nlength = 8\ntransmitter = \"BMS\"\ninterval_ms = 100\n",
                NOT_FROM_FLAGS,
            ),
        )],
    );
    check(
        "CAN frame (legacy editor): two notes stay an array, an empty string is dropped",
        TOML,
        vec![
            (
                json!([{ "op": "SetFrame", "protocol": "can", "key": "0x1",
                    "frame": { "length": 0, "notes": ["a", "b"] } }]),
                Same,
            ),
            (
                json!([{ "op": "SetFrame", "protocol": "can", "key": "0x2",
                    "frame": { "length": 8, "notes": "" } }]),
                Same,
            ),
        ],
    );
}

#[test]
fn frames_through_their_handlers() {
    let frame = |protocol: &str, key: &str, frame: Value| json!([{ "op": "SetFrame", "protocol": protocol, "key": key, "rename_from": "old", "frame": frame }]);
    check(
        r#"can frame through its handler: {"protocol":"can","id":"0x200","extended":false,"fd":true,"bus":1,"copy":"0x100","mirror_of":"0x300"}"#,
        TOML,
        vec![(
            frame("can", "0x200", json!({ "length": 8, "transmitter": "BMS", "interval": 100, "notes": ["n"],
                "extended": false, "fd": true, "bus": 1, "copy": "0x100", "mirror_of": "0x300" })),
            differs(
                with(TOML, "[frame.can.0x200]\ntransmitter = \"BMS\"\ninterval_ms = 100\nnotes = \"n\"\nfd = true\nbus = 1\ncopy = \"0x100\"\nmirror_of = \"0x300\"\n"),
                "facts 2, D7: length 8 is what copy 0x100 gives and extended = false what an 11-bit id gives, so neither is written; one note is a string",
            ),
        )],
    );
    check(
        r#"can frame through its handler: {"protocol":"can","id":"0x200","extended":true,"fd":false} with inherited fields omitted"#,
        TOML,
        vec![(
            frame("can", "0x200", json!({ "length": 8, "transmitter": "BMS", "interval": 100, "extended": true, "fd": false })),
            differs(
                with(TOML, "[frame.can.0x200]\nlength = 8\ntransmitter = \"BMS\"\ninterval_ms = 100\nextended = true\n"),
                NOT_FROM_FLAGS,
            ),
        )],
    );
    check(
        r#"modbus frame through its handler: {"protocol":"modbus","register_number":13021,"node_address":3,"register_type":"holding","register_base":1}"#,
        TOML,
        vec![(
            frame("modbus", "13021", json!({ "length": 1, "interval": 500, "register_number": 13021,
                "node_address": 3, "register_type": "holding" })),
            differs(
                with(TOML, "[frame.modbus.13021]\nnode_address = 3\ninterval_ms = 500\n"),
                "facts 1: the key names the register, so register_number is not written; D8: nor is register_base",
            ),
        )],
    );
    check(
        r#"modbus frame through its handler: {"protocol":"modbus","register_type":"coil","register_base":0} with inherited fields omitted"#,
        TOML,
        vec![(
            frame(
                "modbus",
                "",
                json!({ "length": 4, "transmitter": "Inverter", "notes": "n", "register_type": "coil" }),
            ),
            Refused {
                error: "a frame key is required",
                why: "facts 5: a blank key is refused, not saved as new_register",
            },
        )],
    );
    check(
        r#"serial frame through its handler: {"protocol":"serial","frame_id":"0x10","delimiter":[]}"#,
        TOML,
        vec![(
            frame(
                "serial",
                "0x10",
                json!({ "length": 0, "interval": 250, "delimiter": [] }),
            ),
            Same,
        )],
    );
    check(
        r#"serial frame through its handler: {"protocol":"serial","frame_id":"","delimiter":[192,0]} with inherited fields omitted"#,
        TOML,
        vec![(
            frame(
                "serial",
                "",
                json!({ "length": 12, "transmitter": "Controller", "delimiter": [192, 0] }),
            ),
            Refused {
                error: "a frame key is required",
                why: "facts 8: a blank key is refused, not saved as unnamed_frame",
            },
        )],
    );
    check(
        "Serial frame shorthand",
        TOML,
        vec![(
            json!([{ "op": "SetFrame", "protocol": "serial", "key": "0x11", "rename_from": "0x10",
                "frame": { "length": 6, "delimiter": [126], "transmitter": "Controller", "interval": 50, "notes": "a" } }]),
            differs(
                with(TOML, "[frame.serial.0x11]\nlength = 6\ntransmitter = \"Controller\"\ninterval_ms = 50\nnotes = \"a\"\ndelimiter = [126]\n"),
                "D7: one note is a string wherever notes are written; the generic UpsertFrame wrote [\"a\"]",
            ),
        )],
    );
}

#[test]
fn signals() {
    let new_signal = json!({ "name": "S", "start_bit": 0, "bit_length": 8, "factor": 1, "offset": 0,
        "unit": "", "signed": false, "confidence": "", "notes": "" });
    check(
        "Signal with the editor's new-signal defaults: endianness renamed, empty confidence dropped, defaults passed through",
        TOML,
        vec![(
            json!([{ "op": "UpsertSignal", "owner_path": ["frame", "can", "0x100"], "signal": new_signal }]),
            differs(
                with(TOML, "[[frame.can.\"0x100\".signals]]\nname = \"S\"\nstart_bit = 0\nbit_length = 8\n"),
                "signed = false is the default, so not written",
            ),
        )],
    );
    check(
        "Signal at a full signal path inside a mux case: index from the path, notes become a one-line array",
        TOML,
        vec![(
            json!([{ "op": "UpsertSignal", "owner_path": ["frame", "can", "0x100", "mux", "1"], "index": 3,
                "signal": { "name": "T", "start_bit": 16, "bit_length": 16, "factor": 0.1, "offset": -40, "unit": "C",
                    "signed": true, "endianness": "big", "min": -40, "max": 125, "format": "number",
                    "confidence": "high", "enum": { "0": "Off" }, "notes": "two\nlines" } }]),
            Same,
        )],
    );
    check(
        "Signal delete at a mux case",
        TOML,
        vec![(
            json!([{ "op": "RemoveArrayItem", "array_path": ["frame", "can", "0x100", "mux", "1", "signals"], "index": 2 }]),
            Same,
        )],
    );
    check(
        "Adding a signal, then saving the defaults",
        TOML,
        vec![(
            json!([{ "op": "UpsertSignal", "owner_path": ["frame", "can", "0x100", "mux", "1"], "signal": new_signal }]),
            differs(
                with(TOML, "[[frame.can.\"0x100\".mux.1.signals]]\nname = \"S\"\nstart_bit = 0\nbit_length = 8\n"),
                "signed = false is the default, so not written",
            ),
        )],
    );
}

#[test]
fn muxes_cases_nodes_and_checksums() {
    let owner = json!(["frame", "can", "0x100"]);
    check(
        "Mux upsert and delete, notes to an array",
        TOML,
        vec![
            (
                json!([{ "op": "SetMux", "owner_path": owner, "mux": { "start_bit": 0, "bit_length": 8, "notes": "page" } }]),
                Same,
            ),
            (
                json!([{ "op": "DeleteAtPath", "path": ["frame", "can", "0x100", "mux"] }]),
                Same,
            ),
        ],
    );
    let mux = json!({ "name": "m", "start_bit": 0, "bit_length": 8 });
    check(
        "Saving a mux: an existing mux's path loses its trailing mux",
        TOML,
        vec![
            (
                json!([{ "op": "SetMux", "owner_path": owner, "mux": mux }]),
                Same,
            ),
            (
                json!([{ "op": "SetMux", "owner_path": owner, "mux": mux }]),
                Same,
            ),
            (
                json!([{ "op": "SetMux", "owner_path": ["frame", "can", "0x100", "mux", "4"], "mux": mux }]),
                Same,
            ),
        ],
    );
    let mux_path = json!(["frame", "can", "0x100", "mux"]);
    let case = |key: &str, notes: &str| {
        json!([{ "op": "SetTable", "path": ["frame", "can", "0x100", "mux", key], "value": { "notes": notes },
            "managed_keys": ["notes"], "error_if_exists": true }])
    };
    let rename = |old: &str, new: &str, notes: &str| {
        json!([{ "op": "RenameKey", "parent_path": mux_path, "old": old, "new": new,
            "set_value": { "notes": notes }, "managed_keys": ["notes"], "error_if_exists": true }])
    };
    check(
        "Mux case add, rename and delete",
        TOML,
        vec![
            (case("1", "first"), Same),
            (case("2", ""), Same),
            (rename("1", "0-3", ""), Same),
            (
                json!([{ "op": "DeleteAtPath", "path": ["frame", "can", "0x100", "mux", "2"] }]),
                Same,
            ),
        ],
    );
    check(
        "Mux cases: notes trimmed on add and rename",
        TOML,
        vec![
            (case("5", "  five "), Same),
            (rename("5", "5-6", " "), Same),
        ],
    );

    let add_node = |name: &str, value: Value| {
        json!([{ "op": "SetTable", "path": ["node", name], "value": value,
            "managed_keys": ["device_address", "notes"], "sort_parent_numeric": true, "skip_if_exists": true }])
    };
    let rename_node = |value: Value| {
        json!([{ "op": "RenameKey", "parent_path": ["node"], "old": "BMS", "new": "Pack", "set_value": value,
            "managed_keys": ["device_address", "notes"], "sort_numeric": true,
            "update_transmitter_refs": true, "error_if_exists": true }])
    };
    check(
        "Node add, rename and delete",
        TOML,
        vec![
            (
                add_node("BMS", json!({ "device_address": 3, "notes": "Battery" })),
                Same,
            ),
            (add_node("Charger", json!({ "notes": "" })), Same),
            (rename_node(json!({ "device_address": 0 })), Same),
            (
                json!([{ "op": "DeleteAtPath", "path": ["node", "Pack"] }]),
                Same,
            ),
        ],
    );
    check(
        "Nodes: notes trimmed, blank notes dropped",
        TOML,
        vec![
            (
                add_node(
                    "BMS",
                    json!({ "device_address": 3, "notes": "  Battery  " }),
                ),
                Same,
            ),
            (rename_node(json!({ "notes": "   " })), Same),
        ],
    );

    let checksum = |path: Value, value: Value, index: Value| {
        json!([{ "op": "UpsertArrayItem", "array_path": path, "value": value, "index": index,
            "sort_keys": ["start_byte", "name"] }])
    };
    check(
        "Checksum: endianness only past one byte",
        TOML,
        vec![
            (
                checksum(
                    json!(["frame", "can", "0x100", "checksum"]),
                    json!({ "name": "CRC", "algorithm": "crc8", "start_byte": 7, "byte_length": 1,
                        "calc_start_byte": 0, "calc_end_byte": 7, "notes": "" }),
                    Value::Null,
                ),
                Same,
            ),
            (
                checksum(
                    json!(["frame", "serial", "0x10", "checksum"]),
                    json!({ "name": "CRC16", "algorithm": "crc16_modbus", "start_byte": -2, "byte_length": 2,
                        "calc_start_byte": 0, "calc_end_byte": -2, "endianness": "little", "notes": "Modbus" }),
                    json!(0),
                ),
                Same,
            ),
            (
                json!([{ "op": "RemoveArrayItem", "array_path": ["frame", "can", "0x100", "checksum"],
                    "index": 0, "remove_if_empty": true }]),
                Same,
            ),
        ],
    );
}

#[test]
fn configurations() {
    let serial_checksum = json!({ "algorithm": "xor", "start_byte": -1, "byte_length": 1,
        "calc_start_byte": 0, "calc_end_byte": -1, "big_endian": false });
    check(
        "Config ops: CAN default endianness renamed, serial checksum to camelCase, Modbus passed through",
        TOML,
        vec![(
            json!([
                { "op": "SetMeta", "meta": { "name": "N", "version": 2, "default_frame": "can" } },
                { "op": "SetCanConfig", "config": { "default_byte_order": "big", "default_interval": 100,
                    "default_extended": true, "frame_id_mask": 0x1fff_ff00,
                    "fields": { "source": { "mask": 0xff, "format": "hex" } } } },
                { "op": "SetSerialConfig", "config": { "encoding": "cobs", "byte_order": "little",
                    "header_length": 2, "min_frame_length": 0,
                    "fields": { "id": { "mask": 0xff00, "endianness": "big", "format": "hex" } },
                    "checksum": serial_checksum } },
                { "op": "SetModbusConfig", "config": { "device_address": 7, "register_base": 1,
                    "default_interval": 1000, "default_byte_order": "big", "default_word_order": "little" } }
            ]),
            Same,
        )],
    );
    check(
        "Saving the configuration: CAN mask and header fields parsed, disabled protocols deleted",
        TOML,
        vec![(
            json!([
                { "op": "SetMeta", "meta": { "name": "N", "version": 4, "default_frame": "can" } },
                { "op": "SetCanConfig", "config": { "default_byte_order": "big", "default_interval": 100,
                    "default_extended": true, "frame_id_mask": " 0x1FFFFF00 ",
                    "fields": {
                        " source ": { "mask": "0xFF", "shift": 0, "format": "hex" },
                        "priority": { "mask": "zz", "shift": 26, "format": "decimal" },
                        "": { "mask": "0xF0", "format": "hex" },
                        "blank": { "mask": " ", "format": "hex" }
                    } } },
                { "op": "DeleteAtPath", "path": ["meta", "serial"] },
                { "op": "DeleteAtPath", "path": ["meta", "modbus"] }
            ]),
            Refused {
                error: "mask 'zz' is not hexadecimal",
                why: "facts 7, D7: an unparseable mask refuses the save, never writes 0",
            },
        )],
    );
    check(
        "Saving the configuration: serial header fields and the file's mask carried, Modbus device address from the file",
        TOML,
        vec![(
            json!([
                { "op": "SetMeta", "meta": { "name": "N", "version": 4 } },
                { "op": "DeleteAtPath", "path": ["meta", "can"] },
                { "op": "SetSerialConfig", "config": { "encoding": "raw", "byte_order": "little",
                    "frame_id_mask": 0xff00, "header_length": 3, "min_frame_length": 4,
                    "fields": {
                        "id": { "mask": 0xff00, "endianness": "big", "format": "hex" },
                        " ": { "mask": 0xff, "endianness": "big", "format": "decimal" }
                    },
                    "checksum": { "algorithm": "sum8", "start_byte": -1, "byte_length": 1,
                        "calc_start_byte": 0, "calc_end_byte": -1 } } },
                { "op": "SetModbusConfig", "config": { "device_address": 9, "register_base": 1,
                    "default_interval": 1000, "default_byte_order": "big", "default_word_order": "little" } }
            ]),
            Same,
        )],
    );
}

#[test]
fn new_modbus_frames_are_seeded() {
    let add = |key: &str, frame: Value| json!([{ "op": "AddFrame", "protocol": "modbus", "key": key, "frame": frame }]);
    let seeded = |key: &str, frame: &str, signal: &str| {
        with(
            TOML,
            &format!("[frame.modbus.{key}]\n{frame}\n[[frame.modbus.{key}.signals]]\nname = \"{key}\"\nstart_bit = 0\n{signal}\n"),
        )
    };
    const SEED: &str = "facts 5: the seed is written as a signal, so byte_order, not endianness, and no signed = false";
    check(
        "New Modbus frame seeds one signal: holding, two registers",
        TOML,
        vec![(
            add("5000", json!({ "length": 2, "register_type": "holding" })),
            differs(
                seeded(
                    "5000",
                    "length = 2",
                    "bit_length = 32\nbyte_order = \"big\"",
                ),
                SEED,
            ),
        )],
    );
    check(
        "New Modbus frame seeds one signal: input, length 0 seeds one register",
        TOML,
        vec![(
            add("13021", json!({ "length": 0, "register_type": "input" })),
            Refused {
                error: "at least one register",
                why: "facts 5: a frame of no registers is refused, not written as length = 0 with a 16-bit seed",
            },
        )],
    );
    check(
        "New Modbus frame seeds one signal: coil, four coils, no byte order",
        TOML,
        vec![(
            add("100", json!({ "length": 4, "register_type": "coil" })),
            differs(
                seeded(
                    "100",
                    "length = 4\nregister_type = \"coil\"",
                    "bit_length = 4",
                ),
                SEED,
            ),
        )],
    );
    check(
        "New Modbus frame seeds one signal: discrete, one input",
        TOML,
        vec![(
            add("200", json!({ "length": 1, "register_type": "discrete" })),
            differs(
                seeded("200", "register_type = \"discrete\"", "bit_length = 1"),
                SEED,
            ),
        )],
    );
    check(
        "New Modbus frame seeds one signal: no register type",
        TOML,
        vec![(
            add("300", json!({ "length": 3 })),
            differs(
                seeded("300", "length = 3", "bit_length = 48\nbyte_order = \"big\""),
                SEED,
            ),
        )],
    );
    check(
        "New Modbus frame seeds one signal: a key of spaces names the signal value",
        TOML,
        vec![(
            add("  ", json!({ "length": 1, "register_type": "holding" })),
            Refused {
                error: "a frame key is required",
                why: "facts 5: a blank key is refused, not saved as new_register with a signal named value",
            },
        )],
    );
    check(
        "Editing a Modbus frame seeds nothing",
        TOML,
        vec![(
            json!([{ "op": "SetFrame", "protocol": "modbus", "key": "5000", "rename_from": "5000",
                "frame": { "length": 2, "register_type": "input" } }]),
            Same,
        )],
    );
    check(
        "A blank frame identifier is refused before any op",
        TOML,
        vec![(
            json!([{ "op": "AddFrame", "protocol": "can", "key": "", "frame": { "length": 8 } }]),
            Refused {
                error: "a frame key is required",
                why: "the desktop refuses it too",
            },
        )],
    );
}

#[test]
fn editing_a_tree_node_and_saving_it_unchanged() {
    let can = with(
        "[meta]\nname = \"x\"\nversion = 1\n\n[meta.can]\ndefault_extended = false\ndefault_fd = false\n",
        "[frame.can.\"0x100\"]\nlength = 8\ntransmitter = \"BMS\"\ninterval_ms = 100\n\n\
         [frame.can.\"0x200\"]\nlength = 8\nbus = 1\ncopy = \"0x100\"\nmirror_of = \"0x300\"\nnotes = \"n\"\n\n\
         [frame.can.\"0x300\"]\nlength = 8\n",
    );
    let save = |protocol: &str, key: &str, frame: Value| json!([{ "op": "SetFrame", "protocol": protocol, "key": key, "rename_from": key, "frame": frame }]);
    check(
        "Editing a can tree node, then saving it unchanged: 0x200",
        &can,
        vec![(
            save("can", "0x200", json!({ "length": 8, "transmitter": "BMS", "interval": 100, "notes": ["n"],
                "extended": false, "fd": false, "bus": 1, "copy": "0x100", "mirror_of": "0x300" })),
            differs(
                can.replace("length = 8\nbus = 1", "bus = 1"),
                "facts 2, D7: extended = false is [meta.can]'s default, so not added; length 8 is copy 0x100's, so it goes; one note stays a string",
            ),
        )],
    );
    let modbus = "[meta]\nname = \"x\"\nversion = 1\n\n[meta.modbus]\ndefault_interval = 1000\n\n\
                  [frame.modbus.battery_power]\nregister_number = 13021\nnode_address = 3\nregister_type = \"input\"\n\n\
                  [frame.modbus.\"5000\"]\n";
    check(
        "Editing a modbus tree node, then saving it unchanged: battery_power",
        modbus,
        vec![(
            save(
                "modbus",
                "battery_power",
                json!({ "length": 1, "interval": 1000, "register_number": 13021,
                "node_address": 3, "register_type": "input" }),
            ),
            Same,
        )],
    );
    check(
        "Editing a modbus tree node, then saving it unchanged: 5000",
        modbus,
        vec![(
            save(
                "modbus",
                "5000",
                json!({ "length": 1, "interval": 1000, "register_number": 5000, "register_type": "holding" }),
            ),
            differs(
                modbus,
                "facts 1: the key names the register, so register_number is not written",
            ),
        )],
    );
    let serial = with(
        TOML,
        "[frame.serial.\"0x20\"]\nlength = 16\ndelimiter = [192]\n",
    );
    check(
        "Editing a serial tree node, then saving it unchanged: 0x20",
        &serial,
        vec![(
            save(
                "serial",
                "0x20",
                json!({ "length": 16, "delimiter": [192] }),
            ),
            Same,
        )],
    );
    let inverter = read("modbus.toml");
    check(
        "Editing then saving a Modbus frame as the tree shows it: the model's byte length becomes the register count",
        &inverter,
        vec![(
            save("modbus", "5000", json!({ "length": 2, "interval": 1000, "register_number": 5000, "node_address": 3,
                "register_type": "input", "notes": ["Running state", "Read every second"] })),
            differs(
                inverter.clone(),
                "facts 1, D7: the length is the model's register count, 2, not its byte length, 4; the key names the register and the interval is [meta.modbus]'s, so nothing changes",
            ),
        )],
    );
    let legacy = "[meta]\nname = \"x\"\nversion = 1\n\n[meta.can]\ndefault_interval = 100\n\n\
                  [frame.can.\"0x100\"]\nlength = 8\n\n\
                  [frame.can.\"0x200\"]\ncopy = \"0x100\"\ntransmitter = \"BMS\"\nnotes = \"n\"\n";
    check(
        "Editing then saving a CAN frame in the legacy editor",
        legacy,
        vec![(
            save(
                "can",
                "0x200",
                json!({ "length": 8, "transmitter": "BMS", "interval": 100, "notes": ["n"], "copy": "0x100" }),
            ),
            Same,
        )],
    );
}

#[test]
fn mux_names() {
    let path = |p: &Value| -> Vec<String> { serde_json::from_value(p.clone()).unwrap() };
    let calls: Value = serde_json::from_str(&read("authoring.json")).unwrap();
    let calls = calls["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "Mux names minted from the frame key, start bit and length")
        .unwrap()["input"]
        .clone();
    let named: Vec<Result<String, String>> = calls
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            mux_name(
                &path(&c[0]),
                c[1].as_u64().unwrap() as u32,
                c[2].as_u64().unwrap() as u32,
            )
        })
        .collect();
    let ts = golden("Mux names minted from the frame key, start bit and length");
    let ts: Vec<&str> = ts
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    let pinned: [(&str, Result<&str, &str>, &str); 8] = [
        ("mux_1823_0_8", Ok("mux_1823_0_8"), ""),
        ("mux_1823_8_4", Ok("mux_1823_8_4"), ""),
        ("mux_32_24_8", Ok("mux_32_24_8"), ""),
        (
            "mux_NaN_0_8",
            Ok("mux_heartbeat_0_8"),
            "facts 6: a frame keyed by a name is named by its key",
        ),
        ("mux_1823_3_8_8", Ok("mux_1823_3_8_8"), ""),
        (
            "mux_1823_0-3_16_8",
            Ok("mux_1823_0_3_16_8"),
            "facts 6: a range case is reduced to [A-Za-z0-9_]",
        ),
        (
            "mux_1823_1_24_8",
            Ok("mux_1823_3_1_24_8"),
            "every case on the path is in the name, so nested muxes cannot collide",
        ),
        (
            "mux_256_0_8",
            Err("'0x100' is not a frame or mux case"),
            "the owner must be a frame or mux case path",
        ),
    ];
    for ((lib, name), (pinned_ts, pinned_lib, why)) in named.iter().zip(&ts).zip(pinned) {
        assert_eq!(*name, pinned_ts);
        assert_eq!(
            lib.as_deref(),
            pinned_lib.map_err(String::from).as_deref(),
            "{why}"
        );
    }

    let added = golden("Adding a mux: the default name and owner path");
    let added: Vec<_> = added
        .as_array()
        .unwrap()
        .iter()
        .map(|a| mux_name(&path(&a["path"]), 0, 8).unwrap())
        .collect();
    assert_eq!(
        added,
        ["mux_1823_0_8", "mux_256_0_8", "mux_status_0_8"],
        "facts 6: the TypeScript names status mux_NaN_0_8"
    );

    let nested = golden("Adding a nested mux under a case");
    let owner = path(&nested["path"]);
    assert_eq!(mux_name(&owner, 0, 8).unwrap(), nested["fields"]["name"]);
}

#[test]
fn form_state_cases_exist() {
    for name in FORM_STATE {
        golden(name);
    }
}
