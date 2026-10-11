#![cfg(feature = "ts")]
//! The typed edit ops as `catalog.edits` deserialises them, under the desktop's
//! `Config`, doc comments aside. Every key serde fills by default is optional.

use ts_rs::{Config, TS};
use wiretap_catalog::edit::{
    CanConfigFields, EditOp, FrameFields, HeaderFieldFields, Mask, MetaFields, ModbusConfigFields,
    MuxFields, SerialChecksumFields, SerialConfigFields, SignalFields,
};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.trim_start().starts_with("/**") && !line.trim_start().starts_with('*'))
        .collect()
}

/// Blank text and one note or many are accepted where the op folds them.
#[test]
fn the_field_sets_are_snake_case() {
    assert_eq!(
        decl::<SignalFields>(),
        "type SignalFields = { name?: string, start_bit?: number, bit_length?: number, \
         factor?: number | null, offset?: number | null, unit?: string | null, \
         signed?: boolean | null, byte_order?: Endianness | \"\" | null, \
         min?: number | null, max?: number | null, format?: string | null, \
         confidence?: Confidence | \"\" | null, enum?: { [key in string]: string }, \
         notes?: string | Array<string> | null, display?: DisplayHint | null, };"
    );
    assert_eq!(
        decl::<FrameFields>(),
        "type FrameFields = { length?: number | null, transmitter?: string | null, \
         interval_ms?: number | null, notes?: string | Array<string> | null, \
         extended?: boolean | null, fd?: boolean | null, bus?: number | null, \
         copy?: string | null, mirror_of?: string | null, delimiter?: Array<number>, \
         register_number?: number | null, node_address?: number | null, \
         register_type?: RegisterType | null, };"
    );
    assert_eq!(
        decl::<MuxFields>(),
        "type MuxFields = { name?: string, start_bit?: number, bit_length?: number, \
         notes?: string | Array<string> | null, };"
    );
    assert_eq!(
        decl::<MetaFields>(),
        "type MetaFields = { name: string, version: number, default_frame?: Protocol | null, \
         };"
    );
    assert_eq!(
        decl::<ModbusConfigFields>(),
        "type ModbusConfigFields = { device_address?: number | null, \
         register_base?: number | null, default_interval?: number | null, \
         default_byte_order?: Endianness | null, default_word_order?: Endianness | null, };"
    );
}

#[test]
fn a_header_field_is_a_mask_or_a_position() {
    assert_eq!(
        decl::<CanConfigFields>(),
        "type CanConfigFields = { default_byte_order?: Endianness | null, \
         default_interval?: number | null, default_extended?: boolean | null, \
         default_fd?: boolean | null, frame_id_mask?: Mask | null, \
         fields?: { [key in string]: HeaderFieldFields }, };"
    );
    assert_eq!(
        decl::<SerialConfigFields>(),
        "type SerialConfigFields = { encoding?: string | null, \
         byte_order?: Endianness | null, frame_id_mask?: Mask | null, \
         header_length?: number | null, min_frame_length?: number | null, \
         checksum?: SerialChecksumFields | null, \
         fields?: { [key in string]: HeaderFieldFields }, };"
    );
    assert_eq!(
        decl::<HeaderFieldFields>(),
        "type HeaderFieldFields = { mask?: Mask, start_byte?: number | null, \
         bytes?: number | null, shift?: number | null, format?: string | null, \
         byte_order?: Endianness | null, };"
    );
    assert_eq!(decl::<Mask>(), "type Mask = number | string;");
    assert_eq!(
        decl::<SerialChecksumFields>(),
        "type SerialChecksumFields = { algorithm: string, start_byte: number, \
         byte_length?: number, calc_start_byte?: number, calc_end_byte?: number | null, \
         big_endian?: boolean, };"
    );
}

#[test]
fn every_edit_op_is_tagged_on_op() {
    assert_eq!(
        decl::<EditOp>(),
        "type EditOp = { \"op\": \"SetTable\", path: Array<string>, \
         value: { [key in string]: unknown }, managed_keys?: Array<string>, \
         replace_contents?: boolean, sort_parent_numeric?: boolean, \
         skip_if_exists?: boolean, error_if_exists?: boolean, } | { \"op\": \"UpsertFrame\", \
         protocol: string, key: string, value: { [key in string]: unknown }, \
         managed_keys?: Array<string>, rename_from?: string | null, \
         initial_signals?: Array<{ [key in string]: unknown }>, \
         } | { \"op\": \"UpsertArrayItem\", array_path: Array<string>, \
         value: { [key in string]: unknown }, index?: number | null, \
         sort_keys?: Array<string>, } | { \"op\": \"RemoveArrayItem\", \
         array_path: Array<string>, index: number, remove_if_empty?: boolean, \
         } | { \"op\": \"RenameKey\", parent_path: Array<string>, old: string, new: string, \
         set_value?: { [key in string]: unknown } | null, managed_keys?: Array<string>, \
         sort_numeric?: boolean, update_transmitter_refs?: boolean, \
         error_if_exists?: boolean, } | { \"op\": \"DeleteAtPath\", path: Array<string>, \
         sort_parent_numeric?: boolean, } | { \"op\": \"UpsertSignal\", \
         owner_path: Array<string>, index?: number | null, signal: SignalFields, \
         } | { \"op\": \"SetFrame\", protocol: Protocol, key: string, \
         rename_from?: string | null, frame: FrameFields, } | { \"op\": \"AddFrame\", \
         protocol: Protocol, key: string, frame: FrameFields, } | { \"op\": \"SetMux\", \
         owner_path: Array<string>, mux: MuxFields, } | { \"op\": \"SetMeta\", \
         meta: MetaFields, } | { \"op\": \"SetCanConfig\", config: CanConfigFields, \
         } | { \"op\": \"SetSerialConfig\", config: SerialConfigFields, \
         } | { \"op\": \"SetModbusConfig\", config: ModbusConfigFields, };"
    );
}
