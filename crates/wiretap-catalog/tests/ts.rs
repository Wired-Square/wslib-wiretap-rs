#![cfg(feature = "ts")]
//! Each declaration as the desktop's generated file declares it, under its
//! `Config` (`large_int` as `number`), doc comments aside.

use ts_rs::{Config, TS};
use wiretap_catalog::model::{
    CanConfig, Catalog, ChecksumConfig, ChecksumParameters, Confidence, DisplayHint,
    EffectiveDefaults, Frame, FrameChecksum, FrameTunnel, FunctionCode, HeaderField,
    HeaderFieldPosition, Meta, ModbusConfig, Mux, MuxCase, NodeDef, Protocol, RegisterType,
    SerialConfig, Signal, SignalFormat, TunnelProtocol, ValidationError,
};
use wiretap_catalog::{
    DiffKind, DiffRow, FrameLayout, LayoutRange, LengthRule, RangeKind, RtuSettings, Selector,
    VendorLen,
};

fn decl<T: TS>() -> String {
    T::decl(&Config::new().with_large_int("number"))
        .lines()
        .filter(|line| !line.starts_with("/**") && !line.starts_with(" *"))
        .collect()
}

#[test]
fn a_diff_row_is_the_editors_diff_line() {
    assert_eq!(
        decl::<DiffKind>(),
        r#"type DiffKind = "context" | "add" | "remove";"#
    );
    assert_eq!(
        decl::<DiffRow>(),
        "type DiffLine = { kind: DiffKind, text: string, oldLine: number | null, newLine: number | null, };"
    );
}

#[test]
fn a_register_type_is_its_lower_case_name() {
    assert_eq!(
        decl::<RegisterType>(),
        r#"type RegisterType = "input" | "holding" | "coil" | "discrete";"#
    );
}

/// The desktop's `ModbusRtuOptions.ts`, from its `export type` line on.
#[test]
fn rtu_settings_are_the_desktops_modbus_rtu_options() {
    let full = RtuSettings::decl(&Config::new().with_large_int("number"));
    assert_eq!(
        full,
        r#"type ModbusRtuOptions = { 
/**
 * Device address filter (1-247). `None` syncs on any valid address.
 */
device_address?: number, 
/**
 * Whether a message has to pass its CRC to be framed. `false` is a lenient
 * mode, not "no framing" — see `CrcPolicy::Lenient`.
 */
validate_crc?: boolean, 
/**
 * Function codes the RTU length rules do not model but this line carries.
 * Framed by CRC search instead; empty leaves stock Modbus untouched.
 */
vendor_functions?: Array<number>, 
/**
 * Whether address 0 may start a message, for a master that broadcasts.
 */
allow_broadcast?: boolean, 
/**
 * Frame every function code, declared or not. What a tap on an unknown
 * line wants, at the cost of a fabricated message about once in 260
 * resyncs — see `ModbusRtuStream::frame_any_function`.
 */
any_function?: boolean, };"#
    );
}

/// Served camelCase; a field serde skips when empty is optional.
#[test]
fn a_serial_config_keeps_its_served_camel_case_shape() {
    assert_eq!(
        decl::<SerialConfig>(),
        "type SerialConfig = { encoding?: string | null, byteOrder?: Endianness | null, \
         frameIdMask?: number | null, headerLength?: number | null, \
         minFrameLength?: number | null, checksum?: ChecksumConfig | null, \
         fields?: { [key in string]: HeaderField }, frameIdStartByte?: number | null, \
         frameIdBytes?: number | null, frameIdByteOrder?: Endianness | null, \
         sourceAddressStartByte?: number | null, sourceAddressBytes?: number | null, \
         sourceAddressByteOrder?: Endianness | null, \
         headerFields?: Array<HeaderFieldPosition>, };"
    );
    assert_eq!(
        decl::<ChecksumConfig>(),
        "type ChecksumConfig = { algorithm: string, startByte: number, byteLength: number, \
         calcStartByte: number, calcEndByte?: number | null, bigEndian: boolean, };"
    );
    assert_eq!(
        decl::<HeaderField>(),
        "type HeaderField = { mask?: number | null, shift?: number | null, \
         format?: string | null, endianness?: Endianness | null, startByte?: number | null, \
         bytes?: number | null, };"
    );
    assert_eq!(
        decl::<HeaderFieldPosition>(),
        "type HeaderFieldPosition = { name: string, mask?: number | null, \
         byteOrder: Endianness, format: string, startByte: number, bytes: number, };"
    );
}

/// The resolved catalogue as `catalog.parse` serves it. A field serde skips when
/// empty is optional; numeric map keys are JSON object keys, so strings.
#[test]
fn the_resolved_model_is_served_camel_case() {
    assert_eq!(
        decl::<Protocol>(),
        "type Protocol = \"can\" | \"serial\" | \"modbus\";"
    );
    assert_eq!(
        decl::<SignalFormat>(),
        "type SignalFormat = \"ascii\" | \"utf8\" | \"hex\" | \"enum\" | \"unix_time\" | \"other\";"
    );
    assert_eq!(
        decl::<Confidence>(),
        "type Confidence = \"none\" | \"low\" | \"medium\" | \"high\";"
    );
    assert_eq!(
        decl::<DisplayHint>(),
        "type DisplayHint = { widget: string, [option: string]: unknown };"
    );
    assert_eq!(
        decl::<Signal>(),
        "type Signal = { name?: string | null, startBit?: number | null, \
         bitLength?: number | null, signed?: boolean | null, endianness?: Endianness | null, \
         wordOrder?: Endianness | null, factor?: number | null, offset?: number | null, \
         unit?: string | null, min?: number | null, max?: number | null, \
         format?: SignalFormat | null, enum?: { [key in string]: string } | null, \
         confidence?: Confidence | null, display?: DisplayHint | null, \
         notes?: Array<string>, inherited?: boolean, modbusRegister?: number | null, \
         modbusRegisterCount?: number | null, };"
    );
    assert_eq!(
        decl::<MuxCase>(),
        "type MuxCase = { signals: Array<Signal>, mux?: Mux | null, notes?: Array<string>, };"
    );
    assert_eq!(
        decl::<Mux>(),
        "type Mux = { name?: string | null, startBit: number, bitLength: number, \
         default?: string | null, notes?: Array<string>, \
         cases: { [key in string]: MuxCase }, caseOrder: Array<string>, };"
    );
    assert_eq!(
        decl::<FrameChecksum>(),
        "type FrameChecksum = { name?: string | null, algorithm: string, startByte: number, \
         byteLength: number, endianness?: Endianness | null, calcStartByte: number, \
         calcEndByte?: number | null, notes?: Array<string>, polynomial?: number | null, \
         init?: number | null, xorOut?: number | null, reflectIn?: boolean | null, \
         reflectOut?: boolean | null, offset?: number | null, };"
    );
    assert_eq!(
        decl::<ChecksumParameters>(),
        "type ChecksumParameters = { polynomial?: number | null, init?: number | null, \
         xorOut?: number | null, reflectIn?: boolean | null, reflectOut?: boolean | null, \
         offset?: number | null, };"
    );
    assert_eq!(
        decl::<TunnelProtocol>(),
        "type TunnelProtocol = \"modbus_rtu\";"
    );
    assert_eq!(
        decl::<FrameTunnel>(),
        "type FrameTunnel = { protocol: TunnelProtocol, deviceAddress?: number | null, \
         vendorFunctions?: Array<number>, allowBroadcast?: boolean, notes?: Array<string>, };"
    );
    assert_eq!(
        decl::<Frame>(),
        "type Frame = { key: string, frameId: number, protocol: Protocol, \
         name?: string | null, length: number, transmitter?: string | null, \
         interval?: number | null, bus?: number | null, isExtended?: boolean | null, \
         isFd?: boolean | null, signals: Array<Signal>, mux?: Mux | null, \
         tunnel?: FrameTunnel | null, mirrorOf?: string | null, copyFrom?: string | null, \
         modbusRegisterType?: RegisterType | null, modbusRegisterCount?: number | null, \
         modbusNode?: string | null, modbusDeviceAddress?: number | null, \
         delimiter?: Array<number> | null, notes?: Array<string>, \
         checksums?: Array<FrameChecksum>, inheritedFields?: Array<string>, };"
    );
    assert_eq!(
        decl::<CanConfig>(),
        "type CanConfig = { defaultByteOrder?: Endianness | null, \
         defaultInterval?: number | null, defaultExtended?: boolean | null, \
         defaultFd?: boolean | null, frameIdMask?: number | null, \
         fields?: { [key in string]: HeaderField }, };"
    );
    assert_eq!(
        decl::<ModbusConfig>(),
        "type ModbusConfig = { deviceAddress?: number | null, registerBase?: number | null, \
         defaultInterval?: number | null, defaultByteOrder?: Endianness | null, \
         defaultWordOrder?: Endianness | null, \
         functionCodes?: { [key in string]: FunctionCode }, };"
    );
    assert_eq!(
        decl::<FunctionCode>(),
        "type FunctionCode = { name?: string | null, lengths?: Array<LengthRule>, \
         notes?: Array<string>, };"
    );
    assert_eq!(
        decl::<Meta>(),
        "type Meta = { name: string, version: number, defaultFrame?: Protocol | null, };"
    );
    assert_eq!(
        decl::<NodeDef>(),
        "type NodeDef = { name: string, deviceAddress?: number | null, \
         notes?: Array<string>, };"
    );
    assert_eq!(
        decl::<EffectiveDefaults>(),
        "type EffectiveDefaults = { canByteOrder: Endianness, serialByteOrder: Endianness, \
         modbusByteOrder: Endianness, modbusWordOrder: Endianness, \
         modbusRegisterBase: number, };"
    );
    assert_eq!(
        decl::<Catalog>(),
        "type Catalog = { meta: Meta, protocol: Protocol, can?: CanConfig | null, \
         serial?: SerialConfig | null, modbus?: ModbusConfig | null, frames: Array<Frame>, \
         nodes?: Array<NodeDef>, effectiveDefaults: EffectiveDefaults, };"
    );
    assert_eq!(
        decl::<ValidationError>(),
        "type ValidationError = { field: string, message: string, };"
    );
}

/// `VendorLen` is served through its catalogue form.
#[test]
fn a_length_rule_is_the_catalogues_function_code_layout() {
    assert_eq!(
        decl::<LengthRule>(),
        "type LengthRule = { when?: Selector | null, len: VendorLen, };"
    );
    assert_eq!(
        decl::<Selector>(),
        "type Selector = { offset: number, value: number, };"
    );
    assert_eq!(
        decl::<VendorLen>(),
        "type VendorLen = { fixed: number } | { countAt: number, overhead: number };"
    );
}

#[test]
fn a_frame_layout_is_the_bit_layout_preview() {
    assert_eq!(
        decl::<FrameLayout>(),
        "type FrameLayout = { byteLength: number, ranges: Array<LayoutRange>, };"
    );
    assert_eq!(
        decl::<LayoutRange>(),
        "type LayoutRange = { name?: string | null, startBit: number, bitLength: number, \
         kind: RangeKind, edited?: boolean, };"
    );
    assert_eq!(
        decl::<RangeKind>(),
        "type RangeKind = \"signal\" | \"selector\" | \"checksum\";"
    );
}
