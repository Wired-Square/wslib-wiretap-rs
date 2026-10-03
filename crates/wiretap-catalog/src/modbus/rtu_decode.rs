//! A recovered RTU message as signals: its header, and its register block
//! decoded against the catalogue or, failing that, as raw values.
//!
//! Request and response share one CAN id, so the synthesised names carry the
//! side they came from, or a response would overwrite its request by name.

use super::{coils_to_bytes, exception_name, function_name};
use crate::decode::{decode_frame, Decoded};
use crate::modbus_rtu_stream::{Direction, ModbusRtuMessage};
use crate::model::{Catalog, Frame, RegisterType, SignalFormat};

/// A message's signals. The synthesised `Modbus_{Request|Response}_*` names are
/// a stable contract: saved layouts and dashboards key on them.
#[derive(Debug, Clone, PartialEq)]
pub struct RtuDecode<'c> {
    /// `Modbus_{side}_{Device,Function,Register,Quantity,Exception}`, each when present.
    pub header: Vec<Decoded>,
    /// The register frame's signals, else `Modbus_{side}_Value_{i}`.
    pub values: Vec<Decoded>,
    /// The register frame that decoded `values`.
    pub frame: Option<&'c Frame>,
}

/// A function code and its name, e.g. `0x03 Read Holding Registers`.
pub fn function_label(function: u8) -> String {
    let name = if function & 0x80 != 0 {
        "Exception"
    } else {
        function_name(function).unwrap_or("Unknown")
    };
    format!("0x{function:02X} {name}")
}

/// An exception code and its name, e.g. `0x02 Illegal Data Address`.
pub fn exception_label(code: u8) -> String {
    format!("0x{code:02X} {}", exception_name(code).unwrap_or("Unknown"))
}

/// Decodes a message into its header signals and its register block.
pub fn decode_rtu_message<'c>(catalog: &'c Catalog, msg: &ModbusRtuMessage) -> RtuDecode<'c> {
    let side = match msg.direction {
        Direction::Request => "Request",
        Direction::Response => "Response",
    };
    let (values, frame) = register_signals(catalog, msg, side);
    RtuDecode {
        header: header_signals(msg, side),
        values,
        frame,
    }
}

fn signal(name: String, value: f64, display: String, format: Option<SignalFormat>) -> Decoded {
    Decoded {
        name,
        value,
        scaled: value,
        display,
        unit: None,
        mux_value: None,
        format,
    }
}

fn header_signals(msg: &ModbusRtuMessage, side: &str) -> Vec<Decoded> {
    let name = |field: &str| format!("Modbus_{side}_{field}");

    let mut out = vec![
        signal(
            name("Device"),
            f64::from(msg.device_address),
            msg.device_address.to_string(),
            None,
        ),
        signal(
            name("Function"),
            f64::from(msg.function),
            function_label(msg.function),
            Some(SignalFormat::Enum),
        ),
    ];
    if let Some(reg) = msg.start_register {
        out.push(signal(
            name("Register"),
            f64::from(reg),
            format!("0x{reg:04X}"),
            Some(SignalFormat::Hex),
        ));
    }
    if let Some(qty) = msg.quantity {
        out.push(signal(
            name("Quantity"),
            f64::from(qty),
            qty.to_string(),
            None,
        ));
    }
    if let Some(code) = msg.exception {
        out.push(signal(
            name("Exception"),
            f64::from(code),
            exception_label(code),
            Some(SignalFormat::Enum),
        ));
    }
    out
}

fn register_signals<'c>(
    catalog: &'c Catalog,
    msg: &ModbusRtuMessage,
    side: &str,
) -> (Vec<Decoded>, Option<&'c Frame>) {
    // Coils are re-packed rather than taken from `data_block()`, which for a
    // single-coil write opens with the register address.
    let coils = msg.coils();
    let bytes = if coils.is_empty() {
        msg.register_bytes()
    } else {
        coils_to_bytes(coils)
    };
    if bytes.is_empty() {
        return (Vec::new(), None);
    }
    let bank = RegisterType::from_function_code(msg.function).unwrap_or(RegisterType::Holding);
    let matched = msg
        .start_register
        .and_then(|reg| catalog.modbus_register_frame(reg, bank, msg.device_address));
    if let Some(frame) = matched {
        let decoded = decode_frame(catalog, frame, &bytes);
        if !decoded.signals.is_empty() {
            return (decoded.signals, Some(frame));
        }
    }

    let name = |i: usize| format!("Modbus_{side}_Value_{i}");
    let values = if coils.is_empty() {
        msg.registers()
            .iter()
            .enumerate()
            .map(|(i, &r)| {
                signal(
                    name(i),
                    f64::from(r),
                    format!("0x{r:04X}"),
                    Some(SignalFormat::Hex),
                )
            })
            .collect()
    } else {
        coils
            .iter()
            .enumerate()
            .map(|(i, &on)| {
                let bit = u8::from(on);
                signal(name(i), f64::from(bit), bit.to_string(), None)
            })
            .collect()
    };
    (values, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ModbusRtuStream;

    const CATALOG: &str = r#"
[meta]
name = "sbr"
[frame.can."0x1E0"]
length = 8
[frame.can."0x1E0".tunnel]
protocol = "modbus_rtu"
device_address = 1

[frame.modbus.charge_limits]
register_number = 19938
register_type = "input"
length = 2
node_address = 1
[[frame.modbus.charge_limits.signals]]
name = "Charge_Current_Limit"
start_bit = 0
bit_length = 16
factor = 0.1
unit = "A"
"#;

    fn catalog() -> Catalog {
        Catalog::parse(CATALOG).unwrap()
    }

    struct Decode {
        signals: Vec<Decoded>,
        frame: Option<String>,
    }

    fn decode_message(msg: &ModbusRtuMessage, catalog: &Catalog) -> Decode {
        let d = decode_rtu_message(catalog, msg);
        Decode {
            signals: [d.header, d.values].concat(),
            frame: d.frame.map(|f| f.key.clone()),
        }
    }

    /// One tunnel for the whole exchange, chunked into 8-byte CAN payloads: a
    /// response inherits its register address from the request before it.
    fn exchange(catalog: &Catalog, messages: &[&str]) -> Vec<ModbusRtuMessage> {
        let declared = catalog.frame(0x1E0).unwrap().tunnel.as_ref().unwrap();
        let mut t = catalog.tunnel_stream(declared);
        let mut out = Vec::new();
        for hex in messages {
            for chunk in hex_bytes(hex).chunks(8) {
                out.extend(t.push(chunk));
            }
        }
        out
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn framed(hex: &str) -> Vec<u8> {
        let mut out = hex_bytes(hex);
        out.extend(wiretap_checksum::algorithms::crc16_modbus_checksum(&out).to_le_bytes());
        out
    }

    fn messages(bodies: &[&str]) -> Vec<ModbusRtuMessage> {
        let mut t = ModbusRtuStream::for_address(Some(1));
        bodies
            .iter()
            .flat_map(|b| t.push_bytes(&framed(b)))
            .collect()
    }

    fn display_of(signals: &[Decoded], name: &str) -> String {
        signals
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no signal {name}"))
            .display
            .clone()
    }

    #[test]
    fn a_coil_response_reads_as_coils_not_registers() {
        // FC01: read 10 coils from 0. Two bytes, the second only partly used —
        // `registers` would pair them into one u16 and call it a register.
        let msgs = messages(&["0101000A000A", "010102D502"]);
        let response = msgs.last().unwrap();
        assert_eq!(response.function, 0x01);

        let out = decode_message(response, &catalog());
        let bit = |i: usize| display_of(&out.signals, &format!("Modbus_Response_Value_{i}"));
        // 0xD5 = 1010 1011 LSB-first, 0x02 = 0100 0000 LSB-first.
        assert_eq!(bit(0), "1");
        assert_eq!(bit(1), "0");
        assert_eq!(bit(2), "1");
        assert_eq!(bit(9), "1");
        // Bounded by the quantity the request asked for, not the byte count.
        assert!(!out
            .signals
            .iter()
            .any(|s| s.name == "Modbus_Response_Value_10"));
    }

    #[test]
    fn a_coil_request_carries_no_coils() {
        // The regression this guards: a request's address and quantity bytes are
        // not a coil block, however much `data_block()` will hand them over.
        let msgs = messages(&["0101000A000A"]);
        let out = decode_message(&msgs[0], &catalog());
        assert!(!out.signals.iter().any(|s| s.name.contains("Value_")));
    }

    #[test]
    fn a_coil_frame_decodes_against_the_packed_block() {
        // The bytes handed to the catalogue are the coils re-packed, not
        // `data_block()`: for FC05 that block opens with the register address, so
        // decoding it directly would read the address as the coil data.
        let msgs = messages(&["0105001AFF00"]);
        let coils = msgs[0].coils();
        assert_eq!(coils, vec![true]);
        assert_eq!(
            crate::modbus::coils_to_bytes(coils),
            vec![0x01],
            "one coil packs to one byte"
        );
        assert_eq!(
            msgs[0].data_block(),
            &hex_bytes("001AFF00")[..],
            "whereas the data block still carries the address"
        );
    }

    #[test]
    fn a_single_coil_write_is_one_coil() {
        // FC05 sets one coil with a flag word: 0xFF00 on, 0x0000 off. One coil,
        // not sixteen bits of a packed block and not a register.
        for (body, expected) in [("0105001AFF00", "1"), ("0105001A0000", "0")] {
            let msgs = messages(&[body]);
            let out = decode_message(&msgs[0], &catalog());
            assert_eq!(display_of(&out.signals, "Modbus_Request_Value_0"), expected);
            assert!(!out.signals.iter().any(|s| s.name.ends_with("_Value_1")));
        }
    }

    #[test]
    fn a_register_read_is_unchanged() {
        let msgs = messages(&["01044DE20002", "010404012C0000"]);
        let out = decode_message(msgs.last().unwrap(), &catalog());
        // Decodes through the catalogue entry, factor and all.
        assert_eq!(display_of(&out.signals, "Charge_Current_Limit"), "30");
    }

    #[test]
    fn a_vendor_message_decodes_to_its_header_alone() {
        let mut t = ModbusRtuStream::for_address(Some(1)).with_vendor_functions(&[0x20]);
        let msgs = t.push_bytes(&framed("012001C803111A0002"));
        assert_eq!(msgs.len(), 1);

        let out = decode_message(&msgs[0], &catalog());
        // Nothing models the body, so there are no values and no register signals.
        assert!(msgs[0].registers().is_empty());
        assert!(!out.signals.iter().any(|s| s.name.contains("Value_")));
        assert!(out.frame.is_none());
        assert_eq!(
            display_of(&out.signals, "Modbus_Request_Function"),
            "0x20 Unknown"
        );
    }

    #[test]
    fn request_decodes_to_header_signals() {
        let cat = catalog();
        let msgs = exchange(&cat, &["01044DE20002C691"]);
        let d = decode_message(&msgs[0], &cat);
        assert_eq!(
            display_of(&d.signals, "Modbus_Request_Function"),
            "0x04 Read Input Registers"
        );
        assert_eq!(display_of(&d.signals, "Modbus_Request_Register"), "0x4DE2");
        assert_eq!(display_of(&d.signals, "Modbus_Request_Quantity"), "2");
    }

    #[test]
    fn response_registers_decode_through_the_catalogue() {
        let cat = catalog();
        let msgs = exchange(&cat, &["01044DE20002C691", "01040401F40000BB8A"]);
        assert_eq!(msgs.len(), 2);

        let d = decode_message(&msgs[1], &cat);
        // 500 * 0.1 = 50 A, via the ordinary decode path.
        assert_eq!(display_of(&d.signals, "Charge_Current_Limit"), "50");
        assert_eq!(d.frame.as_deref(), Some("charge_limits"));
    }

    #[test]
    fn request_and_response_signals_do_not_collide() {
        let cat = catalog();
        let msgs = exchange(&cat, &["01044DE20002C691", "01040401F40000BB8A"]);
        let req: Vec<String> = decode_message(&msgs[0], &cat)
            .signals
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let rsp = decode_message(&msgs[1], &cat).signals;
        // Both sides land in a store keyed by signal name, so no name may
        // appear on both — the response would silently replace the request.
        assert!(rsp.iter().all(|s| !req.contains(&s.name)), "{req:?}");
        // And none of them fakes a mux, which the signal table would render as
        // a mux group with the wrong payload bytes.
        assert!(rsp.iter().all(|s| s.mux_value.is_none()));
    }

    #[test]
    fn an_uncatalogued_register_falls_back_to_raw_values() {
        let cat = catalog();
        // Holding registers, so the input-register catalogue entry must not match.
        let msgs = exchange(
            &cat,
            &["01034DE200067292", "01030C01F40000012C000000C80000D570"],
        );
        let d = decode_message(&msgs[1], &cat);
        assert_eq!(display_of(&d.signals, "Modbus_Response_Value_0"), "0x01F4");
        assert_eq!(display_of(&d.signals, "Modbus_Response_Value_2"), "0x012C");
        assert!(d.frame.is_none());
    }

    #[test]
    fn an_exception_response_is_labelled() {
        let cat = catalog();
        let msgs = exchange(&cat, &["01044DE20002C691", "018402C2C1"]);
        assert_eq!(msgs.len(), 2);
        let d = decode_message(&msgs[1], &cat);
        assert_eq!(
            display_of(&d.signals, "Modbus_Response_Exception"),
            "0x02 Illegal Data Address"
        );
        // The exception answers the request, so it names the register that failed.
        assert_eq!(display_of(&d.signals, "Modbus_Response_Register"), "0x4DE2");
    }

    #[test]
    fn labels_carry_the_code_and_its_name() {
        assert_eq!(function_label(0x03), "0x03 Read Holding Registers");
        assert_eq!(function_label(0x84), "0x84 Exception");
        assert_eq!(function_label(0x20), "0x20 Unknown");
        assert_eq!(exception_label(0x02), "0x02 Illegal Data Address");
        assert_eq!(exception_label(0x7F), "0x7F Unknown");
    }
}
