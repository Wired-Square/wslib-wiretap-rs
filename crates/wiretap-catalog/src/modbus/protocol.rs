//! Modbus wire-protocol facts: what a request may ask for, and which bank a
//! function code speaks to.
//!
//! These are properties of Modbus itself, not of any catalogue, and every layer
//! that talks to a device needs them — the RTU reassembler to judge whether a
//! candidate message contradicts itself, a poller to size a read, a scanner to
//! clamp a chunk. Each had grown its own copy. This is the one place the numbers
//! and the function-code table appear.

use crate::model::RegisterType;

/// Longest Modbus RTU message: address + function + byte count + 252 data + CRC.
pub const MAX_RTU_LEN: usize = 256;

/// Shortest Modbus RTU message: address + function + CRC, carrying no body at
/// all. Nothing the spec defines is this short — the smallest is a five-byte
/// exception — but a vendor code may be, and a boundary search has to start
/// somewhere the wire format allows rather than somewhere a code happens to use.
pub const MIN_RTU_LEN: usize = 4;

/// Largest data block any read or write carries: 125 registers, or 2000 coils
/// packed eight to a byte.
pub const MAX_DATA_BYTES: usize = 250;

/// What one Modbus request may read or write, per the spec. A message claiming
/// more than this contradicts itself, whatever its CRC says, and a read asking
/// for more than this is one the device is entitled to refuse.
pub const MAX_REGISTERS_PER_READ: u16 = 125;
pub const MAX_COILS_PER_READ: u16 = 2000;
pub const MAX_REGISTERS_PER_WRITE: u16 = 123;
pub const MAX_COILS_PER_WRITE: u16 = 1968;

/// The name of a Modbus function code, or `None` for one this library does not
/// model. Bare names: how they are presented — with the code, translated, or at
/// all — is the caller's business.
pub fn function_name(function: u8) -> Option<&'static str> {
    Some(match function {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding Registers",
        0x04 => "Read Input Registers",
        0x05 => "Write Single Coil",
        0x06 => "Write Single Register",
        0x0F => "Write Multiple Coils",
        0x10 => "Write Multiple Registers",
        _ => return None,
    })
}

/// The name of a Modbus exception code, or `None` for one the spec does not
/// define. Bare names, as [`function_name`]. Narrower than the reassembler's
/// `0x01..=0x0B` plausibility gate: `0x07` and `0x09` pass that and have no name.
pub fn exception_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "Illegal Function",
        0x02 => "Illegal Data Address",
        0x03 => "Illegal Data Value",
        0x04 => "Server Device Failure",
        0x05 => "Acknowledge",
        0x06 => "Server Device Busy",
        0x08 => "Memory Parity Error",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Device Failed To Respond",
        _ => return None,
    })
}

/// A Modbus exception code, named where the spec names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExceptionCode {
    IllegalFunction,
    IllegalDataAddress,
    IllegalDataValue,
    ServerDeviceFailure,
    Acknowledge,
    ServerDeviceBusy,
    MemoryParityError,
    GatewayPathUnavailable,
    GatewayTargetFailedToRespond,
    Other(u8),
}

impl ExceptionCode {
    pub fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::IllegalFunction,
            0x02 => Self::IllegalDataAddress,
            0x03 => Self::IllegalDataValue,
            0x04 => Self::ServerDeviceFailure,
            0x05 => Self::Acknowledge,
            0x06 => Self::ServerDeviceBusy,
            0x08 => Self::MemoryParityError,
            0x0A => Self::GatewayPathUnavailable,
            0x0B => Self::GatewayTargetFailedToRespond,
            other => Self::Other(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::IllegalFunction => 0x01,
            Self::IllegalDataAddress => 0x02,
            Self::IllegalDataValue => 0x03,
            Self::ServerDeviceFailure => 0x04,
            Self::Acknowledge => 0x05,
            Self::ServerDeviceBusy => 0x06,
            Self::MemoryParityError => 0x08,
            Self::GatewayPathUnavailable => 0x0A,
            Self::GatewayTargetFailedToRespond => 0x0B,
            Self::Other(code) => code,
        }
    }
}

impl std::fmt::Display for ExceptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match exception_name(self.code()) {
            Some(name) => f.write_str(name),
            None => write!(f, "Exception {:#04x}", self.code()),
        }
    }
}

/// Modbus registers → big-endian byte buffer, MSB first per register: the
/// standard on-wire order.
pub fn registers_to_bytes(regs: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(regs.len() * 2);
    for &r in regs {
        bytes.push((r >> 8) as u8);
        bytes.push((r & 0xff) as u8);
    }
    bytes
}

/// A data block back as big-endian `u16` registers, the inverse of
/// [`registers_to_bytes`]. A trailing odd byte — only reachable from an odd
/// `byte_count`, which no read or write produces — is dropped rather than
/// zero-extended into a bogus register.
pub fn bytes_to_registers(block: &[u8]) -> Vec<u16> {
    block
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Coils → packed bytes, eight to a byte and least-significant bit first, the
/// order Modbus reads them back in. A partial trailing byte is zero-filled.
pub fn coils_to_bytes(coils: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0u8; coils.len().div_ceil(8)];
    for (i, &on) in coils.iter().enumerate() {
        if on {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    bytes
}

/// A packed block back as `count` coils, the inverse of [`coils_to_bytes`].
/// The count is asked for rather than inferred: only the request says how many
/// of the last byte's bits are coils and how many are the zero fill. A `count`
/// larger than the block holds is clamped to it.
pub fn bytes_to_coils(block: &[u8], count: usize) -> Vec<bool> {
    (0..count.min(block.len() * 8))
        .map(|i| block[i / 8] & (1 << (i % 8)) != 0)
        .collect()
}

/// The function-code half of [`RegisterType`]. Kept beside the wire constants
/// rather than with the bank semantics in [`crate::model`], because it is the
/// same table the caps below are chosen from.
impl RegisterType {
    /// Which bank a function code reads or writes, or `None` for a code that
    /// addresses no register bank (diagnostics, file records, and anything not
    /// modelled here). The high bit is masked first, so an exception response
    /// resolves to the bank its request asked for.
    pub fn from_function_code(function: u8) -> Option<RegisterType> {
        Some(match function & 0x7F {
            0x01 | 0x05 | 0x0F => RegisterType::Coil,
            0x02 => RegisterType::Discrete,
            0x03 | 0x06 | 0x10 => RegisterType::Holding,
            0x04 => RegisterType::Input,
            _ => return None,
        })
    }

    /// The function code that reads this bank.
    pub fn read_function_code(self) -> u8 {
        match self {
            RegisterType::Coil => 0x01,
            RegisterType::Discrete => 0x02,
            RegisterType::Holding => 0x03,
            RegisterType::Input => 0x04,
        }
    }

    /// How many of this bank one request may read. Coils pack eight to a byte,
    /// so far more of them fit in the same data block.
    pub fn max_per_read(self) -> u16 {
        if self.is_register_bank() {
            MAX_REGISTERS_PER_READ
        } else {
            MAX_COILS_PER_READ
        }
    }

    /// How many data bytes `quantity` of this bank occupies on the wire.
    /// Register banks take two bytes each; coil banks pack eight to a byte.
    pub fn data_bytes(self, quantity: u16) -> usize {
        let quantity = quantity as usize;
        if self.is_register_bank() {
            quantity * 2
        } else {
            quantity.div_ceil(8)
        }
    }

    /// How many bits one address of this bank holds: 16 for a register, one for
    /// a coil. Every span below is this number and a division, which is why it
    /// is written down once.
    pub fn bits_per_address(self) -> u32 {
        if self.is_register_bank() {
            16
        } else {
            1
        }
    }

    /// Which address of this bank a signal's bit offset falls in, counted from
    /// the frame's base. A coil bank holds one bit per address, so a bit offset
    /// *is* a coil offset.
    pub fn address_offset(self, start_bit: u32) -> u32 {
        start_bit / self.bits_per_address()
    }

    /// How many addresses of this bank a signal spans. A partial address costs a
    /// whole one, the same rounding [`Self::data_bytes`] gives a partial byte.
    pub fn address_span(self, bit_length: u32) -> u16 {
        bit_length.div_ceil(self.bits_per_address()) as u16
    }

    /// How many of this bank one request may write, or `None` for a read-only
    /// bank. Lower than the read cap: a write request spends header bytes on the
    /// quantity and byte count that a read response does not.
    pub fn max_per_write(self) -> Option<u16> {
        match self {
            RegisterType::Holding => Some(MAX_REGISTERS_PER_WRITE),
            RegisterType::Coil => Some(MAX_COILS_PER_WRITE),
            RegisterType::Input | RegisterType::Discrete => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_codes_round_trip_through_their_bank() {
        for rt in [
            RegisterType::Coil,
            RegisterType::Discrete,
            RegisterType::Holding,
            RegisterType::Input,
        ] {
            assert_eq!(
                RegisterType::from_function_code(rt.read_function_code()),
                Some(rt)
            );
        }
    }

    #[test]
    fn an_exception_resolves_to_the_bank_its_request_asked_for() {
        assert_eq!(
            RegisterType::from_function_code(0x83),
            Some(RegisterType::Holding)
        );
        assert_eq!(
            RegisterType::from_function_code(0x81),
            Some(RegisterType::Coil)
        );
    }

    #[test]
    fn write_codes_map_to_their_bank() {
        for (func, bank) in [
            (0x05, RegisterType::Coil),
            (0x0F, RegisterType::Coil),
            (0x06, RegisterType::Holding),
            (0x10, RegisterType::Holding),
        ] {
            assert_eq!(RegisterType::from_function_code(func), Some(bank));
        }
    }

    #[test]
    fn unmodelled_codes_have_no_bank_and_no_name() {
        // 0x07 (Read Exception Status), 0x14 (Read File Record) and 0x2B
        // (Encapsulated Transport) are real codes that address no bank.
        for func in [0x00, 0x07, 0x14, 0x2B] {
            assert_eq!(RegisterType::from_function_code(func), None);
            assert_eq!(function_name(func), None);
        }
    }

    #[test]
    fn only_writable_banks_have_a_write_cap() {
        for rt in [
            RegisterType::Coil,
            RegisterType::Discrete,
            RegisterType::Holding,
            RegisterType::Input,
        ] {
            assert_eq!(rt.max_per_write().is_some(), rt.is_writable());
        }
    }

    #[test]
    fn coils_pack_eight_to_a_byte_and_registers_take_two() {
        assert_eq!(RegisterType::Holding.data_bytes(10), 20);
        assert_eq!(RegisterType::Input.data_bytes(1), 2);
        assert_eq!(RegisterType::Coil.data_bytes(8), 1);
        // A partial byte still costs a whole one.
        assert_eq!(RegisterType::Coil.data_bytes(9), 2);
        assert_eq!(RegisterType::Discrete.data_bytes(0), 0);
    }

    #[test]
    fn caps_match_the_bank_they_describe() {
        assert_eq!(RegisterType::Holding.max_per_read(), MAX_REGISTERS_PER_READ);
        assert_eq!(RegisterType::Input.max_per_read(), MAX_REGISTERS_PER_READ);
        assert_eq!(RegisterType::Coil.max_per_read(), MAX_COILS_PER_READ);
        assert_eq!(RegisterType::Discrete.max_per_read(), MAX_COILS_PER_READ);
    }

    #[test]
    fn only_the_exception_codes_the_spec_defines_have_names() {
        assert_eq!(exception_name(0x02), Some("Illegal Data Address"));
        assert_eq!(
            exception_name(0x0B),
            Some("Gateway Target Device Failed To Respond")
        );
        // 0x07 and 0x09 pass the reassembler's 0x01..=0x0B plausibility gate
        // and are still not codes the spec defines. 0x00 is not an exception at
        // all, and 0x0C is past the end.
        for code in [0x00, 0x07, 0x09, 0x0C, 0xFF] {
            assert_eq!(exception_name(code), None, "code {code:#04x}");
        }
    }

    #[test]
    fn every_exception_code_survives_a_round_trip() {
        for code in 0..=u8::MAX {
            assert_eq!(ExceptionCode::from_code(code).code(), code);
        }
    }

    #[test]
    fn exactly_the_named_exception_codes_have_their_own_variant() {
        for code in 0..=u8::MAX {
            assert_eq!(
                matches!(ExceptionCode::from_code(code), ExceptionCode::Other(_)),
                exception_name(code).is_none(),
                "code {code:#04x}"
            );
        }
    }

    #[test]
    fn an_exception_code_displays_its_name_or_its_number() {
        assert_eq!(
            ExceptionCode::IllegalDataAddress.to_string(),
            "Illegal Data Address"
        );
        assert_eq!(
            ExceptionCode::from_code(0x0B).to_string(),
            "Gateway Target Device Failed To Respond"
        );
        assert_eq!(ExceptionCode::from_code(0x07).to_string(), "Exception 0x07");
    }

    #[test]
    fn registers_survive_a_round_trip_through_bytes() {
        let regs = [0x1234, 0x0000, 0xFFFF, 0x00FF];
        assert_eq!(
            registers_to_bytes(&regs),
            [0x12, 0x34, 0, 0, 0xFF, 0xFF, 0, 0xFF]
        );
        assert_eq!(bytes_to_registers(&registers_to_bytes(&regs)), regs);
    }

    #[test]
    fn a_trailing_odd_byte_is_dropped_rather_than_widened() {
        // No read or write produces an odd byte count; zero-extending would
        // invent a register the wire never carried.
        assert_eq!(bytes_to_registers(&[0x12, 0x34, 0x56]), [0x1234]);
        assert_eq!(bytes_to_registers(&[0x12]), [] as [u16; 0]);
        assert_eq!(bytes_to_registers(&[]), [] as [u16; 0]);
    }

    #[test]
    fn coils_pack_least_significant_bit_first() {
        // Bit 0 of byte 0 is the first coil, which is what makes 0x01 "only the
        // first is on" rather than "only the last".
        assert_eq!(coils_to_bytes(&[true, false, false, false]), [0x01]);
        assert_eq!(coils_to_bytes(&[false; 8]), [0x00]);
        assert_eq!(coils_to_bytes(&[true; 8]), [0xFF]);
        // A ninth coil costs a whole byte, zero-filled — the same rule
        // data_bytes states.
        assert_eq!(coils_to_bytes(&[true; 9]), [0xFF, 0x01]);
        assert_eq!(
            coils_to_bytes(&[true; 9]).len(),
            RegisterType::Coil.data_bytes(9)
        );
        assert_eq!(coils_to_bytes(&[]), [] as [u8; 0]);
    }

    #[test]
    fn an_address_holds_sixteen_bits_of_register_and_one_of_coil() {
        assert_eq!(RegisterType::Holding.bits_per_address(), 16);
        assert_eq!(RegisterType::Input.bits_per_address(), 16);
        assert_eq!(RegisterType::Coil.bits_per_address(), 1);
        assert_eq!(RegisterType::Discrete.bits_per_address(), 1);
        // Which is the whole difference between the two address spaces: bit 48
        // is the third register, or the forty-eighth coil.
        assert_eq!(RegisterType::Holding.address_offset(48), 3);
        assert_eq!(RegisterType::Coil.address_offset(48), 48);
    }

    #[test]
    fn a_partial_address_still_costs_a_whole_one() {
        assert_eq!(RegisterType::Holding.address_span(16), 1);
        assert_eq!(RegisterType::Holding.address_span(17), 2);
        assert_eq!(RegisterType::Holding.address_span(32), 2);
        assert_eq!(RegisterType::Coil.address_span(9), 9);
        assert_eq!(RegisterType::Discrete.address_span(1), 1);
        // And a span costs the bytes its bank says it does.
        assert_eq!(RegisterType::Holding.data_bytes(2), 4);
        assert_eq!(RegisterType::Coil.data_bytes(9), 2);
    }

    #[test]
    fn coils_survive_a_round_trip_through_bytes() {
        let coils = [true, false, true, true, false, false, true, true, true];
        assert_eq!(coils_to_bytes(&coils), [0xCD, 0x01]);
        assert_eq!(bytes_to_coils(&coils_to_bytes(&coils), coils.len()), coils);
    }

    #[test]
    fn a_count_past_the_end_of_the_block_is_clamped() {
        // The zero fill of the last byte is not coils, and neither is anything
        // past the block — either would invent a coil the device never sent.
        assert_eq!(bytes_to_coils(&[0xFF], 3), [true; 3]);
        assert_eq!(bytes_to_coils(&[0xFF], 12), [true; 8]);
        assert_eq!(bytes_to_coils(&[], 8), [] as [bool; 0]);
        assert_eq!(bytes_to_coils(&[0xFF], 0), [] as [bool; 0]);
    }
}
