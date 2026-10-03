//! The checksum algorithms themselves: bytes in, value out. Nothing here knows
//! about frames, positions or calculation ranges — that is [`crate::frame`].

use serde::{Deserialize, Serialize};

/// Supported checksum algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    /// XOR of all bytes
    Xor,
    /// sum(bytes) & 0xFF
    Sum8,
    /// CRC-8 polynomial 0x07 (ITU/SMBUS)
    Crc8,
    /// CRC-8 SAE-J1850 polynomial 0x1D (automotive OBD-II)
    Crc8SaeJ1850,
    /// CRC-8 AUTOSAR polynomial 0x2F (AUTOSAR E2E)
    Crc8Autosar,
    /// CRC-8 Maxim polynomial 0x31 (1-Wire devices)
    Crc8Maxim,
    /// CRC-8 CDMA2000 polynomial 0x9B (telecom)
    Crc8Cdma2000,
    /// CRC-8 DVB-S2 polynomial 0xD5 (satellite)
    Crc8DvbS2,
    /// CRC-8 Nissan polynomial 0x85 (Nissan CAN)
    Crc8Nissan,
    /// CRC-16 Modbus polynomial (0xA001)
    Crc16Modbus,
    /// CRC-16 CCITT polynomial (0x1021)
    Crc16Ccitt,
}

/// Every algorithm the sweep considers, in preference order — ties in scoring
/// break towards the earlier entry, so the simple ones come first.
pub const ALL_ALGORITHMS: [ChecksumAlgorithm; 11] = [
    ChecksumAlgorithm::Xor,
    ChecksumAlgorithm::Sum8,
    ChecksumAlgorithm::Crc8,
    ChecksumAlgorithm::Crc8SaeJ1850,
    ChecksumAlgorithm::Crc8Autosar,
    ChecksumAlgorithm::Crc8Maxim,
    ChecksumAlgorithm::Crc8Cdma2000,
    ChecksumAlgorithm::Crc8DvbS2,
    ChecksumAlgorithm::Crc8Nissan,
    ChecksumAlgorithm::Crc16Modbus,
    ChecksumAlgorithm::Crc16Ccitt,
];

impl ChecksumAlgorithm {
    /// Get the output size in bytes for this algorithm.
    pub fn output_bytes(&self) -> usize {
        match self {
            ChecksumAlgorithm::Crc16Modbus | ChecksumAlgorithm::Crc16Ccitt => 2,
            _ => 1,
        }
    }

    /// The catalogue's algorithm id. See [`crate::all_algorithm_ids`] for the
    /// full vocabulary, which adds the two parameterised shapes.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChecksumAlgorithm::Xor => "xor",
            ChecksumAlgorithm::Sum8 => "sum8",
            ChecksumAlgorithm::Crc8 => "crc8",
            ChecksumAlgorithm::Crc8SaeJ1850 => "crc8_sae_j1850",
            ChecksumAlgorithm::Crc8Autosar => "crc8_autosar",
            ChecksumAlgorithm::Crc8Maxim => "crc8_maxim",
            ChecksumAlgorithm::Crc8Cdma2000 => "crc8_cdma2000",
            ChecksumAlgorithm::Crc8DvbS2 => "crc8_dvb_s2",
            ChecksumAlgorithm::Crc8Nissan => "crc8_nissan",
            ChecksumAlgorithm::Crc16Modbus => "crc16_modbus",
            ChecksumAlgorithm::Crc16Ccitt => "crc16_ccitt",
        }
    }
}

impl std::str::FromStr for ChecksumAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ALL_ALGORITHMS
            .iter()
            .find(|a| a.as_str() == s)
            .copied()
            .ok_or_else(|| format!("Unknown checksum algorithm: {s}"))
    }
}

// ============================================================================
// Reflection Helpers
// ============================================================================

/// Reflect (reverse) the bits of a byte.
pub fn reflect8(value: u8) -> u8 {
    value.reverse_bits()
}

/// Reflect (reverse) the bits of a 16-bit value.
pub fn reflect16(value: u16) -> u16 {
    value.reverse_bits()
}

// ============================================================================
// Parameterised CRC Functions (Canonical Implementations)
// ============================================================================

/// CRC-8 with arbitrary parameters.
///
/// # Arguments
/// * `data` - The data to calculate CRC over
/// * `polynomial` - The CRC polynomial (e.g., 0x07 for standard CRC-8)
/// * `init` - Initial CRC value (e.g., 0x00 or 0xFF)
/// * `xor_out` - Final XOR value (e.g., 0x00 or 0xFF)
/// * `reflect` - Whether to use reflected (LSB-first) mode
pub fn crc8_parameterised(data: &[u8], polynomial: u8, init: u8, xor_out: u8, reflect: bool) -> u8 {
    let mut crc = init;

    if reflect {
        // Reflected mode (LSB-first processing)
        let reflected_poly = reflect8(polynomial);
        for &byte in data {
            crc ^= byte;
            for _ in 0..8 {
                if crc & 0x01 != 0 {
                    crc = (crc >> 1) ^ reflected_poly;
                } else {
                    crc >>= 1;
                }
            }
        }
    } else {
        // Normal mode (MSB-first processing)
        for &byte in data {
            crc ^= byte;
            for _ in 0..8 {
                if crc & 0x80 != 0 {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }
    }

    crc ^ xor_out
}

/// CRC-16 with arbitrary parameters.
///
/// # Arguments
/// * `data` - The data to calculate CRC over
/// * `polynomial` - The CRC polynomial (e.g., 0x8005 for CRC-16)
/// * `init` - Initial CRC value (e.g., 0x0000 or 0xFFFF)
/// * `xor_out` - Final XOR value (e.g., 0x0000 or 0xFFFF)
/// * `reflect_in` - Whether to reflect input bytes
/// * `reflect_out` - Whether to reflect the final CRC output
pub fn crc16_parameterised(
    data: &[u8],
    polynomial: u16,
    init: u16,
    xor_out: u16,
    reflect_in: bool,
    reflect_out: bool,
) -> u16 {
    let mut crc = init;

    if reflect_in {
        // Reflected input mode (LSB-first)
        let reflected_poly = reflect16(polynomial);
        for &byte in data {
            crc ^= byte as u16;
            for _ in 0..8 {
                if crc & 0x0001 != 0 {
                    crc = (crc >> 1) ^ reflected_poly;
                } else {
                    crc >>= 1;
                }
            }
        }
    } else {
        // Normal input mode (MSB-first)
        for &byte in data {
            crc ^= (byte as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ polynomial;
                } else {
                    crc <<= 1;
                }
            }
        }
    }

    // Reflecting the input already reverses the register, so the output flag
    // asks whether to undo that — the two agreeing is the no-op case.
    let final_crc = if reflect_out != reflect_in {
        reflect16(crc)
    } else {
        crc
    };

    final_crc ^ xor_out
}

// ============================================================================
// Named Checksum Functions
// ============================================================================

/// XOR of all bytes.
/// Simple but effective for detecting single-bit errors.
pub fn xor_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, b| acc ^ b)
}

/// Simple modulo-256 sum of bytes (8-bit sum).
pub fn sum8_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b))
}

/// CRC-8 with polynomial 0x07 (ITU/SMBUS).
/// Common in many embedded protocols.
pub fn crc8_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x07, 0x00, 0x00, false)
}

/// CRC-8 SAE-J1850 with polynomial 0x1D.
/// Used in automotive OBD-II and CAN protocols.
/// Init: 0xFF, XOR out: 0xFF, Not reflected
pub fn crc8_sae_j1850_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x1D, 0xFF, 0xFF, false)
}

/// CRC-8 AUTOSAR with polynomial 0x2F.
/// Used in AUTOSAR E2E protection.
/// Init: 0xFF, XOR out: 0xFF, Not reflected
pub fn crc8_autosar_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x2F, 0xFF, 0xFF, false)
}

/// CRC-8 Maxim with polynomial 0x31.
/// Used in Dallas/Maxim 1-Wire devices.
/// Init: 0x00, XOR out: 0x00, Reflected (LSB-first)
pub fn crc8_maxim_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x31, 0x00, 0x00, true)
}

/// CRC-8 CDMA2000 with polynomial 0x9B.
/// Used in telecom protocols.
/// Init: 0xFF, XOR out: 0x00, Not reflected
pub fn crc8_cdma2000_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x9B, 0xFF, 0x00, false)
}

/// CRC-8 DVB-S2 with polynomial 0xD5.
/// Used in satellite communications.
/// Init: 0x00, XOR out: 0x00, Not reflected
pub fn crc8_dvb_s2_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0xD5, 0x00, 0x00, false)
}

/// CRC-8 Nissan with polynomial 0x85.
/// Used in Nissan LEAF CAN bus.
/// Init: 0x00, XOR out: 0x00, Not reflected
pub fn crc8_nissan_checksum(data: &[u8]) -> u8 {
    crc8_parameterised(data, 0x85, 0x00, 0x00, false)
}

/// The Modbus polynomial (0x8005) as the reflected algorithm uses it.
const CRC16_MODBUS_POLY_REFLECTED: u16 = 0xA001;

/// One byte's worth of polynomial division, precomputed for all 256 inputs.
const fn crc16_modbus_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut byte = 0usize;
    while byte < 256 {
        let mut crc = byte as u16;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ CRC16_MODBUS_POLY_REFLECTED
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

static CRC16_MODBUS_TABLE: [u16; 256] = crc16_modbus_table();

/// CRC-16 Modbus polynomial (0x8005, reflected).
/// Used by Modbus RTU protocol.
///
/// Table-driven rather than a call to [`crc16_parameterised`], which is the
/// same computation eight branches at a time. This one runs on the streaming
/// path: reassembling an RTU stream CRCs every candidate boundary, and a
/// desynced stream does that once per byte it drops, over a buffer that can be
/// hundreds of bytes long. The general form stays bitwise — the solver sweeps
/// tens of thousands of polynomials through it, so there is no table to build.
pub fn crc16_modbus_checksum(data: &[u8]) -> u16 {
    data.iter().fold(0xFFFF, |crc, &byte| {
        (crc >> 8) ^ CRC16_MODBUS_TABLE[usize::from((crc ^ byte as u16) as u8)]
    })
}

/// Whether a Modbus RTU message carries a valid trailing CRC.
///
/// The CRC is the last two bytes, little-endian, over everything before it —
/// the check every RTU framer and reassembler needs, so it lives here rather
/// than being re-derived at each call site. A message shorter than the minimum
/// (address, function, CRC) is never valid.
pub fn crc16_modbus_valid(message: &[u8]) -> bool {
    if message.len() < 4 {
        return false;
    }
    let (body, crc) = message.split_at(message.len() - 2);
    crc16_modbus_checksum(body) == u16::from_le_bytes([crc[0], crc[1]])
}

/// CRC-16 CCITT polynomial (0x1021, non-reflected).
/// Common in telecommunications and some industrial protocols.
pub fn crc16_ccitt_checksum(data: &[u8]) -> u16 {
    crc16_parameterised(data, 0x1021, 0xFFFF, 0x0000, false, false)
}

/// Calculate a checksum over exactly `data`, using the named algorithm.
///
/// Returns `u16` for every algorithm; the 8-bit ones are zero-extended.
pub fn calculate_checksum_simple(algorithm: ChecksumAlgorithm, data: &[u8]) -> u16 {
    match algorithm {
        ChecksumAlgorithm::Xor => xor_checksum(data) as u16,
        ChecksumAlgorithm::Sum8 => sum8_checksum(data) as u16,
        ChecksumAlgorithm::Crc8 => crc8_checksum(data) as u16,
        ChecksumAlgorithm::Crc8SaeJ1850 => crc8_sae_j1850_checksum(data) as u16,
        ChecksumAlgorithm::Crc8Autosar => crc8_autosar_checksum(data) as u16,
        ChecksumAlgorithm::Crc8Maxim => crc8_maxim_checksum(data) as u16,
        ChecksumAlgorithm::Crc8Cdma2000 => crc8_cdma2000_checksum(data) as u16,
        ChecksumAlgorithm::Crc8DvbS2 => crc8_dvb_s2_checksum(data) as u16,
        ChecksumAlgorithm::Crc8Nissan => crc8_nissan_checksum(data) as u16,
        ChecksumAlgorithm::Crc16Modbus => crc16_modbus_checksum(data),
        ChecksumAlgorithm::Crc16Ccitt => crc16_ccitt_checksum(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ---- XOR --------------------------------------------------------------

    #[test]
    fn test_xor_checksum_basic() {
        // 0x01 ^ 0x02 ^ 0x03 ^ 0x04 ^ 0x05 = 0x01
        assert_eq!(xor_checksum(&[0x01, 0x02, 0x03, 0x04, 0x05]), 0x01);
    }

    #[test]
    fn test_xor_checksum_pairs() {
        assert_eq!(xor_checksum(&[0x01, 0x02, 0x03]), 0x00);
        assert_eq!(xor_checksum(&[0xFF, 0xFF]), 0x00);
        assert_eq!(xor_checksum(&[0xAA, 0x55]), 0xFF);
    }

    #[test]
    fn test_xor_checksum_empty() {
        assert_eq!(xor_checksum(&[]), 0);
    }

    #[test]
    fn test_xor_checksum_single_byte() {
        assert_eq!(xor_checksum(&[0x42]), 0x42);
    }

    // ---- Sum8 -------------------------------------------------------------

    #[test]
    fn test_sum8_checksum_basic() {
        // 0x01 + 0x02 + 0x03 + 0x04 + 0x05 = 0x0F
        assert_eq!(sum8_checksum(&[0x01, 0x02, 0x03, 0x04, 0x05]), 0x0F);
    }

    #[test]
    fn test_sum8_checksum_simple() {
        assert_eq!(sum8_checksum(&[0x01, 0x02, 0x03]), 0x06);
    }

    #[test]
    fn test_sum8_checksum_wrapping() {
        // 0xFF + 0x02 = 0x101, wraps to 0x01
        assert_eq!(sum8_checksum(&[0xFF, 0x02]), 0x01);
        // 0x80 + 0x80 = 0x100, wraps to 0x00
        assert_eq!(sum8_checksum(&[0x80, 0x80]), 0x00);
    }

    #[test]
    fn test_sum8_checksum_empty() {
        assert_eq!(sum8_checksum(&[]), 0);
    }

    // ---- The named CRCs, against the catalogue's "123456789" vectors ------

    #[test]
    fn test_crc8_checksum_test_vector() {
        assert_eq!(crc8_checksum(b"123456789"), 0xF4);
    }

    #[test]
    fn test_crc8_sae_j1850_test_vector() {
        assert_eq!(crc8_sae_j1850_checksum(b"123456789"), 0x4B);
    }

    #[test]
    fn test_crc8_autosar_test_vector() {
        assert_eq!(crc8_autosar_checksum(b"123456789"), 0xDF);
    }

    #[test]
    fn test_crc8_maxim_test_vector() {
        assert_eq!(crc8_maxim_checksum(b"123456789"), 0xA1);
    }

    #[test]
    fn test_crc8_cdma2000_test_vector() {
        assert_eq!(crc8_cdma2000_checksum(b"123456789"), 0xDA);
    }

    #[test]
    fn test_crc8_dvb_s2_test_vector() {
        assert_eq!(crc8_dvb_s2_checksum(b"123456789"), 0xBC);
    }

    #[test]
    fn test_crc16_ccitt_checksum_test_vector() {
        assert_eq!(crc16_ccitt_checksum(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_crc16_modbus_checksum_test_vector() {
        // Known Modbus test vector: device address 0x01, function 0x03, data
        // [0x01, 0x03, 0x00, 0x00, 0x00, 0x0A] -> 0xCDC5
        // (Wire format would be C5 CD in little-endian)
        assert_eq!(
            crc16_modbus_checksum(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]),
            0xCDC5
        );
    }

    #[test]
    fn test_crc16_modbus_standard_check_vector() {
        assert_eq!(crc16_modbus_checksum(b"123456789"), 0x4B37);
    }

    /// The table has to agree with the bitwise general form for every input, not
    /// just the published vectors — it is the same algorithm, and the only
    /// reason to keep both is speed.
    #[test]
    fn test_crc16_modbus_table_matches_the_parameterised_form() {
        // A deterministic LCG, so a failure is reproducible.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut data = Vec::with_capacity(300);
        for _ in 0..300 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            data.push((seed >> 33) as u8);
        }
        for len in 0..=data.len() {
            let slice = &data[..len];
            assert_eq!(
                crc16_modbus_checksum(slice),
                crc16_parameterised(slice, 0x8005, 0xFFFF, 0x0000, true, true),
                "length {len}"
            );
        }
    }

    #[test]
    fn test_crc16_modbus_valid_checks_the_trailing_crc() {
        let body = [0x01u8, 0x03, 0x00, 0x00, 0x00, 0x0A];
        let mut message = body.to_vec();
        message.extend(crc16_modbus_checksum(&body).to_le_bytes());
        assert!(crc16_modbus_valid(&message));

        // One flipped bit anywhere fails it.
        let mut corrupt = message.clone();
        corrupt[0] ^= 0x01;
        assert!(!crc16_modbus_valid(&corrupt));
        let mut bad_crc = message.clone();
        *bad_crc.last_mut().unwrap() ^= 0xFF;
        assert!(!crc16_modbus_valid(&bad_crc));

        // Shorter than address + function + CRC is never a message.
        assert!(!crc16_modbus_valid(&[]));
        assert!(!crc16_modbus_valid(&message[..3]));
    }

    #[test]
    fn test_crc8_nissan_sample_message() {
        // Sample from Nissan LEAF code: {0x6E, 0x0F, 0x0F, 0xFD, 0x08, 0xC0, 0xC3}
        assert_eq!(
            crc8_nissan_checksum(&[0x6E, 0x0F, 0x0F, 0xFD, 0x08, 0xC0, 0xC3]),
            0x3E
        );
    }

    #[test]
    fn test_crc8_nissan_basic() {
        assert_eq!(crc8_nissan_checksum(&[0x01, 0x02, 0x03]), 0x5A);
    }

    /// Empty input returns the algorithm's init XOR its xor-out, not zero — a
    /// distinction the sweep relies on when a calculation range collapses.
    #[test]
    fn test_named_algorithms_on_empty_input() {
        assert_eq!(crc8_checksum(&[]), 0x00);
        assert_eq!(crc8_sae_j1850_checksum(&[]), 0x00); // init 0xFF ^ xorout 0xFF
        assert_eq!(crc8_autosar_checksum(&[]), 0x00); // init 0xFF ^ xorout 0xFF
        assert_eq!(crc8_maxim_checksum(&[]), 0x00);
        assert_eq!(crc8_cdma2000_checksum(&[]), 0xFF); // init 0xFF, no xorout
        assert_eq!(crc8_dvb_s2_checksum(&[]), 0x00);
        assert_eq!(crc8_nissan_checksum(&[]), 0x00);
        assert_eq!(crc16_modbus_checksum(&[]), 0xFFFF);
        assert_eq!(crc16_ccitt_checksum(&[]), 0xFFFF);
    }

    // ---- Dispatch and metadata -------------------------------------------

    #[test]
    fn test_calculate_checksum_simple_all_algorithms() {
        let data = [0x01, 0x02, 0x03];
        assert_eq!(
            calculate_checksum_simple(ChecksumAlgorithm::Xor, &data),
            0x00
        );
        assert_eq!(
            calculate_checksum_simple(ChecksumAlgorithm::Sum8, &data),
            0x06
        );
        assert_eq!(
            calculate_checksum_simple(ChecksumAlgorithm::Crc8, &data),
            0x48
        );
        assert_eq!(
            calculate_checksum_simple(ChecksumAlgorithm::Crc16Modbus, &data),
            0x6161
        );
        assert_eq!(
            calculate_checksum_simple(ChecksumAlgorithm::Crc16Ccitt, &data),
            0xADAD
        );
    }

    /// The id strings are the catalogue's `CHECKSUM_ALGORITHMS`, so a round trip
    /// failing here means a catalogue would stop validating.
    #[test]
    fn test_algorithm_ids_round_trip() {
        for algorithm in ALL_ALGORITHMS {
            assert_eq!(
                ChecksumAlgorithm::from_str(algorithm.as_str()).unwrap(),
                algorithm
            );
        }
        assert_eq!(ChecksumAlgorithm::Xor.as_str(), "xor");
        assert_eq!(ChecksumAlgorithm::Crc8SaeJ1850.as_str(), "crc8_sae_j1850");
        assert_eq!(ChecksumAlgorithm::Crc16Modbus.as_str(), "crc16_modbus");
    }

    #[test]
    fn test_algorithm_from_str_unknown() {
        assert!(ChecksumAlgorithm::from_str("unknown").is_err());
        assert!(ChecksumAlgorithm::from_str("").is_err());
    }

    #[test]
    fn test_algorithm_output_bytes() {
        for algorithm in ALL_ALGORITHMS {
            let expected = match algorithm {
                ChecksumAlgorithm::Crc16Modbus | ChecksumAlgorithm::Crc16Ccitt => 2,
                _ => 1,
            };
            assert_eq!(algorithm.output_bytes(), expected, "{algorithm:?}");
        }
    }

    #[test]
    fn test_reflection() {
        assert_eq!(reflect8(0b1000_0001), 0b1000_0001);
        assert_eq!(reflect8(0b0000_0001), 0b1000_0000);
        assert_eq!(reflect16(0x1021), 0x8408);
    }
}
