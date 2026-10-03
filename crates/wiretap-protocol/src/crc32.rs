//! CRC-32 as IEEE 802.3 defines it: reflected, polynomial `0xEDB88320`, initial
//! value and final XOR `0xFFFFFFFF`. The same CRC as zlib's `crc32` and the
//! `crc32fast` crate, written out so this crate keeps no dependencies.

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |crc, &b| {
        (crc >> 8) ^ TABLE[((crc ^ u32::from(b)) & 0xFF) as usize]
    })
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
        assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
    }
}
