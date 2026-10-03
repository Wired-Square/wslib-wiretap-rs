//! What the text-log codecs share: line numbering and hand-written hex.

/// Non-blank lines, numbered from 1 by their place in the input.
pub(crate) fn numbered<I>(lines: I) -> impl Iterator<Item = (usize, I::Item)>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    lines
        .into_iter()
        .enumerate()
        .filter(|(_, text)| !text.as_ref().trim().is_empty())
        .map(|(i, text)| (i + 1, text))
}

pub(crate) fn push_hex_byte(out: &mut String, byte: u8) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    out.push(DIGITS[usize::from(byte >> 4)] as char);
    out.push(DIGITS[usize::from(byte & 0x0F)] as char);
}

pub(crate) fn nibble(digit: u8) -> Option<u8> {
    (digit as char).to_digit(16).map(|d| d as u8)
}

/// `digits` as one number, when it is 1 to `max_digits` hex digits and nothing else.
pub(crate) fn hex_value(digits: &str, max_digits: usize) -> Option<u32> {
    if !(1..=max_digits).contains(&digits.len()) {
        return None;
    }
    digits
        .bytes()
        .try_fold(0u32, |value, d| Some(value << 4 | u32::from(nibble(d)?)))
}
