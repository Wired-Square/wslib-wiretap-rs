//! Serial framing that isn't a protocol of its own: the delimiter framer and the
//! [`Framed`] output it shares with [`crate::slip`].
//!
//! Modbus RTU framing is `wiretap-catalog`'s `ModbusRtuStream`. The decoders
//! here follow its shape — `feed`, a `flush` that ends a stream but not the
//! decoder, and `bytes_fed` — and count [`Framed::end_offset`] as it counts
//! `ModbusRtuMessage::end_offset`, so a caller can stamp all three alike.

/// Bytes a framer released, and where in its input they ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed {
    pub bytes: Vec<u8>,
    /// Bytes fed through the one that released these, counted as
    /// `ModbusRtuMessage::end_offset` counts them; always at least 1.
    pub end_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelimiterOptions {
    pub delimiter: Vec<u8>,
    /// A frame this long is released without a delimiter.
    pub max_length: usize,
    pub include_delimiter: bool,
}

/// Splits a byte stream at a delimiter, or at a length limit when none comes.
///
/// The delimiter is checked before the limit, so a delimiter straddling the
/// limit is cut. An empty delimiter releases every byte on its own, and a
/// `max_length` of 0 releases every byte and an empty frame after each
/// delimiter.
#[derive(Debug, Clone)]
pub struct DelimiterFramer {
    options: DelimiterOptions,
    buffer: Vec<u8>,
    fed: u64,
}

impl DelimiterFramer {
    pub fn new(options: DelimiterOptions) -> Self {
        Self {
            options,
            buffer: Vec::new(),
            fed: 0,
        }
    }

    /// Feed received bytes, returning every frame they released.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Framed> {
        let mut out = Vec::new();
        for &byte in bytes {
            self.buffer.push(byte);
            self.fed += 1;

            if self.buffer.ends_with(&self.options.delimiter) {
                let mut frame = std::mem::take(&mut self.buffer);
                if !self.options.include_delimiter {
                    frame.truncate(frame.len() - self.options.delimiter.len());
                }
                if !frame.is_empty() {
                    out.push(self.framed(frame));
                }
            }

            if self.buffer.len() >= self.options.max_length {
                let frame = std::mem::take(&mut self.buffer);
                out.push(self.framed(frame));
            }
        }
        out
    }

    /// The residue, if any. The framer carries on after it.
    pub fn flush(&mut self) -> Option<Framed> {
        let residue = std::mem::take(&mut self.buffer);
        (!residue.is_empty()).then(|| self.framed(residue))
    }

    pub fn bytes_fed(&self) -> u64 {
        self.fed
    }

    fn framed(&self, bytes: Vec<u8>) -> Framed {
        Framed {
            bytes,
            end_offset: self.fed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framer(delimiter: &[u8], max_length: usize, include_delimiter: bool) -> DelimiterFramer {
        DelimiterFramer::new(DelimiterOptions {
            delimiter: delimiter.to_vec(),
            max_length,
            include_delimiter,
        })
    }

    fn bytes(frames: &[Framed]) -> Vec<&[u8]> {
        frames.iter().map(|f| f.bytes.as_slice()).collect()
    }

    #[test]
    fn a_stripped_delimiter_splits_frames() {
        let frames = framer(b"\r\n", 256, false).feed(b"Hello\r\nWorld\r\n");
        assert_eq!(bytes(&frames), [b"Hello".as_slice(), b"World"]);
    }

    #[test]
    fn an_included_delimiter_stays_on_its_frame() {
        let frames = framer(b"\r\n", 256, true).feed(b"Hello\r\n");
        assert_eq!(bytes(&frames), [b"Hello\r\n".as_slice()]);
    }

    #[test]
    fn a_frame_reaching_max_length_is_released_and_the_rest_flushes() {
        let mut f = framer(b"\n", 5, false);
        assert_eq!(bytes(&f.feed(b"12345678")), [b"12345".as_slice()]);
        assert_eq!(f.flush().expect("a residue").bytes, b"678");
    }

    #[test]
    fn a_frame_ends_at_its_delimiters_last_byte_whether_kept_or_stripped() {
        for include in [false, true] {
            let frames = framer(b"\r\n", 256, include).feed(b"ab\r\ncde\r\n");
            let ends: Vec<u64> = frames.iter().map(|f| f.end_offset).collect();
            assert_eq!(ends, [4, 9], "include_delimiter = {include}");
        }
    }

    #[test]
    fn a_max_length_split_ends_at_the_byte_reaching_the_limit() {
        let frames = framer(b"\n", 3, false).feed(b"abcdefg");
        let ends: Vec<u64> = frames.iter().map(|f| f.end_offset).collect();
        assert_eq!(ends, [3, 6]);
    }

    #[test]
    fn a_residue_ends_at_bytes_fed() {
        let mut f = framer(b"\n", 256, false);
        f.feed(b"a\nbc");
        let residue = f.flush().expect("a residue");
        assert_eq!(residue.bytes, b"bc");
        assert_eq!(residue.end_offset, f.bytes_fed());
        assert_eq!(residue.end_offset, 4);
    }

    #[test]
    fn a_flush_with_nothing_buffered_releases_nothing() {
        let mut f = framer(b"\n", 256, false);
        f.feed(b"a\n");
        assert_eq!(f.flush(), None);
    }

    #[test]
    fn offsets_keep_counting_from_bytes_fed_across_a_flush() {
        let mut f = framer(b"\n", 256, false);
        f.feed(b"abc");
        assert_eq!(f.flush().expect("a residue").end_offset, 3);

        let frames = f.feed(b"de\n");
        assert_eq!(bytes(&frames), [b"de".as_slice()]);
        assert_eq!(frames[0].end_offset, 6);
        assert_eq!(f.bytes_fed(), 6);
    }

    #[test]
    fn a_crlf_straddling_a_max_length_split_is_cut() {
        let frames = framer(b"\r\n", 5, false).feed(b"abcd\r\nxy\r\n");
        assert_eq!(bytes(&frames), [b"abcd\r".as_slice(), b"\nxy"]);
    }

    #[test]
    fn an_empty_delimiter_releases_every_byte_on_its_own() {
        for include in [false, true] {
            let frames = framer(b"", 256, include).feed(b"abc");
            assert_eq!(bytes(&frames), [b"a".as_slice(), b"b", b"c"]);
        }
    }

    #[test]
    fn a_zero_max_length_releases_every_byte_and_an_empty_frame_after_a_delimiter() {
        let frames = framer(b"\n", 0, false).feed(b"a\nb");
        assert_eq!(bytes(&frames), [b"a".as_slice(), b"", b"b"]);
        let ends: Vec<u64> = frames.iter().map(|f| f.end_offset).collect();
        assert_eq!(ends, [1, 2, 3]);
    }

    #[test]
    fn every_release_ends_at_least_one_byte_in() {
        let inputs: [&[u8]; 4] = [b"", b"\n", b"a\n\nb", b"\r\n\r\nabc"];
        for delimiter in [b"".as_slice(), b"\n", b"\r\n"] {
            for max_length in [0, 1, 3, 256] {
                for include in [false, true] {
                    for input in inputs {
                        let mut f = framer(delimiter, max_length, include);
                        let mut released = f.feed(input);
                        released.extend(f.flush());
                        assert!(
                            released.iter().all(|r| r.end_offset >= 1),
                            "{delimiter:?} {max_length} {include} {input:?}"
                        );
                    }
                }
            }
        }
    }
}
