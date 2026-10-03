//! SLIP (RFC 1055), both directions.
//!
//! Protocol reference: <https://www.rfc-editor.org/rfc/rfc1055>, and
//! `docs/slip.md` for what this decoder does beyond it.
//!
//! [`SlipDecoder`] is lenient where the RFC leaves a byte undefined: `ESC`
//! before an ordinary byte keeps both, and `ESC` before `END` is dropped. Its
//! buffer is unbounded until an `END` arrives, unless built with a cap.

use crate::framing::Framed;

pub const END: u8 = 0xC0;
pub const ESC: u8 = 0xDB;
pub const ESC_END: u8 = 0xDC;
pub const ESC_ESC: u8 = 0xDD;

/// Splits a SLIP byte stream into unescaped frames. Empty frames are skipped.
#[derive(Debug, Clone, Default)]
pub struct SlipDecoder {
    buffer: Vec<u8>,
    in_escape: bool,
    fed: u64,
    max_frame_len: Option<usize>,
    abandoning: bool,
    abandoned: u64,
}

impl SlipDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// A frame that grows past `max` bytes is abandoned up to the next `END`
    /// and counted in [`abandoned_frames`](Self::abandoned_frames).
    pub fn with_max_frame_len(max: usize) -> Self {
        Self {
            max_frame_len: Some(max),
            ..Self::default()
        }
    }

    /// Feed received bytes, returning every frame an `END` released.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Framed> {
        let mut out = Vec::new();
        for &byte in bytes {
            self.fed += 1;
            let escaped = std::mem::take(&mut self.in_escape);
            match byte {
                END => {
                    self.abandoning = false;
                    out.extend(self.take());
                }
                _ if self.abandoning => {}
                ESC => self.in_escape = true,
                ESC_END if escaped => self.buffer.push(END),
                ESC_ESC if escaped => self.buffer.push(ESC),
                _ => {
                    if escaped {
                        self.buffer.push(ESC);
                    }
                    self.buffer.push(byte);
                }
            }
            if self
                .max_frame_len
                .is_some_and(|max| self.buffer.len() > max)
            {
                self.buffer.clear();
                self.abandoning = true;
                self.abandoned += 1;
            }
        }
        out
    }

    /// The residue, if any; also clears a pending escape and ends an abandoned
    /// frame.
    pub fn flush(&mut self) -> Option<Framed> {
        self.in_escape = false;
        self.abandoning = false;
        self.take()
    }

    pub fn bytes_fed(&self) -> u64 {
        self.fed
    }

    /// Frames abandoned for outgrowing the cap, since the decoder was built.
    pub fn abandoned_frames(&self) -> u64 {
        self.abandoned
    }

    fn take(&mut self) -> Option<Framed> {
        (!self.buffer.is_empty()).then(|| Framed {
            bytes: std::mem::take(&mut self.buffer),
            end_offset: self.fed,
        })
    }
}

/// `END`, `data` escaped, `END`: the leading `END` flushes line noise.
pub fn encode_into(out: &mut Vec<u8>, data: &[u8]) {
    out.push(END);
    for &byte in data {
        match byte {
            END => out.extend_from_slice(&[ESC, ESC_END]),
            ESC => out.extend_from_slice(&[ESC, ESC_ESC]),
            _ => out.push(byte),
        }
    }
    out.push(END);
}

pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    encode_into(&mut out, data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(frames: &[Framed]) -> Vec<&[u8]> {
        frames.iter().map(|f| f.bytes.as_slice()).collect()
    }

    #[test]
    fn end_separates_frames() {
        let frames = SlipDecoder::new().feed(&[END, 0x01, 0x02, 0x03, END, 0x04, 0x05, END]);
        assert_eq!(
            bytes(&frames),
            [[0x01, 0x02, 0x03].as_slice(), &[0x04, 0x05]]
        );
    }

    #[test]
    fn escape_sequences_decode_to_end_and_esc() {
        let frames = SlipDecoder::new().feed(&[ESC, ESC_END, ESC, ESC_ESC, END]);
        assert_eq!(bytes(&frames), [[END, ESC].as_slice()]);
    }

    #[test]
    fn an_encoded_frame_decodes_to_itself() {
        let original = [0x01, END, 0x02, ESC, 0x03];
        let frames = SlipDecoder::new().feed(&encode(&original));
        assert_eq!(bytes(&frames), [original.as_slice()]);
    }

    #[test]
    fn encode_into_appends_to_what_is_already_there() {
        let mut out = vec![0xAA];
        encode_into(&mut out, &[0x01, END]);
        assert_eq!(out, [0xAA, END, 0x01, ESC, ESC_END, END]);
    }

    #[test]
    fn an_esc_before_an_ordinary_byte_keeps_both() {
        let frames = SlipDecoder::new().feed(&[0x01, ESC, 0x02, END]);
        assert_eq!(bytes(&frames), [[0x01, ESC, 0x02].as_slice()]);
    }

    #[test]
    fn an_esc_before_end_is_dropped_and_the_frame_released() {
        let frames = SlipDecoder::new().feed(&[0x01, ESC, END]);
        assert_eq!(bytes(&frames), [[0x01].as_slice()]);
    }

    #[test]
    fn a_frame_ends_at_its_end_byte() {
        let frames = SlipDecoder::new().feed(&[END, 0x01, END, END, 0x02, ESC, ESC_END, END, 0x03]);
        let ends: Vec<u64> = frames.iter().map(|f| f.end_offset).collect();
        assert_eq!(ends, [3, 8]);
    }

    #[test]
    fn flush_returns_the_residue_ending_at_bytes_fed() {
        let mut d = SlipDecoder::new();
        assert!(d.feed(&[0x01, 0x02, 0x03]).is_empty());
        let residue = d.flush().expect("a residue");
        assert_eq!(residue.bytes, [0x01, 0x02, 0x03]);
        assert_eq!(residue.end_offset, d.bytes_fed());
        assert_eq!(d.flush(), None);
    }

    #[test]
    fn offsets_keep_counting_from_bytes_fed_across_a_flush() {
        let mut d = SlipDecoder::new();
        d.feed(&[0x01, 0x02]);
        assert_eq!(d.flush().expect("a residue").end_offset, 2);

        let frames = d.feed(&[0x03, END]);
        assert_eq!(bytes(&frames), [[0x03].as_slice()]);
        assert_eq!(frames[0].end_offset, 4);
        assert_eq!(d.bytes_fed(), 4);
    }

    #[test]
    fn every_release_ends_at_least_one_byte_in() {
        let inputs: [&[u8]; 5] = [
            &[],
            &[END],
            &[ESC],
            &[END, END, 0x01],
            &[0x01, ESC, END, ESC],
        ];
        for input in inputs {
            let mut d = SlipDecoder::new();
            let mut released = d.feed(input);
            released.extend(d.flush());
            assert!(released.iter().all(|r| r.end_offset >= 1), "{input:?}");
        }
    }

    #[test]
    fn a_frame_at_the_cap_is_released() {
        let mut d = SlipDecoder::with_max_frame_len(3);
        let frames = d.feed(&[0x01, ESC, ESC_END, 0x03, END]);
        assert_eq!(bytes(&frames), [[0x01, END, 0x03].as_slice()]);
        assert_eq!(d.abandoned_frames(), 0);
    }

    #[test]
    fn a_frame_past_the_cap_is_abandoned_up_to_the_next_end_and_counted() {
        let mut d = SlipDecoder::with_max_frame_len(3);
        let frames = d.feed(&[0x01, 0x02, 0x03, 0x04, 0x05, END, 0x06, END]);
        assert_eq!(bytes(&frames), [[0x06].as_slice()]);
        assert_eq!(frames[0].end_offset, 8);
        assert_eq!(d.abandoned_frames(), 1);
    }

    #[test]
    fn an_escaped_end_does_not_end_an_abandoned_frame() {
        let mut d = SlipDecoder::with_max_frame_len(2);
        let frames = d.feed(&[0x01, 0x02, 0x03, ESC, ESC_END, 0x04, END, 0x05, END]);
        assert_eq!(bytes(&frames), [[0x05].as_slice()]);
        assert_eq!(d.abandoned_frames(), 1);
    }

    #[test]
    fn a_line_that_never_ends_is_counted_once_and_holds_nothing() {
        let mut d = SlipDecoder::with_max_frame_len(8);
        assert!(d.feed(&[0x01; 1000]).is_empty());
        assert_eq!(d.abandoned_frames(), 1);
        assert_eq!(d.flush(), None);
    }

    #[test]
    fn a_flush_ends_an_abandoned_frame() {
        let mut d = SlipDecoder::with_max_frame_len(2);
        d.feed(&[0x01, 0x02, 0x03]);
        assert_eq!(d.flush(), None);
        assert_eq!(bytes(&d.feed(&[0x04, END])), [[0x04].as_slice()]);
    }

    #[test]
    fn an_uncapped_decoder_never_abandons() {
        let mut d = SlipDecoder::new();
        let mut input = vec![0x01; 100_000];
        input.push(END);
        assert_eq!(d.feed(&input)[0].bytes.len(), 100_000);
        assert_eq!(d.abandoned_frames(), 0);
    }

    #[test]
    fn a_slip_escape_cut_off_by_a_flush_does_not_carry_over() {
        let mut d = SlipDecoder::new();
        d.feed(&[0x01, ESC]);
        d.flush();

        let frames = d.feed(&[ESC_END, END]);
        assert_eq!(bytes(&frames), [[ESC_END].as_slice()]);
    }
}
