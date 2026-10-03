# SLIP (Serial Line Internet Protocol)

**Source:** [RFC 1055](https://www.rfc-editor.org/rfc/rfc1055).

SLIP frames packets on a serial line by marking where each one ends. It was
written for IP, but it frames any payload, and serial devices use it for their
own binary messages.

The [`slip`](../src/slip.rs) module implements it in both directions. What it
implements is [§4](#4-what-this-crate-implements).

---

## 1. Special bytes

| Name | Value | Meaning |
|------|-------|---------|
| `END` | `0xC0` | ends a frame |
| `ESC` | `0xDB` | the next byte is escaped |
| `ESC_END` | `0xDC` | after `ESC`: a literal `0xC0` |
| `ESC_ESC` | `0xDD` | after `ESC`: a literal `0xDB` |

A payload `0xC0` goes on the wire as `ESC ESC_END`, and a payload `0xDB` as
`ESC ESC_ESC`. Every other byte goes as itself.

---

## 2. Framing

```
END  <escaped payload>  END
```

The RFC only requires the trailing `END`. It recommends a leading one as well,
so a receiver discards any line noise before the frame as an empty frame.
Back-to-back `END`s therefore frame nothing, and a receiver skips them.

---

## 3. Errors

The RFC leaves `ESC` followed by anything other than `ESC_END` or `ESC_ESC`
undefined, and suggests keeping the byte. It has no length limit, checksum or
type field. Anything like that belongs to the payload.

---

## 4. What this crate implements

| | Item |
|---|---|
| Decode | `SlipDecoder` → `framing::Framed`, with `feed`, `flush`, `bytes_fed` and `abandoned_frames` |
| Encode | `encode_into`, `encode`, both with the leading `END` |
| Constants | `END`, `ESC`, `ESC_END`, `ESC_ESC` |

**Lenient decode.** `ESC` then an ordinary byte keeps both bytes. `ESC` then
`END` drops the `ESC` and releases the frame. Empty frames are never released.

**Unbounded by default.** `SlipDecoder::new()` buffers until an `END` arrives, so
a line that never sends one grows it without limit. `with_max_frame_len(max)`
caps it: a frame that grows past `max` bytes is dropped, the bytes up to the next
`END` are discarded with it, and `abandoned_frames()` counts it once. An escaped
`END` is data, so it does not end an abandoned frame. A `flush` ends one too.

**Offsets.** A frame's `end_offset` counts the bytes fed through its `END`. A
`flush` returns what is buffered, ending at `bytes_fed()`, and clears a pending
`ESC`. The decoder carries on after it, and the count continues.
