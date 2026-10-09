# wiretap-decode

The protocol-agnostic decode core of the [`wslib-wiretap-rs`](../../) workspace: the
numeric and bit primitives every catalogue decoder shares, with no dependency on
the catalogue model.

## What's here

- **`extract_field`** — a signal's bits in its bank's ordering: the one place
  the word-swap rule lives, and the one that knows a coil block is read
  least-significant-bit-first and never swapped (`BitOrder`)
- **`extract_bits`** — a bitfield as `f64`, honouring endianness and sign
- **`apply_word_swap`** — 16-bit "CDAB" word order
- **`scale`** — `raw × factor + offset` as an exact `Decimal`, so `3374 × 0.1`
  is `337.4` and not `337.40000000000003`; `None` when an input is non-finite
  or the value leaves `Decimal`'s range
- **`format_decimal`, `format_hex`, `format_unix_time`, `decode_text`** — value
  formatting
- **`frame_id::extract_frame_id`** — a serial message's frame id: one byte, or
  two in either order, counted from either end (`FrameIdField`, `FrameIdWidth`)
- **`frame_id::format_frame_id`** — a frame id for display, `0x07B` standard
  and `0x0000007B` extended
- **`PayloadField`, `ScaledField`** — a bit field cut from a payload without a
  catalogue, read through `extract_bits`, and the same field through `scale`;
  `ScaledField`'s JSON is the desktop's `HypothesisParams`
- **`byte_name`, `parse_byte_name`** — the name a whole-byte field is saved
  under, `byte_<offset>_<bits>b_<le|be>` (8 to 64 bits); the older `byte[i]`
  still reads as one little-endian byte
- **`hex::parse_bytes`, `hex::parse_bytes_lenient`** — a typed hex byte string
  (`01 04`, `0x01,0x04`, `0104`): strict fails with a `HexError` naming the bad
  token, lenient drops it

## Using it

Consumed by path within the workspace — [`wiretap-catalog`](../wiretap-catalog)
builds both its `decode_by_id` path and its Modbus register decode on these, so
there is one extraction and scaling implementation. Released as part of the
workspace `vX.Y.Z` tag; not pinned directly.
