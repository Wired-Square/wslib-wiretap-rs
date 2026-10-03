# WireTAP Capture Import Record

The body the WireTAP desktop streams to a gateway to upload a local capture
into a capture database. The HTTP endpoint, its authentication and its
`create` switch belong to WireTAP-Server's gateway; this is only the record.

The [`import`](../src/import.rs) module implements both ends. What it
implements is [§3](#3-what-this-crate-implements).

---

## 1. Record

A body is records back to back. There is no header, framing, count or
checksum around them: the stream ends where the body does. **All integers are
little-endian.**

| offset | size  | field      | notes                                        |
|--------|-------|------------|-----------------------------------------------|
| 0      | 8     | `ts_us`    | i64 — epoch µs                               |
| 8      | 4     | `id_flags` | u32 — the [ingest](ingest.md) CAN `id_flags` |
| 12     | 1     | `bus`      | u8 — bus number                              |
| 13     | 1     | `len`      | u8 — payload length, 0–64                    |
| 14     | `len` | payload    | the frame's data                             |

`id_flags` is bits 0–28 arbitration id, bit 29 extended, bit 30 FD, bit 31
dir (0 = rx, 1 = tx) — the ingest protocol's CAN word, bit for bit. There is
no `kind`: every record is CAN.

---

## 2. Errors

A `len` over 64 is refused as soon as its header arrives, and the rest of the
body with it: with no framing, nothing after a bad length can be found. A body
that ends part-way through a record is truncated.

---

## 3. What this crate implements

| | Item |
|---|---|
| Encode | `encode_record_into` |
| Decode | `take_record` → `Record`, streaming: `Ok(None)` until a whole record is buffered |
| Constants | `RECORD_HEADER` |

**Clamped encode.** A payload over 64 bytes is cut to 64, as
`ingest::encode_record_into` cuts one to its kind's limit.

**Truncation is the caller's.** `take_record` cannot tell a body that ended
from one still arriving; bytes left in the buffer at the end of the body are a
truncated record.
