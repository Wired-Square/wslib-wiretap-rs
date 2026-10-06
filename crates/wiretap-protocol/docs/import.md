# WireTAP Capture Import Body

The body the WireTAP desktop streams to a gateway to upload a local capture
into a capture database. The HTTP endpoint, its authentication and its
`create` switch belong to WireTAP-Server's gateway; this is only the body.

The [`import`](../src/import.rs) module implements both ends. What it
implements is [§4](#4-what-this-crate-implements).

---

## 1. Header

Every body starts with five bytes, once, before its first record:

| offset | size | field     | notes                    |
|--------|------|-----------|--------------------------|
| 0      | 4    | `magic`   | `"WTIM"`                 |
| 4      | 1    | `version` | u8 — 2                   |

There is no negotiation. A gateway takes exactly one version and refuses a
body with any other. **Upgrade every gateway before any desktop**: a gateway
that predates the header reads a versioned body as headerless records and
stores garbage without an error, while a current gateway refuses an older
desktop's body outright.

Version 1 was the headerless body: records from the first byte, without
`flags`. It is no longer accepted; it fails the magic check.

---

## 2. Record

After the header, records back to back. There is no framing, count or
checksum around them: the stream ends where the body does. **All integers are
little-endian.**

| offset | size  | field      | notes                                        |
|--------|-------|------------|-----------------------------------------------|
| 0      | 8     | `ts_us`    | i64 — epoch µs                               |
| 8      | 4     | `id_flags` | u32 — the [ingest](ingest.md) CAN `id_flags` |
| 12     | 1     | `flags`    | u8 — the ingest CAN `flags`                  |
| 13     | 1     | `bus`      | u8 — bus number                              |
| 14     | 1     | `len`      | u8 — payload length, 0–64                    |
| 15     | `len` | payload    | the frame's data                             |

`id_flags` is bits 0–28 arbitration id, bit 29 extended, bit 30 FD, bit 31
dir (0 = rx, 1 = tx). `flags` is bit 0 RTR, bit 1 BRS, bit 2 ESI, bits 3–6 an
RTR's length code, bit 7 reserved. Both are the ingest protocol's CAN record
words, bit for bit, with the same rules: BRS and ESI only with FD, the length
code only with RTR. An RTR record's `len` is 0. There is no `kind`: every
record is CAN.

---

## 3. Errors

A body whose first four bytes are not `"WTIM"` is refused, as is one whose
version is not the one the gateway takes; the error names the version found
and the one supported. A `len` over 64 is refused as soon as its record header
arrives, and the rest of the body with it: with no framing, nothing after a
bad length can be found. A body that ends part-way through a record is
truncated.

---

## 4. What this crate implements

| | Item |
|---|---|
| Encode | `encode_header_into`, then `encode_record_into` from a `CanFrame` |
| Decode | `parse_header`, then `take_record` / `parse_record` → `Record`, streaming: `Ok(None)` until a whole header or record is buffered |
| Unpack | `Record::fields` → `ingest::RecordFields`, `Record::into_can` → `CanFrame` |
| Constants | `MAGIC`, `VERSION`, `BODY_HEADER`, `RECORD_HEADER` |

The flag bits are not mapped here: `encode_record_into` packs through
`ingest::RecordFields::from_can` and `to_wire`, and `Record::fields` unpacks
through `RecordFields::from_wire`.

**Clamped encode.** A payload over 64 bytes is cut to 64, as
`ingest::encode_record_into` cuts one to its kind's limit, and a remote
frame's payload is dropped.

**Truncation is the caller's.** `take_record` cannot tell a body that ended
from one still arriving; bytes left in the buffer at the end of the body are a
truncated record.
