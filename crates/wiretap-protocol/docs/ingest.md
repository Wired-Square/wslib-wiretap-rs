# WireTAP Binary Ingest Protocol (v3)

A compact TCP protocol for pushing batches of captured frames — CAN, or the
messages a serial tap recovers — into WireTAP-Server from microcontroller-class
capture devices (ESP32, STM32, etc.). The server feeds them into the same
pipeline as local capture: batching, relay to the gateway, and the SQLite disk
cache for outage resilience. It is also the protocol the server speaks as a
*client* in `[forward]` mode, so one codec covers both ends.

Design priorities, in order: tiny client footprint (fixed little-endian
layouts pack directly as C structs — no varint or text encoding), bounded
buffer sizes known at compile time, and at-least-once delivery with explicit
backpressure.

Version 3 adds what catalogue assignment needs: a capture daemon names itself
and its devices in `HELLO`, the gateway answers with the catalogue assigned to
each device, and the daemon pulls a catalogue it doesn't have with
`CATALOG_GET`. It also adds raw serial records. See [v2 → v3](#v2--v3).

Both ends of the codec are this crate's [`ingest`](../src/ingest.rs) module,
and so is the server's session, as a sans-io state machine (see
[Server session](#server-session)). The tokio drivers stay in WireTAP-Server:
the gateway's in `crates/wiretap-backend/src/ingest/`, the capture daemon's
listener in `crates/wiretap-server/src/ingest.rs` and its forward client in
`crates/wiretap-server/src/forward.rs`. A Python reference client and loopback
test suite is WireTAP-Server's `tools/test_ingest_client.py`.

## Transport and framing

One TCP connection per device. **All integers are little-endian.** Every
message, in both directions, is framed as:

| offset | size | field    | notes                                          |
|--------|------|----------|------------------------------------------------|
| 0      | 2    | `length` | u16 — bytes from `type` to end of body (CRC excluded) |
| 2      | 1    | `type`   | u8 message type                                |
| 3      | N    | body     | `length - 1` bytes                             |
| 3+N    | 4    | `crc32`  | u32 — IEEE CRC-32 over `type` + body           |

Limits: `length` ≤ 65535, so a message is at most ~64 KiB on the wire. A
message that fails its CRC is not processed (a corrupt `BATCH` gets a
`status = 1` ACK so the client can resend; anything else is ignored).

Message types (high bit set = server → client):

| type   | name        | direction        |
|--------|-------------|------------------|
| `0x01` | `HELLO`     | client → server  |
| `0x81` | `HELLO_ACK` | server → client  |
| `0x02` | `BATCH`     | client → server  |
| `0x82` | `ACK`       | server → client  |
| `0x03` | `PING`      | client → server  |
| `0x83` | `PONG`      | server → client  |
| `0x04` | `CATALOG_GET` | client → server, v3 |
| `0x84` | `CATALOG`   | server → client, v3 |
| `0x05` | `CATALOG_STATUS` | client → server, v3, no reply |
| `0x85` | `CLOSE`     | server → client, v3 |

Unknown message types are ignored by the server (forward compatibility). To a
v1 or v2 session, `CATALOG_GET` and `CATALOG_STATUS` are.

## Session start: HELLO / HELLO_ACK

The client must send `HELLO` first; a `BATCH` before successful HELLO causes
the server to drop the connection.

`HELLO` body:

| offset | size | field           | notes                                  |
|--------|------|-----------------|----------------------------------------|
| 0      | 4    | magic           | ASCII `"WTAP"`                         |
| 4      | 1    | `proto_version` | 2                                      |
| 5      | 1    | `flags`         | bit 0 = `TIME_RELATIVE` (see below)    |
| 6      | 1    | `token_len`     | 0–255                                  |
| 7      | n    | token           | API key / shared secret, compared constant-time |
| 7+n    | 1    | `db_len`        | 0–63 (before v3 optional — absent means 0) |
| 8+n    | m    | database        | target capture database name: a lowercase letter, then `[a-z0-9_]`, at most 63 (`valid_database_name`) |
| 8+n+m  | 1    | `id_len`        | v3: 0–63                               |
| 9+n+m  | i    | `daemon_id`     | v3: `[a-z0-9][a-z0-9._-]*` (`valid_daemon_id`), or empty |
| 9+n+m+i | 1   | `dev_count`     | v3: 0–255                              |
| 10+n+m+i | …  | devices         | v3: `dev_count` × `{ bus u8, name_len u8, name }` |

In v3 every field is present. Bytes after the last field are ignored.

**The daemon id and device map (v3).** `daemon_id` names the capture daemon,
and the gateway keys its catalogue assignments by `(daemon_id, interface)`. It
is ASCII: a lowercase letter or digit, then lowercase letters, digits, `.`, `_`
or `-`, at most 63 bytes. Empty is legal on the wire and means an anonymous
client, a microcontroller ingestor, say; the capture daemon never sends it,
which its own configuration enforces. The device map is this session's bus →
interface map: each `bus` its records name, and the interface behind it as
UTF-8, 1–255 bytes (`can0`, `/dev/ttyUSB0`, a by-id path). It lists only the
devices whose records the session carries. An anonymous `HELLO` sends
`dev_count` 0: devices are keyed by the daemon id, so there is nothing to key
them by. The interface is what is keyed, not the bus, because bus numbers
are positional (CAN first, then serial, plus `--bus-offset`) and an edit
renumbers them, where the interface is unique per daemon.

A v3 `HELLO` that breaks these rules — an id outside the charset or over 63
bytes, an empty or non-UTF-8 name, a bus or a name twice, devices with no id,
a field cut short —
is malformed, like a `HELLO` with a bad magic: the server closes the connection
without an answer. A `HELLO` must fit the u16 `length` (a body of at most
65 534 bytes), which a full device map of long names can overrun;
`encode_hello` refuses one that doesn't, and one the server would find
malformed.

The database field selects which capture database the frames land in.
Empty (or absent, for older clients) means the server's default database.
Against the WireTAP backend gateway, an unknown database name is
**auto-created** (schema applied) when the server allows it and the API key
permits — so a freshly flashed ingestor for a new capture provisions its own
database on first connect. A key may be pinned to one database server-side;
HELLO naming any other database is rejected as bad auth. The capture daemon's
own listener logs the field and ignores it: its forward link names the
daemon's own `[forward]` database, so the gateway never sees the device's.

`HELLO_ACK` body:

| offset | size | field              | notes                                |
|--------|------|--------------------|---------------------------------------|
| 0      | 1    | `status`           | 0 = ok, 1 = bad auth, 2 = bad version, 3 = bad database (invalid name, or auto-create disabled), 4 = unavailable (see below) |
| 1      | 1    | `accepted_version` | server protocol version               |
| 2      | 8    | `server_time_us`   | u64 — server wall clock, epoch µs     |
| 10     | 1    | `count`            | v3, status 0 only: assignments that follow |
| 11     | …    | assignments        | v3, status 0 only: `count` × `{ bus u8, blob_sha [20] }` |

`count` and the assignments are present exactly when `status` is 0 and
`accepted_version` is 3, and a client reads them only then. A refusal is
always the 10-byte v2 layout, whatever version it names, so every client
reads every refusal alike. An assignment is the SHA-1 of the catalogue blob
the gateway assigned to the interface behind `bus`, translated through the
`HELLO`'s device map. A bus with no entry has no gateway assignment, so the
daemon falls back to its last good copy, then `/etc`, then none. At most 255
assignments fit `count`; `encode_hello_ack` refuses more.

On any non-zero status the server closes the connection after the ACK.
`server_time_us` lets a clock-capable device synchronise before sending
absolute timestamps.

Status 3 means never: this database won't be served, so a retry gets the same
answer. Status 4 means not yet: the server can't serve the database right now
(an outage, or a schema check or migration in progress), and the client backs
off and retries. A client that predates 4 treats it, like any non-zero status,
as a refusal.

**Versions.** A client speaks one version and there is no negotiation. A
server refuses a version it does not take with `status = 2`, and
`accepted_version` names the newest it does, so the refused end can say which
side is behind; otherwise `accepted_version` is the client's own. The version
check comes before authentication. The gateway takes versions 2 and 3, so a
capture daemon that has not been upgraded keeps flowing through a gateway that
has. The capture daemon's own listener takes 2 and 3 too, because deployed
firmware speaks v2; it has no
assignments, so it answers a v3 `HELLO` with `count` 0 and every `CATALOG_GET`
with status 1.

## Frame delivery: BATCH / ACK

`BATCH` body:

| offset | size | field        | notes                                       |
|--------|------|--------------|----------------------------------------------|
| 0      | 4    | `seq`        | u32 — client-chosen, echoed in the ACK      |
| 4      | 8    | `base_ts_us` | u64 — epoch µs (0 when `TIME_RELATIVE`)     |
| 12     | 2    | `count`      | u16 — records that follow (≤ 256 default)   |
| 14     | …    | records      | `count` records, in any order               |

Each record:

| offset | size  | field         | notes                                       |
|--------|-------|---------------|----------------------------------------------|
| 0      | 4     | `delta_ts_us` | u32 — µs offset from `base_ts_us`           |
| 4      | 1     | `kind`        | u8 — 0 = CAN, 1 = Modbus, 2 = raw serial (v3); anything else is malformed |
| 5      | 1     | `flags`       | u8 — per kind, below; bit 7 reserved for every kind |
| 6      | 1     | `bus`         | u8 — bus number (the device's interface index) |
| 7      | 2     | `len`         | u16 — payload length, capped per kind       |
| 9      | 4     | `id_flags`    | u32 — per kind, below; bit 31 is always dir (0 = rx, 1 = tx) |
| 13     | `len` | payload       | raw bytes                                   |

| kind | `id_flags`                                              | `flags`             | payload, `len`                       |
|------|---------------------------------------------------------|---------------------|--------------------------------------|
| 0 CAN    | bits 0–28 arbitration id, bit 29 extended, bit 30 FD | bit 0 RTR, bit 1 BRS, bit 2 ESI, bits 3–6 an RTR's length code | the frame's data, 0–64               |
| 1 Modbus | bits 8–15 unit (slave address), bits 0–7 function code | bit 0 = CRC valid | the whole RTU message, CRC included, 0–256 |
| 2 raw serial | bits 0–30 read sequence | 0 | the bytes one read returned, 1–256 |

Bit 7 of `flags` is reserved for every kind: a sender writes 0 and a receiver
ignores it, so it never makes a record malformed. Direction is `id_flags` bit
31 for every kind, never a `flags` bit. A flag never repeats what the payload
already says: a Modbus exception is the function code's `0x80` bit, so it has
no flag of its own.

A CAN record's `flags` say what `id_flags` has no room for: bit 0 a remote
frame (RTR), bit 1 the bit rate switch (BRS) and bit 2 the error state
indicator (ESI). Bits 3–6 carry the length code an RTR requests, 0–15 — the
raw DLC code, not a byte count — and are 0 on a data frame. There is one
encoding per frame: BRS and ESI are written only with `id_flags` bit 30 (FD),
and the code only with RTR; a receiver reads what is there but ignores a BRS
or ESI without FD and a code without RTR. The bits are `CanFlags`' RTR, BRS
and ESI, the table storage and the desktop share. They were added in v3 with
no version bump: no receiver checked a CAN record's `flags`, which was 0, and
an older one ignores the byte.

A Modbus record's `id_flags` is also the `id` the archive stores, so an
inventory groups the archive by conversation — `0x0120` is unit 1, function
`0x20`. The tap that produces them transmits nothing, so its records carry
`dir = 0`.

A raw serial record (v3 only; in a v2 batch kind 2 is malformed) carries a
serial port's bytes as read, unframed. Its read sequence counts reads from the
port's open, wrapping at 2^31 (`& 0x7fff_ffff`, `raw_serial_id`), so a gap or a
restart shows; a read longer than 256 bytes is split across records. `dir` is
0.

Per-record overhead is 13 bytes; a classic 8-byte frame costs 21 bytes on the
wire. The u32 delta limits a batch's span to ~71 minutes — irrelevant in
practice since batches should be flushed at least every few seconds.

**Two limits bound a batch, and a client must split at whichever comes
first.** `count` is capped at 256 by default (`max_batch_frames`). The frame's
`length` field is a u16, so the body is at most 65 534 bytes — and 256
full-size Modbus records are 68 878, so a batch of long messages splits by
bytes before it reaches the count. Past the limit the length prefix wraps
and the receiver loses framing; nothing refuses it for you. `fit_batch`
finds the split.

**Timestamps.** With an absolute clock (NTP, GPS, or synced from
`server_time_us`): set `base_ts_us` to epoch µs and deltas relative to it.
Without a clock: set the `TIME_RELATIVE` HELLO flag, use any monotonic µs
counter (e.g. µs since boot) as the delta base, and send `base_ts_us = 0`.
The server stamps the **newest** record in the batch — the largest delta,
wherever it sits — with its arrival time and back-dates the others by their
delta differences: accurate to within network latency, with correct
inter-frame spacing. A device interleaving two buses need not sort.
`Batch::base_ts_us` computes that base, and `Batch::stamped` each record's
stamp.

`ACK` body:

| offset | size | field       | notes                                          |
|--------|------|-------------|--------------------------------------------------|
| 0      | 4    | `seq`       | u32 — echoes the BATCH seq                      |
| 4      | 1    | `status`    | 0 = ok (durably stored), 1 = CRC error, 2 = malformed (don't resend), 3 = server can't store now (database unavailable) |
| 5      | 1    | `queue_pct` | u8 — reserved, always 0 (the gateway writes synchronously and keeps no queue) |

**ACK-after-write.** The gateway writes each batch to PostgreSQL **before**
replying. A `status = 0` ACK therefore means the frames are durably stored, not
merely buffered — there is no in-gateway queue that could be lost on a restart.
If the database is unavailable the gateway replies `status = 3`, which the
client treats as "retry later" (cache and back off).

**Delivery semantics (at-least-once).** Keep each batch buffered until its
seq is ACKed with status 0. Resend on: status 1, status 3 (after a backoff),
no ACK within a timeout, or reconnect. Status 2 means no retry will store this
batch, because the server refused its content: keep it aside (a dead-letter
file, say), don't resend it, and carry on with the next. Occasional duplicate frames from resends are acceptable in the
archive; exact-once is deliberately not attempted. Sequence numbers only
correlate ACKs to batches — they need not be contiguous and the server does
not deduplicate.

## Catalogue pull: CATALOG_GET / CATALOG (v3)

A daemon fetches a catalogue blob it doesn't hold by the SHA-1 a `HELLO_ACK`
assigned, one chunk at a time.

`CATALOG_GET` body:

| offset | size | field      | notes                                    |
|--------|------|------------|------------------------------------------|
| 0      | 20   | `blob_sha` | the SHA-1 of the blob                    |
| 20     | 4    | `offset`   | u32 — where in the blob the chunk starts |

`CATALOG` body:

| offset | size | field       | notes                                    |
|--------|------|-------------|------------------------------------------|
| 0      | 1    | `status`    | 0 = ok, 1 = unknown hash, 2 = unavailable now (back off and retry), 3 = bad offset (past the end) |
| 1      | 20   | `blob_sha`  | echoes the request                       |
| 21     | 4    | `total_len` | u32 — the whole blob's length; 0 unless ok or bad offset |
| 25     | 4    | `offset`    | u32 — echoes the request                 |
| 29     | …    | data        | the rest of the body: the blob from `offset`, at most 65 504 bytes; empty unless ok |

The client starts at offset 0 and asks again at `offset + data.len()` until it
reaches `total_len` (`Catalog::next`). A chunk is as long as the server makes
it, up to the cap, so the client takes the length from the body. An ok chunk
that runs past `total_len`, or stops short of it with no data, is malformed. A
request past the end of the blob gets status 3 with the real `total_len`, so
the client can start again; one exactly at the end gets an empty ok chunk. The
protocol carries the SHA as opaque bytes; checking the assembled blob against
it is the daemon's.

`CATALOG_GET` is valid only after an accepted `HELLO`; before one it closes
the connection, as a `BATCH` does. One shorter than 24 bytes closes it too. It
may come between batches: the server answers each message in turn, so a
`CATALOG` is never mistaken for an `ACK`.

A `CATALOG_GET` can go unanswered: one that fails its CRC is ignored, like any
message but a `BATCH`, and so is one sent in a v1 or v2 session. A client
bounds its wait for `CATALOG` and asks again, as it resends an unacknowledged
`BATCH`.

## Catalogue status: CATALOG_STATUS (v3)

A daemon tells the server which catalogue each of its buses decodes with, and
which it last turned down. The server sends no reply.

`CATALOG_STATUS` body:

| offset | size | field     | notes                                    |
|--------|------|-----------|------------------------------------------|
| 0      | 1    | `count`   | 0–255 entries                            |
| 1      | 43 × `count` | entries | `count` × `{ bus u8, source u8, active_sha [20], refused_sha [20], refusal u8 }` |

- `source`: 0 = none, 1 = local (the `/etc` file; `active_sha` is the git blob
  SHA-1 of its bytes), 2 = assigned.
- `refusal`: 0 = none, 1 = hash mismatch, 2 = did not parse, 3 = fetch failed.
  `refused_sha` is the blob turned down.

Each entry is the whole state of one bus, keyed by `bus` and translated
through the `HELLO`'s device map, as assignments are. **A message is a full
snapshot:** it lists every bus in the device map, and the server replaces the
session's state with it rather than merging. The daemon sends one after the
pulls that follow each `HELLO_ACK`, and again whenever a device's effective
catalogue changes.

It is malformed, and the server closes the connection, when it is shorter than
`1 + 43 × count`, lists a bus twice, has a `source` above 2, a `source` 0 with
a non-zero `active_sha` or a `source` 1–2 with an all-zero one, or a `refusal`
0 with a non-zero `refused_sha` or a `refusal` 1 or more with an all-zero one.
Bytes after the last entry are ignored. An unknown `refusal` (4 or more) is
not malformed: it reads as `Refusal::Other`, so a later daemon can add a reason
without a version bump. Checking each bus against the device map is the
server's choice.

`CATALOG_STATUS` is valid only after an accepted `HELLO`; before one it closes
the connection, as `CATALOG_GET` does. In a v1 or v2 session it is ignored.
`encode_catalog_status` refuses more than 255 entries, and one the server
would find malformed.

## Reassignment (v3)

There is no push. When an administrator changes a daemon's assignment, the
gateway closes that daemon's session, after the reply it owes and a `CLOSE`;
the daemon reconnects as after any drop, and the new `HELLO_ACK` carries the
new assignments. There is no "id in use" or "assignment refused" status in v3.

## Server close: CLOSE (v3)

The server tells the client why it is closing the connection, then closes it.

`CLOSE` body:

| offset | size | field    | notes                                    |
|--------|------|----------|------------------------------------------|
| 0      | 1    | `reason` | 0 = reassigned: the session's catalogue assignment changed; reconnect and read the new one |

A client treats any `CLOSE`, an unknown `reason` included, as the server
closing deliberately rather than an outage. Bytes after `reason` are ignored.
Only a version 3 session is sent one; an older client sees the connection
close.

## Keepalive: PING / PONG

Both bodies are empty. Send `PING` at the server's configured interval
(30 s by default) whenever no batches are flowing; the server
drops connections silent for 3× that interval. Any received message counts
as activity, so a busy device never needs to ping.

## Server configuration

The listener's `[ingest]` settings — port, token, keepalive interval and
`max_batch_frames` — belong to WireTAP-Server; see its configuration docs. The
token is sent in clear text, so deploy on a trusted network or wrap the
connection in a VPN or stunnel if it crosses untrusted segments.

## Server session

`ServerSession` is the server's side of one connection, with no I/O and no
clock. The caller feeds it what the socket reads (`receive`), acts on what
`poll` returns, and writes the bytes `answer_hello` and `ack` return.
`ServerConfig` holds where the gateway and the capture daemon differ: which
versions are taken, and whether a `BATCH` too short to carry its header closes
the connection or gets a malformed `ACK` for seq 0.

- **One reply per message, in order.** `poll` returns `None` while a `HELLO`
  verdict, an `ACK` or a `CATALOG` is owed: after `Hello` or `HelloRefused`
  until `answer_hello`, after `Batch` or `Nack` until `ack`, after `CatalogGet`
  until `answer_catalog`, which takes the blob or a status and cuts the chunk.
  `CatalogStatus` owes no reply, so the next `poll` carries on.
- **`Nack` carries no bytes.** The caller makes them with `ack(seq, status,
  queue_pct)`, as for a batch, so every `ACK` goes through one path.
- **The machine checks the version, before auth.** One it doesn't take comes
  back as `HelloRefused(2)`, still answered through `answer_hello`. Any non-zero
  verdict — a re-`HELLO`'s included — is followed by `Close(Refused(status))`.
- **The caller owns** authentication, the database, an `ACK`'s status and
  `queue_pct`, the assignments and the blobs, stamping (`IncomingBatch` carries
  the latest accepted `HELLO`'s `time_relative` and version, and `hello()` is
  that `HELLO`, daemon id and device map included), and the idle timeout: any
  byte read resets it, and `idle_limit()` hands back the configured limit.
- **Reassignment is the caller's to trigger.** `close_reassigned()` closes the
  session with `Close(Reassigned)` once any owed reply is answered, after a
  `Reply` carrying `CLOSE` to a version 3 session.

## Sizing guidance for clients

A worst-case CAN batch (256 × classic CAN, 8-byte payloads) is
`7 + 14 + 256 × 21 = 5397` bytes — one static buffer. With a 500 kbit/s bus
at full load (~4000 frames/s), flushing 256-frame batches means ~16 batches/s
≈ 84 KB/s of TCP traffic, comfortably inside ESP32 Wi-Fi capability. Flush
partial batches on a timer (e.g. 250 ms) so quiet buses still record promptly.
A device carrying Modbus or raw serial records needs a 64 KiB buffer, or a smaller
`count` of its own choosing.

---

## v1 → v2

Version 1 carried CAN only: a 10-byte record of `delta_ts_us u32 | id_flags
u32 | bus u8 | len u8`, with every bit of `id_flags` allocated and a payload of
at most 64 bytes. Version 2 changed the `0x02 BATCH` record in place rather
than adding a message type beside it: a `kind` byte says what the record is,
`flags` carries what the kind needs, and `len` grew to a u16 so a Modbus RTU
message fits whole. A CAN record's `id_flags` is bit-identical to v1's.

**Upgrade order is gateway first, then capture daemons.** The gateway accepts
both versions for one release, so a daemon still on v1 keeps flowing between
the two steps; a v2 daemon against a v1 gateway is refused at the handshake
and caches to disk until the gateway is upgraded. The daemon's log names both
versions when that happens.

## v2 → v3

Version 3 is one bump for two needs, so the gateway is deployed first once,
not twice: catalogue assignment, and raw serial records. Every message not
named here is the same bytes in both versions.

- `HELLO` gained `daemon_id` and the device map after `database`, and every
  field became required.
- `HELLO_ACK` gained `count` and the assignments, present when `status` is 0
  and `accepted_version` is 3. A refusal is unchanged.
- `CATALOG_GET` (`0x04`) and `CATALOG` (`0x84`) are new.
- `CATALOG_STATUS` (`0x05`) was added later in v3, with no version bump: a v3
  server that predates it ignores it as an unknown type.
- `CLOSE` (`0x85`) was added later in v3 too, with no version bump.
- A CAN record's `flags` (RTR, BRS, ESI and an RTR's length code) were added
  later in v3, with no version bump: the byte was 0, and a receiver that
  predates them ignores it. A v2 batch's CAN record parses the same bits.
- Record kind 2, raw serial, is new; in a v2 batch it stays malformed.

**Upgrade order is gateway first, then capture daemons.** The gateway takes
both versions, so a daemon still on v2 keeps flowing between the two steps,
with no assignments; a v3 daemon against a v2 gateway is
refused at the handshake, `accepted_version` 2, and caches to disk until the
gateway is upgraded. The capture daemon's listener keeps taking v2, so
firmware that ingests through a daemon needs no upgrade.
