# Test Pattern

A protocol for proving a CAN link carries what it claims to. Two endpoints
exchange frames over a physical bus: one **initiates** and measures — drops,
duplicates, reordering, round-trip time, and whether every payload arrived
intact — while the other **responds**. Either end can take either role.

It exists because a capture tool's own transport is the one thing its captures
cannot check. A codec that truncates a payload, confuses a data length code for
a byte count, or silently downgrades a CAN FD frame to classic produces a
capture that looks entirely healthy.

---

## 1. Two message classes

**Framed** messages — ping, latency, control, status — carry an 8-byte header.
That is what lets them share a bus with each other and with real traffic.

**Sweep** messages carry no header at all, because the thing they test is length
itself. A frame carrying an 8-byte header cannot be shorter than 8 bytes, and 8
is exactly where a payload length and a data length *code* are the same number —
so a header-carrying message is blind to the entire class of fault where one is
mistaken for the other. Sweep frames put the code in the arbitration id and give
the whole payload over to test bytes, which makes all sixteen codes reachable,
including zero.

---

## 2. Framed messages

Exactly eight bytes. There is no length field — a CAN frame's own length is it —
so a shorter payload is not a truncated message, it is not one of these at all.
A longer one is an FD frame padded out to its length code, and the padding is
not part of the message.

```
Byte 0     Tag
Byte 1     Flags
Bytes 2-3  Sequence counter, big-endian u16
Bytes 4-7  Type-specific
```

### 2.1 Tag (byte 0)

| Value | Name | Direction |
|-------|------|-----------|
| `0x01` | Ping request | initiator → responder |
| `0x02` | Ping reply | responder → initiator |
| `0x03` | Throughput | either, one-way |
| `0x04` | Latency probe | initiator → responder |
| `0x05` | Latency reply | responder → initiator |
| `0x06` | Control | either |
| `0x07` | Status report | either |

### 2.2 Flags (byte 1)

```
Bit 0     Data mode        0 = frames, 1 = byte stream
Bits 1-3  Interface index  0-7
Bits 4-7  Run tag          0-15
```

**The run tag is what makes two initiators on one bus safe.** A receiver
discards any framed message whose run tag is not its own, so one run's sequence
numbers cannot be counted as another's drops. The initiator picks a tag, names
it in `Start`, and stamps every frame of the run with it.

Control messages are exempt: a `Hello` has to be answerable by a responder that
has not yet been told a run tag.

### 2.3 Sequence counter (bytes 2-3)

Big-endian u16, incremented per transmitted frame, wrapping 65535 → 0. Control
and status messages carry zero rather than consuming a number, so a receiver's
tracker never sees them.

### 2.4 Type-specific bytes (4-7)

| Tag | Bytes 4-7 |
|-----|-----------|
| Ping request / reply | zero |
| Throughput | byte 4 = fill pattern id (§5), rest zero |
| Latency probe / reply | sender's microsecond clock, low 32 bits, big-endian |
| Control | §3 |
| Status | §4 |

A latency probe's timestamp is echoed **untouched**. The initiator measures
against its own clock; reading the wire value back would make the result depend
on two clocks agreeing. It wraps every 71m34s, so an implementation that does
read it must difference modulo 2³².

---

## 3. Control messages

Byte 4 is the command; bytes 5-7 are its body.

| Code | Name | Body |
|------|------|------|
| `0x01` | Start | mode, run tag, — |
| `0x02` | Stop | — |
| `0x03` | Set rate | target frames/sec, big-endian u16 |
| `0x04` | Request status | — |
| `0x05` | Hello | — |
| `0x85` | Hello reply | capability bits, bus, — |

A run reads:

```
initiator ──── Hello ─────────────▶  (broadcast; who is out there?)
          ◀─── Hello reply ───────   capabilities, bus
          ──── Start(mode, run) ──▶  bind the responder to this run
          ──── … traffic … ───────▶
          ◀─── … replies … ───────
          ──── Request status ────▶
          ◀─── 4 × status ────────
          ──── Stop ──────────────▶
```

`Hello` is the only message a responder answers while idle — it is how an
initiator discovers anything is there at all, and the reply doubles as the
capability exchange. Capability bits: `0x01` answers CAN FD, `0x02` answers
extended ids.

Because `Start` tells the responder when a run begins and what was expected of
it, the counters it reports in §4 are real rather than assumed.

An unrecognised command code is carried to the caller rather than dropped, so a
newer peer's traffic is visibly unhandled instead of silently ignored.

---

## 4. Status reports

One frame per counter, four in all. Byte 4 is the field, bytes 5-7 the value as
a big-endian u24.

| Field | Meaning |
|-------|---------|
| `0x00` | frames received |
| `0x01` | frames transmitted |
| `0x02` | drops |
| `0x03` | frames per second |

A counter is 24 bits on this wire. A longer run **saturates at 16,777,215**
rather than wrapping to a small number that would read as a healthy link.

---

## 5. Fill patterns

For throughput frames, byte 4 names how the payload beyond the header is filled,
so a receiver can detect corruption rather than only loss.

| Id | Pattern |
|----|---------|
| `0x00` | sequential — `byte[i] = i` |
| `0x01` | walking bit — `01 02 04 08 10 20 40 80` |
| `0x02` | counter — every byte is the sequence number's low 8 bits |
| `0x03` | alternating — `AA 55` |
| `0xFF` | none — zero fill |

---

## 6. The sweep

The part that validates CAN FD, and the only part that can.

```
initiator → responder    id = 0x7E0 + code    payload = fill of that code's length
responder → initiator    id = 0x7C0 + code    payload = exactly what it received
```

The low nibble of the id is the **data length code**, 0-15. The payload is the
full length that code names, filled deterministically from the code and the byte
position, so both ends agree without negotiating and no two codes produce the
same bytes.

The exchange is lock-step: one request, one echo, then the next code. It runs
inside a run already bound by `Start`, which is what keeps it unambiguous
without a run tag of its own.

The initiator compares the echo against **what the code names**, not against
what it sent. An endpoint that answered with a different length has failed even
if every byte it did send was right — which is precisely how a length-versus-code
confusion presents.

| Sweep | Codes | Lengths |
|-------|-------|---------|
| Classic CAN | 0-8 | 0-8 |
| CAN FD | 0-15 | 0-8, then 12, 16, 20, 24, 32, 48, 64 |

Classic stops at 8 because codes above it are legal on the wire and still mean
8 bytes, so sweeping them would test the same length nine times.

Lengths with no code of their own — 9, 10, 11, 13-15 and so on — are not swept.
A transmitter must round them up to the next code and pad, which is an encoder
property provable without a bus, and is asserted in this crate's own tests.

---

## 7. CAN mapping

| Id | Message |
|----|---------|
| `0x7F0` | ping request |
| `0x7F1` | ping reply |
| `0x7F2` | throughput, initiator → responder |
| `0x7F3` | throughput, responder → initiator |
| `0x7F4` | latency probe |
| `0x7F5` | latency reply |
| `0x7F6` | control |
| `0x7F7` | status report |
| `0x7E0`-`0x7EF` | sweep request, low nibble = length code |
| `0x7C0`-`0x7CF` | sweep echo, low nibble = length code |

**Extended ids.** The eight framed ids have a 29-bit form at `0x1F0007F0 + n`,
for exercising extended addressing. A responder answers on the width it was
asked on: a run using 29-bit ids that received 11-bit replies would report a
dead link. Every other id in this table is 11-bit only, sweeps included: an
extended frame whose id is numerically one of them is not Test Pattern.

**CAN FD.** A framed message padded out to its length code; the padding is not
part of the message. A responder that has not claimed the FD capability answers
classically whatever it was asked on.

**Carrying this over GVRET.** No special mapping — GVRET moves CAN frames, and
these are CAN frames. See [`docs/gvret.md`](gvret.md).

---

## 8. Test modes

| Mode | What it does | What it measures |
|------|--------------|------------------|
| Echo | pings at a set rate; responder replies to each | response rate, drops, duplicates, reordering |
| Sweep | one frame per length code, lock-step | payload integrity at every length |
| Throughput | frames as fast as the transport allows, one-way | sustained frames/sec, loss, corruption |
| Latency | probes at a low rate to avoid queueing | RTT min/max/mean/p50/p95/p99 |
| Reliability | echo at a moderate rate, for minutes or hours | cumulative drops over time |

---

## 9. Sequence analysis

| Condition | Reading |
|-----------|---------|
| `seq == expected` | delivered in order |
| `seq` ahead by less than 32768 | that many frames dropped; the gap is recorded |
| `seq` behind, or ahead by 32768 or more | reordered, or already counted as dropped |
| `seq` seen before | duplicate |

The first frame defines where a stream starts — a tracker that assumed zero
would count everything before the frame it first saw as dropped, so a responder
joining a run in progress would report a broken link.

A backwards jump of more than half the sequence space is the counter wrapping,
not thirty thousand frames arriving late.

Duplicate detection covers the whole 16-bit space for the life of a run.

---

## 10. What this crate implements

[`testpattern`](../src/testpattern.rs): the whole contract above, both sides.

| | Item |
|---|---|
| Framed messages | `Message`, `Command`, `encode`, `decode`, `Flags` |
| Ids | `ID_*`, `extended_id`, `is_test_pattern_frame`, `sweep_code` |
| Sweep | `sweep_payload`, `sweep_codes`, `sweep_echo_matches` |
| Analysis | `SequenceTracker`, `Latencies` → `LatencyStats` |
| The reply side | `Responder::on_frame` → `Vec<Reply>` |

`Responder` is sans-io: feed it a frame, transmit what it hands back. It answers
`Hello` while idle, binds to a run on `Start`, echoes pings, latency probes and
sweeps while that run is live, reports its counters on request, and goes quiet on
`Stop`. It returns a `Vec` rather than a single reply because a status request is
answered by four frames; an empty one does not allocate.

### Documented, and deliberately not acted on here

Three parts of the contract above are encoded and decoded but go no further, so
that a peer implementing them is understood rather than rejected:

- **The byte-stream mapping** (§1 data-mode flag) — carrying these payloads over
  a serial link with COBS or SLIP framing, tag byte alone identifying the type.
  Nothing here encodes or decodes the framing. It is specified because the
  message layout is transport-independent and a byte-stream implementation
  should not have to reinvent it.
- **The throughput return stream** (`0x7F3`) — a responder streaming its own
  counters back at the initiator. The id is part of the map; `Responder` counts
  throughput frames and does not answer them.
- **`Set rate`** — `Responder` decodes it and ignores it, because a responder
  that only echoes has no rate of its own to set. It is for one that streams.
