# PCAN-USB USB protocol

**Source:** the Linux kernel driver,
[`drivers/net/can/usb/peak_usb/pcan_usb.c`](https://github.com/torvalds/linux/blob/master/drivers/net/can/usb/peak_usb/pcan_usb.c),
with the timestamp handling and USB plumbing in `pcan_usb_core.c` beside it
(GPL-2.0, PEAK-System Technik GmbH, Stéphane Grosjean).

PCAN-USB is PEAK-System's classic single-channel adapter: an SJA1000 CAN
controller behind a full-speed USB microcontroller. On Linux the kernel's
`peak_usb` driver claims it and an application sees SocketCAN; on Windows and
macOS an application without PEAK's own driver drives the endpoints itself.

The [`pcan_usb`](../src/pcan_usb.rs) module implements the layouts, the record
decoder and the bit timing maths for that second case. What it implements is
[§8](#8-what-this-crate-implements).

---

## 1. General structure

Two bulk endpoint pairs on interface 0, at fixed addresses. Multi-byte fields
are little-endian. There are no checksums — USB provides integrity.

```
Commands:   bulk OUT 0x01, replies on bulk IN 0x81   16 bytes each
Messages:   bulk OUT 0x02, bulk IN 0x82               64 bytes each
```

The kernel keeps four 64-byte bulk-IN transfers in flight on `0x82`.

---

## 2. USB identification

| Field | Value | Device |
|-------|-------|--------|
| VID | `0x0C72` | PEAK-System Technik |
| PID | `0x000C` | PCAN-USB — **this protocol** |

The same vendor's other adapters speak a different protocol (`pcan_usb_pro.c`,
`pcan_usb_fd.c`) and are **not** this one; the FD family's is
[`pcan_usb_fd.md`](pcan_usb_fd.md):

| PID | Device |
|-----|--------|
| `0x000D` | PCAN-USB Pro |
| `0x0011` | PCAN-USB Pro FD |
| `0x0012` | PCAN-USB FD |
| `0x0013` | PCAN-Chip USB |
| `0x0014` | PCAN-USB X6 |

The adapter has no USB serial-number string. Its serial number is read with
the `SN` command ([§3](#3-commands)) and printed as `%08X`; `FFFFFFFF` is one
that was never programmed.

### 2.1 Device revision

`bcdDevice >> 8` is the revision the kernel keys features on:

| Revision | Adds |
|----------|------|
| > 3 | silent (listen-only) mode |
| ≥ 41 | self-reception (SRR) and one-shot transmission |

Below revision 4 the kernel skips the silent-mode command, so listen-only is
silently not applied.

---

## 3. Commands

Written to bulk OUT `0x01`, 16 bytes, with a 1 s timeout:

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       1     function
1       1     number
2–15    14    args
```

A `GET` is the command (args zero) followed by a 16-byte read on bulk IN
`0x81`; the reply's args carry the answer.

| Function | Code | Number | Args | Meaning |
|----------|------|--------|------|---------|
| `BITRATE` | 1 | `SET` 2 | `[0]` BTR1, `[1]` BTR0 | bus timing ([§4](#4-bit-timing)) |
| `SET_BUS` | 3 | `XCVER` 2 | `[0]` 0/1 | transceiver off/on |
| `SET_BUS` | 3 | `SILENT_MODE` 3 | `[0]` 0/1 | silent (listen-only) mode |
| `DEVID` | 4 | `GET` 1 | reply `[0]` | the device id, a user-set byte |
| `SN` | 6 | `GET` 1 | reply `[0..4]` u32 LE | serial number |
| `REGISTER` | 9 | `SET` 2 | `[1]` mode | SJA1000 mode: 0 normal, 1 init (reset) |
| `EXT_VCC` | 10 | `SET` 2 | `[0]` 0/1 | external 5 V supply |
| `ERR_FR` | 11 | `SET` 2 | `[0]` mask | bus-event reporting |
| `LED` | 12 | `SET` 2 | `[0]` 0/1 | LED |

`GET` is number 1 and `SET` 2. The `ERR_FR` mask the kernel sends is `0x06`:
`RXERR` (`0x02`) and `TXERR` (`0x04`), asking for a bus-event record on every
change of the error counters.

---

## 4. Bit timing

An SJA1000 clocked at 8 MHz (half the 16 MHz crystal), with the kernel's
constraints:

| tseg1 | tseg2 | sjw | brp |
|-------|-------|-----|-----|
| 1–16 | 1–8 | 1–4 | 1–64, step 1 |

```
BTR0 = ((brp − 1) & 0x3F) | (((sjw − 1) & 0x03) << 6)
BTR1 = ((prop_seg + phase_seg1 − 1) & 0x0F) | (((phase_seg2 − 1) & 0x07) << 4)
       bit 7 of BTR1: triple sampling

bitrate      = 8 000 000 / (brp × (1 + tseg1 + tseg2))
sample_point =              (1 + tseg1) / (1 + tseg1 + tseg2)
```

The kernel derives these with `can_calc_bittiming`: it walks `tseg` from
`(tseg1_max + tseg2_max) × 2 + 1` down, takes the smallest bitrate error and
then the smallest sample-point error that does not pass the reference, and
refuses anything more than 5% out. Without a requested sample point it uses
CiA's: 75% above 800 kbit/s, 80% above 500 kbit/s, 87.5% otherwise. The
synchronisation jump width is `max(1, min(phase_seg1, phase_seg2 / 2))`.

At the standard rates this gives PEAK's own published register values:

| Bitrate | BTR0 | BTR1 | Sample point |
|---------|------|------|--------------|
| 1 Mbit/s | `0x00` | `0x14` | 75% |
| 800 kbit/s | `0x00` | `0x16` | 80% |
| 500 kbit/s | `0x00` | `0x1C` | 87.5% |
| 250 kbit/s | `0x01` | `0x1C` | 87.5% |
| 125 kbit/s | `0x03` | `0x1C` | 87.5% |

The slowest rate is 5 kbit/s (brp 64, 25 quanta). The search also accepts
2 Mbit/s (brp 1, 4 quanta), above what classic CAN allows.

---

## 5. Received messages

Each bulk-IN transfer on `0x82` is one message:

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       1     (unchecked)
1       1     record count
2–      …     records
```

A 0-byte transfer carries nothing; 1 or 2 bytes is a length error. A record
that runs past the end ends the message; the records before it stand.

### 5.1 Status/length byte

Every record starts with it:

| Bit(s) | Mask | Meaning |
|--------|------|---------|
| 7 | `0x80` | `TIMESTAMP` — a status record carries a stamp |
| 6 | `0x40` | `INTERNAL` — a status record, not a frame |
| 5 | `0x20` | `EXT_ID` — 29-bit id |
| 4 | `0x10` | `RTR` |
| 3–0 | `0x0F` | DLC, or a status record's length |

### 5.2 Timestamps

The device counts 16-bit ticks of 42.666 µs, so the count wraps every 2.8 s:

```
µs = (ticks × 44 739 243) >> 20
```

Within one message, the **first** timestamped record carries the full 16-bit
count, LE; **every later** timestamped record carries one byte, the low byte.
A low byte smaller than the previous one means the high byte has incremented.
Data records are always timestamped; status records only with bit 7.

### 5.3 Data record (`INTERNAL` clear)

```
status/len
id          4 bytes LE: (id << 3) | flags   with EXT_ID
            2 bytes LE: (id << 5) | flags   without
timestamp   2 bytes, or 1 (§5.2)
data        DLC bytes, unless RTR; the frame's payload is the first min(DLC, 8)
client id   1 byte, only when the id's SRR flag is set and not RTR
```

| Id flag | Value | Meaning |
|---------|-------|---------|
| `SRR` | `0x01` | self-reception: this host's own send, handed back |
| `AT` | `0x02` | single-shot (transmit only) |

### 5.4 Status record (`INTERNAL` set)

```
status/len
function    1 byte
number      1 byte
timestamp   2 bytes or 1, only with bit 7 (§5.2)
data        rec_len bytes
```

`rec_len` is the DLC nibble, except where the table says otherwise.

| Function | Code | rec_len | Content |
|----------|------|---------|---------|
| `ERROR` | 1 | DLC | `number` is the error flags below |
| `ANALOG` | 2 | 2 | analogue values (ignored by the kernel) |
| `BUSLOAD` | 3 | 1 | bus load (ignored by the kernel) |
| `TS` | 4 | DLC | a 16-bit LE sync stamp in the first 2 data bytes |
| `BUSEVT` | 5 | DLC | `number` `0x00` or `0x80` (counters falling, rising): data `[1]` rxerr, `[2]` txerr |

An unknown function is skipped by its `rec_len`. A `TS` record replaces the
running 16-bit count, but not the low byte the next one-byte stamp is compared
with.

| Error flag | Value |
|------------|-------|
| `TXFULL` | `0x01` |
| `RXQOVR` | `0x02` — receive overrun |
| `BUS_LIGHT` | `0x04` — error warning |
| `BUS_HEAVY` | `0x08` — error passive |
| `BUS_OFF` | `0x10` |
| `RXQEMPTY` | `0x20` |
| `QOVR` | `0x40` |
| `TXQFULL` | `0x80` |

---

## 6. Transmit message

Always the full 64 bytes, on bulk OUT `0x02`, one frame each:

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────
0       1     2 (a CAN frame)
1       1     1 (one record)
2       1     status/len: DLC | RTR 0x10 | EXT_ID 0x20
3–      4/2   id, as §5.3, with SRR in its flags to ask for the frame back
…       DLC   data, none for RTR
…       1     0x80 (a client id), whenever SRR is set — RTR included
63      1     a rolling sequence number (the kernel's tx count & 0xFF)
```

Everything else is zero.

---

## 7. Start and stop

The kernel's sequence, across probe, bit-timing set and open:

```
1.  GET SN
2.  SET_BUS XCVER 0          bus off
3.  REGISTER SET init (1)
4.  GET DEVID
5.  BITRATE SET              BTR1, BTR0
6.  ERR_FR SET 0x06          a failure is only a warning
7.  SET_BUS SILENT_MODE      listen-only 0/1; only on revision > 3
8.  EXT_VCC SET 0
9.  SET_BUS XCVER 1          bus on
10. wait 10 ms               the device's start-up time
```

The kernel submits its bulk-IN transfers before step 6. Stopping is
`SET_BUS XCVER 0` then `REGISTER SET init`.

---

## 8. What this crate implements

The layouts, the decoder and the timing maths, in
[`pcan_usb`](../src/pcan_usb.rs). Driving the USB endpoints is the caller's.

| | Item |
|---|---|
| Identity | `VID`, `PID`, `EP_*`, `MESSAGE_BYTES`, `device_rev`, `SILENT_MODE_FROM_REV`, `SELF_RECEPTION_FROM_REV` |
| Commands | `Command` and its constructors, `function`, `number`, `BERR_MASK` |
| Replies | `serial_number` |
| Timing | `btr_for_bitrate`, `Btr` and its decoded fields, `BITTIMING`, `CLOCK_HZ`, and `bittiming::cia_sample_point` |
| Timestamps | `ticks_to_us`, `TICK_SCALE`, `TICK_SHIFT` |
| Received | `decode_message`, `Record`, `Frame`, `status_len`, `id_flags`, `record`, `error_flags` |
| Transmit | `encode_transmit` |

`btr_for_bitrate` encodes what [`bittiming::calculate`](../src/bittiming.rs)
gives for `BITTIMING`: a port of the kernel's `can_calc_bittiming` and
`can_update_sample_point`, down to their unsigned arithmetic, so it answers what
the kernel would. `decode_message` returns frames, errors, syncs and bus events
with their raw 16-bit stamps; unwrapping them across messages is the caller's.
Analogue and bus-load records are skipped. Nothing here sets triple sampling,
one-shot or the LED, or reads or sets the device id.
