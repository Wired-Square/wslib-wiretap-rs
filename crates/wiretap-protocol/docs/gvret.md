# GVRET binary serial protocol

**Source:** [collin80/GVRET](https://github.com/collin80/GVRET) (MIT, Collin Kidder,
Michael Neuweiler, Charles Galpin). Command reference:
[M2RET `CommProtocol.txt`](https://github.com/collin80/M2RET/blob/master/CommProtocol.txt).

GVRET (Generalized Electric Vehicle Reverse Engineering Tool) is firmware for
Arduino-class hardware — GEVCU, CANDue, EVTVDue, ESP32-RET, M2RET — that exposes
one or more CAN buses over USB serial or TCP using a compact binary protocol.
SavvyCAN is the reference client.

The [`gvret`](../src/gvret.rs) module implements both ends of the frame-streaming
subset: the host end a client speaks, and the device end a capture server speaks
to look like an adapter. Everything below is the protocol; what the module
implements of it is [§7](#7-what-this-crate-implements).

---

## 1. General structure

Every packet starts with a sync byte (`0xF1`) and a command byte. The transport
is a byte stream with no length prefix and no message boundary: a reader knows
how long a packet is from its opcode alone, which is why an unknown opcode
cannot be skipped and a reader has to resynchronise on the next `0xF1`.

```
Host → Device:  [0xF1] [CMD] [data...]
Device → Host:  [0xF1] [CMD] [data...]
```

A frame packet in either direction is followed by one more byte whose meaning no
two implementations agree on. See [§5](#5-the-trailing-byte).

Binary mode must be activated before binary packets are accepted ([§2](#2-binary-mode-activation)).

---

## 2. Binary mode activation

Send `0xE7` while the device is in its default text (LAWICEL) state. In practice
clients send it twice, and the device switches off text mode and begins
accepting and emitting binary packets:

```
Host → Device:  [0xE7] [0xE7]
```

There is no acknowledgement. A client that opens a connection without sending
this reads nothing back, however it asks.

---

## 3. Command reference

Opcodes are a 0-based sequential enum in `GVRET.h`:

| Opcode | Enum name                 | Direction      | Meaning                          |
|--------|---------------------------|----------------|----------------------------------|
| `0x00` | `PROTO_BUILD_CAN_FRAME`   | host → device  | transmit a CAN frame             |
| `0x00` | `PROTO_BUILD_CAN_FRAME`   | device → host  | a frame received off the bus     |
| `0x01` | `PROTO_TIME_SYNC`         | both           | request / device timestamp       |
| `0x02` | `PROTO_DIG_INPUTS`        | both           | request / digital input states   |
| `0x03` | `PROTO_ANA_INPUTS`        | both           | request / analog input values    |
| `0x04` | `PROTO_SET_DIG_OUT`       | host → device  | set digital output states        |
| `0x05` | `PROTO_SETUP_CANBUS`      | host → device  | configure bus speeds and modes   |
| `0x06` | `PROTO_GET_CANBUS_PARAMS` | both           | request / current bus config     |
| `0x07` | `PROTO_GET_DEV_INFO`      | both           | request / device metadata        |
| `0x08` | `PROTO_SET_SW_MODE`       | host → device  | enable single-wire CAN           |
| `0x09` | `PROTO_KEEPALIVE`         | device → host  | heartbeat                        |
| `0x0A` | `PROTO_SET_SYSTYPE`       | host → device  | set hardware platform type       |
| `0x0B` | `PROTO_ECHO_CAN_FRAME`    | host → device  | loopback test                    |
| `0x0C` | `PROTO_GET_NUMBUSES`      | both           | request / bus count              |
| `0x0D` | `PROTO_GET_EXT_BUSES`     | both           | request / SWCAN parameters       |
| `0x0E` | `PROTO_SET_EXT_BUSES`     | host → device  | configure SWCAN and extended buses |

---

## 4. Packet formats

### 4.1 Received CAN frame (device → host) — `0x00`

Emitted for every frame received on an active bus:

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0       1     Sync:      0xF1
1       1     Command:   0x00
2–5     4     Timestamp: microseconds since the connection opened, u32 LE
6–9     4     Frame ID:  u32 LE; bit 31 set = extended (29-bit)
10      1     Bus+DLC:   bits [7:4] bus number, bits [3:0] data length CODE
11–N    0–64  Data:      the payload the code names
N+1     1     The trailing byte (§5)
```

**Frame ID encoding**

- Standard (11-bit): `ID & 0x07FF`, bit 31 clear
- Extended (29-bit): `ID & 0x1FFFFFFF`, bit 31 set (`0x80000000`)

**Bus/DLC byte.** The low nibble is a **data length code**, not a byte count.
Upstream GVRET only defines codes 0–8, where the two are the same number; a
device streaming CAN FD uses the ISO 11898-2:2015 codes 9–15, where they are
not. A reader that treats the nibble as a length reads 13 bytes of a 32-byte
frame and then parses the rest of the payload as packets.

| DLC code | Bytes |
|----------|-------|
| 0–8      | 0–8   |
| 9        | 12    |
| 10       | 16    |
| 11       | 20    |
| 12       | 24    |
| 13       | 32    |
| 14       | 48    |
| 15       | 64    |

**The timestamp wraps.** It is a `u32` of microseconds, so it rolls over every
71 minutes 34 seconds. It counts from the connection, not from any epoch, and
carries no relationship to a host clock.

**There is no CAN FD flag.** The protocol has no way to say a frame was FD. A
reader that needs to know infers it from the payload length.

**SavvyCAN reads FD frames short.** It takes the nibble as a byte count, so a
code 9–15 frame shows as 9–15 bytes, and an `F1 00` in the unread tail starts a
phantom frame that swallows the next one. Its own FD opcode, `0x14`, is worse: it
hangs the parser under Qt 5 and shifts the data under Qt 6
([collin80/SavvyCAN#1121](https://github.com/collin80/SavvyCAN/issues/1121)).
So FD stays on `0x00` with length codes, decided 2026-10-01 after a test against
SavvyCAN.

### 4.2 Transmit CAN frame (host → device) — `0x00`

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0       1     Sync:      0xF1
1       1     Command:   0x00
2–5     4     Frame ID:  u32 LE; bit 31 = extended
6       1     Bus:       0 = CAN0, 1 = CAN1, 2 = SWCAN
7       1     Length:    number of data bytes — a COUNT, not a code
8–N     0–64  Data:      payload bytes
N+1     1     The trailing byte (§5)
```

Note the asymmetry with §4.1: a transmit has no timestamp, and byte 7 is a byte
count where a received frame carries a length code. That is the protocol's, not
any implementation's.

If the frame ID is `0x100` and single-wire mode is active, the device emits a
SWCAN wakeup sequence before transmitting.

### 4.3 Time sync — `0x01`

Host request: `[0xF1] [0x01]`

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       1     0xF1
1       1     0x01
2–5     4     Timestamp: u32 LE microseconds
```

### 4.4 Digital inputs — `0x02`

Host request: `[0xF1] [0x02]`

```
Offset  Size  Description
──────  ────  ───────────────────────────────────────────────────────
0       1     0xF1
1       1     0x02
2       1     Pin states: bit 0 = pin 0 … (pins 0–3)
3       1     Checksum
```

### 4.5 Analog inputs — `0x03`

Host request: `[0xF1] [0x03]`

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────
0       1     0xF1
1       1     0x03
2–3     2     Analog 0: u16 LE
4–5     2     Analog 1
6–7     2     Analog 2
8–9     2     Analog 3
10      1     Checksum
```

### 4.6 Set digital outputs — `0x04`

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0       1     0xF1
1       1     0x04
2       1     Output states: bit N = state of output pin N (0–7)
3       1     Checksum
```

No response.

### 4.7 Setup CAN bus — `0x05`

Configures CAN0 and CAN1 speed and mode, persisted to EEPROM.

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────────
0       1     0xF1
1       1     0x05
2–5     4     CAN0 config: u32 LE
                bit 31: extended status flag (enables bits 30–29)
                bit 30: enable CAN0
                bit 29: listen-only mode
                bits 28–0: bus speed in bps (max 1,000,000)
6–9     4     CAN1 config: same structure
10      1     Checksum
```

Speed is clamped to 1,000,000 bps. The device then enters promiscuous mode and
reloads settings.

### 4.8 Get CAN bus parameters — `0x06`

Host request: `[0xF1] [0x06]`. Response is 12 bytes:

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────
0       1     0xF1
1       1     0x06
2       1     CAN0 flags: bit 0 = enabled, bit 1 = listen-only
3–6     4     CAN0 speed: u32 LE bps
7       1     CAN1 flags: bit 0 = enabled, bit 1 = listen-only, bit 2 = SWCAN
8–11    4     CAN1 speed: u32 LE bps
```

This legacy reply describes at most two buses. A device with more is only
honest about them through `0x0C`.

### 4.9 Get device info — `0x07`

Host request: `[0xF1] [0x07]`. Response is **8 bytes** — a reader that consumes
seven leaves one behind:

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────
0       1     0xF1
1       1     0x07
2–3     2     Build number: u16 LE
4       1     EEPROM version
5       1     File output type
6       1     Auto-start logging flag
7       1     Single-wire mode enabled flag
```

### 4.10 Set single-wire mode — `0x08`

```
Offset  Size  Description
──────  ────  ──────────────────────────────────
0       1     0xF1
1       1     0x08
2       1     Mode: 0x10 = enable, else disable
3       1     Checksum
```

No response.

### 4.11 Keepalive — `0x09`

The host asks, and a live device answers `DE AD`. SavvyCAN asks every 250 ms and
drops the link after 10 unanswered asks, 2.5 s.

```
Host → Device:  [0xF1] [0x09]
Device → Host:  [0xF1] [0x09] [0xDE] [0xAD]
```

### 4.12 Set system type — `0x0A`

Selects the hardware variant; triggers an EEPROM write and a settings reload.

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────
0       1     0xF1
1       1     0x0A
2       1     System type: 0 = CANDue, 1 = GEVCU,
                2 = CANDue v1.3–v2.1, 3 = CANDue v2.2
3       1     Checksum
```

No response.

### 4.13 Echo CAN frame — `0x0B`

Identical to §4.2, but the device returns the frame to the host instead of
transmitting it. Loopback testing.

### 4.14 Get number of buses — `0x0C`

Host request: `[0xF1] [0x0C]`. Response is 3 bytes:

```
Offset  Size  Description
──────  ────  ─────────────────────────────
0       1     0xF1
1       1     0x0C
2       1     Bus count
```

The `collin80` firmware answers a fixed `0x03` (CAN0, CAN1, SWCAN); a
GVRET-compatible bridge answers with however many buses it exposes. A client
should treat an implausible count as a device that does not really implement
this, not as a fact — and a device need not implement it at all.

### 4.15 Get extended buses — `0x0D`

Host request: `[0xF1] [0x0D]`.

```
Offset  Size  Description
──────  ────  ───────────────────────────────────────────────────
0       1     0xF1
1       1     0x0D
2       1     SWCAN flags: bit 0 = enabled, bit 1 = listen-only
3–6     4     SWCAN speed: u32 LE bps
7       1     Bus 4 enabled (reserved)
8–11    4     Bus 4 speed (reserved)
12      1     Bus 5 enabled (reserved)
13–16   4     Bus 5 speed (reserved)
```

### 4.16 Set extended buses — `0x0E`

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────────────────────────
0       1     0xF1
1       1     0x0E
2–5     4     SWCAN config: u32 LE, same bit layout as §4.7 (max 100,000 bps)
6–9     4     Bus 4 config (reserved)
10–13   4     Bus 5 config (reserved)
14      1     Checksum
```

---

## 5. The trailing byte

**Every participant in this protocol disagrees about the byte after a frame's
payload, and the dialect they all actually speak is written down correctly in
none of them.**

- The **spec** (§4.1) calls it a checksum "currently always `0x00`" on a
  device→host frame, and an XOR of every preceding byte on a host→device
  transmit.
- `collin80/GVRET`'s **firmware** emits it and *requires* it — `BUILD_CAN_FRAME`
  does not dispatch until it arrives — while the XOR comparison that would check
  it is commented out.
- **SavvyCAN** sends a hardcoded `0`, not an XOR.
- This crate writes `0x00` on a device→host frame, and appends **nothing** at
  all on a transmit. Real adapters accept that.

Nothing validates it, and nothing can: a device that required a correct XOR
would reject SavvyCAN. Every end of this protocol is a live participant, so this
is recorded rather than fixed — changing it is a protocol change, not a refactor.

A reader that does not consume the byte is safe rather than correct: no sender
in the field puts `0xF1` there, so the resync scan discards it, and there is
nothing to discard when it is absent.

The control replies in §4.4 to §4.12 that show a checksum column carry it as the
firmware writes it; nothing in this crate reads or emits those packets.

---

## 6. Resynchronisation

There is no framing, so a reader that loses its place recovers by scanning
forward to the next `0xF1` and trying again. Consequences worth stating:

- An **unknown opcode** cannot be length-skipped — its length is unknown. The
  only safe move is to drop the sync byte and rescan, which may find a real
  header in the very next byte.
- A **partial packet** must stay buffered, not be dropped: consuming a header
  whose body has not arrived parses the body as packets.
- A stream carrying no `0xF1` at all is noise, and a reader should bound how
  much of it it will hold.

---

## 7. What this crate implements

The frame-streaming subset — everything needed to capture from a device or to be
one — in [`gvret`](../src/gvret.rs):

| | Host end (client) | Device end (server) |
|---|---|---|
| Binary mode | `SYNC` | `Decoder::is_binary` |
| Frames | `DeviceDecoder` → `DeviceMessage::Frame` | `encode_frame_into` |
| Transmit | `encode_transmit_into` | `Decoder` → `ClientCommand::Transmit` |
| Timebase `0x01` | `DeviceMessage::Timebase` | `encode_timebase` |
| Bus params `0x06` | `DeviceMessage::CanbusParams` | `encode_canbus_params` |
| Device info `0x07` | `DeviceMessage::DevInfo` | `encode_dev_info` |
| Keepalive `0x09` | `DeviceMessage::Keepalive` | `encode_keepalive` |
| Bus count `0x0C` | `DeviceMessage::NumBuses` | `encode_num_buses` |
| Requests | `REQ_TIMEBASE`, `REQ_CANBUS_PARAMS`, `REQ_DEV_INFO`, `REQ_KEEPALIVE`, `REQ_NUM_BUSES` | — |

Not implemented, in either direction: digital and analog I/O (`0x02`–`0x04`),
bus configuration (`0x05`, `0x0E`), single-wire mode (`0x08`), system type
(`0x0A`), echo (`0x0B`) and extended buses (`0x0D`). A `DeviceDecoder` drops
their bytes on the resync scan; a `Decoder` consumes the two header bytes and
ignores the request.

CAN FD is carried by using the ISO length codes in the bus/DLC nibble, which
upstream does not define. Both directions here read that nibble as a code, and a
caller infers FD from the resulting payload length because the protocol has no
flag for it.
