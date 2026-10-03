# SLCAN (Lawicel serial line CAN)

**Source:** [Lawicel CAN232 v3](http://www.can232.com/docs/can232_v3.pdf).
**CAN FD extension:** [Elmue CANable 2.5 firmware](https://github.com/Elmue/CANable-2.5-firmware-Slcan-and-Candlelight)
([updater](https://netcult.ch/elmue/CANable%20Firmware%20Update/)).

SLCAN is an ASCII protocol for exchanging CAN frames over a serial (usually USB
CDC) connection. Lawicel defined it for the CAN232 adapter; CANable, CANable Pro
and most other USB-CAN adapters speak it. The Elmue CANable 2.5 firmware extends
it with CAN FD frame types and data-phase bitrate commands.

The [`slcan`](../src/slcan.rs) module implements the whole of it, both
directions. What it implements is [§7](#7-what-this-crate-implements).

---

## 1. General structure

Every command and every frame is an ASCII string terminated by a carriage
return. Frames flow in both directions in the same format. Lines are
self-delimiting, so unlike GVRET a malformed line costs only itself.

```
Host → Device:  <command>\r
Device → Host:  <response>\r   or   0x07 (bell)
Frame, either way:  <prefix><id><dlc><data>\r
```

A bare `\r` is the device saying a command succeeded. A bell (`0x07`) says it
failed, and ends whatever line was in progress.

---

## 2. Command reference

### 2.1 Configuration

| Command | Meaning | Notes |
|---------|---------|-------|
| `S0`–`S8` | set nominal (arbitration) bitrate | table in §2.3 |
| `Y0`–`Y8` | set CAN FD data-phase bitrate | Elmue; implicitly enables FD |
| `s<P>,<S1>,<S2>,<SJW>` | set custom nominal bitrate | prescaler, segment 1, segment 2, SJW |
| `y<P>,<S1>,<S2>,<SJW>` | set custom FD data bitrate | Elmue |
| `M0` | normal mode | participates in arbitration, sends ACKs |
| `M1` | silent mode | no ACK, no transmit, passive observation |
| `O` | open the channel | frames flow after this |
| `C` | close the channel | stops everything, resets the bitrate settings |

### 2.2 Queries

| Command | Response | Meaning |
|---------|----------|---------|
| `V` | `V<version>` | firmware version — two shapes, see §5 |
| `v` | `v<version>` | hardware version (optional) |
| `N` | `N<serial>` | serial number (optional) |

### 2.3 Nominal bitrate codes

| Code | Bitrate | | Code | Bitrate |
|------|---------|-|------|---------|
| `S0` | 10 kbit/s | | `S5` | 250 kbit/s |
| `S1` | 20 kbit/s | | `S6` | 500 kbit/s |
| `S2` | 50 kbit/s | | `S7` | 750 kbit/s |
| `S3` | 100 kbit/s | | `S8` | 1 Mbit/s |
| `S4` | 125 kbit/s | | | |

### 2.4 CAN FD data-phase bitrate codes (Elmue)

| Code | Bitrate | | Code | Bitrate |
|------|---------|-|------|---------|
| `Y0` | 500 kbit/s | | `Y4` | 4 Mbit/s |
| `Y1` | 1 Mbit/s | | `Y5` | 5 Mbit/s |
| `Y2` | 2 Mbit/s | | `Y8` | 8 Mbit/s |

There is no code for a rate outside these tables. The `s`/`y` custom-timing
commands exist for that, and nothing here builds one.

---

## 3. Frame formats

The prefix character carries every flag a frame has: id width, remote-request,
FD and bit rate switch. There are eight of them.

### 3.1 Classic CAN

| Prefix | Form | Meaning |
|--------|------|---------|
| `t` | `t<ID:3hex><DLC:1hex><DATA:2hex×DLC>` | standard (11-bit) data frame |
| `T` | `T<ID:8hex><DLC:1hex><DATA:2hex×DLC>` | extended (29-bit) data frame |
| `r` | `r<ID:3hex><DLC:1hex>` | standard remote request — no data |
| `R` | `R<ID:8hex><DLC:1hex>` | extended remote request |

```
t1234AABBCCDD     ID 0x123, DLC 4, data AA BB CC DD
T123456788AABBCCDDEEFF0011    ID 0x12345678, DLC 8
r1234             ID 0x123, DLC 4, no payload
```

A classic frame's DLC is 0–8, and is both the code and the byte count.

### 3.2 CAN FD (Elmue extension)

| Prefix | ID width | BRS |
|--------|----------|-----|
| `d` | standard | no |
| `D` | extended | no |
| `b` | standard | yes |
| `B` | extended | yes |

The structure is the same, but the DLC digit is a **data length code**, so above
8 it is not the byte count:

```
d7E09112233445566778899AABBCC
  FD standard, ID 0x7E0, code 9 — twelve bytes of payload, 24 hex characters
```

CAN FD has no remote-request frame, so there is no FD equivalent of `r`/`R`.

### 3.3 CAN FD length codes (ISO 11898-2:2015)

| Code | Bytes | | Code | Bytes |
|------|-------|-|------|-------|
| 0–8 | 0–8 | | 12 | 24 |
| 9 | 12 | | 13 | 32 |
| 10 | 16 | | 14 | 48 |
| 11 | 20 | | 15 | 64 |

There is no code for 9, 10 or 11 bytes. A payload of one of those sizes goes out
under the next code up, and the line must carry the full number of hex bytes
that code names — CAN FD pads, and a line whose hex ran out early is rejected.

---

## 4. Initialisation

```
1.  clear the serial buffers, wait ~200 ms for a USB device to settle
2.  C\r              close any channel left open
3.  S6\r             nominal bitrate
4.  Y2\r             FD data-phase bitrate — only when FD is wanted
5.  M0\r or M1\r     normal or silent
6.  O\r              open — frames flow
```

Each step wants a short pause after it (~50 ms is enough) because the device
answers each command and some firmware is unhappy being written to mid-reply.
On disconnect, `C\r`.

---

## 5. Version replies

Standard firmware answers `V` with a short string:

```
V1013
```

which by CANable convention reads as version 1.0.13.

The Elmue firmware answers with labelled fields **run together with no
separator**:

```
V+Board: MultiboardMCU: STM32G431DevID: 1128Firmware: 2490643Slcan: 100Clock: 160Limits: 512,256,128,128,32,32,16,16
```

so each field ends where the next label begins, not at any delimiter. `MCU:`
ends at `DevID:`; `Board:` ends at `MCU:`.

**This reply is the CAN FD capability check.** SLCAN has no capability query, so
the extended shape — the presence of a `Firmware:` field — is the only way to
know a device speaks the §3.2 prefixes.

---

## 6. Error handling

- **Bell (`0x07`)** — a command failed. Discard the line in progress; the
  connection is fine.
- **A malformed line** — bad hex, a wrong length, an unknown prefix — is that
  line's problem alone. Lines are self-delimiting.
- **An unterminated line** should be abandoned past some bound. A 64-byte FD
  frame is about 139 characters and an Elmue version reply about 200, so a bound
  wants to be loose; it is there to stop a device that never sends a terminator
  from growing a buffer forever.

---

## 7. What this crate implements

All of §2, §3 and §5, in [`slcan`](../src/slcan.rs):

| | Item |
|---|---|
| Framing | `LineDecoder` → `Line::Frame` / `Line::Reply`, with the bell and the length bound |
| Frames, in | `parse_frame` — all eight prefixes, `Frame` carries `rtr`, `fd` and `brs` |
| Frames, out | `encode_frame_into`, `Frame::data`, `Frame::remote` |
| Bitrates | `NOMINAL_BITRATES`, `DATA_BITRATES`, `bitrate_command`, `data_bitrate_command` |
| Commands | `OPEN`, `CLOSE`, `MODE_NORMAL`, `MODE_SILENT`, `QUERY_VERSION`, `QUERY_HW_VERSION`, `QUERY_SERIAL` |
| Versions | `parse_version` → `Version`, including Elmue detection |

Not implemented: the `s`/`y` custom-timing commands. Only the preset codes are
built.

**Timestamps.** The protocol carries none. A caller stamps a frame itself, so
inter-frame timing is limited by host scheduling rather than by the adapter.
