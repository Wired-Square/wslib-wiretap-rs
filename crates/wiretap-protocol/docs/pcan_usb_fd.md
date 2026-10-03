# PCAN-USB FD family USB protocol (uCAN)

**Source:** the Linux kernel driver,
[`drivers/net/can/usb/peak_usb/pcan_usb_fd.c`](https://github.com/torvalds/linux/blob/master/drivers/net/can/usb/peak_usb/pcan_usb_fd.c),
with the uCAN layouts in
[`include/linux/can/dev/peak_canfd.h`](https://github.com/torvalds/linux/blob/master/include/linux/can/dev/peak_canfd.h),
the vendor requests and endpoint layout in `pcan_usb_pro.c` and `pcan_usb_pro.h`,
and the USB plumbing in `pcan_usb_core.c` (GPL-2.0, PEAK-System Technik GmbH,
Stéphane Grosjean).

This is the protocol of PEAK-System's CAN FD adapters: the PCAN-USB FD, the
PCAN-Chip USB, the PCAN-USB Pro FD and the PCAN-USB X6. **Everything here is
read from the kernel source; none of it has met a device.** No adapter of this
family has been on the bench, so every layout, sequence and constant below is
the kernel's word, untested against a wire. On Linux the kernel's `peak_usb`
driver claims these adapters and an application sees SocketCAN; on Windows and
macOS an application without PEAK's own driver drives the endpoints itself.

The [`pcan_usb_fd`](../src/pcan_usb_fd.rs) module implements the layouts, the
record decoder and the transmit encoder for that second case, with the bit
timing search in [`bittiming`](../src/bittiming.rs). What it implements is
[§9](#9-what-this-crate-implements).

---

## 1. General structure

A command pipe and a data pipe, both bulk, plus two vendor requests on the
default control pipe. Multi-byte fields are little-endian and every structure
is packed. There are no checksums — USB provides integrity.

```
Commands:   bulk OUT 0x01                     lists of 8-byte records, ≤ 512 bytes
Data in:    bulk IN  0x82, both channels      2048-byte transfers of records
Data out:   bulk OUT 0x02 (channel 0), 0x03 (channel 1)   one frame, ≤ 512 bytes
```

Those are PCAN-USB Pro's addresses, the defaults. Firmware whose info record
([§3](#3-vendor-requests)) is of type 2 or more names its own, and those win.
Nothing is read from the command IN endpoint (`0x81`).

The kernel keeps four 2048-byte bulk-IN transfers in flight. Commands and sends
each have a 1 s timeout.

The controller is clocked at 80 MHz, which the host tells the device with
`CLK_SET` ([§4](#4-commands)).

---

## 2. USB identification

| Field | Value | Device | Channels |
|-------|-------|--------|----------|
| VID | `0x0C72` | PEAK-System Technik | |
| PID | `0x0012` | PCAN-USB FD | 1 |
| PID | `0x0013` | PCAN-Chip USB | 1 |
| PID | `0x0011` | PCAN-USB Pro FD | 2 |
| PID | `0x0014` | PCAN-USB X6 | 2 per USB device |

The kernel binds two channels per X6 USB device it sees, so an X6's six
channels are three devices to the host.

The classic PCAN-USB (`0x000C`) speaks another protocol; see
[`pcan_usb.md`](pcan_usb.md). So does the PCAN-USB Pro (`0x000D`), which this
crate does not implement.

### 2.1 The CAN interface

The PCAN-USB FD's CAN interface is interface 0. For the other three the kernel
takes any interface whose endpoints all lie in PCAN-USB Pro's layout — `0x01`,
`0x81`, `0x02`, `0x82`, `0x03`, `0x83` — and refuses one with any other.

### 2.2 USB speed

On a link that isn't high speed the firmware can't reassemble a 512-byte command
list, so the host writes it in 64-byte transfers, the last one the remainder.

---

## 3. Vendor requests

On the default control pipe: `bmRequestType` vendor, recipient *other* (`0x43`
out, `0xC3` in), `wIndex` 0. The kernel allows 10 s.

| Request | `bRequest` | `wValue` | Direction | Data |
|---------|-----------|----------|-----------|------|
| `INFO` `FW` | 0 | 1 | IN | 36 bytes: the firmware info below |
| `FCT` `DRVLD` | 2 | 5 | OUT | 16 bytes: `[0, loaded, 0 …]` |

`DRVLD` 1 tells the device a driver has it; the kernel sends it once at probe,
and `DRVLD` 0 when it lets go.

### 3.1 Firmware info (`pcan_ufd_fw_info`)

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       2     size_of
2       2     type — 2 or more carries the endpoints below
4       1     hw_type
5       3     bootloader version
8       1     hw_version (the PCB)
9       3     firmware version, major first
12      8     dev_id[2], a user-set id per channel
20      4     ser_no — FFFFFFFF is one never programmed
24      4     flags
28      1     cmd_out_ep          ┐
29      1     cmd_in_ep           │ only when type ≥ 2
30      2     data_out_ep[2]      │
32      1     data_in_ep          │
33      3     (unused)            ┘
```

Firmware from 2.0 can be told ISO or non-ISO CAN FD ([§4.5](#45-options));
before it, it is non-ISO and fixed.

---

## 4. Commands

Written to the command OUT endpoint as one list of 8-byte records. Each record
starts with `opcode_channel`, a u16:

```
opcode_channel = (channel << 12) | (opcode & 0x3FF)
```

A list shorter than 512 − 8 bytes ends with an end-of-collection record, eight
`0xFF` bytes (opcode `0x3FF`); a list that fills the buffer does not.

| Opcode | Code | Layout |
|--------|------|--------|
| `NOP` | `0x000` | |
| `RESET_MODE` | `0x001` | command |
| `NORMAL_MODE` | `0x002` | command |
| `LISTEN_ONLY_MODE` | `0x003` | command |
| `TIMING_SLOW` | `0x004` | §4.1 |
| `TIMING_FAST` | `0x005` | §4.1 |
| `SET_STD_FILTER` | `0x006` | |
| `FILTER_STD` | `0x008` | §4.2 |
| `TX_ABORT` | `0x009` | |
| `WR_ERR_CNT` | `0x00A` | §4.3 |
| `SET_EN_OPTION` | `0x00B` | §4.4, §4.5 |
| `CLR_DIS_OPTION` | `0x00C` | §4.4, §4.5 |
| `RX_BARRIER` | `0x010` | |
| `CLK_SET` | `0x080` | §4.6, USB adapters only |
| `DEVID_SET` | `0x081` | USB adapters only |
| `LED_SET` | `0x086` | §4.6, USB adapters only |

A plain *command* is `opcode_channel` and six zero bytes.

### 4.1 Bit timing

| Offset | Size | `TIMING_SLOW` (nominal) | `TIMING_FAST` (CAN FD data) |
|--------|------|-------------------------|-----------------------------|
| 0 | 2 | opcode_channel | opcode_channel |
| 2 | 1 | ewl, the error warning limit: 96 | (unused) |
| 3 | 1 | `(sjw − 1) & 0x7F`, bit 7 triple sampling | `(sjw − 1) & 0x0F` |
| 4 | 1 | `(phase_seg2 − 1) & 0x7F` | `(phase_seg2 − 1) & 0x0F` |
| 5 | 1 | `(prop_seg + phase_seg1 − 1) & 0xFF` | `(prop_seg + phase_seg1 − 1) & 0x1F` |
| 6 | 2 | `(brp − 1) & 0x3FF` | `(brp − 1) & 0x3FF` |

The kernel's constraints, from an 80 MHz clock:

| Phase | tseg1 | tseg2 | sjw | brp |
|-------|-------|-------|-----|-----|
| Nominal | 1–256 | 1–128 | 1–128 | 1–1024, step 1 |
| Data | 1–32 | 1–16 | 1–16 | 1–1024, step 1 |

The kernel derives the timing with `can_calc_bittiming`, as for the classic
adapter ([`pcan_usb.md` §4](pcan_usb.md#4-bit-timing)): CiA's sample point
unless one is given, the smallest bitrate error then the smallest sample-point
error, nothing more than 5% out. At 80 MHz this gives:

| Bitrate | brp | prop_seg | phase_seg1 | phase_seg2 | sjw | Sample point |
|---------|-----|----------|------------|------------|-----|--------------|
| 500 kbit/s nominal | 1 | 69 | 70 | 20 | 10 | 87.5% |
| 2 Mbit/s data | 1 | 14 | 15 | 10 | 5 | 75% |

### 4.2 Filter

```
0  2  opcode_channel
2  2  row, 0–63
4  4  mask: bit j passes standard id row × 32 + j
```

The kernel opens a channel with all 64 rows at `0xFFFFFFFF`: 64 records, 512
bytes, the whole buffer, so no end-of-collection follows.

### 4.3 Error counters

```
0  2  opcode_channel
2  2  sel_mask: TE 0x4000 | RE 0x8000 — which counters to write
4  1  tx_counter
5  1  rx_counter
6  2  (unused)
```

### 4.4 USB options (`pcan_ufd_options`)

```
0  2  opcode_channel
2  2  ucan_mask
4  2  (unused)
6  2  usb_mask
```

`SET_EN_OPTION` enables the bits, `CLR_DIS_OPTION` clears them. The kernel
enables `ERROR` (`0x0001`) in `ucan_mask` and `CALIBRATION` (`0x8000`) in
`usb_mask` when it opens the first channel, and clears them when it closes the
last. `BUSLOAD` is `0x0002`.

### 4.5 ISO CAN FD (`pucan_options`)

```
0  2  opcode_channel
2  2  options: CANFD_ISO 0x0004
4  4  (unused)
```

`SET_EN_OPTION` makes the channel ISO CAN FD, `CLR_DIS_OPTION` non-ISO. The
kernel sends it only to firmware from 2.0, and there sends ISO unless asked for
non-ISO — in classic mode too.

### 4.6 Clock and LED

```
0  2  opcode_channel
2  1  mode
3  5  (unused)
```

`CLK_SET` mode 0 is 80 MHz (1–5 are 60, 40, 30, 24 and 20 MHz). `LED_SET` mode
0 leaves the LED to the device; 1 fast blink, 2 slow, 3 on, 4 off.

---

## 5. Received messages

Each bulk-IN transfer is a run of records, each starting:

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       2     size, of the whole record
2       2     type
4       4     ts_low
8       4     ts_high
```

The next record starts `size` bytes on. A zero `size` ends the run. A record
with fewer than 12 bytes left, a `size` running past the transfer, a `size`
below its type's minimum, a frame whose payload is short, or a record naming a
channel past the second ends it too; the records before it stand.

`(ts_high << 32) | ts_low` is the device's clock in µs, which the kernel hands
up as the frame's hardware stamp as it is.

| Type | Code | Minimum size | Body after the 12-byte head |
|------|------|--------------|------------------------------|
| `CAN_RX` | `0x0001` | 28 | §5.1 |
| `ERROR` | `0x0002` | 16 | channel_type_d (channel in the low nibble), code_g, tx_err_cnt, rx_err_cnt |
| `STATUS` | `0x0003` | 16 | channel_p_w_b (channel low; `RX_BARRIER` 0x10, `PASSIVE` 0x20, `WARNING` 0x40, `BUSOFF` 0x80), 3 unused |
| `BUSLOAD` | `0x0004` | 12 | |
| `CALIBRATION` | `0x0100` | 16 | usb_frame_index u16, 2 unused — the device's periodic clock reference |
| `OVERRUN` | `0x0101` | 16 | channel (low nibble), 3 unused |

Any other type is skipped by its `size`.

### 5.1 `CAN_RX`

```
Offset  Size  Description
──────  ────  ──────────────────────────
12      4     tag_low
16      4     tag_high
20      1     channel_dlc: channel in the low nibble, DLC in the high
21      1     client
22      2     flags
24      4     can_id
28      …     data
```

| Flag | Value | Meaning |
|------|-------|---------|
| `SELF_RECEIVE` | `0x80` | |
| `ESI` | `0x40` | error state indicator |
| `BRS` | `0x20` | bit rate switch |
| `EXT_DATA_LEN` | `0x10` | a CAN FD frame |
| `SINGLE_SHOT` | `0x08` | |
| `LOOPED_BACK` | `0x04` | |
| `EXT_ID` | `0x02` | 29-bit id |
| `RTR` | `0x01` | remote frame |

A CAN FD frame's length is the DLC's CAN FD length; a classic frame's is
`min(DLC, 8)`. Unless `RTR`, `size − 28` must be at least that length.

---

## 6. Transmit message

On the channel's data OUT endpoint, one frame per transfer:

```
Offset  Size  Description
──────  ────  ──────────────────────────
0       2     size = align4(20 + length)
2       2     type 0x1000 (CAN_TX)
4       8     tag_low, tag_high: zero
12      1     channel_dlc: (channel & 0x0F) | (DLC << 4)
13      1     client: zero
14      2     flags, as §5.1
16      4     can_id, masked to 29 or 11 bits
20      …     data, zero-padded to size
size    4     zero: a null size ending the list
```

The transfer is `size + 4` bytes. A CAN FD frame sets `EXT_DATA_LEN`, `BRS` and
`ESI` as asked, with the DLC of its length; a classic frame the DLC as given,
and `RTR`. `EXT_ID` for a 29-bit id. The kernel sets `SINGLE_SHOT` in one-shot
mode and never `SELF_RECEIVE`.

---

## 7. Start and stop

The kernel's sequence, across probe, bit-timing set and open, for channel *c*:

```
1.  INFO FW                      control IN
2.  FCT DRVLD 1                  control OUT
3.  CLK_SET 0                    80 MHz
4.  LED_SET 0
5.  RESET_MODE                   bus off
6.  TIMING_SLOW
7.  TIMING_FAST                  CAN FD only
8.  FILTER_STD × 64              all ids through
9.  SET_EN_OPTION                ERROR, CALIBRATION; first channel open only
10. WR_ERR_CNT, [SET_EN_OPTION CANFD_ISO], NORMAL_MODE or LISTEN_ONLY_MODE
                                 one list; the ISO record from firmware 2.0
```

Each numbered step is its own command list, bar 1 and 2, which are control
transfers. The kernel submits its bulk-IN transfers before step 8. Stopping is
`CLR_DIS_OPTION` (`ERROR`, `CALIBRATION`; last channel only) then `RESET_MODE`;
unloading adds `LED_SET` 4 and `DRVLD` 0.

---

## 8. Timestamps and calibration

The kernel uses a `CALIBRATION` record, after ignoring the first five, only to
tie its time reference to the device's; the frame stamps it hands up are the
64-bit µs count as the record carries it.

---

## 9. What this crate implements

The layouts, the decoder and the encoder, in
[`pcan_usb_fd`](../src/pcan_usb_fd.rs), and the timing search in
[`bittiming`](../src/bittiming.rs). Driving the USB endpoints is the caller's.

| | Item |
|---|---|
| Identity | `VID`, `PID_*`, `Product`, `PRODUCTS`, `product`, `is_can_interface`, `Endpoints` |
| Vendor requests | `request`, `INFO_FW`, `FCT_DRVLD`, `driver_loaded`, `FirmwareInfo` |
| Commands | `Command`, `opcode`, `opcode_channel`, `END_OF_COLLECTION`, `reset_mode`, `normal_mode`, `listen_only_mode`, `clock_set`, `led_set`, `timing_slow`, `timing_fast`, `filter_std`, `accept_all`, `reset_error_counters`, `set_options`, `option`, `USB_CALIBRATION`, `set_iso`, `bus_on`, `command_list`, `transfers` |
| Timing | `NOMINAL_BITTIMING`, `DATA_BITTIMING`, `CLOCK_HZ`, and `bittiming::calculate` |
| Received | `decode_messages`, `Message`, `Frame`, `message`, `flags`, `status` |
| Transmit | `encode_transmit` |

`decode_messages` returns frames, errors, statuses, overruns and calibrations
with their 64-bit stamps; bus-load records are skipped. `encode_transmit` pads
a payload shorter than its DLC's length with zeros, where the kernel sends
whatever its buffer held. Nothing here sets triple sampling, one-shot,
self-reception or non-ISO mode, aborts a send, or reads or sets the device id.
