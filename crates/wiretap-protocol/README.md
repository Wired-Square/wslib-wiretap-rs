# wiretap-protocol

The wire protocols WireTAP speaks, as scalars — the part of the
[`wslib-wiretap-rs`](../../) workspace that two repositories have to agree on byte
for byte. It depends on nothing at all: no serde, no async runtime, no driver.

## What's here

Each module has a reference document beside it in [`docs/`](docs/), which says
what the protocol is and what part of it this crate implements.

- **`can`** — `CanFrame` and `Direction`: the CAN frame as it is on the bus,
  which every CAN transport in `wiretap-io` hands over (re-exported there as
  `can::CanFrame`); and `ErrorFrame`, what a SocketCAN error frame says about
  the controller
- **`dlc`** — the CAN data length code table, `dlc_to_len`, `len_to_dlc` and
  `payload_dlc`. The wire carries a *code*, a database column stores a
  *length*, and above 8 bytes on CAN FD the two differ
- **`gvret`** ([docs](docs/gvret.md)) — the GVRET serial protocol, both ends:
  the host end a client speaks, and the device end a capture server speaks to
  look like an adapter. SavvyCAN is the reference client
- **`slcan`** ([docs](docs/slcan.md)) — the Lawicel ASCII protocol most USB-CAN
  adapters speak, with the CAN FD extension the CANable 2.5 firmware added:
  line framing, frames, commands and version replies
- **`slip`** ([docs](docs/slip.md)) — SLIP (RFC 1055), both directions: a
  decoder that reports where each frame ended, and the encoder
- **`gs_usb`** ([docs](docs/gs_usb.md)) — the candleLight USB protocol: host
  frames and their hardware timestamp, the control-transfer layouts and the bit
  timing maths
- **`pcan_usb`** ([docs](docs/pcan_usb.md)) — PEAK-System's classic PCAN-USB
  protocol: the commands, the SJA1000 bit timing, the bulk-IN records with
  their one-byte timestamps, and the transmit message
- **`pcan_usb_fd`** ([docs](docs/pcan_usb_fd.md)) — PEAK-System's uCAN protocol,
  for the PCAN-USB FD, PCAN-Chip USB, PCAN-USB Pro FD and PCAN-USB X6: the
  vendor requests, the command lists, the CAN FD bit timing, the received
  records with their 64-bit µs stamps, and the transmit message. **Untested**:
  read from the kernel driver, with no device of the family to check it against
- **`bittiming`** — the kernel's `can_calc_bittiming`, which both PEAK modules
  time from
- **`socketcan`** ([docs](docs/socketcan.md)) — Linux's `can_frame` and
  `canfd_frame`, and the flags packed alongside an id. A kernel ABI rather than
  a wire format; see the module header
- **`testpattern`** ([docs](docs/test-pattern.md)) — two endpoints proving a CAN
  link carries what it claims to: a length sweep across every data length code,
  plus ping, latency and the control handshake that binds a run. Both sides,
  with the reply half as a sans-io state machine
- **`ingest`** ([docs](docs/ingest.md)) — the binary ingest protocol (v3), both
  ends: framing and its CRC-32, the handshake with its catalogue assignments,
  batches of CAN, Modbus and raw serial records, the id-flag layout, the
  catalogue pull and status, and the server's session as a sans-io state machine.
  WireTAP-Server's gateway and capture daemon drive it; their tokio drivers
  stay there
- **`import`** ([docs](docs/import.md)) — the WireTAP desktop's HTTP
  capture-import body, both ends: a versioned header, then CAN records with
  the ingest CAN record's `id_flags` and `flags`
- **`candump`** ([docs](docs/candump.md)) — can-utils' `candump -L` log line,
  with `-x`'s direction, and the `cansend` frame inside it: a line written from
  a `CanFrame`, and parsed back with every flag and its absolute time
- **`savvycan`** ([docs](docs/savvycan.md)) — the SavvyCAN/GVRET CSV capture
  file, in the file's shape rather than a CAN frame's, so a serial or Modbus row
  past 64 bytes fits
- **`framing`** — serial framing that isn't a protocol: the delimiter framer
  and the `Framed` output it shares with `slip`. Its decoders count end offsets
  as `wiretap-catalog`'s `ModbusRtuStream` does

## Using it

```toml
wiretap-protocol = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.1.4" }
```

Either URL form works, and the workspace README says why `https` is usually the one a consumer
wants.

Encoders take a caller's buffer and scalars —
`encode_frame_into(out, ts_us, arb_id, extended, bus, data, is_fd)` — because
each consumer's frame type is its own and they are not reconcilable: one is
CAN-only and stores no length code, the next is multi-protocol and is a serde
contract with a frontend. The one frame type here is `can::CanFrame`, the CAN
frame on the bus, and only `candump`, whose format is that frame, takes it. It
follows that the crate depends on nothing: a client
speaking one of these protocols should not have to take a capture stack to do
it.

Where a protocol packs several independent flags into one field — SLCAN's prefix
character, a gs_usb host frame's id word — a module names a struct for its own
wire shape instead, because an encoder taking six positional booleans is a
defect waiting to happen. That struct is still the wire's, never a consumer's.

**Before changing `gvret`:** the trailing byte after a frame's payload is a
checksum every participant guesses differently, and the dialect they all
actually speak is written down correctly in none of them. The module header
records it and it is deliberately left alone — all four ends are live, so
changing it is a protocol change rather than a refactor.
