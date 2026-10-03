# SocketCAN frame layouts

**Source:** `include/uapi/linux/can.h` in the Linux kernel.

SocketCAN is Linux's CAN networking stack. An application opens an `AF_CAN`
socket and reads and writes frames as fixed-size structures.

Unlike everything else in this crate, **these bytes are a kernel ABI, not a wire
format.** They never leave the machine that made them, so the id is
*native*-endian and the layouts carry the padding a C compiler put there.
Reading them as little-endian works by accident on every machine anyone runs
this on, and would be wrong on the one where it mattered.

The [`socketcan`](../src/socketcan.rs) module exists because an application
talking to a raw socket has to spell these layouts somewhere, and spelling them
once next to the data length code table beats spelling them inline at every
`write`. An application using a binding that hands out typed frames should use
that instead.

---

## 1. `struct can_frame` — 16 bytes

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────
0–3     4     can_id: arbitration id with flags (§3), NATIVE-endian
4       1     len: payload length, 0–8
5–7     3     padding
8–15    8     data
```

The kernel calls byte 4 `can_dlc` in older headers and `len` in newer ones. It
is a byte count either way — classic CAN has no code above 8.

## 2. `struct canfd_frame` — 72 bytes

```
Offset  Size  Description
──────  ────  ──────────────────────────────────────────────
0–3     4     can_id, NATIVE-endian
4       1     len: payload LENGTH, 0–64 — not a length code
5       1     flags (§4)
6–7     2     reserved
8–71    64    data
```

**Byte 4 is a length, not a data length code**, in both structures. SocketCAN
converts at its own edge, so an application reading these never meets the code.
That is the opposite of gs_usb, which carries the code on an FD frame, and of
GVRET, which carries it on a received one.

**A read's size says which structure it is.** A `read` that returned 72 bytes is
a `canfd_frame`; anything shorter is a `can_frame`, whatever its length byte
claims.

---

## 3. The id word

| Bit(s) | Mask | Meaning |
|--------|------|---------|
| 31 | `0x80000000` | `CAN_EFF_FLAG` — extended (29-bit) id |
| 30 | `0x40000000` | `CAN_RTR_FLAG` — remote transmission request |
| 29 | `0x20000000` | `CAN_ERR_FLAG` — an error frame; the payload is an error class |
| 28–0 | `0x1FFFFFFF` | `CAN_EFF_MASK` — the arbitration id |

With `CAN_EFF_FLAG` clear the id is 11 bits (`CAN_SFF_MASK`, `0x7FF`), and the
bits between are not part of it. A reader that masks to 29 bits regardless
reports an id the bus never carried.

`CAN_EFF_FLAG` sits at the same bit as GVRET's extended-id flag. That is a
coincidence, not a contract.

---

## 4. CAN FD flags

| Bit | Value | Name |
|-----|-------|------|
| 0 | `0x01` | `CANFD_BRS` — bit rate switch |
| 1 | `0x02` | `CANFD_ESI` — error state indicator |

A classic `can_frame` has no flags byte; byte 5 there is padding.

---

## 5. What this crate implements

[`socketcan`](../src/socketcan.rs): both layouts and the id word.

| | Item |
|---|---|
| Sizes | `CLASSIC_FRAME_BYTES`, `FD_FRAME_BYTES` |
| Id | `CAN_EFF_FLAG`, `CAN_RTR_FLAG`, `CAN_ERR_FLAG`, `CAN_EFF_MASK`, `CAN_SFF_MASK`, `split_can_id`, `make_can_id` |
| Flags | `fd_flags` |
| Frames | `Frame`, `Frame::new`, `parse_frame`, `encode_frame_into` |

Nothing here opens a socket, binds an interface, or touches the error-frame
payload, the broadcast manager, ISO-TP or J1939.
