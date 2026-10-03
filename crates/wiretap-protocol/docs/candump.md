# candump log (`candump -L`)

**Source:** [can-utils](https://github.com/linux-can/can-utils), `lib.c`
(`snprintf_can_frame`) and `candump.c`.

The text log can-utils writes with `candump -L` and replays with `canplayer`,
one frame per line. `-x` adds the direction. The frame inside a line is the
one `cansend` takes on its command line.

The [`candump`](../src/candump.rs) module implements both ends. What it
implements is [§4](#4-what-this-crate-implements).

---

## 1. Line

```
(1727000000.000042) can0 123#DEADBEEF
(1727000000.000043) can0 18DAF110##1A5A5 T
```

Three fields, then an optional fourth, separated by whitespace:

| field | form | notes |
|-------|------|-------|
| time | `(seconds.fraction)` | epoch; written as 10 and 6 digits, read as any seconds and a 1–6 digit fraction |
| interface | a name with no whitespace | which interface is which bus is the reader's |
| frame | §2 | |
| direction | `T` or `R` | `-x` only: sent by this end, or received |

---

## 2. Frame

| form | frame |
|------|-------|
| `123#DEADBEEF` | classic, 0–8 bytes |
| `12345678#…` | extended |
| `123#R`, `123#R5` | remote, with an optional length code 0–8 |
| `123##1DEADBEEF` | CAN FD, 0–64 bytes, after one flags digit |

The id is **3 hex digits, or 8 for an extended id**: width says extended, not
value, so `00000123` is an extended id. Data is whole hex bytes, and `cansend`
allows a `.` between them. The FD flags digit is hex, with BRS 1 and ESI 2. A
remote frame is classic only.

---

## 3. Errors

Each line stands alone, so a bad one costs only itself. Every refusal is an
`ErrorKind` with a stable `code()`, and `lines` numbers it from 1, counting
blank lines.

---

## 4. What this crate implements

| | Item |
|---|---|
| Encode | `encode_line_into`, from a `can::CanFrame` and a direction |
| Decode | `parse_line` → `Line`; `parse_frame` for a bare `cansend` frame, such as a CSV cell |
| A file | `lines` → `Result<Line, Error>` per non-blank line |
| Errors | `ErrorKind`, `Error { line, kind }` |

**Kept as written.** Times stay absolute, and an FD payload keeps its written
length rather than being padded to a length code. A parsed frame is on bus 0.

**A bad line is the caller's.** `lines` yields it as an `Err` and carries on;
whether a file with no good line is refused is the caller's call.
