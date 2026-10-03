# SavvyCAN/GVRET CSV

**Source:** [SavvyCAN](https://github.com/collin80/SavvyCAN)'s GVRET CSV
format, as the WireTAP desktop writes it.

A capture file, one frame per row after a header. SavvyCAN reads and writes
it, and the WireTAP desktop exports serial and Modbus captures in it too.

The [`savvycan`](../src/savvycan.rs) module implements both ends. What it
implements is [§4](#4-what-this-crate-implements).

---

## 1. Header

```
Time Stamp,ID,Extended,Dir,Bus,LEN,D1,D2,D3,D4,D5,D6,D7,D8
```

One `Dn` column per data byte of the file's longest row: the length itself up
to 8 and past 64, and between them the CAN FD length that fits (9 → `D12`).

A reader places columns by name, case-insensitively, with these aliases:
`time stamp`/`timestamp`/`time`, `id`, `extended`/`ext`, `dir`/`direction`,
`bus`, `len`/`dlc`/`length`, `d1`/`data1`/`byte1`. A file whose first line names
none has no header and takes the order above.

---

## 2. Row

```
1727000000000042,00000123,false,Rx,0,2,DE,AD,,,,,,
```

| column | form |
|--------|------|
| `Time Stamp` | whole µs |
| `ID` | hex, written as 8 digits, read at any width, with or without `0x` |
| `Extended` | `true` or `false` |
| `Dir` | `Rx` or `Tx`; a file without the column is all `Rx` |
| `Bus` | 0–255 |
| `LEN` | the payload's length in bytes |
| `D1`… | one hex byte each, `LEN` of them, then empty cells |

There is no FD, BRS, ESI or RTR column: a CAN reader takes FD as `LEN > 8`.

---

## 3. Errors

Each row stands alone. Every refusal is an `ErrorKind` with a stable `code()`,
and `rows` numbers it from 1, counting blank lines and the header.

---

## 4. What this crate implements

| | Item |
|---|---|
| Encode | `data_columns`, `encode_header_into`, `encode_row_into` |
| Decode | `parse_header` → `Columns`; `parse_row` → `Row` |
| A file | `rows` → `Result<Row, Error>` per non-blank row |
| Errors | `ErrorKind`, `Error { line, kind }` |

**A row is the file's shape**, not a `CanFrame`: its payload may be any length.

**Kept as written.** Times stay absolute; nothing is rebased or guessed.

**A bad row is the caller's.** `rows` yields it as an `Err` and carries on.
