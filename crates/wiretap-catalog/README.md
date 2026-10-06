# wiretap-catalog

Parser, validator, decoder, writer and DBC bridge for **WireTAP-format device
catalogues** (TOML), across **CAN, Serial and Modbus**. The top of the
[`wslib-wiretap-rs`](../../) workspace.

A catalogue describes a device's frames and registers and how to decode them —
an inverter, a battery, a meter, a CAN ECU. WireTAP and the Home Assistant ESS
add-on share this schema, and this crate is the one implementation of it, so
decoding happens once in Rust rather than per consumer.

## What's here

- **`Catalog::parse`** — CAN, Serial and Modbus sections into one resolved
  model: mirror/copy inheritance, header-field masks, mux trees, and the Modbus
  authoring shorthands
- **`validate::validate`** — `{ field, message }` findings: signal and mux
  rules, DBC-name compatibility, Modbus register resolution
- **`decode::decode_frame` / `decode_by_id`** — bytes to signal values.
  1–64 bit signed and unsigned (to 2048 for string formats),
  `factor`/`offset`, byte and word order
  (Sungrow "CDAB"), `enum`/`hex`/`ascii`/`utf8`/`unix_time`, and mux selection
  (single, range `0-3`, list `1,2,5`, nested)
- **`modbus`** — the register poll/encode *model*, sharing the same
  bit-extraction core: what a read covers, how its block decodes, and how a
  write encodes. **There is no poller and no transport here** — nothing in this
  crate opens a socket or keeps a clock; a consumer drives the reads and brings
  the bytes back. `modbus::PollSchedule` says which frames are due, backing off
  one the device rejects, but takes the time from the consumer, which owns the
  clock, the socket and the loop. It sits on `modbus::ItemSchedule`, which does
  the same for any list of reads in any bank, such as `modbus::chunk_ranges`
  makes from address ranges when there is no catalogue. `modbus::RegisterSweep`
  plans a discovery sweep over such a range the same way: it says which read
  is next and takes back what the device did, retrying a busy chunk (0x05/0x06)
  a few times, bisecting a refused chunk down to single addresses and marking a silent one (or a gateway's 0x0A/0x0B) absent
  whole; the answers come back as `AddressBlock` runs and gaps. Values are exact
  `Decimal`, so scaling never introduces binary-float artefacts. A coil or
  discrete read decodes through `modbus::decode_coil_frame`,
  least-significant-bit-first the way Modbus packs it; byte and word order are
  a register bank's and are ignored there. A write encodes to `ModbusWrite`s
  tagged with their `WriteBank`, one per holding register or per coil, a coil
  signal in the same order the decoder reads it
- **`modbus_rtu_stream::ModbusRtuStream`** — reassembles an RTU byte stream,
  boundaries from the RTU length rules and CRC-16/Modbus gating every message.
  Serves a plain serial port and a protocol tunnelled inside a CAN frame id.
  Stateful and order-dependent: feed every frame, in order, one stream per source.
  Declare `vendor_functions` / `allow_broadcast` for a line carrying vendor
  function codes or a broadcasting master — both off by default, because guessing
  at either is how a framer invents messages out of noise. A catalogue declares
  its devices' vendor codes in `[meta.modbus.function_code.<code>]`, with
  `lengths` rules that frame a code exactly rather than by a CRC search that can
  stop a byte short; `Catalog::rtu_options()` builds a serial line from them, and
  `Catalog::tunnel_stream()` gives every `[…tunnel]` them too. A tunnel's own
  table and a caller's builder methods add more; the sources union. A **tap**
  wants the other default and says so
  with `frame_any_function()`: frame every code, decode the modelled ones. A
  recovered message carries its values as a `Payload` (`registers()` and
  `coils()` read it), a `direction_basis` saying whether its side is fact or a
  guess, and `end_offset` — where it sat in the input, which
  against `bytes_fed()` is what back-dates the burst a sync releases at once.
  `ModbusRtuOptions` carries a line's settings as one value and builds the
  stream; `ModbusRtuOptions::tapped()` is the tap's
- **`modbus_rtu_tap::RtuTap`** — that stream off a serial line, on the caller's
  clock: `push` takes one read's bytes and the time it returned, and each
  `TappedMessage` is stamped when its last byte arrived, back-dated by
  `LineSettings::wire_time`. Stamps never go backwards, even when the clock
  does
- **`framing_detect::detect`** — which framing a raw serial byte stream uses:
  SLIP and Modbus RTU scored by running their framers (`wiretap-protocol`'s
  `SlipDecoder`, and the stream a `ModbusRtuOptions` builds, vendor rules and
  all), six delimiters by counting positions. Candidates come ranked with their
  frame statistics and typed `Evidence`; the wording is the caller's. `Unframed`
  names the undeclared codes and broadcasts RTU skipped, and the declared codes
  whose length rules rejected every message
- **`modbus::decode_rtu_message`** — a recovered message as signals: its
  header as `Modbus_{Request|Response}_{Device,Function,Register,Quantity,Exception}`,
  and its register block through the catalogue's register frame, else as
  `Modbus_{side}_Value_{i}`. Those synthesised names are stable: saved layouts
  and dashboards key on them. `function_label` and `exception_label` give the
  code with its name, as `0x03 Read Holding Registers`
- **`dbc`** — import a Vector `.dbc` and export back, including extended
  (`SG_MUL_VAL_`) and flattened multiplex modes
- **`edit::apply_edit` / `apply_edits`** — comment- and formatting-preserving
  in-place edits via `toml_edit`; only the targeted entry changes. The typed ops
  (`UpsertSignal`, `SetFrame`, `SetMux`, `SetMeta`, `Set{Can,Serial,Modbus}Config`)
  write only the keys they model and leave defaults out, so a catalogue can be
  built from empty text as `apply_edits("", ops)`
- **`migrate::migrate`** — upgrade a catalogue's *text* to the current schema,
  comment-preserving and idempotent
- **`mirror`** — `MirrorTracker` / `MirrorVerdict`, live validation that a
  mirrored frame still matches the frame it copies

## Using it

```toml
wiretap-catalog = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.1.4" }
```

```rust
use wiretap_catalog::{Catalog, decode, validate};

let cat = Catalog::parse(toml_text)?;          // shorthands + mirror/copy resolved
let errors = validate::validate(toml_text);    // field-path + message findings

let frame = cat.frame(0x123).unwrap();
let out = decode::decode_frame(&cat, frame, &bytes);
for s in &out.signals {
    println!("{} = {} {}", s.name, s.display, s.unit.as_deref().unwrap_or(""));
}
```

While iterating, pin the tag but add a local `[patch]` or `path` override
against a working checkout, so a change needs no push and no tag to test.

## The schema, briefly

```toml
[meta]
name = "Sungrow SHx"

[meta.modbus]
register_base = 0            # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
default_word_order = "little"

[node."Slave 1"]             # a Modbus slave; it owns the device address
device_address = 1

[frame.modbus.battery_status]   # one Modbus read of a register block
node_address = 1                # which slave, matched by address
register_number = 13019
register_type = "input"         # input | holding | coil | discrete
length = 9                      # register count
interval_ms = 5000              # poll interval

[[frame.modbus.battery_status.signals]]   # a bit-slice of the block
name = "Battery_SoC"
start_bit = 48
bit_length = 16
factor = 0.1
unit = "%"
```

Three shorthands and one fallback are worth knowing:

- **Register from the key** — omit `register_number` and name the frame by its
  register: `[frame.modbus.0x32F9]` or `[frame.modbus.13049]`. An explicit
  `register_number` still wins.
- **Signal-less register** — a register that *is* a single value needs no
  `[[signals]]`; put the decoding fields at frame level and one full-width
  signal is synthesised (`length × 16` bits for a register bank, `length` for a
  coil or discrete one — so a one-coil frame is a single 0/1).
- **Poll interval** — top-level `interval_ms`, else `[meta.modbus]
  .default_interval`, else 5000 ms. The legacy `[tx]` table is still read.
- **Legacy device address** — a catalogue setting `[meta.modbus]
  .device_address` with no nodes still parses: a slave node is synthesised from
  it and orphaned registers attach to it. A register with no `node_address`
  falls back to that, else `1`.
