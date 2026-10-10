# wiretap-analysis

Payload analysis for WireTAP frames in the [`wslib-wiretap-rs`](../../) workspace:
which bytes are worth solving as a checksum at all, the geometries to solve them
over, the scan that drives both across a capture, and what every other byte
does.

Where [`wiretap-checksum`](../wiretap-checksum) answers *what algorithm is this
byte*, this crate answers the prior and cheaper question — *is this byte a
checksum* — which usually decides the answer, because most links carry no
checksum on most frame ids.

## What's here

- **`checksum_evidence`** — the per-column verdict: which bytes could be a
  checksum at all
- **`solve_targets`** — each surviving column crossed with every calculation
  range `wiretap-checksum::calc_ranges` offers, so a checksum that skips a
  leading type byte reaches the solver and not only the sweep
- **`scan_frames` / `scan_groups`** — group by frame id, sample, identify,
  sweep, solve, rank
- **`profile_bytes`** — byte roles for one frame id: each column from the front
  classed static, counter (linear or looping), sensor, value or unknown, with
  mux detection (`detect_mux`) splitting a multiplexed frame into cases, and
  the patterns that span adjacent columns (`find_patterns`): 16-bit counters,
  16- and 32-bit sensors, text, and the byte order they imply. Input is oldest
  first and contiguous; ordering is the caller's job
- **`serial_structure`** — a serial link's candidate id bytes (one or two, in
  bytes 0–4) and source-address bytes (in the five after the best id), each
  with its values, a 0–100 confidence and the reasons as codes, not text.
  Checksum candidates stay `wiretap-checksum::detect_checksum`'s
- **`hypothesis::rank_fields`** — a sweep of candidate bit fields over one
  frame's payload (`Sweep`), each a `wiretap-decode` `PayloadField` scored 0–100
  against its byte profile, best first, with the reasons as codes. Capping the
  list is the caller's
- **`analyse_order`** — message order over a time-ordered capture, per bus:
  the periods ids group into, the ids that start a cycle and the sequence after
  them, mux and burst timing, and which ids appear on more than one bus. Gaps
  never cross buses; one call per protocol
- **`mirror_groups`** — ids whose changing payloads match within a time window,
  scored from the sparser id's side
- **`byte_notes`** — a byte profile's notes as codes (`ByteNote`), frame and
  mux-case level; the wording is the caller's
- **`draft::Draft`** — a catalogue in the making, one frame per protocol and
  key: Payload Changes (`apply_profiles`) and Frame Order (`apply_orders`)
  merged in either order, and `to_ops`, the typed `wiretap-catalog` edit ops
  that write it, with hex signals over every byte nothing else claims
  (`default_signals`). `draft::candidate_signals` lists the `byte_*` fields
  worth charting over a byte range
- **`query`** — the analytical query kernels over rows already read, oldest
  first, answering in `wiretap-gateway`'s result types: byte and frame changes,
  mirror validation (`mirror_compare_set` for a catalogue's inherited bytes), mux
  statistics, first/last, frequency, distribution, gaps and masked pattern
  search. Every kernel stops at `limit` results, never rows

Per-byte-column statistics live in [`wiretap-checksum`](../wiretap-checksum),
beside the addressing they are indexed by; reach for them there directly. Roles
read the same statistics from the front (`Anchor::Front`) rather than keeping
their own.

The classifier's thresholds are the desktop's TypeScript ones, pinned by the
golden fixture in `tests/fixtures/byte_roles`; the ranking's weights are pinned
the same way in `tests/fixtures/hypothesis`, and message order, mirrors and notes
in `tests/fixtures/analysis`, each difference from the TypeScript named in its
test.

## Using it

```toml
wiretap-analysis = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.3.0" }
```

Nothing in this workspace depends on it; its consumers are outside.

Identification **narrows** the search rather than deciding it, and the property
the tests pin is the one that matters — a real checksum must never be filtered
out. That argument is in `src/checksum.rs`, beside the test that holds it.
