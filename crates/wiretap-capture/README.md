# wiretap-capture

The WireTAP desktop's capture store, in the [`wslib-wiretap-rs`](../../)
workspace: a SQLite database of captures, each a run of frames or of raw serial
bytes, with its metadata and events. The desktop records into it; anything else
that reads a capture file (a CLI, a headless MCP) reads it through the same
functions.

Every function takes the `rusqlite::Connection`, re-exported as
`wiretap_capture::rusqlite` so a consumer builds against the same SQLite.
Opening the file, where it lives, when to clear it and what to log are the
application's. A `Connection` is `!Sync`; `CaptureSource` shares one behind a
`Mutex`.

## What's here

- **`migrate`** — every recorded migration newer than the database's stamp,
  returning what it applied; **`tune`** — WAL and the pragmas a live database
  runs under
- **`StoredFrame`** — one `frames` row, the protocol an open string so a row
  written under a protocol this build doesn't know reads back as it was.
  `StoredFrame::can` and `to_can` are its `wiretap_protocol::can::CanFrame`
  view. **`FrameRecord`** is what an insert reads, borrowed, so an
  application's own frame type goes in without a copy
- **frames** — `insert_frames` and `clear_and_refill`; reads paged, filtered by
  a `FrameSelection`, the tail, chunks by rowid, by index and by time, the next
  selected frame, counts, `get_frame_info`, `get_latest_frames` and
  `search_frames`. `STORED_LENGTH` is a row's length as SQL
- **bytes** — `insert_bytes`, paged, tail, whole and by time
- **metadata and events** — `CaptureMetadata` rows; events as
  `wiretap_gateway::Event`; `copy_capture_data`, `delete_capture_data` and
  `sweep_non_persistent`, the clear on start
- **analysis** — `sample_frame_payloads` (spread over the whole capture) and
  `tail_frame_payloads` (the newest run), `frame_inventory`, the
  `inventory_statement` and `inventory_row` it is made of, `read_rows`, which
  runs a `wiretap_gateway::Sql` with a cancel flag, and `CaptureSource`, a
  capture as `wiretap-analysis`'s `PayloadSource` and `FrameSource`

The off-by-default `ts` feature derives `ts_rs::TS` on `CaptureKind`,
`TimestampedByte`, `CaptureMetadata` and `CaptureFrameInfo`;
`cargo test -p wiretap-capture --features ts` pins them to the desktop's.

## Schema migrations

**Any change to the schema must be a recorded migration.** No feature code
issues DDL, not even an idempotent `IF NOT EXISTS`: a recorded migration runs
exactly once from a known shape, which neither ad-hoc DDL nor inferring the
shape can promise once databases from different builds mix. The databases are
already on users' disks, so the table, column and index names, the
`schema_migrations` rows and the version numbers are a contract.

- `PRAGMA user_version` is the schema version; 0 is unstamped, any shape from
  before versioning.
- `schema_migrations` is the audit trail: one row per migration applied
  (`version`, `name`, `applied_at` in epoch seconds).
- Each migration applies in its own transaction with its audit row and version
  stamp, so a crash never leaves a step half-applied or applied but unrecorded.

To add one:

1. Write `migrations/NNNN_short_name.sql`, `NNNN` the next version zero-padded.
   Plain SQL, applied verbatim in one transaction.
2. Append it to `MIGRATIONS` in `src/schema.rs` as
   `MigrationStep::Sql(include_str!("../migrations/NNNN_short_name.sql"))`.
3. Add a test exercising the step.

The rules:

- **Never edit or renumber a shipped migration.** Fix a mistake with a new one.
- **Never infer state from the schema's shape.** The v1 baseline
  (`baseline_capture_schema`, in Rust) is the one exception: it normalises the
  unstamped databases, including the legacy `buffer_*` ones, and every
  migration after it starts from a known, stamped shape.
- `MigrationStep::Rust` is for logic SQL can't express; prefer a SQL file, which
  reviews as plain text.

## Using it

```toml
wiretap-capture = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.8.0" }
```

```rust
let mut conn = wiretap_capture::rusqlite::Connection::open(path)?;
wiretap_capture::migrate(&mut conn)?;
wiretap_capture::tune(&conn)?;
let frames = wiretap_capture::get_all_frames(&conn, capture_id)?;
```

SQLite allows one `libsqlite3-sys` per build, so a consumer that also depends on
`rusqlite` directly has to be on the same version, 0.40, with `bundled`: the
store's `json_each` and `->>` need a newer SQLite than some systems ship.
