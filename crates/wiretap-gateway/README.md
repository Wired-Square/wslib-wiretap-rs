# wiretap-gateway

The WireTAP gateway's HTTP API as serde types — the part of the
[`wslib-wiretap-rs`](../../) workspace that WireTAP-Server emits and the WireTAP
desktop parses. It depends on `serde` alone: no HTTP client, no database, no
async runtime, unless the off-by-default `client` feature asks for one.

The off-by-default `ts` feature derives `ts_rs::TS` on `QuerySpec`, `RowWindow`,
`Protocol` (as `ArchiveProtocol`) and the query results, for an app to export;
nothing here writes a `.ts` file.

## What's here

- **`query`** — the nine analytical results with their `QueryStats`: byte and
  frame changes, mirror validation, mux statistics, first/last, frequency,
  distribution, gap analysis and pattern search
- **`archive`** — `InventoryEntry`, `TimeBounds`, the `/frames` cursor batch,
  `/payloads` and the import result
- **`events`** — `Event`, and the `NewEvent` and `EventPatch` a client sends
- **`activity`** — `pg_stat_activity` rows and the cancel/terminate answer
- **`server`** — `Health`, the database list and `ErrorBody`
- **`params`** — `FrameFilter`, the query and `/payloads` bodies that flatten
  it, the `GET` query strings, and the `Protocol` they name
- **`filter`** — `FrameRowFilter`, the rows a query reads, and `sql_where`, the
  SQLite `WHERE` clause over a desktop capture's `frames`, as an `Sql`: `?` per
  value and `inlined()` for showing, a fragment or a whole statement alike
- **`spec`** — `QuerySpec`, the ten queries as one value tagged by `type`:
  bounds in µs, durations in ms, `limit` counting results. Its `row_filters` are
  what it reads, a `Protocol` matching each `CaptureProtocol` a capture stores it
  as (CAN with CAN FD, Modbus with Modbus RTU); turning it into the params above
  is `request`'s
- **`request`** — `QuerySpec::request`, a spec as the gateway's path and body for a
  client reading one protocol, and `rfc3339`, a µs bound as the gateway takes it
- **`admin`** — the daemons and their devices, catalogue assignment and the
  stored catalogues; see [The admin API](#the-admin-api)
- **`client`** — under the `client` feature; see [The client](#the-client)

Field names, types and order are the wire contract. No type refuses an unknown
field, so a newer gateway can add one; fields a pre-0.1.4 gateway leaves out
(`max_len`, `len`) parse as `None`, and the `/frames` row's `is_rtr`, `is_brs`
and `is_esi`, which a gateway before schema v4 leaves out, as `false`. `Health`'s
fields, a database's `schema_state` and the list's `schema_version`, which an
older gateway may leave out, parse as empty, `false` or `0`. A request
whose `protocol` is `None` leaves the key out, which the gateway reads as CAN.

## The admin API

All admin role. A SHA is the catalogue's git blob SHA-1, as 40 lowercase hex
characters, and timestamps are epoch µs.

| endpoint | body | answers |
|----------|------|---------|
| `GET /v1/admin/daemons` | | 200 `DaemonList` |
| `PUT /v1/admin/assignments` | `AssignCatalog` | 200 `AssignedCatalog`, 400 `CatalogRejected`, 409 `AssignmentConflict` |
| `DELETE /v1/admin/assignments?daemon_id&interface&expected` | `UnassignParams` | 204, 409 `AssignmentConflict` |
| `GET /v1/admin/catalogs/{sha}` | | 200 `StoredCatalog` |

**`expected` guards a `PUT` or `DELETE` against a concurrent change.** A SHA
must match the one assigned now; `""` means "only if this interface is
unassigned"; absent means no guard. On a mismatch the answer is 409, and its
`current` is the SHA assigned now (`null` for none), so the client can show
what it lost to and retry without another `GET`.

A 400's `findings`, and a 200's `warnings`, are `CatalogFinding`s: the same
JSON as `wiretap_catalog::ValidationError` (`{ "field", "message" }`), which a
test in `wiretap-catalog` holds them to. The catalogue has no warning tier yet,
so `warnings` is empty until the server produces one.

`DaemonDevice.active` is the device's latest ingest `CATALOG_STATUS`, `null`
before one; `bus` is `null` for an interface assigned but never seen.

## The client

`client` is an HTTP client for the gateway on `reqwest` 0.12, off by default.
`GatewayClient` holds a base URL and a key, sent as a bearer token unless empty;
its clones, and those from `with_endpoint`, share one connection pool and one
registry of running queries, which `cancel` reaches by query id whichever
gateway runs it. `db(name, protocol)` reads one database as one protocol:
inventory, payloads, time bounds, events, import, activity, the queries and a
`FrameCursor` over `/frames`. The admin API is `daemons`, `stored_catalogue`,
`assign_catalogue` and `unassign_catalogue`, the last two answering an
`AssignOutcome`: `Done` with any warnings, `Rejected` with its findings, or
`Conflict` with the SHA assigned now. A failure is a `ClientError`, whose text is
the gateway's own `error` when it sent one.

It runs on the caller's tokio runtime and brings no TLS. For `https://`, enable a
TLS backend on `reqwest` in your own manifest, and Cargo unifies it in:

```toml
wiretap-gateway = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.6.0", features = ["client"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }  # or "native-tls"
```

## Using it

```toml
wiretap-gateway = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.6.0" }
```
