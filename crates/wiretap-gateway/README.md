# wiretap-gateway

The WireTAP gateway's HTTP API as serde types — the part of the
[`wslib-wiretap-rs`](../../) workspace that WireTAP-Server emits and the WireTAP
desktop parses. It depends on `serde` alone: no HTTP client, no database, no
async runtime.

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
- **`admin`** — the daemons and their devices, catalogue assignment and the
  stored catalogues; see [The admin API](#the-admin-api)

Field names, types and order are the wire contract. No type refuses an unknown
field, so a newer gateway can add one; fields a pre-0.1.4 gateway leaves out
(`max_len`, `len`) parse as `None`, and the `/frames` row's `is_rtr`, `is_brs`
and `is_esi`, which a gateway before schema v4 leaves out, as `false`. A request
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

## Using it

```toml
wiretap-gateway = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.2.0" }
```
