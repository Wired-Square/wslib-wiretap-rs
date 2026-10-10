//! The WireTAP gateway's HTTP API, as the JSON both ends agree on.
//!
//! WireTAP-Server emits these and the WireTAP desktop parses them, so a field's
//! name, type and position are the contract. Nothing here opens a connection or
//! touches a database; the server maps its rows into these types and the client
//! sends and receives them.
//!
//! No type refuses unknown fields, so a newer gateway can add one without
//! breaking an older client. Enum-like strings (`endianness`, `dir`,
//! `schema_state`, `rollup_state`, `source`, `reason`) stay `String` for the
//! same reason.
//!
//! - [`query`] — the analytical query results and their [`QueryStats`].
//! - [`archive`] — inventory, time bounds, frame batches, payloads and import.
//! - [`events`] — a database's annotations.
//! - [`activity`] — `pg_stat_activity` and the cancel/terminate answer.
//! - [`server`] — health, the database list and the error body.
//! - [`params`] — the request bodies and query strings, and [`Protocol`].
//! - [`filter`] — the rows a query reads, as a SQLite `WHERE` clause over a capture.
//! - [`admin`] — the daemons, their catalogue assignments and the stored catalogues.

pub mod activity;
pub mod admin;
pub mod archive;
pub mod events;
pub mod filter;
pub mod params;
pub mod query;
pub mod server;

pub use activity::*;
pub use admin::*;
pub use archive::*;
pub use events::*;
pub use filter::*;
pub use params::*;
pub use query::*;
pub use server::*;
