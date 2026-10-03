//! DBC import/export — convert between the WireTAP TOML catalogue format and
//! Vector DBC.
//!
//! Moved verbatim from WireTAP's `src-tauri/src/dbc_{import,export}.rs`; both
//! are self-contained (only `can_dbc`, `toml` and `std`). They operate on TOML
//! text, not the unified [`crate::Catalog`] model — folding them onto the model
//! is a later refactor.

pub mod export;
pub mod import;

pub use export::{render_catalog_as_dbc, render_catalog_as_dbc_with_mode, MuxExportMode};
pub use import::convert_dbc_to_toml;
