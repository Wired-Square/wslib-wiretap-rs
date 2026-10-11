//! The WireTAP desktop's capture store: a SQLite database of captures, each a run
//! of frames or of raw bytes, with its metadata and events.
//!
//! Every function takes the connection; opening it, where the file lives and
//! when to clear it are the application's. [`migrate`] brings any database this
//! store has ever written to the current schema, and [`tune`] sets the pragmas a
//! live one runs under. The schema is a contract with databases already on
//! users' disks: see the README before changing it.

mod error;
mod frames;
mod schema;

mod read;
mod search;

mod model;

pub use rusqlite;
pub use wiretap_protocol::can::Direction;

pub use error::CaptureError;
pub use frames::{clear_and_refill, insert_frames, FrameRecord, StoredFrame, STORED_LENGTH};
pub use schema::{migrate, tune, Applied};

pub use read::{
    count_frames_before_rowid, find_offset_for_timestamp, find_rowid_for_timestamp, get_all_frames,
    get_frame_at_index, get_frame_count, get_frame_info, get_frames_paginated,
    get_frames_paginated_filtered, get_frames_tail_filtered, get_frames_tail_rows,
    get_latest_frames, get_next_filtered_frame, get_rowid_range, non_can_protocols,
    read_frame_chunk, read_frame_chunk_reverse,
};
pub use search::search_frames;

pub use model::{CaptureFrameInfo, CaptureKind, CaptureMetadata, TimestampedByte};
