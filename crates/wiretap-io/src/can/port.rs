//! The serial port GVRET and SLCAN read a device through: D's serialport port,
//! read-write and exclusive.

use std::io;

use tokio::{
    task::spawn_blocking,
    time::{timeout_at, Instant},
};

use crate::serial::{blocking::Port, Access, LineSettings, SerialError, SerialOptions};

use super::CanError;

pub(super) fn open(path: &str, line: LineSettings) -> Result<Port, CanError> {
    let options = SerialOptions {
        access: Access::ReadWrite,
        ..SerialOptions::default()
    };
    Port::open(path, line, &options).map_err(error)
}

/// `open` on the blocking pool, so a stalled OS open can't outlast `deadline`:
/// its thread is abandoned then, and the port closed when it returns.
pub(super) async fn open_before(
    path: &str,
    line: LineSettings,
    deadline: Instant,
) -> Result<Port, CanError> {
    let owned = path.to_owned();
    match timeout_at(deadline, spawn_blocking(move || open(&owned, line))).await {
        Ok(opened) => opened.map_err(|e| CanError::Read(io::Error::other(e)))?,
        Err(_) => Err(CanError::Open {
            device: path.to_owned(),
            source: io::ErrorKind::TimedOut.into(),
        }),
    }
}

/// Cancel-safe: writes `outbound` first, and returns at least a byte.
pub(super) async fn read(port: &mut Port, outbound: &mut Vec<u8>) -> Result<Vec<u8>, CanError> {
    if !outbound.is_empty() {
        let _ = port.write(outbound).await;
    }
    port.read().await.map_err(error)
}

fn error(error: SerialError) -> CanError {
    match error {
        SerialError::Open { path, source } => CanError::Open {
            device: path,
            source,
        },
        SerialError::Closed => CanError::Closed,
        SerialError::Read(e) => CanError::Read(e),
        e @ (SerialError::UnsupportedBaud(_) | SerialError::InvalidSettings(_)) => {
            CanError::Config(e.to_string())
        }
    }
}
