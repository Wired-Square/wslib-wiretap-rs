#[cfg(feature = "modbus-task")]
use std::io;
use std::time::Duration;

#[cfg(feature = "modbus-task")]
use super::ResolveError;
use super::{ExceptionCode, TransportError};

/// Why a request produced no data. The two variants are the scanner's
/// question: did the device answer at all?
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The device answered; the connection is kept.
    #[error("{code}")]
    Exception {
        code: ExceptionCode,
        latency: Duration,
    },
    /// No usable answer; the socket has been dropped.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl RequestError {
    pub fn device_replied(&self) -> bool {
        matches!(self, Self::Exception { .. })
    }
}

/// `io::Error` isn't `Clone`, and the task reports one loss twice: to the read
/// or write that hit it, and in `Disconnected`.
#[cfg(feature = "modbus-task")]
impl TransportError {
    pub(super) fn duplicate(&self) -> Self {
        match self {
            Self::Resolve { endpoint, reason } => Self::Resolve {
                endpoint: endpoint.clone(),
                reason: match reason {
                    ResolveError::Io(e) => ResolveError::Io(duplicate_io(e)),
                    ResolveError::NoAddresses => ResolveError::NoAddresses,
                    ResolveError::TimedOut => ResolveError::TimedOut,
                },
            },
            Self::Connect { addr, source } => Self::Connect {
                addr: *addr,
                source: duplicate_io(source),
            },
            Self::ConnectTimeout { addr, after } => Self::ConnectTimeout {
                addr: *addr,
                after: *after,
            },
            Self::Timeout { after } => Self::Timeout { after: *after },
            Self::Io(e) => Self::Io(duplicate_io(e)),
            Self::Closed => Self::Closed,
            Self::Protocol(message) => Self::Protocol(message.clone()),
        }
    }
}

#[cfg(feature = "modbus-task")]
fn duplicate_io(e: &io::Error) -> io::Error {
    e.raw_os_error().map_or_else(
        || io::Error::new(e.kind(), e.to_string()),
        io::Error::from_raw_os_error,
    )
}
