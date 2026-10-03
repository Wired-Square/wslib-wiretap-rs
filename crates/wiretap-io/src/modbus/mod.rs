//! A Modbus TCP connection to one endpoint, the [`Poller`] that reads a
//! schedule over it, and, with `modbus-task`, the task that runs both.
//!
//! The lifecycle: connects are lazy and resolve the endpoint every time; any
//! [`TransportError`] drops the socket, so the next request reconnects; an
//! exception keeps it. There is no retry and no backoff in the connection or
//! the poller — when to try again is the caller's, or the task's.

mod error;
mod poller;
mod request;
#[cfg(feature = "modbus-task")]
mod task;
mod tcp;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(feature = "modbus-write")]
mod write;
#[cfg(all(feature = "modbus-task", feature = "modbus-write"))]
mod writer;

pub use crate::net::{tcp_endpoint, ResolveError, TransportError};
pub use error::RequestError;
pub use poller::{Banks, ItemId, PollEvent, Poller, Step, StepEnd, UnitSource};
pub use request::{DeviceIdCode, DeviceIdentification, ReadData, ReadRequest, Reading};
#[cfg(feature = "modbus-task")]
pub use task::{spawn, PollTask, TaskEvent, TaskOptions};
pub use tcp::{ModbusTcp, TcpOptions};
pub use wiretap_catalog::modbus::ExceptionCode;
#[cfg(feature = "modbus-write")]
pub use write::{Readback, ReadbackKind, WriteOutcome, WriteReport};
#[cfg(all(feature = "modbus-task", feature = "modbus-write"))]
pub use writer::{PollWriter, WriteRefused};
