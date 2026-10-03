//! A serial port, read by a task on the ambient tokio runtime, which reopens
//! the line when it goes away and, with `serial-write`, serves writes between
//! reads.
//!
//! Read-only on Linux and macOS opens the path `O_RDONLY` and reads it through
//! the reactor; Windows, and read-write everywhere, go through serialport on
//! the blocking pool. The task yields each read's bytes unframed: framing is
//! the caller's.

use std::{io, time::Duration, time::SystemTime};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep_until, Instant},
};

pub use wiretap_catalog::modbus_rtu_tap::{LineSettings, Parity};

#[cfg(any(windows, feature = "serial-write"))]
pub(crate) mod blocking;
#[cfg(feature = "serial-ports")]
mod listing;
#[cfg(unix)]
mod unix;
#[cfg(feature = "serial-write")]
mod writer;

#[cfg(feature = "serial-ports")]
pub use listing::{ports, PortInfo, PortKind, UsbPort};
#[cfg(feature = "serial-write")]
use writer::Job;
#[cfg(feature = "serial-write")]
pub use writer::{SerialWriter, WriteRefused};

/// How the port is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Access {
    #[default]
    ReadOnly,
    /// Through serialport, on every OS.
    #[cfg(feature = "serial-write")]
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialOptions {
    pub access: Access,
    /// Refuse any later open of the line while it is held: `TIOCEXCL` on Linux
    /// and macOS, and serialport's `flock` as well for `ReadWrite`. Windows
    /// always opens a port exclusively.
    pub exclusive: bool,
    /// The most one read returns.
    pub read_buffer: usize,
    /// The wait before each reopen after a loss; `None` ends the task on the
    /// first loss.
    pub reopen: Option<Duration>,
    /// The event queue's bound. When it is full the task waits for the
    /// consumer, and still serves writes.
    pub events: usize,
    /// The write queue's bound, used with `serial-write`.
    pub writes: usize,
}

impl Default for SerialOptions {
    fn default() -> Self {
        Self {
            access: Access::ReadOnly,
            exclusive: true,
            read_buffer: 4096,
            reopen: Some(Duration::from_secs(1)),
            events: 64,
            writes: 8,
        }
    }
}

#[derive(Debug)]
pub enum SerialEvent {
    /// The first event, and the first after every reopen.
    Connected,
    /// One read's bytes, never empty, and the wall clock when the read returned.
    Read { bytes: Vec<u8>, at: SystemTime },
    /// `consecutive` counts failures since the last `Connected`, the loss that
    /// ended it included. With `retry_in: None` this is the last event.
    Disconnected {
        error: SerialError,
        consecutive: u32,
        retry_in: Option<Duration>,
    },
}

/// Each reason is short and single-line, as `TransportError`'s are.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SerialError {
    #[error("cannot open {path}: {source}")]
    Open { path: String, source: io::Error },
    #[error("{0} baud is not supported")]
    UnsupportedBaud(u32),
    #[error("invalid line settings: {0:?}")]
    InvalidSettings(LineSettings),
    /// The read returned zero: the line went away.
    #[error("line closed")]
    Closed,
    #[error("read failed: {0}")]
    Read(io::Error),
}

/// Owns the task: dropping it stops the task and closes the port.
pub struct SerialTask {
    events: mpsc::Receiver<SerialEvent>,
    /// `None` on a read-only port.
    #[cfg_attr(not(feature = "serial-write"), allow(dead_code))]
    jobs: Option<mpsc::Sender<Job>>,
    handle: JoinHandle<()>,
}

/// Opens the port now, on the caller's task, then spawns the task that reads
/// it. Panics outside a tokio runtime.
pub fn open(
    path: impl Into<String>,
    line: LineSettings,
    options: SerialOptions,
) -> Result<SerialTask, SerialError> {
    let path = path.into();
    let port = Port::open(&path, line, &options)?;
    let (events, event_rx) = mpsc::channel(options.events.max(1));
    let (jobs, job_rx) = mpsc::channel(options.writes.max(1));
    let writable = options.access != Access::ReadOnly;
    let task = Task {
        path,
        line,
        options,
        events,
        jobs: job_rx,
        failures: 0,
    };
    Ok(SerialTask {
        events: event_rx,
        jobs: writable.then_some(jobs),
        handle: tokio::spawn(task.run(port)),
    })
}

impl SerialTask {
    /// `None` once the task has ended.
    pub async fn next_event(&mut self) -> Option<SerialEvent> {
        self.events.recv().await
    }

    /// Lets a write in flight finish, answers queued writes `Stopped`, and
    /// returns once the port is closed.
    pub async fn stop(mut self) {
        self.events.close();
        let _ = (&mut self.handle).await;
    }

    #[cfg(feature = "serial-write")]
    pub fn writer(&self) -> SerialWriter {
        SerialWriter::new(self.jobs.clone())
    }
}

impl Drop for SerialTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn check(line: LineSettings) -> Result<(), SerialError> {
    line.validate()
        .map_err(|_| SerialError::InvalidSettings(line))
}

enum Port {
    #[cfg(unix)]
    Termios(unix::Port),
    #[cfg(any(windows, feature = "serial-write"))]
    Serialport(blocking::Port),
}

impl Port {
    fn open(path: &str, line: LineSettings, options: &SerialOptions) -> Result<Self, SerialError> {
        match options.access {
            #[cfg(unix)]
            Access::ReadOnly => unix::Port::open(path, line, options).map(Self::Termios),
            #[cfg(windows)]
            Access::ReadOnly => blocking::Port::open(path, line, options).map(Self::Serialport),
            #[cfg(feature = "serial-write")]
            Access::ReadWrite => blocking::Port::open(path, line, options).map(Self::Serialport),
        }
    }

    /// Cancel-safe.
    async fn read(&mut self) -> Result<Vec<u8>, SerialError> {
        match self {
            #[cfg(unix)]
            Self::Termios(port) => port.read().await,
            #[cfg(any(windows, feature = "serial-write"))]
            Self::Serialport(port) => port.read().await,
        }
    }

    #[cfg(feature = "serial-write")]
    async fn write(&mut self, mut bytes: Vec<u8>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Termios(_) => Err(io::ErrorKind::Unsupported.into()),
            Self::Serialport(port) => port.write(&mut bytes).await,
        }
    }

    async fn close(self) {
        match self {
            #[cfg(unix)]
            Self::Termios(port) => port.close().await,
            #[cfg(any(windows, feature = "serial-write"))]
            Self::Serialport(port) => port.close().await,
        }
    }
}

#[cfg(not(feature = "serial-write"))]
enum Job {}

#[cfg(not(feature = "serial-write"))]
impl Job {
    async fn run(self, _: Option<&mut Port>) {
        match self {}
    }
}

struct Task {
    path: String,
    line: LineSettings,
    options: SerialOptions,
    events: mpsc::Sender<SerialEvent>,
    jobs: mpsc::Receiver<Job>,
    failures: u32,
}

impl Task {
    async fn run(mut self, mut port: Port) {
        loop {
            let loss = if self.emit(SerialEvent::Connected, Some(&mut port)).await {
                self.read_until_lost(&mut port).await
            } else {
                None
            };
            port.close().await;
            let Some(error) = loss else { return };
            let Some(reopened) = self.reopen(error).await else {
                return;
            };
            port = reopened;
        }
    }

    /// `None` once the consumer has closed the queue.
    async fn read_until_lost(&mut self, port: &mut Port) -> Option<SerialError> {
        loop {
            let read = tokio::select! {
                biased;
                () = self.events.closed() => return None,
                Some(job) = self.jobs.recv() => {
                    job.run(Some(port)).await;
                    continue;
                }
                read = port.read() => read,
            };
            match read {
                Ok(bytes) => {
                    let at = SystemTime::now();
                    if !self.emit(SerialEvent::Read { bytes, at }, Some(port)).await {
                        return None;
                    }
                }
                Err(error) => return Some(error),
            }
        }
    }

    async fn reopen(&mut self, mut error: SerialError) -> Option<Port> {
        loop {
            self.failures = self.failures.saturating_add(1);
            let retry_in = self.options.reopen;
            let disconnected = SerialEvent::Disconnected {
                error,
                consecutive: self.failures,
                retry_in,
            };
            if !self.emit(disconnected, None).await {
                return None;
            }
            let until = Instant::now() + retry_in?;
            loop {
                tokio::select! {
                    biased;
                    () = self.events.closed() => return None,
                    Some(job) = self.jobs.recv() => job.run(None).await,
                    () = sleep_until(until) => break,
                }
            }
            match Port::open(&self.path, self.line, &self.options) {
                Ok(port) => {
                    self.failures = 0;
                    return Some(port);
                }
                Err(e) => error = e,
            }
        }
    }

    /// Waits for room in the queue, serving writes meanwhile; false once the
    /// consumer has closed it. With no port the line is down.
    async fn emit(&mut self, event: SerialEvent, mut port: Option<&mut Port>) -> bool {
        loop {
            tokio::select! {
                biased;
                permit = self.events.reserve() => {
                    return permit.map(|permit| permit.send(event)).is_ok();
                }
                Some(job) = self.jobs.recv() => job.run(port.as_deref_mut()).await,
            }
        }
    }
}

#[allow(dead_code)]
fn futures_are_send(mut task: SerialTask) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&task.next_event());
    is_send(&task);
    is_send(&task.stop());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(data_bits: u8, stop_bits: u8) -> LineSettings {
        LineSettings {
            baud: 9600,
            data_bits,
            parity: Parity::None,
            stop_bits,
        }
    }

    #[test]
    fn the_defaults_are_the_servers() {
        let options = SerialOptions::default();
        assert_eq!(options.access, Access::ReadOnly);
        assert!(options.exclusive);
        assert_eq!(options.read_buffer, 4096);
        assert_eq!(options.reopen, Some(Duration::from_secs(1)));
        assert_eq!(options.events, 64);
        assert_eq!(options.writes, 8);
    }

    #[test]
    fn five_to_eight_data_bits_and_one_or_two_stop_bits_are_valid() {
        for data_bits in 5..=8 {
            for stop_bits in 1..=2 {
                assert!(check(line(data_bits, stop_bits)).is_ok());
            }
        }
        for bad in [line(4, 1), line(9, 1), line(8, 0), line(8, 3)] {
            assert!(matches!(check(bad), Err(SerialError::InvalidSettings(l)) if l == bad));
        }
    }
}
