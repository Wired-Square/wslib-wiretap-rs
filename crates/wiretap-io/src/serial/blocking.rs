//! serialport, read on the blocking pool with the desktop's 50 ms timeout, so a
//! stop or a write waits for at most one read. serialport opens every port
//! read-write, and a Windows one always exclusively; without `serial-write` no
//! write code exists.

use std::{io, mem, time::Duration};

use serialport::{DataBits, FlowControl, SerialPort, StopBits};
use tokio::task::{spawn_blocking, JoinHandle};

use super::{check, LineSettings, Parity, SerialError, SerialOptions};

const READ_TIMEOUT: Duration = Duration::from_millis(50);

type Boxed = Box<dyn SerialPort>;

pub(crate) struct Port {
    state: State,
    /// A read that finished while a write waited for the port.
    unread: Option<io::Result<Vec<u8>>>,
    read_buffer: usize,
}

enum State {
    Idle(Boxed),
    /// Kept across a cancelled `read`, so the next call or `close` picks it up.
    Reading(JoinHandle<(Boxed, io::Result<Vec<u8>>)>),
    /// Kept across a cancelled `write`, as `Reading` is.
    #[cfg_attr(not(feature = "serial-write"), allow(dead_code))]
    Writing(JoinHandle<(Boxed, io::Result<()>)>),
    Gone,
}

impl Port {
    pub(crate) fn open(
        path: &str,
        line: LineSettings,
        options: &SerialOptions,
    ) -> Result<Self, SerialError> {
        check(line)?;
        let builder = serialport::new(path, line.baud)
            .data_bits(match line.data_bits {
                5 => DataBits::Five,
                6 => DataBits::Six,
                7 => DataBits::Seven,
                _ => DataBits::Eight,
            })
            .parity(match line.parity {
                Parity::None => serialport::Parity::None,
                Parity::Even => serialport::Parity::Even,
                Parity::Odd => serialport::Parity::Odd,
            })
            .stop_bits(match line.stop_bits {
                2 => StopBits::Two,
                _ => StopBits::One,
            })
            .flow_control(FlowControl::None)
            .timeout(READ_TIMEOUT);
        #[cfg(unix)]
        let builder = builder.exclusive(options.exclusive);
        let port = builder.open().map_err(|e| SerialError::Open {
            path: path.to_owned(),
            source: e.into(),
        })?;
        Ok(Self {
            state: State::Idle(port),
            unread: None,
            read_buffer: options.read_buffer.max(1),
        })
    }

    /// Cancel-safe.
    pub(crate) async fn read(&mut self) -> Result<Vec<u8>, SerialError> {
        loop {
            let read = match self.unread.take() {
                Some(read) => read,
                None => self.next_read().await?,
            };
            match read {
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                Ok(bytes) if bytes.is_empty() => return Err(SerialError::Closed),
                read => return read.map_err(SerialError::Read),
            }
        }
    }

    /// `write_all` then `flush`, once any read or write in flight has returned.
    /// Cancel-safe: `bytes` is taken only when the write starts.
    #[cfg(feature = "serial-write")]
    pub(crate) async fn write(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        if let State::Reading(_) = self.state {
            self.unread = Some(self.next_read().await.map_err(io::Error::other)?);
        }
        let _ = self.written().await;
        let State::Idle(mut port) = mem::replace(&mut self.state, State::Gone) else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        let bytes = mem::take(bytes);
        self.state = State::Writing(spawn_blocking(move || {
            let written = port.write_all(&bytes).and_then(|()| port.flush());
            (port, written)
        }));
        self.written().await
    }

    /// A second handle on the idle port, for a write that can't wait for a read.
    /// It shares the port's settings, so it must not change them.
    #[cfg(feature = "serial-write")]
    pub(crate) fn try_clone(&self) -> io::Result<Box<dyn io::Write + Send>> {
        let State::Idle(port) = &self.state else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        Ok(port.try_clone()?)
    }

    pub(crate) async fn close(self) {
        match self.state {
            State::Reading(handle) => {
                let _ = handle.await;
            }
            State::Writing(handle) => {
                let _ = handle.await;
            }
            State::Idle(_) | State::Gone => {}
        }
    }

    /// The write in flight's result, if there is one.
    async fn written(&mut self) -> io::Result<()> {
        let State::Writing(handle) = &mut self.state else {
            return Ok(());
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, written) = joined.map_err(io::Error::other)?;
        self.state = State::Idle(port);
        written
    }

    async fn next_read(&mut self) -> Result<io::Result<Vec<u8>>, SerialError> {
        let _ = self.written().await;
        self.state = match mem::replace(&mut self.state, State::Gone) {
            State::Idle(port) => {
                let len = self.read_buffer;
                State::Reading(spawn_blocking(move || read_once(port, len)))
            }
            other => other,
        };
        let State::Reading(handle) = &mut self.state else {
            return Err(SerialError::Closed);
        };
        let joined = handle.await;
        self.state = State::Gone;
        let (port, read) = joined.map_err(|e| SerialError::Read(io::Error::other(e)))?;
        self.state = State::Idle(port);
        Ok(read)
    }
}

fn read_once(mut port: Boxed, len: usize) -> (Boxed, io::Result<Vec<u8>>) {
    let mut buf = vec![0; len];
    let read = port.read(&mut buf).map(|n| {
        buf.truncate(n);
        buf
    });
    (port, read)
}
