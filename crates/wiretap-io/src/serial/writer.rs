use std::io;

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

use super::Port;

/// Why a write never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriteRefused {
    /// The port was opened [`Access::ReadOnly`](super::Access::ReadOnly).
    #[error("port is read-only")]
    ReadOnly,
    /// The line is down: nothing reached the wire.
    #[error("not connected")]
    Disconnected,
    #[error("write queue full")]
    QueueFull,
    /// The task has ended, or ended before this write ran.
    #[error("serial task stopped")]
    Stopped,
}

/// Writes to a [`SerialTask`](super::SerialTask)'s port, between its reads.
/// Every write is answered, and none waits through a reopen. Once queued, a
/// write runs even if its future is dropped.
#[derive(Clone)]
pub struct SerialWriter {
    /// `None` on a read-only port.
    jobs: Option<mpsc::Sender<Job>>,
}

type Reply = oneshot::Sender<Result<io::Result<()>, WriteRefused>>;

pub(super) struct Job {
    bytes: Vec<u8>,
    reply: Reply,
}

impl SerialWriter {
    pub(super) fn new(jobs: Option<mpsc::Sender<Job>>) -> Self {
        Self { jobs }
    }

    /// `write_all` then `flush`. A failed write leaves the line up: the next
    /// read decides.
    pub async fn write(&self, bytes: Vec<u8>) -> Result<io::Result<()>, WriteRefused> {
        let jobs = self.jobs.as_ref().ok_or(WriteRefused::ReadOnly)?;
        let (reply, answer) = oneshot::channel();
        jobs.try_send(Job { bytes, reply }).map_err(|e| match e {
            TrySendError::Full(_) => WriteRefused::QueueFull,
            TrySendError::Closed(_) => WriteRefused::Stopped,
        })?;
        answer.await.unwrap_or(Err(WriteRefused::Stopped))
    }

    /// Writes queued and not yet taken.
    pub fn queued(&self) -> usize {
        self.jobs
            .as_ref()
            .map_or(0, |jobs| jobs.max_capacity() - jobs.capacity())
    }
}

impl Job {
    /// With no port the line is down.
    pub(super) async fn run(self, port: Option<&mut Port>) {
        let answer = match port {
            Some(port) => Ok(port.write(self.bytes).await),
            None => Err(WriteRefused::Disconnected),
        };
        let _ = self.reply.send(answer);
    }
}

#[allow(dead_code)]
fn futures_are_send(writer: SerialWriter) {
    fn is_send<T: Send>(_: &T) {}
    fn is_sync<T: Sync>(_: &T) {}
    is_send(&writer);
    is_sync(&writer);
    is_send(&writer.write(Vec::new()));
}
