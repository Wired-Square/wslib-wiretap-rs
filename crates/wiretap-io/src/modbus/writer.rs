use std::time::Duration;

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use wiretap_catalog::modbus::ModbusWrite;

use super::{ModbusTcp, RequestError, TransportError, WriteReport};

/// Why a write never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriteRefused {
    /// The link is down: nothing reached the wire.
    #[error("not connected")]
    Disconnected,
    #[error("write queue full")]
    QueueFull,
    /// The task has ended, or ended before this write ran.
    #[error("poll task stopped")]
    Stopped,
}

/// Writes over a [`PollTask`](super::PollTask)'s own connection, between its
/// steps. Every write is answered, and none waits through a reconnect backoff.
/// Once queued, a write runs even if its future is dropped.
#[derive(Clone)]
pub struct PollWriter {
    jobs: mpsc::Sender<Job>,
}

type Reply<R> = oneshot::Sender<Result<R, WriteRefused>>;
type Acknowledged = Result<Duration, RequestError>;

pub(super) enum Job {
    Verified {
        unit: Option<u8>,
        writes: Vec<ModbusWrite>,
        reply: Reply<WriteReport>,
    },
    Registers {
        unit: Option<u8>,
        start: u16,
        values: Vec<u16>,
        reply: Reply<Acknowledged>,
    },
    Coils {
        unit: Option<u8>,
        start: u16,
        values: Vec<bool>,
        reply: Reply<Acknowledged>,
    },
}

impl PollWriter {
    pub(super) fn new(jobs: mpsc::Sender<Job>) -> Self {
        Self { jobs }
    }

    pub async fn write_verified(
        &self,
        unit: Option<u8>,
        writes: Vec<ModbusWrite>,
    ) -> Result<WriteReport, WriteRefused> {
        self.submit(|reply| Job::Verified {
            unit,
            writes,
            reply,
        })
        .await
    }

    pub async fn write_registers(
        &self,
        unit: Option<u8>,
        start: u16,
        values: Vec<u16>,
    ) -> Result<Acknowledged, WriteRefused> {
        self.submit(|reply| Job::Registers {
            unit,
            start,
            values,
            reply,
        })
        .await
    }

    pub async fn write_coils(
        &self,
        unit: Option<u8>,
        start: u16,
        values: Vec<bool>,
    ) -> Result<Acknowledged, WriteRefused> {
        self.submit(|reply| Job::Coils {
            unit,
            start,
            values,
            reply,
        })
        .await
    }

    /// Commands queued and not yet taken.
    pub fn queued(&self) -> usize {
        self.jobs.max_capacity() - self.jobs.capacity()
    }

    async fn submit<R>(&self, job: impl FnOnce(Reply<R>) -> Job) -> Result<R, WriteRefused> {
        let (reply, answer) = oneshot::channel();
        self.jobs.try_send(job(reply)).map_err(|e| match e {
            TrySendError::Full(_) => WriteRefused::QueueFull,
            TrySendError::Closed(_) => WriteRefused::Stopped,
        })?;
        answer.await.unwrap_or(Err(WriteRefused::Stopped))
    }
}

impl Job {
    /// Returns the error if the write lost the link.
    pub(super) async fn run(self, conn: &mut ModbusTcp) -> Option<TransportError> {
        match self {
            Job::Verified {
                unit,
                writes,
                reply,
            } => {
                let (report, lost) = conn.write_verified_keeping_loss(unit, &writes).await;
                let _ = reply.send(Ok(report));
                lost
            }
            Job::Registers {
                unit,
                start,
                values,
                reply,
            } => answer(reply, conn.write_registers(unit, start, &values).await),
            Job::Coils {
                unit,
                start,
                values,
                reply,
            } => answer(reply, conn.write_coils(unit, start, &values).await),
        }
    }

    pub(super) fn refuse(self) {
        match self {
            Job::Verified { reply, .. } => {
                let _ = reply.send(Err(WriteRefused::Disconnected));
            }
            Job::Registers { reply, .. } | Job::Coils { reply, .. } => {
                let _ = reply.send(Err(WriteRefused::Disconnected));
            }
        }
    }
}

fn answer(reply: Reply<Acknowledged>, result: Acknowledged) -> Option<TransportError> {
    let lost = match &result {
        Err(RequestError::Transport(error)) => Some(error.duplicate()),
        _ => None,
    };
    let _ = reply.send(Ok(result));
    lost
}

#[allow(dead_code)]
fn futures_are_send(writer: PollWriter) {
    fn is_send<T: Send>(_: &T) {}
    fn is_sync<T: Sync>(_: &T) {}
    is_send(&writer);
    is_sync(&writer);
    is_send(&writer.write_verified(None, Vec::new()));
    is_send(&writer.write_registers(None, 0, Vec::new()));
    is_send(&writer.write_coils(None, 0, Vec::new()));
}
