use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
};

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use wiretap_protocol::{ARB_MASK_EXT, ARB_MASK_STD};

use super::CanFrame;

/// Why a send never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SendRefused {
    #[error("listen-only")]
    ListenOnly,
    /// The device is down: nothing reached it.
    #[error("not connected")]
    Disconnected,
    #[error("send queue full")]
    QueueFull,
    /// The task has ended, or ended before this send ran.
    #[error("CAN task stopped")]
    Stopped,
    #[error("{0}")]
    Unsupported(Unsupported),
}

/// What the frame asks for that the transport can't say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unsupported {
    #[error("CAN FD is not supported")]
    Fd,
    #[error("bit rate switching is not supported")]
    Brs,
    #[error("remote frames are not supported")]
    Rtr,
    #[error("bus {0} is not on the device")]
    Bus(u8),
    #[error("{0} bytes is too long")]
    Length(usize),
    #[error("id {0:#x} does not fit")]
    Id(u32),
}

/// What the open device can send, for refusing a frame before it is queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub fd: bool,
    pub brs: bool,
    pub rtr: bool,
    /// `None` refuses no bus.
    pub buses: Option<u8>,
}

impl Limits {
    /// Refuses only what no device could send, so a send with none is
    /// answered `Disconnected`.
    pub const ANY: Self = Self {
        fd: true,
        brs: true,
        rtr: true,
        buses: None,
    };

    /// A length is checked before a flag: GVRET has no FD flag, so what it
    /// can't carry is the length.
    fn check(&self, frame: &CanFrame) -> Result<(), Unsupported> {
        let id_mask = if frame.extended {
            ARB_MASK_EXT
        } else {
            ARB_MASK_STD
        };
        let fd = frame.fd && self.fd;
        let max_len = if fd { 64 } else { 8 };
        if frame.arb_id & !id_mask != 0 {
            Err(Unsupported::Id(frame.arb_id))
        } else if frame.data.len() > max_len {
            Err(Unsupported::Length(frame.data.len()))
        } else if frame.fd && !self.fd {
            Err(Unsupported::Fd)
        } else if fd && frame.brs && !self.brs {
            Err(Unsupported::Brs)
        } else if frame.rtr && (frame.fd || !self.rtr) {
            Err(Unsupported::Rtr)
        } else if self.buses.is_some_and(|buses| frame.bus >= buses) {
            Err(Unsupported::Bus(frame.bus))
        } else {
            Ok(())
        }
    }
}

/// Sends through a [`CanTask`](super::CanTask)'s device, between its reads.
/// Every send is answered, and none waits through a reopen. Once queued, a
/// send runs even if its future is dropped.
#[derive(Clone)]
pub struct CanWriter {
    jobs: mpsc::Sender<Job>,
    listen_only: bool,
    limits: Arc<Mutex<Limits>>,
}

type Reply = oneshot::Sender<Result<io::Result<()>, SendRefused>>;

pub(super) struct Job {
    pub frame: CanFrame,
    pub reply: Reply,
}

impl CanWriter {
    pub(super) fn new(
        jobs: mpsc::Sender<Job>,
        listen_only: bool,
        limits: Arc<Mutex<Limits>>,
    ) -> Self {
        Self {
            jobs,
            listen_only,
            limits,
        }
    }

    /// Answered once the device has taken the frame, not once the bus has. A
    /// failed write leaves the device up: the next read decides.
    pub async fn send(&self, frame: CanFrame) -> Result<io::Result<()>, SendRefused> {
        self.submit(frame)?.await
    }

    /// [`send`](Self::send), with the refusals that need no device answered
    /// now and the device's answer left to the returned future.
    pub fn submit(
        &self,
        frame: CanFrame,
    ) -> Result<impl Future<Output = Result<io::Result<()>, SendRefused>> + Send, SendRefused> {
        self.admit(&frame)?;
        let permit = self.jobs.try_reserve().map_err(|e| match e {
            TrySendError::Full(()) => SendRefused::QueueFull,
            TrySendError::Closed(()) => SendRefused::Stopped,
        })?;
        Ok(queue(permit, frame))
    }

    /// [`submit`](Self::submit), waiting for room in the queue instead of
    /// refusing it full.
    pub async fn send_when_ready(
        &self,
        frame: CanFrame,
    ) -> Result<impl Future<Output = Result<io::Result<()>, SendRefused>> + Send, SendRefused> {
        self.admit(&frame)?;
        let permit = self
            .jobs
            .reserve()
            .await
            .map_err(|_| SendRefused::Stopped)?;
        Ok(queue(permit, frame))
    }

    fn admit(&self, frame: &CanFrame) -> Result<(), SendRefused> {
        if self.listen_only {
            return Err(SendRefused::ListenOnly);
        }
        let limits = *self.limits.lock().unwrap_or_else(|e| e.into_inner());
        limits.check(frame).map_err(SendRefused::Unsupported)
    }

    /// Sends queued and not yet taken.
    pub fn queued(&self) -> usize {
        self.jobs.max_capacity() - self.jobs.capacity()
    }
}

fn queue(
    permit: mpsc::Permit<'_, Job>,
    frame: CanFrame,
) -> impl Future<Output = Result<io::Result<()>, SendRefused>> + Send {
    let (reply, answer) = oneshot::channel();
    permit.send(Job { frame, reply });
    async { answer.await.unwrap_or(Err(SendRefused::Stopped)) }
}

#[allow(dead_code)]
fn futures_are_send(writer: CanWriter, frame: CanFrame) {
    fn is_send<T: Send>(_: &T) {}
    fn is_sync<T: Sync>(_: &T) {}
    is_send(&writer);
    is_sync(&writer);
    is_send(&writer.send(frame.clone()));
    is_send(&writer.send_when_ready(frame));
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        pin::{pin, Pin},
        task::Poll,
    };

    use super::*;

    const CLASSIC: Limits = Limits {
        fd: false,
        brs: false,
        rtr: false,
        buses: Some(2),
    };

    fn frame(fd: bool, len: usize) -> CanFrame {
        CanFrame::data(0, 0x123, false, fd, false, vec![0; len])
    }

    #[test]
    fn a_frame_the_transport_cant_say_is_refused_by_what_it_asks_for() {
        let fd = Limits {
            fd: true,
            rtr: true,
            buses: None,
            ..CLASSIC
        };
        let cases = [
            (
                CLASSIC,
                CanFrame::data(0, 0x800, false, false, false, vec![]),
                Unsupported::Id(0x800),
            ),
            (
                fd,
                CanFrame::data(0, 0x2000_0000, true, false, false, vec![]),
                Unsupported::Id(0x2000_0000),
            ),
            (CLASSIC, frame(true, 12), Unsupported::Length(12)),
            (fd, frame(false, 9), Unsupported::Length(9)),
            (fd, frame(true, 65), Unsupported::Length(65)),
            (CLASSIC, frame(true, 8), Unsupported::Fd),
            (
                fd,
                CanFrame::data(0, 1, false, true, true, vec![]),
                Unsupported::Brs,
            ),
            (CLASSIC, CanFrame::remote(0, 1, false, 8), Unsupported::Rtr),
            (
                fd,
                {
                    let mut remote = CanFrame::remote(0, 1, false, 0);
                    remote.fd = true;
                    remote
                },
                Unsupported::Rtr,
            ),
            (
                CLASSIC,
                CanFrame::data(2, 1, false, false, false, vec![]),
                Unsupported::Bus(2),
            ),
        ];
        for (limits, frame, refused) in cases {
            assert_eq!(limits.check(&frame), Err(refused), "{frame:?}");
        }
    }

    #[test]
    fn a_frame_the_transport_can_say_passes() {
        let open = Limits {
            fd: true,
            brs: true,
            rtr: true,
            buses: None,
        };
        let cases = [
            (CLASSIC, frame(false, 8)),
            (
                CLASSIC,
                CanFrame::data(1, 0x1FFF_FFFF, true, false, true, vec![]),
            ),
            (open, CanFrame::data(200, 1, false, true, true, vec![0; 64])),
            (open, CanFrame::remote(0, 0x7FF, false, 8)),
        ];
        for (limits, frame) in cases {
            assert_eq!(limits.check(&frame), Ok(()), "{frame:?}");
        }
    }

    fn writer(listen_only: bool) -> (CanWriter, mpsc::Receiver<Job>) {
        let (jobs, queue) = mpsc::channel(1);
        let writer = CanWriter::new(jobs, listen_only, Arc::new(Mutex::new(CLASSIC)));
        (writer, queue)
    }

    #[tokio::test]
    async fn submit_refuses_without_the_device_and_leaves_its_answer_to_the_future() {
        assert_eq!(
            writer(true).0.submit(frame(false, 8)).err(),
            Some(SendRefused::ListenOnly)
        );
        let (writer, mut queue) = writer(false);
        assert_eq!(
            writer.submit(frame(true, 8)).err(),
            Some(SendRefused::Unsupported(Unsupported::Fd))
        );
        let answer = writer.submit(frame(false, 8)).unwrap();
        assert_eq!(
            writer.submit(frame(false, 8)).err(),
            Some(SendRefused::QueueFull)
        );
        queue.recv().await.unwrap().reply.send(Ok(Ok(()))).unwrap();
        assert!(matches!(answer.await, Ok(Ok(()))));
        drop(queue);
        assert_eq!(
            writer.submit(frame(false, 8)).err(),
            Some(SendRefused::Stopped)
        );
    }

    fn full_writer(listen_only: bool) -> (CanWriter, mpsc::Receiver<Job>) {
        let (writer, queue) = writer(listen_only);
        let reply = oneshot::channel().0;
        writer
            .jobs
            .try_send(Job {
                frame: frame(false, 8),
                reply,
            })
            .unwrap();
        (writer, queue)
    }

    async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
        poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
    }

    #[tokio::test]
    async fn send_when_ready_waits_for_a_full_queue_where_submit_refuses() {
        let (writer, mut queue) = full_writer(false);
        assert_eq!(
            writer.submit(frame(false, 8)).err(),
            Some(SendRefused::QueueFull)
        );
        let mut waiting = pin!(writer.send_when_ready(frame(false, 1)));
        assert!(poll_once(waiting.as_mut()).await.is_pending());
        queue.recv().await.unwrap();
        let answer = waiting.await.unwrap();
        let job = queue.recv().await.unwrap();
        assert_eq!(job.frame, frame(false, 1));
        job.reply.send(Ok(Ok(()))).unwrap();
        assert!(matches!(answer.await, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn send_when_ready_refuses_before_waiting() {
        let (listen_only, _queue) = full_writer(true);
        let refused = poll_once(pin!(listen_only.send_when_ready(frame(false, 8)))).await;
        assert!(matches!(refused, Poll::Ready(Err(SendRefused::ListenOnly))));
        let (writer, _queue) = full_writer(false);
        let refused = poll_once(pin!(writer.send_when_ready(frame(true, 8)))).await;
        assert!(matches!(
            refused,
            Poll::Ready(Err(SendRefused::Unsupported(Unsupported::Fd)))
        ));
    }

    #[tokio::test]
    async fn a_task_stopping_while_send_when_ready_waits_is_stopped() {
        let (writer, queue) = full_writer(false);
        let mut waiting = pin!(writer.send_when_ready(frame(false, 8)));
        assert!(poll_once(waiting.as_mut()).await.is_pending());
        drop(queue);
        assert_eq!(waiting.await.err(), Some(SendRefused::Stopped));
    }

    #[tokio::test]
    async fn dropping_send_when_ready_while_it_waits_queues_nothing() {
        let (writer, mut queue) = full_writer(false);
        let mut waiting = Box::pin(writer.send_when_ready(frame(false, 8)));
        assert!(poll_once(waiting.as_mut()).await.is_pending());
        drop(waiting);
        queue.recv().await.unwrap();
        assert_eq!(writer.queued(), 0);
        assert!(queue.try_recv().is_err());
    }
}
