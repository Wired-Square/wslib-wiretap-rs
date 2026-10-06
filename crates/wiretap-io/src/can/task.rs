use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep_until, Instant},
};

use super::{
    clock::{DeviceClock, Received},
    writer::{Job, Limits},
    BusState, CanError, CanEvent, CanFrame, CanOptions, CanWriter, DeviceInfo, Direction,
    SendRefused,
};

/// One transport's device, as the task drives it.
pub(crate) trait Device: Sized + Send + 'static {
    /// What opens it, kept for every reopen.
    type Config: Send + 'static;

    /// Opens and starts the device, honouring `listen_only`.
    fn open(
        config: &Self::Config,
        options: &CanOptions,
    ) -> impl Future<Output = Result<(Self, DeviceInfo), CanError>> + Send;

    fn limits(&self) -> Limits;

    /// An open's error that says the device isn't there, for `wait_for_device`.
    fn absent(_: &CanError) -> bool {
        false
    }

    /// Cancel-safe. May return no frames.
    fn read(&mut self) -> impl Future<Output = Result<Vec<Received>, CanError>> + Send;

    fn write(&mut self, frame: &CanFrame) -> impl Future<Output = io::Result<()>> + Send;

    /// What the device has learnt of its bus since last asked, oldest first.
    /// A device holding any has `read` return at once.
    fn bus_reports(&mut self) -> Vec<BusState> {
        Vec::new()
    }

    /// Between reads, once their bus reports are out: what can't be done in a
    /// cancellable `read`.
    fn recover(&mut self) -> impl Future<Output = ()> + Send {
        async {}
    }

    fn close(self) -> impl Future<Output = ()> + Send;
}

/// Owns the task: dropping it stops the task and closes the device.
pub struct CanTask {
    events: mpsc::Receiver<CanEvent>,
    writer: CanWriter,
    handle: JoinHandle<()>,
}

/// Opens the device now, on the caller's task, then spawns the task that reads
/// it, which `wait_for_device` leaves an absent device to. Panics outside a
/// tokio runtime.
#[cfg_attr(
    not(any(
        feature = "can-gvret",
        all(feature = "can-slcan", not(target_os = "ios")),
        all(
            any(feature = "can-gsusb", feature = "can-pcan"),
            any(target_os = "macos", target_os = "windows")
        ),
        all(feature = "can-socketcan", target_os = "linux")
    )),
    allow(
        dead_code,
        reason = "with no transport compiled in, only the tests call it"
    )
)]
pub(crate) async fn open<D: Device>(
    config: D::Config,
    options: CanOptions,
) -> Result<CanTask, CanError> {
    let waits = options.wait_for_device && options.reopen.is_some();
    let first = match D::open(&config, &options).await {
        Err(error) if !(waits && D::absent(&error)) => return Err(error),
        first => first,
    };
    let limits = first
        .as_ref()
        .map_or(Limits::ANY, |(device, _)| device.limits());
    let limits = Arc::new(Mutex::new(limits));
    let (events, event_rx) = mpsc::channel(options.events.max(1));
    let (jobs, job_rx) = mpsc::channel(options.writes.max(1));
    let writer = CanWriter::new(jobs, options.listen_only, limits.clone());
    let task = Task {
        config,
        clock: DeviceClock::new(options.time),
        options,
        events,
        jobs: job_rx,
        limits,
        failures: 0,
    };
    Ok(CanTask {
        events: event_rx,
        writer,
        handle: tokio::spawn(task.run(first)),
    })
}

impl CanTask {
    /// `None` once the task has ended.
    pub async fn next_event(&mut self) -> Option<CanEvent> {
        self.events.recv().await
    }

    /// Lets a send in flight finish, answers queued sends `Stopped`, and
    /// returns once the device is closed.
    pub async fn stop(mut self) {
        self.events.close();
        let _ = self.handle.await;
    }

    pub fn writer(&self) -> CanWriter {
        self.writer.clone()
    }
}

impl Job {
    /// With no device it is down.
    async fn run<D: Device>(self, device: Option<&mut D>) {
        let answer = match device {
            Some(device) => Ok(device.write(&self.frame).await),
            None => Err(SendRefused::Disconnected),
        };
        let _ = self.reply.send(answer);
    }
}

enum Turn {
    Closed,
    Send(Job),
    Read(Result<Vec<Received>, CanError>),
}

struct Task<D: Device> {
    config: D::Config,
    options: CanOptions,
    events: mpsc::Sender<CanEvent>,
    jobs: mpsc::Receiver<Job>,
    limits: Arc<Mutex<Limits>>,
    clock: DeviceClock,
    failures: u32,
}

impl<D: Device> Task<D> {
    async fn run(mut self, first: Result<(D, DeviceInfo), CanError>) {
        let mut opened = match first {
            Ok(opened) => Some(opened),
            Err(error) => self.reopen(error).await,
        };
        while let Some((mut device, info)) = opened {
            *self.limits.lock().unwrap_or_else(|e| e.into_inner()) = device.limits();
            self.clock.reset();
            let loss = if self
                .emit(CanEvent::Connected(info), Some(&mut device))
                .await
            {
                self.read_until_lost(&mut device).await
            } else {
                None
            };
            device.close().await;
            let Some(error) = loss else { return };
            opened = self.reopen(error).await;
        }
    }

    /// `None` once the consumer has closed the queue.
    async fn read_until_lost(&mut self, device: &mut D) -> Option<CanError> {
        let mut just_sent = false;
        loop {
            let read = match self.next_turn(device, just_sent).await {
                Turn::Closed => return None,
                Turn::Send(job) => {
                    job.run(Some(device)).await;
                    just_sent = true;
                    continue;
                }
                Turn::Read(read) => read,
            };
            just_sent = false;
            let mut received = match read {
                Ok(received) => received,
                Err(error) => return Some(error),
            };
            let at = SystemTime::now();
            if !self.options.own_frames {
                received.retain(|r| r.direction == Direction::Rx);
            }
            if !received.is_empty() {
                let reads = self.clock.stamp(at, received);
                if !self.emit(CanEvent::Read(reads), Some(device)).await {
                    return None;
                }
            }
            for report in device.bus_reports() {
                if !self.emit(CanEvent::Bus(report), Some(device)).await {
                    return None;
                }
            }
            device.recover().await;
        }
    }

    /// Sends come first, but a read that is ready goes ahead of the next send,
    /// so a flood of sends can't starve the reads.
    async fn next_turn(&mut self, device: &mut D, just_sent: bool) -> Turn {
        if just_sent {
            tokio::select! {
                biased;
                () = self.events.closed() => Turn::Closed,
                read = device.read() => Turn::Read(read),
                Some(job) = self.jobs.recv() => Turn::Send(job),
            }
        } else {
            tokio::select! {
                biased;
                () = self.events.closed() => Turn::Closed,
                Some(job) = self.jobs.recv() => Turn::Send(job),
                read = device.read() => Turn::Read(read),
            }
        }
    }

    async fn reopen(&mut self, mut error: CanError) -> Option<(D, DeviceInfo)> {
        loop {
            self.failures = self.failures.saturating_add(1);
            let retry_in = self.options.reopen;
            let disconnected = CanEvent::Disconnected {
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
                    Some(job) = self.jobs.recv() => job.run::<D>(None).await,
                    () = sleep_until(until) => break,
                }
            }
            match D::open(&self.config, &self.options).await {
                Ok(opened) => {
                    self.failures = 0;
                    return Some(opened);
                }
                Err(e) => error = e,
            }
        }
    }

    /// Waits for room in the queue, serving sends meanwhile; false once the
    /// consumer has closed it. With no device it is down.
    async fn emit(&mut self, event: CanEvent, mut device: Option<&mut D>) -> bool {
        loop {
            tokio::select! {
                biased;
                permit = self.events.reserve() => {
                    return permit.map(|permit| permit.send(event)).is_ok();
                }
                Some(job) = self.jobs.recv() => job.run(device.as_deref_mut()).await,
            }
        }
    }
}

#[allow(dead_code)]
fn futures_are_send(mut task: CanTask) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&task.next_event());
    is_send(&task);
    is_send(&task.stop());
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::sync::{mpsc::UnboundedSender, Semaphore};

    use super::*;
    use crate::can::{clock::Stamp, Unsupported};

    type Script = Result<Vec<Received>, CanError>;

    /// What the test sees of the fake device, across its reopens.
    struct Rig {
        reads: Mutex<Option<mpsc::UnboundedReceiver<Script>>>,
        opens: Mutex<VecDeque<Result<DeviceInfo, CanError>>>,
        written: Mutex<Vec<CanFrame>>,
        written_by_each_read: Mutex<Vec<usize>>,
        writes_allowed: Semaphore,
        writing: AtomicUsize,
        closes: AtomicUsize,
    }

    struct Fake {
        reads: Option<mpsc::UnboundedReceiver<Script>>,
        rig: Arc<Rig>,
    }

    const LIMITS: Limits = Limits {
        fd: false,
        brs: false,
        rtr: false,
        buses: Some(2),
    };

    impl Device for Fake {
        type Config = Arc<Rig>;

        async fn open(rig: &Arc<Rig>, _: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
            let info = rig
                .opens
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(DeviceInfo::default()))?;
            let reads = rig.reads.lock().unwrap().take();
            Ok((
                Self {
                    reads,
                    rig: rig.clone(),
                },
                info,
            ))
        }

        fn limits(&self) -> Limits {
            LIMITS
        }

        fn absent(error: &CanError) -> bool {
            matches!(error, CanError::Open { source, .. } if source.kind() == io::ErrorKind::NotFound)
        }

        async fn read(&mut self) -> Result<Vec<Received>, CanError> {
            let reads = self.reads.as_mut().expect("one device open at a time");
            let script = match reads.recv().await {
                Some(script) => script,
                None => std::future::pending().await,
            };
            let written = self.rig.written.lock().unwrap().len();
            self.rig.written_by_each_read.lock().unwrap().push(written);
            script
        }

        async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
            self.rig.writing.fetch_add(1, Ordering::SeqCst);
            self.rig.writes_allowed.acquire().await.unwrap().forget();
            self.rig.written.lock().unwrap().push(frame.clone());
            Ok(())
        }

        async fn close(self) {
            *self.rig.reads.lock().unwrap() = self.reads;
            self.rig.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn rig(opens: Vec<Result<DeviceInfo, CanError>>) -> (Arc<Rig>, UnboundedSender<Script>) {
        let (script, reads) = mpsc::unbounded_channel();
        let rig = Rig {
            reads: Mutex::new(Some(reads)),
            opens: Mutex::new(opens.into()),
            written: Mutex::default(),
            written_by_each_read: Mutex::default(),
            writes_allowed: Semaphore::new(Semaphore::MAX_PERMITS),
            writing: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        };
        (Arc::new(rig), script)
    }

    fn options(reopen: Option<Duration>) -> CanOptions {
        CanOptions {
            reopen,
            ..CanOptions::default()
        }
    }

    fn waiting(reopen: Duration) -> CanOptions {
        CanOptions {
            wait_for_device: true,
            ..options(Some(reopen))
        }
    }

    fn frame(arb_id: u32) -> CanFrame {
        CanFrame::data(0, arb_id, false, false, false, vec![1, 2])
    }

    fn received(arb_id: u32, direction: Direction) -> Received {
        Received {
            frame: frame(arb_id),
            direction,
            stamp: Stamp::Read,
            overflow: false,
        }
    }

    fn gone() -> CanError {
        CanError::Open {
            device: "fake".into(),
            source: io::ErrorKind::NotFound.into(),
        }
    }

    async fn next(task: &mut CanTask) -> CanEvent {
        tokio::time::timeout(Duration::from_secs(5), task.next_event())
            .await
            .expect("an event in time")
            .expect("the task running")
    }

    async fn settle(until: impl Fn() -> bool) {
        for _ in 0..10_000 {
            if until() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("never settled");
    }

    #[tokio::test]
    async fn connected_comes_first_with_the_device_info_then_each_read() {
        let info = DeviceInfo {
            buses: Some(3),
            ..DeviceInfo::default()
        };
        let (rig, script) = rig(vec![Ok(info.clone())]);
        let mut task = open::<Fake>(rig, options(None)).await.unwrap();
        script
            .send(Ok(vec![
                received(1, Direction::Rx),
                received(2, Direction::Rx),
            ]))
            .unwrap();
        assert!(matches!(next(&mut task).await, CanEvent::Connected(i) if i == info));
        let CanEvent::Read(reads) = next(&mut task).await else {
            panic!("a read");
        };
        let ids: Vec<u32> = reads.iter().map(|r| r.frame.arb_id).collect();
        assert_eq!(ids, [1, 2]);
    }

    #[tokio::test]
    async fn an_overflow_reaches_the_consumer_on_its_frame() {
        let (rig, script) = rig(vec![]);
        let mut task = open::<Fake>(rig, options(None)).await.unwrap();
        next(&mut task).await;
        script
            .send(Ok(vec![
                received(1, Direction::Rx),
                Received {
                    overflow: true,
                    ..received(2, Direction::Rx)
                },
            ]))
            .unwrap();
        let CanEvent::Read(reads) = next(&mut task).await else {
            panic!("a read");
        };
        let flagged: Vec<(u32, bool)> =
            reads.iter().map(|r| (r.frame.arb_id, r.overflow)).collect();
        assert_eq!(flagged, [(1, false), (2, true)]);
    }

    #[tokio::test]
    async fn a_failed_open_is_the_callers_error_unless_an_absent_device_is_waited_for() {
        let refused = CanError::Open {
            device: "fake".into(),
            source: io::ErrorKind::PermissionDenied.into(),
        };
        let unwaited = CanOptions {
            wait_for_device: true,
            ..options(None)
        };
        for (error, options) in [
            (gone(), options(Some(Duration::from_millis(1)))),
            (gone(), unwaited),
            (refused, waiting(Duration::from_millis(1))),
        ] {
            let (rig, _script) = rig(vec![Err(error)]);
            assert!(matches!(
                open::<Fake>(rig, options).await,
                Err(CanError::Open { .. })
            ));
        }
    }

    #[tokio::test]
    async fn an_absent_device_waited_for_is_a_disconnect_that_refuses_sends_disconnected() {
        let (rig, _script) = rig(vec![Err(gone())]);
        let mut task = open::<Fake>(rig, waiting(Duration::from_secs(60)))
            .await
            .unwrap();
        let CanEvent::Disconnected {
            error,
            consecutive,
            retry_in,
        } = next(&mut task).await
        else {
            panic!("a disconnect");
        };
        assert!(matches!(error, CanError::Open { .. }));
        assert_eq!((consecutive, retry_in), (1, Some(Duration::from_secs(60))));
        let off_the_device = CanFrame::data(5, 1, false, false, false, vec![]);
        let refused = task.writer().send(off_the_device).await.unwrap_err();
        assert_eq!(refused, SendRefused::Disconnected);
    }

    #[tokio::test]
    async fn an_absent_device_waited_for_connects_once_it_opens_and_takes_its_limits() {
        let (rig, script) = rig(vec![Err(gone())]);
        let mut task = open::<Fake>(rig.clone(), waiting(Duration::from_millis(1)))
            .await
            .unwrap();
        assert!(matches!(
            next(&mut task).await,
            CanEvent::Disconnected { consecutive: 1, .. }
        ));
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        script.send(Ok(vec![received(1, Direction::Rx)])).unwrap();
        assert!(matches!(next(&mut task).await, CanEvent::Read(_)));
        let writer = task.writer();
        assert!(writer.send(frame(0x42)).await.unwrap().is_ok());
        assert_eq!(*rig.written.lock().unwrap(), [frame(0x42)]);
        let off_the_device = CanFrame::data(5, 1, false, false, false, vec![]);
        let refused = writer.send(off_the_device).await.unwrap_err();
        assert_eq!(refused, SendRefused::Unsupported(Unsupported::Bus(5)));
    }

    #[tokio::test]
    async fn an_empty_read_is_not_an_event_and_own_frames_are_dropped_unless_asked_for() {
        for own_frames in [false, true] {
            let (rig, script) = rig(vec![]);
            let options = CanOptions {
                own_frames,
                ..options(None)
            };
            let mut task = open::<Fake>(rig, options).await.unwrap();
            next(&mut task).await;
            script.send(Ok(vec![])).unwrap();
            script.send(Ok(vec![received(1, Direction::Tx)])).unwrap();
            script
                .send(Ok(vec![
                    received(2, Direction::Tx),
                    received(3, Direction::Rx),
                ]))
                .unwrap();
            let mut seen = Vec::new();
            while seen.last() != Some(&(3, Direction::Rx)) {
                let CanEvent::Read(reads) = next(&mut task).await else {
                    panic!("a read");
                };
                assert!(!reads.is_empty());
                seen.extend(reads.iter().map(|r| (r.frame.arb_id, r.direction)));
            }
            let expected = if own_frames {
                vec![(1, Direction::Tx), (2, Direction::Tx), (3, Direction::Rx)]
            } else {
                vec![(3, Direction::Rx)]
            };
            assert_eq!(seen, expected);
        }
    }

    #[tokio::test]
    async fn consecutive_counts_the_loss_and_each_failed_reopen() {
        let (rig, script) = rig(vec![Ok(DeviceInfo::default()), Err(gone()), Err(gone())]);
        let mut task = open::<Fake>(rig.clone(), options(Some(Duration::from_millis(1))))
            .await
            .unwrap();
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        for round in 0..2 {
            script.send(Err(CanError::Closed)).unwrap();
            let mut expected = 1;
            loop {
                match next(&mut task).await {
                    CanEvent::Disconnected {
                        error,
                        consecutive,
                        retry_in,
                    } => {
                        assert_eq!(consecutive, expected);
                        assert_eq!(retry_in, Some(Duration::from_millis(1)));
                        let first = expected == 1;
                        assert_eq!(matches!(error, CanError::Closed), first);
                        expected += 1;
                    }
                    CanEvent::Connected(_) => break,
                    other => panic!("{other:?}"),
                }
            }
            assert_eq!(expected, if round == 0 { 4 } else { 2 });
        }
        assert_eq!(rig.closes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_dropped_task_still_closes_its_device() {
        let (rig, _script) = rig(vec![]);
        let mut task = open::<Fake>(rig.clone(), options(None)).await.unwrap();
        next(&mut task).await;
        drop(task);
        settle(|| rig.closes.load(Ordering::SeqCst) == 1).await;
    }

    #[tokio::test]
    async fn without_reopen_the_first_loss_is_the_last_event_and_the_device_is_closed_first() {
        let (rig, script) = rig(vec![]);
        let mut task = open::<Fake>(rig.clone(), options(None)).await.unwrap();
        next(&mut task).await;
        script.send(Err(CanError::Unresponsive)).unwrap();
        let CanEvent::Disconnected {
            error,
            consecutive,
            retry_in,
        } = next(&mut task).await
        else {
            panic!("a loss");
        };
        assert!(matches!(error, CanError::Unresponsive));
        assert_eq!((consecutive, retry_in), (1, None));
        assert_eq!(rig.closes.load(Ordering::SeqCst), 1);
        assert!(task.next_event().await.is_none());
        let writer = task.writer();
        assert_eq!(
            writer.send(frame(1)).await.unwrap_err(),
            SendRefused::Stopped
        );
    }

    #[tokio::test]
    async fn a_full_event_queue_still_serves_sends() {
        let (rig, script) = rig(vec![]);
        let options = CanOptions {
            events: 1,
            ..options(None)
        };
        let mut task = open::<Fake>(rig.clone(), options).await.unwrap();
        script.send(Ok(vec![received(1, Direction::Rx)])).unwrap();
        let writer = task.writer();
        assert!(writer.send(frame(0x42)).await.unwrap().is_ok());
        assert_eq!(*rig.written.lock().unwrap(), [frame(0x42)]);
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        assert!(matches!(next(&mut task).await, CanEvent::Read(_)));
    }

    #[tokio::test]
    async fn a_send_is_refused_listen_only_at_once() {
        let (rig, _script) = rig(vec![]);
        let options = CanOptions {
            listen_only: true,
            ..options(None)
        };
        let task = open::<Fake>(rig.clone(), options).await.unwrap();
        let refused = task.writer().send(frame(1)).await.unwrap_err();
        assert_eq!(refused, SendRefused::ListenOnly);
        assert!(rig.written.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_frame_the_device_cant_say_is_refused_before_it_is_queued() {
        let (rig, _script) = rig(vec![]);
        let task = open::<Fake>(rig.clone(), options(None)).await.unwrap();
        let writer = task.writer();
        let too_long = CanFrame::data(0, 1, false, true, false, vec![0; 12]);
        let refused = writer.send(too_long).await.unwrap_err();
        assert_eq!(refused, SendRefused::Unsupported(Unsupported::Length(12)));
        let off_the_device = CanFrame::data(2, 1, false, false, false, vec![]);
        let refused = writer.send(off_the_device).await.unwrap_err();
        assert_eq!(refused, SendRefused::Unsupported(Unsupported::Bus(2)));
        assert_eq!(writer.queued(), 0);
    }

    #[tokio::test]
    async fn a_send_while_down_is_refused_disconnected() {
        let (rig, script) = rig(vec![]);
        let mut task = open::<Fake>(rig.clone(), options(Some(Duration::from_secs(60))))
            .await
            .unwrap();
        next(&mut task).await;
        script.send(Err(CanError::Closed)).unwrap();
        assert!(matches!(
            next(&mut task).await,
            CanEvent::Disconnected { .. }
        ));
        let refused = task.writer().send(frame(1)).await.unwrap_err();
        assert_eq!(refused, SendRefused::Disconnected);
    }

    #[tokio::test]
    async fn a_full_send_queue_is_refused_at_once_and_stop_answers_what_was_queued() {
        let (rig, _script) = rig(vec![]);
        rig.writes_allowed.forget_permits(Semaphore::MAX_PERMITS);
        let options = CanOptions {
            writes: 1,
            ..options(None)
        };
        let mut task = open::<Fake>(rig.clone(), options).await.unwrap();
        next(&mut task).await;
        let writer = task.writer();
        let in_flight = tokio::spawn({
            let writer = writer.clone();
            async move { writer.send(frame(1)).await }
        });
        settle(|| rig.writing.load(Ordering::SeqCst) == 1).await;
        let queued = tokio::spawn({
            let writer = writer.clone();
            async move { writer.send(frame(2)).await }
        });
        settle(|| writer.queued() == 1).await;
        assert_eq!(
            writer.send(frame(3)).await.unwrap_err(),
            SendRefused::QueueFull
        );

        let stopping = tokio::spawn(task.stop());
        rig.writes_allowed.add_permits(1);
        stopping.await.unwrap();
        assert!(in_flight.await.unwrap().unwrap().is_ok());
        assert_eq!(queued.await.unwrap().unwrap_err(), SendRefused::Stopped);
        assert_eq!(*rig.written.lock().unwrap(), [frame(1)]);
        assert_eq!(rig.closes.load(Ordering::SeqCst), 1);
        assert_eq!(
            writer.send(frame(4)).await.unwrap_err(),
            SendRefused::Stopped
        );
    }

    #[tokio::test]
    async fn a_ready_read_goes_between_queued_sends_and_a_quiet_device_delays_none() {
        let (rig, script) = rig(vec![]);
        let options = CanOptions {
            writes: 8,
            ..options(None)
        };
        let task = open::<Fake>(rig.clone(), options).await.unwrap();
        let writer = task.writer();
        for id in 0..3 {
            script.send(Ok(vec![received(id, Direction::Rx)])).unwrap();
        }
        let answers: Vec<_> = (0..6).map(|id| writer.submit(frame(id)).unwrap()).collect();
        for answer in answers {
            answer.await.unwrap().unwrap();
        }
        assert_eq!(*rig.written_by_each_read.lock().unwrap(), [1, 2, 3]);
        task.stop().await;
    }
}
