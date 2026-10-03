use std::{future::pending, time::Duration};

use tokio::{
    sync::mpsc,
    task::JoinHandle,
    time::{sleep_until, Instant},
};

#[cfg(feature = "modbus-write")]
use super::{writer::Job, PollWriter};
use super::{ItemId, ModbusTcp, PollEvent, Poller, StepEnd, TransportError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskOptions {
    /// The first wait after a loss, doubling per consecutive failure.
    pub reconnect_initial: Duration,
    pub reconnect_max: Duration,
    /// The event queue's bound. When it is full the task waits for the
    /// consumer, and still serves writes.
    pub events: usize,
    /// The write queue's bound, used with `modbus-write`.
    pub writes: usize,
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self {
            reconnect_initial: Duration::from_secs(1),
            reconnect_max: Duration::from_secs(30),
            events: 64,
            writes: 8,
        }
    }
}

#[derive(Debug)]
pub enum TaskEvent<T> {
    Connected,
    /// One step's events; never empty.
    Batch(Vec<PollEvent<T>>),
    /// `consecutive` counts failures since the last `Connected`, the loss that
    /// ended it included.
    Disconnected {
        error: TransportError,
        consecutive: u32,
        retry_in: Duration,
    },
    /// The last event: every item is retired and the task has exited.
    AllRetired,
}

/// Owns the task: dropping it stops the task at its next await.
pub struct PollTask<T> {
    events: mpsc::Receiver<TaskEvent<T>>,
    commands: mpsc::UnboundedSender<Command>,
    #[cfg_attr(not(feature = "modbus-write"), allow(dead_code))]
    jobs: mpsc::Sender<Job>,
    handle: JoinHandle<()>,
}

enum Command {
    Pause,
    Resume,
    Retire(ItemId),
    Stop,
}

/// Runs `poller` over `conn` on the ambient tokio runtime, reconnecting with
/// backoff. Panics outside a runtime. `conn` may already be connected.
pub fn spawn<T: Clone + Send + 'static>(
    conn: ModbusTcp,
    poller: Poller<T>,
    options: TaskOptions,
) -> PollTask<T> {
    let (event_tx, events) = mpsc::channel(options.events.max(1));
    let (commands, command_rx) = mpsc::unbounded_channel();
    let (jobs, job_rx) = mpsc::channel(options.writes.max(1));
    let task = Task {
        conn,
        poller,
        options,
        events: event_tx,
        commands: command_rx,
        jobs: job_rx,
        link: Link::Down,
        paused: false,
        failures: 0,
        exit: None,
    };
    PollTask {
        events,
        commands,
        jobs,
        handle: tokio::spawn(task.run()),
    }
}

impl<T> PollTask<T> {
    /// `None` once the task has ended.
    pub async fn next_event(&mut self) -> Option<TaskEvent<T>> {
        self.events.recv().await
    }

    /// No reads; writes and reconnects carry on.
    pub fn pause(&self) {
        self.send(Command::Pause);
    }

    /// Whatever fell due during the pause is read once.
    pub fn resume(&self) {
        self.send(Command::Resume);
    }

    /// Applied before the next step.
    pub fn retire(&self, id: ItemId) {
        self.send(Command::Retire(id));
    }

    /// Lets an in-flight write batch finish, answers queued writes `Stopped`,
    /// and returns once the socket is closed.
    pub async fn stop(mut self) {
        self.send(Command::Stop);
        let _ = (&mut self.handle).await;
    }

    #[cfg(feature = "modbus-write")]
    pub fn writer(&self) -> PollWriter {
        PollWriter::new(self.jobs.clone())
    }

    fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }
}

impl<T> Drop for PollTask<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(not(feature = "modbus-write"))]
enum Job {}

#[cfg(not(feature = "modbus-write"))]
impl Job {
    async fn run(self, _: &mut ModbusTcp) -> Option<TransportError> {
        match self {}
    }

    fn refuse(self) {
        match self {}
    }
}

/// The task's view of the link, not the socket's: with
/// `reconnect_per_request` there is no socket between requests.
enum Link {
    Down,
    Up,
    /// Down, and not yet reported.
    Lost(TransportError),
}

enum Exit {
    Stop,
    AllRetired,
}

struct Task<T> {
    conn: ModbusTcp,
    poller: Poller<T>,
    options: TaskOptions,
    events: mpsc::Sender<TaskEvent<T>>,
    commands: mpsc::UnboundedReceiver<Command>,
    jobs: mpsc::Receiver<Job>,
    link: Link,
    paused: bool,
    failures: u32,
    exit: Option<Exit>,
}

impl<T: Clone + Send> Task<T> {
    async fn run(mut self) {
        while self.exit.is_none() {
            match std::mem::replace(&mut self.link, Link::Down) {
                Link::Down => self.connect().await,
                Link::Lost(error) => self.back_off(error).await,
                Link::Up => {
                    self.link = Link::Up;
                    self.poll().await;
                }
            }
        }
        self.jobs.close();
        while self.jobs.try_recv().is_ok() {}
        self.conn.disconnect().await;
        if let Some(Exit::AllRetired) = self.exit {
            self.emit(TaskEvent::AllRetired).await;
        }
    }

    /// Queued writes wait for the attempt, which `connect_timeout` bounds.
    async fn connect(&mut self) {
        match self.conn.connect().await {
            Ok(()) => {
                self.link = Link::Up;
                self.failures = 0;
                self.emit(TaskEvent::Connected).await;
            }
            Err(error) => self.link = Link::Lost(error),
        }
    }

    async fn back_off(&mut self, error: TransportError) {
        self.failures = self.failures.saturating_add(1);
        let retry_in = self
            .options
            .reconnect_initial
            .saturating_mul(2u32.saturating_pow(self.failures - 1))
            .min(self.options.reconnect_max);
        self.emit(TaskEvent::Disconnected {
            error,
            consecutive: self.failures,
            retry_in,
        })
        .await;
        let until = Instant::now() + retry_in;
        while self.exit.is_none() {
            tokio::select! {
                biased;
                command = self.commands.recv() => self.command(command),
                Some(job) = self.jobs.recv() => self.serve(job).await,
                () = sleep_until(until) => break,
            }
        }
    }

    async fn poll(&mut self) {
        let due = if self.paused {
            None
        } else {
            self.poller.next_due()
        };
        tokio::select! {
            biased;
            command = self.commands.recv() => self.command(command),
            Some(job) = self.jobs.recv() => self.serve(job).await,
            () = sleep_until_due(due) => self.step().await,
        }
    }

    async fn step(&mut self) {
        let now = Instant::now().into_std();
        let step = self.poller.step(&mut self.conn, now).await;
        match step.end {
            StepEnd::Done => {}
            StepEnd::ConnectFailed(error) => self.link = Link::Lost(error),
            StepEnd::Lost => {
                if let Some(PollEvent::Transport { error, .. }) = step.events.last() {
                    self.link = Link::Lost(error.duplicate());
                }
            }
        }
        if !step.events.is_empty() {
            self.emit(TaskEvent::Batch(step.events)).await;
        }
    }

    /// Waits for room in the event queue, serving commands and writes
    /// meanwhile, and gives up only on `stop`.
    async fn emit(&mut self, event: TaskEvent<T>) {
        let events = self.events.clone();
        loop {
            tokio::select! {
                biased;
                permit = events.reserve() => {
                    match permit {
                        Ok(permit) => permit.send(event),
                        Err(_) => self.exit = Some(Exit::Stop),
                    }
                    return;
                }
                command = self.commands.recv() => {
                    self.command(command);
                    if let Some(Exit::Stop) = self.exit {
                        return;
                    }
                }
                Some(job) = self.jobs.recv() => self.serve(job).await,
            }
        }
    }

    async fn serve(&mut self, job: Job) {
        if !matches!(self.link, Link::Up) {
            return job.refuse();
        }
        if let Some(error) = job.run(&mut self.conn).await {
            self.link = Link::Lost(error);
        }
    }

    fn command(&mut self, command: Option<Command>) {
        match command {
            Some(Command::Pause) => self.paused = true,
            Some(Command::Resume) => self.paused = false,
            Some(Command::Retire(id)) => {
                let live = self.poller.live_count();
                self.poller.retire(id);
                if live > 0 && self.poller.live_count() == 0 {
                    self.exit.get_or_insert(Exit::AllRetired);
                }
            }
            Some(Command::Stop) | None => self.exit = Some(Exit::Stop),
        }
    }
}

async fn sleep_until_due(due: Option<std::time::Instant>) {
    match due {
        Some(due) => sleep_until(Instant::from_std(due)).await,
        None => pending().await,
    }
}

#[allow(dead_code)]
fn futures_are_send(mut task: PollTask<usize>) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&task.next_event());
    is_send(&task);
    is_send(&task.stop());
}
