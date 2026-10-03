#![cfg(feature = "can-gvret")]

mod support;

use std::{
    future::Future,
    io,
    ops::Range,
    sync::{Arc, Mutex},
    time::{Duration, Instant, UNIX_EPOCH},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Notify},
    task::JoinHandle,
};

use support::within;
use wiretap_io::can::{
    gvret::{self, GvretOptions, Link},
    CanError, CanEvent, CanFrame, CanOptions, CanRead, CanTask, DeviceInfo, SendRefused,
    TransportError, Unsupported,
};
use wiretap_protocol::gvret::{
    encode_dev_info, encode_frame, encode_keepalive, encode_num_buses, encode_transmit,
    ClientCommand, Decoder, REQ_DEV_INFO, REQ_NUM_BUSES, SYNC,
};

const ASK: [u8; 2] = [0xF1, 0x09];

#[derive(Clone)]
struct Behaviour {
    buses: Option<u8>,
    /// Which keepalive asks on a connection are answered, counting from 0.
    answers: Range<usize>,
    /// Sent before the bus count reply, as a device already streaming does.
    handshake_frames: Vec<u8>,
    after_queries: AfterQueries,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AfterQueries {
    Reply,
    Close,
    Reset,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            buses: Some(2),
            answers: 0..usize::MAX,
            handshake_frames: Vec::new(),
            after_queries: AfterQueries::Reply,
        }
    }
}

#[derive(Default)]
struct State {
    /// What the host sent, per connection.
    received: Vec<Vec<u8>>,
    asks: usize,
}

enum Out {
    Bytes(Vec<u8>),
    Close,
}

/// A GVRET device on loopback or a pty's master, built from `wiretap-protocol`'s
/// own device end.
struct FakeGvret {
    link: Link,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    outbox: mpsc::UnboundedSender<Out>,
    serving: JoinHandle<()>,
}

impl Drop for FakeGvret {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

#[derive(Clone, Copy)]
enum Over {
    Tcp,
    #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
    Pty,
}

impl Over {
    async fn start(self, behaviour: Behaviour) -> FakeGvret {
        match self {
            Self::Tcp => FakeGvret::start(behaviour).await,
            #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
            Self::Pty => FakeGvret::pty(behaviour),
        }
    }

    /// Longer than a round trip: a serial write waits out a read's 50 ms timeout.
    fn tick(self) -> Duration {
        match self {
            Self::Tcp => Duration::from_millis(20),
            #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
            Self::Pty => Duration::from_millis(150),
        }
    }
}

impl FakeGvret {
    async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let link = Link::Tcp {
            endpoint: listener.local_addr().unwrap().to_string(),
            connect_timeout: Duration::from_secs(1),
        };
        Self::serve(link, behaviour, |connection, out_rx| async move {
            let out_rx = Arc::new(tokio::sync::Mutex::new(out_rx));
            while let Ok((stream, _)) = listener.accept().await {
                let mut out = out_rx.clone().lock_owned().await;
                connection.clone().serve(End::Tcp(stream), &mut out).await;
            }
        })
    }

    /// The pty's slave is held open, so the master reads no hang-up before the
    /// task opens it.
    #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
    fn pty(behaviour: Behaviour) -> Self {
        use std::os::fd::AsRawFd;

        use nix::{
            fcntl::{fcntl, FcntlArg, OFlag},
            pty::openpty,
            unistd::ttyname,
        };
        let pty = openpty(None, None).expect("openpty");
        let path = ttyname(&pty.slave).expect("ttyname");
        fcntl(pty.master.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("fcntl");
        let master = tokio::io::unix::AsyncFd::new(std::fs::File::from(pty.master)).unwrap();
        let link = Link::Serial {
            path: path.to_str().expect("utf-8 path").to_owned(),
            line: serial::LINE,
        };
        let slave = pty.slave;
        Self::serve(link, behaviour, |connection, mut out_rx| async move {
            let _slave = slave;
            connection.serve(End::Pty(master), &mut out_rx).await;
        })
    }

    fn serve<F: Future<Output = ()> + Send + 'static>(
        link: Link,
        behaviour: Behaviour,
        run: impl FnOnce(Connection, mpsc::UnboundedReceiver<Out>) -> F,
    ) -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let changed = Arc::new(Notify::new());
        let (outbox, out_rx) = mpsc::unbounded_channel();
        let connection = Connection {
            behaviour,
            state: state.clone(),
            changed: changed.clone(),
        };
        Self {
            link,
            state,
            changed,
            outbox,
            serving: tokio::spawn(run(connection, out_rx)),
        }
    }

    fn link(&self) -> Link {
        self.link.clone()
    }

    fn send(&self, bytes: Vec<u8>) {
        self.outbox.send(Out::Bytes(bytes)).unwrap();
    }

    fn close(&self) {
        self.outbox.send(Out::Close).unwrap();
    }

    async fn until(&self, done: impl Fn(&State) -> bool) {
        loop {
            let changed = self.changed.notified();
            if done(&self.state.lock().unwrap()) {
                return;
            }
            changed.await;
        }
    }

    fn state<T>(&self, read: impl FnOnce(&State) -> T) -> T {
        read(&self.state.lock().unwrap())
    }
}

#[derive(Clone)]
struct Connection {
    behaviour: Behaviour,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
}

impl Connection {
    async fn serve(self, mut stream: End, out: &mut mpsc::UnboundedReceiver<Out>) {
        {
            let mut state = self.state.lock().unwrap();
            state.received.push(Vec::new());
            state.asks = 0;
        }
        let mut decoder = Decoder::new();
        let mut buf = [0; 1024];
        loop {
            tokio::select! {
                n = stream.read(&mut buf) => {
                    let Ok(n @ 1..) = n else { return };
                    let mut reply = Vec::new();
                    for command in decoder.feed(&buf[..n]) {
                        match command {
                            ClientCommand::DevInfo => reply.extend(encode_dev_info()),
                            ClientCommand::Keepalive => {
                                let mut state = self.state.lock().unwrap();
                                if self.behaviour.answers.contains(&state.asks) {
                                    reply.extend(encode_keepalive());
                                }
                                state.asks += 1;
                            }
                            ClientCommand::NumBuses => match self.behaviour.after_queries {
                                AfterQueries::Reply => {
                                    reply.extend(&self.behaviour.handshake_frames);
                                    if let Some(buses) = self.behaviour.buses {
                                        reply.extend(encode_num_buses(buses));
                                    }
                                }
                                AfterQueries::Close => return,
                                AfterQueries::Reset => {
                                    stream.reset();
                                    return;
                                }
                            },
                            _ => {}
                        }
                    }
                    self.state.lock().unwrap().received.last_mut().unwrap().extend(&buf[..n]);
                    self.changed.notify_waiters();
                    if stream.write_all(&reply).await.is_err() {
                        return;
                    }
                }
                out = out.recv() => match out {
                    Some(Out::Bytes(bytes)) => stream.write_all(&bytes).await.unwrap(),
                    Some(Out::Close) | None => return,
                },
            }
        }
    }
}

/// What the fake device reads and writes through.
enum End {
    Tcp(TcpStream),
    #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
    Pty(tokio::io::unix::AsyncFd<std::fs::File>),
}

impl End {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf).await,
            #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
            Self::Pty(master) => {
                use std::io::Read;
                master
                    .async_io(tokio::io::Interest::READABLE, |mut f| f.read(buf))
                    .await
            }
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.write_all(bytes).await,
            #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
            Self::Pty(master) => {
                use std::io::Write;
                let mut rest = bytes;
                while !rest.is_empty() {
                    let n = master
                        .async_io(tokio::io::Interest::WRITABLE, |mut f| f.write(rest))
                        .await?;
                    rest = &rest[n..];
                }
                Ok(())
            }
        }
    }

    fn reset(&self) {
        match self {
            Self::Tcp(stream) => stream.set_zero_linger().unwrap(),
            #[cfg(all(feature = "can-gvret-serial", target_os = "linux"))]
            Self::Pty(_) => unimplemented!("a pty has no reset"),
        }
    }
}

fn gvret_options(keepalive: Option<Duration>) -> GvretOptions {
    let mut options = GvretOptions::default();
    options.probe_timeout = Duration::from_millis(200);
    options.keepalive = keepalive;
    options
}

fn can_options(reopen: Option<Duration>) -> CanOptions {
    let mut options = CanOptions::default();
    options.reopen = reopen;
    options
}

async fn open(device: &FakeGvret, keepalive: Option<Duration>) -> CanTask {
    gvret::open(device.link(), gvret_options(keepalive), can_options(None))
        .await
        .unwrap()
}

async fn open_err(link: Link) -> CanError {
    match gvret::open(link, gvret_options(None), can_options(None)).await {
        Ok(_) => panic!("the open should fail"),
        Err(error) => error,
    }
}

async fn next(task: &mut CanTask) -> CanEvent {
    task.next_event().await.expect("the task running")
}

async fn connected(task: &mut CanTask) -> DeviceInfo {
    match next(task).await {
        CanEvent::Connected(info) => info,
        other => panic!("expected Connected, got {other:?}"),
    }
}

async fn read(task: &mut CanTask) -> Vec<CanRead> {
    match next(task).await {
        CanEvent::Read(reads) => reads,
        other => panic!("expected a read, got {other:?}"),
    }
}

async fn lost(task: &mut CanTask) -> CanError {
    match next(task).await {
        CanEvent::Disconnected { error, .. } => error,
        other => panic!("expected Disconnected, got {other:?}"),
    }
}

fn micros(read: &CanRead) -> i64 {
    read.at.duration_since(UNIX_EPOCH).unwrap().as_micros() as i64
}

#[tokio::test]
async fn a_device_that_answers_is_connected_with_its_bus_count_build_and_keepalive() {
    within(
        cases::a_device_that_answers_is_connected_with_its_bus_count_build_and_keepalive(Over::Tcp),
    )
    .await
}

#[tokio::test]
async fn a_silent_device_has_no_bus_count_and_refuses_no_bus() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            buses: None,
            answers: 0..0,
            ..Behaviour::default()
        })
        .await;
        let mut task = open(&device, Some(Duration::from_secs(60))).await;
        let info = connected(&mut task).await;
        assert_eq!(info.buses, None);
        assert!(!info.keepalive);
        let far_bus = CanFrame::data(9, 0x123, false, false, false, vec![1]);
        assert!(task.writer().send(far_bus).await.unwrap().is_ok());
    })
    .await
}

#[tokio::test]
async fn a_device_reporting_no_buses_reports_zero_and_refuses_no_bus() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            buses: Some(0),
            ..Behaviour::default()
        })
        .await;
        let mut task = open(&device, None).await;
        assert_eq!(connected(&mut task).await.buses, Some(0));
        let bus = CanFrame::data(0, 0x123, false, false, false, vec![1]);
        assert!(task.writer().send(bus).await.unwrap().is_ok());
    })
    .await
}

#[tokio::test]
async fn a_device_that_closes_during_the_probe_is_the_callers_error() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            after_queries: AfterQueries::Close,
            ..Behaviour::default()
        })
        .await;
        assert!(matches!(open_err(device.link()).await, CanError::Closed));
    })
    .await
}

#[tokio::test]
async fn a_read_error_during_the_probe_is_the_callers_error() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            after_queries: AfterQueries::Reset,
            ..Behaviour::default()
        })
        .await;
        assert!(matches!(open_err(device.link()).await, CanError::Read(_)));
    })
    .await
}

#[tokio::test]
async fn a_refused_connect_is_a_connect_error() {
    within(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        drop(listener);
        let link = Link::Tcp {
            endpoint,
            connect_timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            open_err(link).await,
            CanError::Connect(TransportError::Connect { .. })
        ));
    })
    .await
}

#[tokio::test]
async fn frames_sent_during_the_handshake_come_in_the_first_read_stamped_by_device_time() {
    within(
        cases::frames_sent_during_the_handshake_come_in_the_first_read_stamped_by_device_time(
            Over::Tcp,
        ),
    )
    .await
}

#[tokio::test]
async fn frames_in_one_segment_are_stamped_apart_by_device_time() {
    within(async {
        let device = FakeGvret::start(Behaviour::default()).await;
        let mut task = open(&device, None).await;
        connected(&mut task).await;
        let segment: Vec<u8> = (0..5u32)
            .flat_map(|i| encode_frame(50_000 + i * 700, 0x300 + i, false, 0, &[i as u8], false))
            .collect();
        device.send(segment);
        let mut seen = 0;
        while seen < 5 {
            let reads = read(&mut task).await;
            for r in &reads {
                assert_eq!(
                    micros(r) - micros(&reads[0]),
                    (r.device_us.unwrap() - reads[0].device_us.unwrap()) as i64
                );
            }
            seen += reads.len();
        }
    })
    .await
}

#[tokio::test]
async fn a_send_goes_out_as_encode_transmits_bytes_with_no_trailing_byte() {
    within(cases::a_send_goes_out_as_encode_transmits_bytes_with_no_trailing_byte(Over::Tcp)).await
}

#[tokio::test]
async fn a_send_gvret_cannot_say_is_refused() {
    within(async {
        let device = FakeGvret::start(Behaviour::default()).await;
        let task = open(&device, None).await;
        let writer = task.writer();
        let cases = [
            (
                CanFrame::data(0, 1, false, true, false, vec![0; 8]),
                Unsupported::Fd,
            ),
            (
                CanFrame::data(0, 1, false, true, true, vec![0; 8]),
                Unsupported::Fd,
            ),
            (CanFrame::remote(0, 1, false, 4), Unsupported::Rtr),
            (
                CanFrame::data(0, 1, false, false, false, vec![0; 9]),
                Unsupported::Length(9),
            ),
            (
                CanFrame::data(0, 1, false, true, false, vec![0; 12]),
                Unsupported::Length(12),
            ),
            (
                CanFrame::data(2, 1, false, false, false, vec![]),
                Unsupported::Bus(2),
            ),
        ];
        for (frame, refused) in cases {
            assert_eq!(
                writer.send(frame).await.unwrap_err(),
                SendRefused::Unsupported(refused)
            );
        }
    })
    .await
}

#[tokio::test]
async fn listen_only_still_handshakes_and_refuses_every_send() {
    within(async {
        let device = FakeGvret::start(Behaviour::default()).await;
        let mut options = can_options(None);
        options.listen_only = true;
        let mut task = gvret::open(device.link(), gvret_options(None), options)
            .await
            .unwrap();
        assert_eq!(connected(&mut task).await.buses, Some(2));
        let frame = CanFrame::data(0, 1, false, false, false, vec![]);
        assert_eq!(
            task.writer().send(frame).await.unwrap_err(),
            SendRefused::ListenOnly
        );
    })
    .await
}

#[tokio::test]
async fn a_peer_close_is_closed_and_the_task_reconnects() {
    within(async {
        let device = FakeGvret::start(Behaviour::default()).await;
        let mut task = gvret::open(
            device.link(),
            gvret_options(None),
            can_options(Some(Duration::from_millis(10))),
        )
        .await
        .unwrap();
        connected(&mut task).await;
        device.close();
        let CanEvent::Disconnected {
            error,
            consecutive,
            retry_in,
        } = next(&mut task).await
        else {
            panic!("a loss");
        };
        assert!(matches!(error, CanError::Closed));
        assert_eq!(
            (consecutive, retry_in),
            (1, Some(Duration::from_millis(10)))
        );
        assert_eq!(connected(&mut task).await.buses, Some(2));
        assert_eq!(device.state(|s| s.received.len()), 2);
    })
    .await
}

#[tokio::test]
async fn a_device_that_answered_is_unresponsive_after_ten_unanswered_asks() {
    within(cases::a_device_that_answered_is_unresponsive_after_ten_unanswered_asks(Over::Tcp)).await
}

#[tokio::test]
async fn the_watchdog_arms_on_the_first_answer_after_the_handshake() {
    within(cases::the_watchdog_arms_on_the_first_answer_after_the_handshake(Over::Tcp)).await
}

#[tokio::test]
async fn a_device_that_never_answers_is_never_dropped() {
    within(cases::a_device_that_never_answers_is_never_dropped(
        Over::Tcp,
    ))
    .await
}

#[tokio::test]
async fn sends_between_keepalives_arrive_whole_and_in_order() {
    within(cases::sends_between_keepalives_arrive_whole_and_in_order(
        Over::Tcp,
    ))
    .await
}

fn transmitted_ids(bytes: &[u8]) -> Vec<u32> {
    Decoder::new()
        .feed(bytes)
        .into_iter()
        .filter_map(|command| match command {
            ClientCommand::Transmit { arb_id, .. } => Some(arb_id),
            _ => None,
        })
        .collect()
}

const PROBE: Duration = Duration::from_secs(2);

#[tokio::test]
async fn a_probe_sends_sync_and_the_two_asks_and_nothing_else() {
    within(cases::a_probe_sends_sync_and_the_two_asks_and_nothing_else(
        Over::Tcp,
    ))
    .await
}

#[tokio::test]
async fn a_probe_of_a_silent_device_has_no_bus_count_at_its_deadline() {
    within(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let link = Link::Tcp {
            endpoint: listener.local_addr().unwrap().to_string(),
            connect_timeout: Duration::from_secs(1),
        };
        let holding = tokio::spawn(async move {
            let _accepted = listener.accept().await;
            std::future::pending::<()>().await
        });
        let asked = Instant::now();
        let info = gvret::probe(link, Duration::from_millis(300))
            .await
            .unwrap();
        let took = asked.elapsed();
        assert_eq!((info.buses, info.firmware), (None, None));
        assert!(took >= Duration::from_millis(300) && took < Duration::from_millis(600));
        holding.abort();
    })
    .await
}

#[tokio::test]
async fn a_probe_keeps_the_build_from_a_device_that_never_gives_a_bus_count() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            buses: None,
            ..Behaviour::default()
        })
        .await;
        let info = gvret::probe(device.link(), Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(info.buses, None);
        assert_eq!(info.firmware.as_deref(), Some("400"));
    })
    .await
}

#[tokio::test]
async fn a_probe_of_a_device_that_closes_is_closed() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            after_queries: AfterQueries::Close,
            ..Behaviour::default()
        })
        .await;
        let error = gvret::probe(device.link(), PROBE).await.unwrap_err();
        assert!(matches!(error, CanError::Closed), "{error:?}");
    })
    .await
}

#[tokio::test]
async fn frames_before_the_bus_count_dont_hide_it_from_a_probe() {
    within(async {
        let device = FakeGvret::start(Behaviour {
            handshake_frames: encode_frame(1_000, 0x100, false, 0, &[1, 2], false),
            ..Behaviour::default()
        })
        .await;
        let info = gvret::probe(device.link(), PROBE).await.unwrap();
        assert_eq!(info.buses, Some(2));
    })
    .await
}

#[tokio::test]
async fn a_probe_connect_gets_no_longer_than_the_probe() {
    within(async {
        let (_guard, silent) = support::silent_addr().await;
        let link = Link::Tcp {
            endpoint: silent.to_string(),
            connect_timeout: Duration::from_secs(10),
        };
        let asked = Instant::now();
        let error = gvret::probe(link, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                CanError::Connect(TransportError::ConnectTimeout { .. })
            ),
            "{error:?}"
        );
        assert!(asked.elapsed() < Duration::from_millis(600));
    })
    .await
}

#[cfg(feature = "can-gvret-serial")]
mod serial {
    use wiretap_io::serial::{LineSettings, Parity};

    use super::*;

    pub const LINE: LineSettings = LineSettings {
        baud: 115_200,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: 1,
    };

    fn link(path: &str, line: LineSettings) -> Link {
        Link::Serial {
            path: path.to_owned(),
            line,
        }
    }

    #[tokio::test]
    async fn a_missing_path_is_the_callers_open_error() {
        let missing = "/nonexistent/wiretap-gvret";
        match within(open_err(link(missing, LINE))).await {
            CanError::Open { device, .. } => assert_eq!(device, missing),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_probe_of_a_missing_path_is_the_callers_open_error() {
        let missing = "/nonexistent/wiretap-gvret";
        let error = within(gvret::probe(link(missing, LINE), PROBE)).await;
        assert!(matches!(error, Err(CanError::Open { device, .. }) if device == missing));
    }

    #[tokio::test]
    async fn invalid_line_settings_are_a_config_error() {
        let bad = LineSettings {
            data_bits: 9,
            ..LINE
        };
        let error = within(open_err(link("/nonexistent/wiretap-gvret", bad))).await;
        assert!(matches!(error, CanError::Config(_)), "{error:?}");
    }

    /// serialport can't open a macOS pty: it sets the rate with `IOSSIOSPEED`,
    /// which a pty refuses with `ENOTTY`.
    #[cfg(target_os = "linux")]
    mod pty {
        use super::*;

        #[tokio::test]
        async fn a_device_that_answers_is_connected_with_its_bus_count_build_and_keepalive() {
            within(
                cases::a_device_that_answers_is_connected_with_its_bus_count_build_and_keepalive(
                    Over::Pty,
                ),
            )
            .await
        }

        #[tokio::test]
        async fn a_probe_sends_sync_and_the_two_asks_and_nothing_else() {
            within(cases::a_probe_sends_sync_and_the_two_asks_and_nothing_else(
                Over::Pty,
            ))
            .await
        }

        #[tokio::test]
        async fn frames_sent_during_the_handshake_come_in_the_first_read_stamped_by_device_time() {
            within(
                cases::frames_sent_during_the_handshake_come_in_the_first_read_stamped_by_device_time(
                    Over::Pty,
                ),
            )
            .await
        }

        #[tokio::test]
        async fn a_send_goes_out_as_encode_transmits_bytes_with_no_trailing_byte() {
            within(
                cases::a_send_goes_out_as_encode_transmits_bytes_with_no_trailing_byte(Over::Pty),
            )
            .await
        }

        #[tokio::test]
        async fn sends_between_keepalives_arrive_whole_and_in_order() {
            within(cases::sends_between_keepalives_arrive_whole_and_in_order(
                Over::Pty,
            ))
            .await
        }

        #[tokio::test]
        async fn a_device_that_answered_is_unresponsive_after_ten_unanswered_asks() {
            within(
                cases::a_device_that_answered_is_unresponsive_after_ten_unanswered_asks(Over::Pty),
            )
            .await
        }

        #[tokio::test]
        async fn the_watchdog_arms_on_the_first_answer_after_the_handshake() {
            within(cases::the_watchdog_arms_on_the_first_answer_after_the_handshake(Over::Pty))
                .await
        }

        #[tokio::test]
        async fn a_device_that_never_answers_is_never_dropped() {
            within(cases::a_device_that_never_answers_is_never_dropped(
                Over::Pty,
            ))
            .await
        }

        /// serialport reads a pty's hang-up as `POLLHUP`, which it reports as
        /// `BrokenPipe` rather than zero bytes.
        #[tokio::test]
        async fn a_hang_up_is_closed_or_a_read_error() {
            within(async {
                let device = FakeGvret::pty(Behaviour::default());
                let mut task = open(&device, None).await;
                connected(&mut task).await;
                device.close();
                match lost(&mut task).await {
                    CanError::Closed => {}
                    CanError::Read(e) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe, "{e}"),
                    other => panic!("{other:?}"),
                }
                assert!(task.next_event().await.is_none());
            })
            .await
        }
    }
}

/// Run over TCP above, and over a pty in `serial::pty`.
mod cases {
    use super::*;

    pub async fn a_probe_sends_sync_and_the_two_asks_and_nothing_else(over: Over) {
        let device = over.start(Behaviour::default()).await;
        let info = gvret::probe(device.link(), PROBE).await.unwrap();
        assert_eq!(info.buses, Some(2));
        assert_eq!(info.firmware.as_deref(), Some("400"));
        assert!(!info.keepalive);
        tokio::time::sleep(over.tick() * 2).await;
        let probed = [&SYNC[..], &REQ_DEV_INFO, &REQ_NUM_BUSES].concat();
        assert_eq!(device.state(|s| s.received.concat()), probed);
    }

    /// The keepalive's ticks cancel the task's reads, and with them any write
    /// they had started.
    pub async fn sends_between_keepalives_arrive_whole_and_in_order(over: Over) {
        let device = over
            .start(Behaviour {
                answers: 0..0,
                ..Behaviour::default()
            })
            .await;
        let task = open(&device, Some(Duration::from_millis(1))).await;
        let writer = task.writer();
        for id in 0..20 {
            let frame = CanFrame::data(0, id, false, false, false, vec![id as u8]);
            assert!(writer.send(frame).await.unwrap().is_ok());
        }
        device
            .until(|s| transmitted_ids(&s.received[0]).len() >= 20)
            .await;
        let ids = device.state(|s| transmitted_ids(&s.received[0]));
        assert_eq!(ids, (0..20).collect::<Vec<u32>>());
    }

    pub async fn a_device_that_answers_is_connected_with_its_bus_count_build_and_keepalive(
        over: Over,
    ) {
        let device = over
            .start(Behaviour {
                buses: Some(3),
                ..Behaviour::default()
            })
            .await;
        let mut task = open(&device, Some(Duration::from_secs(60))).await;
        let info = connected(&mut task).await;
        assert_eq!(info.buses, Some(3));
        assert_eq!(info.firmware.as_deref(), Some("400"));
        assert!(info.keepalive);
        let handshake = [&SYNC[..], &REQ_DEV_INFO, &ASK, &REQ_NUM_BUSES].concat();
        assert_eq!(device.state(|s| s.received[0].clone()), handshake);
    }

    pub async fn frames_sent_during_the_handshake_come_in_the_first_read_stamped_by_device_time(
        over: Over,
    ) {
        let counters = [1_000_000, 1_000_250, 1_002_000];
        let handshake_frames = [
            encode_frame(counters[0], 0x100, false, 0, &[1, 2], false),
            encode_frame(counters[1], 0x1234_5678, true, 1, &[3; 8], false),
            encode_frame(counters[2], 0x200, false, 0, &[4; 12], true),
        ]
        .concat();
        let device = over
            .start(Behaviour {
                handshake_frames,
                ..Behaviour::default()
            })
            .await;
        let mut task = open(&device, None).await;
        connected(&mut task).await;
        let reads = read(&mut task).await;
        let frames: Vec<CanFrame> = reads.iter().map(|r| r.frame.clone()).collect();
        assert_eq!(
            frames,
            [
                CanFrame::data(0, 0x100, false, false, false, vec![1, 2]),
                CanFrame::data(1, 0x1234_5678, true, false, false, vec![3; 8]),
                CanFrame::data(0, 0x200, false, true, false, vec![4; 12]),
            ]
        );
        let device_us: Vec<u64> = reads.iter().map(|r| r.device_us.unwrap()).collect();
        assert_eq!(device_us, counters.map(u64::from));
        for r in &reads {
            assert_eq!(
                micros(r) - micros(&reads[0]),
                (r.device_us.unwrap() - device_us[0]) as i64
            );
        }
    }

    pub async fn a_send_goes_out_as_encode_transmits_bytes_with_no_trailing_byte(over: Over) {
        let device = over.start(Behaviour::default()).await;
        let task = open(&device, None).await;
        let writer = task.writer();
        let standard = CanFrame::data(1, 0x7FF, false, false, false, vec![1, 2, 3]);
        let extended = CanFrame::data(0, 0x1ABC_DEF0, true, false, false, vec![9; 8]);
        assert!(writer.send(standard).await.unwrap().is_ok());
        assert!(writer.send(extended).await.unwrap().is_ok());

        let expected = [
            &SYNC[..],
            &REQ_DEV_INFO,
            &REQ_NUM_BUSES,
            &encode_transmit(0x7FF, false, 1, &[1, 2, 3]),
            &encode_transmit(0x1ABC_DEF0, true, 0, &[9; 8]),
        ]
        .concat();
        device
            .until(|s| s.received[0].len() >= expected.len())
            .await;
        assert_eq!(device.state(|s| s.received[0].clone()), expected);
    }

    pub async fn a_device_that_answered_is_unresponsive_after_ten_unanswered_asks(over: Over) {
        let device = over
            .start(Behaviour {
                answers: 0..1,
                ..Behaviour::default()
            })
            .await;
        let mut task = open(&device, Some(over.tick())).await;
        assert!(connected(&mut task).await.keepalive);
        assert!(matches!(lost(&mut task).await, CanError::Unresponsive));
        device.until(|s| s.asks >= 11).await;
        assert_eq!(device.state(|s| s.asks), 11);
    }

    pub async fn the_watchdog_arms_on_the_first_answer_after_the_handshake(over: Over) {
        let device = over
            .start(Behaviour {
                answers: 3..4,
                ..Behaviour::default()
            })
            .await;
        let mut task = open(&device, Some(over.tick())).await;
        assert!(!connected(&mut task).await.keepalive);
        assert!(matches!(lost(&mut task).await, CanError::Unresponsive));
        device.until(|s| s.asks >= 14).await;
        assert_eq!(device.state(|s| s.asks), 14);
    }

    pub async fn a_device_that_never_answers_is_never_dropped(over: Over) {
        let device = over
            .start(Behaviour {
                answers: 0..0,
                ..Behaviour::default()
            })
            .await;
        let mut task = open(&device, Some(over.tick())).await;
        assert!(!connected(&mut task).await.keepalive);
        device.until(|s| s.asks >= 12).await;
        device.send(encode_frame(7, 0x42, false, 0, &[1], false));
        assert_eq!(read(&mut task).await[0].frame.arb_id, 0x42);
    }
}
