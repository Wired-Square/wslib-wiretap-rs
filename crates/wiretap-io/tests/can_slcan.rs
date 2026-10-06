#![cfg(feature = "can-slcan")]

mod support;

use std::time::Duration;

use support::within;
use wiretap_io::{
    can::{
        slcan::{self, SlcanOptions},
        CanError, CanOptions,
    },
    serial::{LineSettings, Parity},
};

const LINE: LineSettings = LineSettings {
    baud: 115_200,
    data_bits: 8,
    parity: Parity::None,
    stop_bits: 1,
};

const MISSING: &str = "/nonexistent/wiretap-slcan";

fn slcan_options(path: &str) -> SlcanOptions {
    SlcanOptions {
        path: path.to_owned(),
        line: LINE,
        bitrate: 500_000,
        data_bitrate: None,
    }
}

fn can_options(listen_only: bool) -> CanOptions {
    let mut options = CanOptions::default();
    options.listen_only = listen_only;
    options.reopen = None;
    options
}

async fn open_err(slcan: SlcanOptions) -> CanError {
    match slcan::open(slcan, can_options(false)).await {
        Ok(_) => panic!("the open should fail"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn a_missing_path_is_the_callers_open_error() {
    match within(open_err(slcan_options(MISSING))).await {
        CanError::Open { device, .. } => assert_eq!(device, MISSING),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn invalid_line_settings_are_a_config_error() {
    let mut options = slcan_options(MISSING);
    options.line.data_bits = 9;
    let error = within(open_err(options)).await;
    assert!(matches!(error, CanError::Config(_)), "{error:?}");
}

#[tokio::test]
async fn a_rate_slcan_cannot_name_is_a_config_error_listing_the_rates_before_the_port_opens() {
    let mut nominal = slcan_options(MISSING);
    nominal.bitrate = 400_000;
    let mut data = slcan_options(MISSING);
    data.data_bitrate = Some(3_000_000);
    for (options, listed) in [(nominal, "10000, 20000"), (data, "500000, 1000000")] {
        match within(open_err(options)).await {
            CanError::Config(text) => assert!(text.contains(listed), "{text}"),
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn a_probe_of_a_missing_path_or_bad_settings_fails_before_asking_anything() {
    let error = within(slcan::probe(MISSING, LINE, Duration::from_secs(2))).await;
    assert!(matches!(error, Err(CanError::Open { device, .. }) if device == MISSING));
    let bad = LineSettings {
        data_bits: 9,
        ..LINE
    };
    let error = within(slcan::probe(MISSING, bad, Duration::from_secs(2))).await;
    assert!(matches!(error, Err(CanError::Config(_))), "{error:?}");
}

/// serialport can't open a macOS pty: it sets the rate with `IOSSIOSPEED`,
/// which a pty refuses with `ENOTTY`.
#[cfg(target_os = "linux")]
mod pty {
    use std::{
        io::{self, Read, Write},
        os::fd::AsRawFd,
        sync::{Arc, Mutex},
        time::Instant,
    };

    use nix::{
        fcntl::{fcntl, FcntlArg, OFlag},
        pty::openpty,
        unistd::ttyname,
    };
    use tokio::{
        io::{unix::AsyncFd, Interest},
        sync::{mpsc, Notify},
        task::JoinHandle,
    };
    use wiretap_io::can::{
        CanEvent, CanFrame, CanRead, CanTask, DeviceInfo, SendRefused, Unsupported,
    };
    use wiretap_protocol::slcan::BELL;

    use super::*;

    const STANDARD: &str = "V1013";
    const ELMUE: &str = "V+Board: MultiboardMCU: STM32G431DevID: 1128Firmware: 2490643Slcan: 100Clock: 160Limits: 512,256,128,128,32,32,16,16";

    #[derive(Clone)]
    struct Behaviour {
        version: &'static str,
        /// Commands answered with a bell.
        refuse: Vec<&'static str>,
        /// Answers nothing at all, as some firmware does.
        silent: bool,
        /// Sent in the same write as the answer to `O`.
        after_open: &'static str,
        /// Sent ahead of every answer, as by a channel left open.
        streaming: &'static str,
    }

    impl Default for Behaviour {
        fn default() -> Self {
            Self {
                version: STANDARD,
                refuse: Vec::new(),
                silent: false,
                after_open: "",
                streaming: "",
            }
        }
    }

    enum Out {
        Bytes(Vec<u8>),
        Close,
    }

    /// An SLCAN device on a pty's master. Its slave is held open, so the
    /// master reads no hang-up before the task opens it.
    struct FakeSlcan {
        path: String,
        received: Arc<Mutex<Vec<u8>>>,
        changed: Arc<Notify>,
        outbox: mpsc::UnboundedSender<Out>,
        serving: JoinHandle<()>,
    }

    impl Drop for FakeSlcan {
        fn drop(&mut self) {
            self.serving.abort();
        }
    }

    impl FakeSlcan {
        fn start(behaviour: Behaviour) -> Self {
            let pty = openpty(None, None).expect("openpty");
            let path = ttyname(&pty.slave).expect("ttyname");
            fcntl(pty.master.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("fcntl");
            let master = AsyncFd::new(std::fs::File::from(pty.master)).unwrap();
            let received = Arc::new(Mutex::new(Vec::new()));
            let changed = Arc::new(Notify::new());
            let (outbox, out_rx) = mpsc::unbounded_channel();
            let serving = tokio::spawn(serve(
                master,
                pty.slave,
                behaviour,
                received.clone(),
                changed.clone(),
                out_rx,
            ));
            Self {
                path: path.to_str().expect("utf-8 path").to_owned(),
                received,
                changed,
                outbox,
                serving,
            }
        }

        fn options(&self) -> SlcanOptions {
            slcan_options(&self.path)
        }

        fn send(&self, lines: &str) {
            self.outbox.send(Out::Bytes(lines.into())).unwrap();
        }

        fn close(&self) {
            self.outbox.send(Out::Close).unwrap();
        }

        fn received(&self) -> String {
            String::from_utf8(self.received.lock().unwrap().clone()).unwrap()
        }

        async fn until_received(&self, tail: &str) {
            loop {
                let changed = self.changed.notified();
                if self.received().ends_with(tail) {
                    return;
                }
                changed.await;
            }
        }
    }

    async fn serve(
        master: AsyncFd<std::fs::File>,
        _slave: impl Sized,
        behaviour: Behaviour,
        received: Arc<Mutex<Vec<u8>>>,
        changed: Arc<Notify>,
        mut out: mpsc::UnboundedReceiver<Out>,
    ) {
        let mut line = Vec::new();
        let mut buf = [0; 1024];
        loop {
            tokio::select! {
                n = master.async_io(Interest::READABLE, |mut f| f.read(&mut buf)) => {
                    let Ok(n @ 1..) = n else { return };
                    let mut reply = Vec::new();
                    for &byte in &buf[..n] {
                        if byte != b'\r' {
                            line.push(byte);
                            continue;
                        }
                        let command = String::from_utf8(std::mem::take(&mut line)).unwrap();
                        reply.extend(behaviour.streaming.as_bytes());
                        if !behaviour.silent || behaviour.refuse.contains(&command.as_str()) {
                            reply.extend(answer(&behaviour, &command));
                        }
                    }
                    received.lock().unwrap().extend(&buf[..n]);
                    changed.notify_waiters();
                    if write_all(&master, &reply).await.is_err() {
                        return;
                    }
                }
                out = out.recv() => match out {
                    Some(Out::Bytes(bytes)) => write_all(&master, &bytes).await.unwrap(),
                    Some(Out::Close) | None => return,
                },
            }
        }
    }

    fn answer(behaviour: &Behaviour, command: &str) -> Vec<u8> {
        if behaviour.refuse.contains(&command) {
            return vec![BELL];
        }
        match command {
            "V" => format!("{}\r", behaviour.version).into(),
            "v" => b"v0201\r".to_vec(),
            "N" => b"NA1B2\r".to_vec(),
            "O" => format!("\r{}", behaviour.after_open).into(),
            transmit if transmit.starts_with(['t', 'T', 'r', 'R', 'd', 'D', 'b', 'B']) => {
                b"z\r".to_vec()
            }
            _ => b"\r".to_vec(),
        }
    }

    async fn write_all(master: &AsyncFd<std::fs::File>, bytes: &[u8]) -> io::Result<()> {
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = master
                .async_io(Interest::WRITABLE, |mut f| f.write(rest))
                .await?;
            rest = &rest[n..];
        }
        Ok(())
    }

    async fn open(slcan: SlcanOptions, listen_only: bool) -> CanTask {
        slcan::open(slcan, can_options(listen_only)).await.unwrap()
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

    const START: &str = "C\rV\rN\rS6\rM0\rO\r";

    #[tokio::test]
    async fn the_start_sequence_is_sent_byte_for_byte_and_fills_the_device_info() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut task = open(device.options(), false).await;
            let info = connected(&mut task).await;
            assert_eq!(device.received(), START);
            assert_eq!(info.buses, Some(1));
            assert_eq!(info.firmware.as_deref(), Some("1.0.13"));
            assert_eq!(info.serial.as_deref(), Some("A1B2"));
            assert!(!info.fd && !info.keepalive);
        })
        .await
    }

    #[tokio::test]
    async fn an_elmue_device_with_a_data_rate_is_opened_for_fd_and_sends_it() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                version: ELMUE,
                ..Behaviour::default()
            });
            let mut options = device.options();
            options.data_bitrate = Some(2_000_000);
            let mut task = open(options, false).await;
            let info = connected(&mut task).await;
            assert_eq!(device.received(), "C\rV\rN\rS6\rY2\rM0\rO\r");
            assert!(info.fd);
            assert_eq!(info.firmware.as_deref(), Some("2490643"));
            assert_eq!(info.hardware.as_deref(), Some("Multiboard STM32G431"));

            let fd = CanFrame::data(0, 0x7E0, false, true, true, vec![0x11; 12]);
            task.writer().send(fd).await.unwrap().unwrap();
            device
                .until_received(&format!("b7E09{}\r", "11".repeat(12)))
                .await;
        })
        .await
    }

    #[tokio::test]
    async fn fd_without_the_elmue_firmware_is_a_config_error_before_any_bitrate() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut options = device.options();
            options.data_bitrate = Some(2_000_000);
            let error = slcan::open(options, can_options(false)).await.err();
            assert!(matches!(error, Some(CanError::Config(_))), "{error:?}");
            assert_eq!(device.received(), "C\rV\rN\r");
        })
        .await
    }

    #[tokio::test]
    async fn a_refused_command_the_open_depends_on_fails_it() {
        let cases = [
            ("S6", false, "C\rV\rN\rS6\r"),
            ("M1", true, "C\rV\rN\rS6\rM1\r"),
            ("O", false, START),
        ];
        for (refused, listen_only, sent) in cases {
            within(async {
                let device = FakeSlcan::start(Behaviour {
                    refuse: vec![refused],
                    ..Behaviour::default()
                });
                let error = slcan::open(device.options(), can_options(listen_only))
                    .await
                    .err()
                    .expect("the open should fail");
                if refused == "O" {
                    assert!(matches!(error, CanError::Handshake(_)), "{error:?}");
                } else {
                    assert!(matches!(error, CanError::Config(_)), "{refused}: {error:?}");
                }
                assert_eq!(device.received(), sent);
            })
            .await
        }
    }

    #[tokio::test]
    async fn a_refused_close_or_normal_mode_and_a_silent_device_still_open() {
        let behaviours = [
            Behaviour {
                refuse: vec!["C", "M0"],
                ..Behaviour::default()
            },
            Behaviour {
                silent: true,
                ..Behaviour::default()
            },
        ];
        for behaviour in behaviours {
            within(async {
                let silent = behaviour.silent;
                let device = FakeSlcan::start(behaviour);
                let mut task = open(device.options(), false).await;
                let info = connected(&mut task).await;
                assert_eq!(device.received(), START);
                assert_eq!(info.firmware.is_none(), silent);
            })
            .await
        }
    }

    #[tokio::test]
    async fn listen_only_opens_in_silent_mode_and_refuses_every_send() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut task = open(device.options(), true).await;
            connected(&mut task).await;
            assert_eq!(device.received(), "C\rV\rN\rS6\rM1\rO\r");
            let frame = CanFrame::data(0, 0x123, false, false, false, vec![1]);
            assert_eq!(
                task.writer().send(frame).await.unwrap_err(),
                SendRefused::ListenOnly
            );
            task.stop().await;
            device.until_received("C\rV\rN\rS6\rM1\rO\rC\r").await;
        })
        .await
    }

    #[tokio::test]
    async fn frames_arrive_on_bus_0_with_no_device_clock_even_right_behind_the_open() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                version: ELMUE,
                after_open: "t1232AABB\r",
                ..Behaviour::default()
            });
            let mut options = device.options();
            options.data_bitrate = Some(2_000_000);
            let mut task = open(options, false).await;
            connected(&mut task).await;
            let payload: Vec<u8> = (1..=24).collect();
            let hex: String = payload.iter().map(|b| format!("{b:02X}")).collect();
            device.send(&format!("z\rR123456783\rB12345678C{hex}\r"));
            let mut reads = Vec::new();
            while reads.len() < 3 {
                reads.extend(read(&mut task).await);
            }
            let frames: Vec<CanFrame> = reads.iter().map(|r| r.frame.clone()).collect();
            assert_eq!(
                frames,
                [
                    CanFrame::data(0, 0x123, false, false, false, vec![0xAA, 0xBB]),
                    CanFrame::remote(0, 0x1234_5678, true, 3),
                    CanFrame::data(0, 0x1234_5678, true, true, true, payload),
                ]
            );
            assert!(reads.iter().all(|r| r.device_us.is_none()));
        })
        .await
    }

    #[tokio::test]
    async fn sends_go_out_as_encode_frames_lines_and_what_slcan_cannot_say_is_refused() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut task = open(device.options(), false).await;
            connected(&mut task).await;
            let writer = task.writer();
            let data = CanFrame::data(0, 0x123, false, false, false, vec![1, 2]);
            writer.send(data).await.unwrap().unwrap();
            let remote = CanFrame::remote(0, 0x1ABC_DEF0, true, 5);
            writer.send(remote).await.unwrap().unwrap();
            device.until_received("t12320102\rR1ABCDEF05\r").await;

            let fd = CanFrame::data(0, 0x123, false, true, false, vec![0; 12]);
            assert_eq!(
                writer.send(fd).await.unwrap_err(),
                SendRefused::Unsupported(Unsupported::Length(12))
            );
            let fd = CanFrame::data(0, 0x123, false, true, false, vec![0; 8]);
            assert_eq!(
                writer.send(fd).await.unwrap_err(),
                SendRefused::Unsupported(Unsupported::Fd)
            );
            let bus_1 = CanFrame::data(1, 0x123, false, false, false, vec![]);
            assert_eq!(
                writer.send(bus_1).await.unwrap_err(),
                SendRefused::Unsupported(Unsupported::Bus(1))
            );
            task.stop().await;
            device.until_received("R1ABCDEF05\rC\r").await;
        })
        .await
    }

    /// serialport reads a pty's hang-up as `POLLHUP`, which it reports as
    /// `BrokenPipe` rather than zero bytes.
    #[tokio::test]
    async fn a_hang_up_is_closed_or_a_read_error() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut task = open(device.options(), false).await;
            connected(&mut task).await;
            device.close();
            match next(&mut task).await {
                CanEvent::Disconnected {
                    error: CanError::Closed,
                    ..
                } => {}
                CanEvent::Disconnected {
                    error: CanError::Read(e),
                    ..
                } => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe, "{e}"),
                other => panic!("{other:?}"),
            }
            assert!(task.next_event().await.is_none());
        })
        .await
    }

    /// The task gets a runtime of its own, so dropping it leaves the device's.
    #[tokio::test]
    async fn a_runtime_shut_down_without_stop_still_closes_the_slcan_channel() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let options = device.options();
            let opened = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let task = runtime.block_on(async {
                    let mut task = open(options, false).await;
                    connected(&mut task).await;
                    task
                });
                drop(runtime);
                task
            });
            device.until_received(&format!("{START}C\r")).await;
            drop(opened);
        })
        .await
    }

    #[tokio::test]
    async fn a_stopped_task_closes_the_channel_once() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let mut task = open(device.options(), false).await;
            connected(&mut task).await;
            task.stop().await;
            sent_only(&device, &format!("{START}C\r")).await;
        })
        .await
    }

    const PROBE: Duration = Duration::from_secs(2);

    async fn probe(device: &FakeSlcan, timeout: Duration) -> Result<DeviceInfo, CanError> {
        slcan::probe(&device.path, LINE, timeout).await
    }

    /// Long enough for a write after the probe returned to arrive.
    async fn sent_only(device: &FakeSlcan, sent: &str) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(device.received(), sent);
    }

    #[tokio::test]
    async fn a_probe_asks_v_v_and_n_after_c_and_writes_nothing_else() {
        within(async {
            let device = FakeSlcan::start(Behaviour::default());
            let info = probe(&device, PROBE).await.unwrap();
            sent_only(&device, "C\rV\rv\rN\r").await;
            assert_eq!(info.buses, Some(1));
            assert_eq!(info.firmware.as_deref(), Some("1.0.13"));
            assert_eq!(info.hardware.as_deref(), Some("0201"));
            assert_eq!(info.serial.as_deref(), Some("A1B2"));
            assert!(!info.fd && !info.keepalive && info.clock_hz.is_none());
        })
        .await
    }

    #[tokio::test]
    async fn an_elmue_version_names_the_hardware_so_v_is_not_asked() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                version: ELMUE,
                ..Behaviour::default()
            });
            let info = probe(&device, PROBE).await.unwrap();
            sent_only(&device, "C\rV\rN\r").await;
            assert!(info.fd);
            assert_eq!(info.firmware.as_deref(), Some("2490643"));
            assert_eq!(info.hardware.as_deref(), Some("Multiboard STM32G431"));
        })
        .await
    }

    #[tokio::test]
    async fn a_device_silent_to_all_is_a_handshake_error_within_the_timeout() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                silent: true,
                ..Behaviour::default()
            });
            let asked = Instant::now();
            let error = probe(&device, PROBE).await.unwrap_err();
            assert!(matches!(error, CanError::Handshake(_)), "{error:?}");
            assert!(asked.elapsed() < PROBE);
            sent_only(&device, "C\rV\rv\rN\r").await;
        })
        .await
    }

    #[tokio::test]
    async fn a_probe_returns_by_its_deadline_however_slow_the_device() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                silent: true,
                ..Behaviour::default()
            });
            let asked = Instant::now();
            let error = probe(&device, Duration::from_millis(300))
                .await
                .unwrap_err();
            assert!(matches!(error, CanError::Handshake(_)), "{error:?}");
            assert!(asked.elapsed() < Duration::from_millis(600));
        })
        .await
    }

    #[tokio::test]
    async fn a_bell_to_v_counts_as_an_answer() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                refuse: vec!["V"],
                silent: true,
                ..Behaviour::default()
            });
            let info = probe(&device, PROBE).await.unwrap();
            assert_eq!(
                (info.firmware, info.hardware, info.serial),
                (None, None, None)
            );
        })
        .await
    }

    #[tokio::test]
    async fn frames_from_a_channel_left_open_dont_hide_the_answers() {
        within(async {
            let device = FakeSlcan::start(Behaviour {
                streaming: "t1232AABB\r",
                ..Behaviour::default()
            });
            let info = probe(&device, PROBE).await.unwrap();
            assert_eq!(info.firmware.as_deref(), Some("1.0.13"));
            assert_eq!(info.hardware.as_deref(), Some("0201"));
            assert_eq!(info.serial.as_deref(), Some("A1B2"));
        })
        .await
    }
}
