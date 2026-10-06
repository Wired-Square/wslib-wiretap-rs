#![cfg(all(feature = "serial", any(target_os = "macos", target_os = "linux")))]

use std::{
    fs::File,
    future::Future,
    io::{ErrorKind, Read, Write},
    os::{fd::AsRawFd, unix::fs::symlink},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use nix::{
    errno::Errno,
    fcntl::{fcntl, FcntlArg, OFlag},
    pty::openpty,
    unistd::ttyname,
};
use tokio::time::{sleep, timeout};
use wiretap_io::serial::{
    open, LineSettings, Parity, SerialError, SerialEvent, SerialOptions, SerialTask,
};

const LINE: LineSettings = LineSettings {
    baud: 9600,
    data_bits: 8,
    parity: Parity::None,
    stop_bits: 1,
};

/// A pty whose slave only the code under test holds open.
struct Pty {
    master: File,
    slave: PathBuf,
}

impl Pty {
    /// macOS can hand out a pty whose old slave is still closing, which fails
    /// `ENXIO`.
    fn new() -> Self {
        let pty = (0..100)
            .find_map(|_| match openpty(None, None) {
                Err(Errno::ENXIO) => {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
                opened => Some(opened.expect("openpty")),
            })
            .expect("openpty kept failing ENXIO");
        let slave = ttyname(&pty.slave).expect("ttyname");
        fcntl(pty.master.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("fcntl");
        Self {
            master: pty.master.into(),
            slave,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).expect("write to the master");
    }

    /// The master reads a hang-up once no slave is open: zero on macOS, `EIO`
    /// on Linux.
    fn slave_closed(&mut self) -> bool {
        match self.master.read(&mut [0]) {
            Ok(0) => true,
            Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => true,
            Err(e) if e.kind() == ErrorKind::WouldBlock => false,
            other => panic!("{other:?}"),
        }
    }
}

fn path(p: &Path) -> String {
    p.to_str().expect("utf-8 path").to_owned()
}

fn quick() -> SerialOptions {
    SerialOptions {
        reopen: Some(Duration::from_millis(50)),
        ..SerialOptions::default()
    }
}

async fn within<F: Future>(test: F) -> F::Output {
    timeout(Duration::from_secs(5), test)
        .await
        .expect("timed out")
}

async fn next(task: &mut SerialTask) -> SerialEvent {
    within(task.next_event()).await.expect("the task ended")
}

async fn connected(task: &mut SerialTask) {
    let event = next(task).await;
    assert!(matches!(event, SerialEvent::Connected), "{event:?}");
}

async fn read_exactly(task: &mut SerialTask, len: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < len {
        match next(task).await {
            SerialEvent::Read { bytes, .. } => {
                assert!(!bytes.is_empty());
                got.extend(bytes);
            }
            other => panic!("{other:?}"),
        }
    }
    got
}

/// A pty hang-up reads as `EIO` on Linux rather than zero.
fn is_hang_up(error: &SerialError) -> bool {
    match error {
        SerialError::Closed => true,
        SerialError::Read(e) => {
            cfg!(target_os = "linux") && e.raw_os_error() == Some(nix::libc::EIO)
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { nix::libc::geteuid() == 0 }
}

#[tokio::test]
async fn bytes_arrive_as_a_read_stamped_when_it_returned() {
    let mut pty = Pty::new();
    let mut task = open(path(&pty.slave), LINE, quick()).expect("open");
    connected(&mut task).await;

    let before = SystemTime::now();
    pty.send(b"\x01\x03\x00\x00");
    let SerialEvent::Read { bytes, at } = next(&mut task).await else {
        panic!("expected a read");
    };
    let after = SystemTime::now();
    assert_eq!(bytes, b"\x01\x03\x00\x00");
    assert!(
        before <= at && at <= after,
        "{before:?} <= {at:?} <= {after:?}"
    );
    within(task.stop()).await;
}

#[tokio::test]
async fn a_read_is_at_most_read_buffer_long() {
    let mut pty = Pty::new();
    let options = SerialOptions {
        read_buffer: 3,
        ..quick()
    };
    let mut task = open(path(&pty.slave), LINE, options).expect("open");
    connected(&mut task).await;

    pty.send(b"abcdefgh");
    let mut got = Vec::new();
    while got.len() < 8 {
        let SerialEvent::Read { bytes, .. } = next(&mut task).await else {
            panic!("expected a read");
        };
        assert!(bytes.len() <= 3, "{bytes:?}");
        got.extend(bytes);
    }
    assert_eq!(got, b"abcdefgh");
    within(task.stop()).await;
}

fn waiting() -> SerialOptions {
    SerialOptions {
        wait_for_device: true,
        ..quick()
    }
}

#[tokio::test]
async fn a_missing_path_fails_the_first_open_at_the_caller_unless_waited_for() {
    let missing = "/nonexistent/wiretap-serial";
    let unwaited = SerialOptions {
        reopen: None,
        ..waiting()
    };
    for options in [quick(), unwaited] {
        match open(missing, LINE, options) {
            Err(SerialError::Open { path, source }) => {
                assert_eq!(path, missing);
                assert_eq!(source.kind(), ErrorKind::NotFound);
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("opened a missing path"),
        }
    }
}

#[tokio::test]
async fn waiting_returns_every_failure_but_a_missing_path_at_once() {
    let bad = LineSettings {
        data_bits: 9,
        ..LINE
    };
    let refused = open("/nonexistent/wiretap-serial", bad, waiting());
    assert!(matches!(refused, Err(SerialError::InvalidSettings(l)) if l == bad));
    let not_a_port = open(path(&std::env::temp_dir()), LINE, waiting());
    assert!(matches!(not_a_port, Err(SerialError::Open { .. })));
}

#[tokio::test]
async fn a_missing_path_waited_for_is_a_disconnect_until_it_appears() {
    let dir = std::env::temp_dir().join(format!("wiretap-serial-wait-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let link = dir.join("tty");
    let _ = std::fs::remove_file(&link);

    let mut task = open(path(&link), LINE, waiting()).expect("open");
    match next(&mut task).await {
        SerialEvent::Disconnected {
            error: SerialError::Open { source, .. },
            consecutive: 1,
            retry_in: Some(_),
        } => assert_eq!(source.kind(), ErrorKind::NotFound),
        other => panic!("{other:?}"),
    }

    let mut pty = Pty::new();
    symlink(&pty.slave, &link).expect("symlink");
    loop {
        match next(&mut task).await {
            SerialEvent::Connected => break,
            SerialEvent::Disconnected {
                error: SerialError::Open { .. },
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }
    pty.send(b"here");
    assert_eq!(read_exactly(&mut task, 4).await, b"here");

    within(task.stop()).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "serial-write")]
#[tokio::test]
async fn a_missing_path_waited_for_refuses_writes_disconnected() {
    use wiretap_io::serial::{Access, WriteRefused};

    let options = SerialOptions {
        access: Access::ReadWrite,
        reopen: Some(Duration::from_secs(60)),
        ..waiting()
    };
    let mut task = open("/nonexistent/wiretap-serial", LINE, options).expect("open");
    let event = next(&mut task).await;
    assert!(
        matches!(event, SerialEvent::Disconnected { consecutive: 1, .. }),
        "{event:?}"
    );
    let refused = within(task.writer().write(b"x".to_vec())).await;
    assert!(
        matches!(refused, Err(WriteRefused::Disconnected)),
        "{refused:?}"
    );
    within(task.stop()).await;
}

#[tokio::test]
async fn invalid_settings_are_refused_before_the_path_is_opened() {
    let bad = LineSettings {
        data_bits: 9,
        ..LINE
    };
    let refused = open("/nonexistent/wiretap-serial", bad, quick());
    assert!(matches!(refused, Err(SerialError::InvalidSettings(l)) if l == bad));
}

/// macOS ptys ignore `TIOCEXCL`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_exclusive_open_refuses_a_second_open() {
    if is_root() {
        eprintln!("skipped: root bypasses TIOCEXCL");
        return;
    }
    let pty = Pty::new();
    let mut first = open(path(&pty.slave), LINE, quick()).expect("open");
    connected(&mut first).await;

    let relaxed = SerialOptions {
        exclusive: false,
        ..quick()
    };
    match open(path(&pty.slave), LINE, relaxed.clone()) {
        Err(SerialError::Open { source, .. }) => {
            assert_eq!(source.raw_os_error(), Some(nix::libc::EBUSY), "{source}");
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("a second open got past TIOCEXCL"),
    }
    within(first.stop()).await;
}

#[tokio::test]
async fn without_exclusive_a_second_open_succeeds() {
    let pty = Pty::new();
    let relaxed = SerialOptions {
        exclusive: false,
        ..quick()
    };
    let first = open(path(&pty.slave), LINE, relaxed.clone()).expect("open");
    let second = open(path(&pty.slave), LINE, relaxed).expect("second open");
    within(first.stop()).await;
    within(second.stop()).await;
}

#[tokio::test]
async fn stop_returns_once_the_port_is_closed() {
    let mut pty = Pty::new();
    let mut task = open(path(&pty.slave), LINE, quick()).expect("open");
    connected(&mut task).await;
    assert!(!pty.slave_closed());

    within(task.stop()).await;
    assert!(pty.slave_closed());
}

#[tokio::test]
async fn dropping_the_task_closes_the_port() {
    let mut pty = Pty::new();
    let mut task = open(path(&pty.slave), LINE, quick()).expect("open");
    connected(&mut task).await;
    assert!(!pty.slave_closed());

    drop(task);
    within(async {
        while !pty.slave_closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_lost_line_is_reopened_and_failed_reopens_count() {
    let dir = std::env::temp_dir().join(format!("wiretap-serial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let link = dir.join("tty");
    let _ = std::fs::remove_file(&link);

    let first = Pty::new();
    let mut second = Pty::new();
    symlink(&first.slave, &link).expect("symlink");
    let mut task = open(path(&link), LINE, quick()).expect("open");
    connected(&mut task).await;

    // Unplugged: the path is gone, then the line.
    std::fs::remove_file(&link).expect("unlink");
    drop(first);
    match next(&mut task).await {
        SerialEvent::Disconnected {
            error,
            consecutive: 1,
            retry_in: Some(_),
        } => assert!(is_hang_up(&error), "{error:?}"),
        other => panic!("{other:?}"),
    }
    match next(&mut task).await {
        SerialEvent::Disconnected {
            error: SerialError::Open { .. },
            consecutive: 2,
            retry_in: Some(_),
        } => {}
        other => panic!("{other:?}"),
    }

    // Replugged as a fresh tty.
    symlink(&second.slave, &link).expect("symlink");
    let mut consecutive = 2;
    loop {
        match next(&mut task).await {
            SerialEvent::Connected => break,
            SerialEvent::Disconnected {
                error: SerialError::Open { .. },
                consecutive: n,
                ..
            } => {
                assert_eq!(n, consecutive + 1);
                consecutive = n;
            }
            other => panic!("{other:?}"),
        }
    }
    second.send(b"back");
    assert_eq!(read_exactly(&mut task, 4).await, b"back");

    within(task.stop()).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn without_reopen_the_task_ends_on_the_first_loss() {
    let pty = Pty::new();
    let options = SerialOptions {
        reopen: None,
        ..quick()
    };
    let mut task = open(path(&pty.slave), LINE, options).expect("open");
    connected(&mut task).await;

    drop(pty);
    match next(&mut task).await {
        SerialEvent::Disconnected {
            error,
            consecutive: 1,
            retry_in: None,
        } => assert!(is_hang_up(&error), "{error:?}"),
        other => panic!("{other:?}"),
    }
    assert!(within(task.next_event()).await.is_none());
}

#[tokio::test]
async fn a_full_event_queue_waits_and_drops_nothing() {
    let mut pty = Pty::new();
    let options = SerialOptions {
        events: 1,
        ..quick()
    };
    let mut task = open(path(&pty.slave), LINE, options).expect("open");

    let mut sent = Vec::new();
    for chunk in 0u8..20 {
        let bytes = [chunk; 16];
        pty.send(&bytes);
        sent.extend(bytes);
        sleep(Duration::from_millis(5)).await;
    }

    connected(&mut task).await;
    assert_eq!(read_exactly(&mut task, sent.len()).await, sent);
    within(task.stop()).await;
}

#[cfg(feature = "serial-write")]
#[tokio::test]
async fn a_read_only_port_refuses_writes() {
    let pty = Pty::new();
    let mut task = open(path(&pty.slave), LINE, quick()).expect("open");
    connected(&mut task).await;

    let writer = task.writer();
    let refused = within(writer.write(b"x".to_vec())).await;
    assert!(
        matches!(refused, Err(wiretap_io::serial::WriteRefused::ReadOnly)),
        "{refused:?}"
    );
    assert_eq!(writer.queued(), 0);
    within(task.stop()).await;
}

/// serialport can't open a macOS pty: it sets the rate with `IOSSIOSPEED`,
/// which a pty refuses with `ENOTTY`.
#[cfg(all(feature = "serial-write", target_os = "linux"))]
mod writes {
    use std::{fs::OpenOptions, time::Instant};

    use nix::sys::termios::{tcflow, FlowArg};
    use wiretap_io::serial::{Access, SerialWriter, WriteRefused};

    use super::*;

    fn read_write() -> SerialOptions {
        SerialOptions {
            access: Access::ReadWrite,
            ..quick()
        }
    }

    impl Pty {
        async fn receive(&mut self, len: usize) -> Vec<u8> {
            let mut got = Vec::new();
            within(async {
                while got.len() < len {
                    let mut buf = [0; 256];
                    match self.master.read(&mut buf) {
                        Ok(n) => got.extend(&buf[..n]),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            sleep(Duration::from_millis(5)).await;
                        }
                        Err(e) => panic!("{e}"),
                    }
                }
            })
            .await;
            got
        }

        /// Opened before the task's exclusive open, which doesn't evict it.
        fn slave_handle(&self) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.slave)
                .expect("open the slave")
        }
    }

    fn spawn_write(
        writer: &SerialWriter,
        bytes: Vec<u8>,
    ) -> tokio::task::JoinHandle<Result<std::io::Result<()>, WriteRefused>> {
        let writer = writer.clone();
        tokio::spawn(async move { writer.write(bytes).await })
    }

    #[tokio::test]
    async fn a_write_reaches_the_other_end() {
        let mut pty = Pty::new();
        let mut task = open(path(&pty.slave), LINE, read_write()).expect("open");
        connected(&mut task).await;

        let written = spawn_write(&task.writer(), b"\x01\x06\x00\x01".to_vec());
        assert_eq!(pty.receive(4).await, b"\x01\x06\x00\x01");
        let written = within(written).await.expect("join");
        assert!(matches!(written, Ok(Ok(()))), "{written:?}");

        pty.send(b"back");
        assert_eq!(read_exactly(&mut task, 4).await, b"back");

        let started = Instant::now();
        within(task.stop()).await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(pty.slave_closed());
    }

    #[tokio::test]
    async fn a_read_write_open_is_exclusive_unless_turned_off() {
        let pty = Pty::new();
        let mut first = open(path(&pty.slave), LINE, read_write()).expect("open");
        connected(&mut first).await;
        match open(path(&pty.slave), LINE, read_write()) {
            Err(SerialError::Open { .. }) => {}
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a second open got past the exclusive open"),
        }
        within(first.stop()).await;

        let shared = SerialOptions {
            exclusive: false,
            ..read_write()
        };
        let first = open(path(&pty.slave), LINE, shared.clone()).expect("open");
        let second = open(path(&pty.slave), LINE, shared).expect("second open");
        within(first.stop()).await;
        within(second.stop()).await;
    }

    #[tokio::test]
    async fn a_write_while_the_line_is_down_is_refused_at_once() {
        let pty = Pty::new();
        let options = SerialOptions {
            reopen: Some(Duration::from_secs(60)),
            ..read_write()
        };
        let mut task = open(path(&pty.slave), LINE, options).expect("open");
        connected(&mut task).await;

        drop(pty);
        let event = next(&mut task).await;
        assert!(
            matches!(event, SerialEvent::Disconnected { .. }),
            "{event:?}"
        );
        let refused = within(task.writer().write(b"x".to_vec())).await;
        assert!(
            matches!(refused, Err(WriteRefused::Disconnected)),
            "{refused:?}"
        );
        within(task.stop()).await;
    }

    #[tokio::test]
    async fn a_write_is_served_while_the_event_queue_is_full() {
        let mut pty = Pty::new();
        let options = SerialOptions {
            events: 1,
            ..read_write()
        };
        let mut task = open(path(&pty.slave), LINE, options).expect("open");

        // `Connected` fills the queue, so the task is left waiting to emit this.
        pty.send(b"in");
        sleep(Duration::from_millis(100)).await;
        let written = spawn_write(&task.writer(), b"out".to_vec());
        assert_eq!(pty.receive(3).await, b"out");
        let written = within(written).await.expect("join");
        assert!(matches!(written, Ok(Ok(()))), "{written:?}");

        connected(&mut task).await;
        assert_eq!(read_exactly(&mut task, 2).await, b"in");
        within(task.stop()).await;
    }

    #[tokio::test]
    async fn a_failed_write_leaves_the_line_up() {
        let mut pty = Pty::new();
        let slave = pty.slave_handle();
        let mut task = open(path(&pty.slave), LINE, read_write()).expect("open");
        connected(&mut task).await;
        let writer = task.writer();

        // Output suspended: the write times out waiting for room.
        tcflow(&slave, FlowArg::TCOOFF).expect("tcflow");
        let failed = within(writer.write(b"lost".to_vec())).await;
        match failed {
            Ok(Err(e)) => assert_eq!(e.kind(), ErrorKind::TimedOut, "{e}"),
            other => panic!("{other:?}"),
        }
        tcflow(&slave, FlowArg::TCOON).expect("tcflow");

        pty.send(b"still up");
        assert_eq!(read_exactly(&mut task, 8).await, b"still up");
        let written = spawn_write(&writer, b"again".to_vec());
        assert_eq!(pty.receive(5).await, b"again");
        assert!(matches!(within(written).await, Ok(Ok(Ok(())))));
        within(task.stop()).await;
    }

    #[tokio::test]
    async fn stop_answers_the_queued_writes_stopped() {
        let pty = Pty::new();
        let slave = pty.slave_handle();
        let options = SerialOptions {
            writes: 2,
            ..read_write()
        };
        let mut task = open(path(&pty.slave), LINE, options).expect("open");
        connected(&mut task).await;
        let writer = task.writer();

        // Output suspended: the first write holds the task for a write timeout
        // while the rest queue.
        tcflow(&slave, FlowArg::TCOOFF).expect("tcflow");
        let first = spawn_write(&writer, b"held".to_vec());
        sleep(Duration::from_millis(10)).await;
        let queued = [
            spawn_write(&writer, b"a".to_vec()),
            spawn_write(&writer, b"b".to_vec()),
        ];
        within(async {
            while writer.queued() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let refused = within(writer.write(b"c".to_vec())).await;
        assert!(
            matches!(refused, Err(WriteRefused::QueueFull)),
            "{refused:?}"
        );

        within(task.stop()).await;
        let held = within(first).await.expect("join");
        assert!(matches!(held, Ok(Err(_))), "{held:?}");
        for write in queued {
            let answer = within(write).await.expect("join");
            assert!(matches!(answer, Err(WriteRefused::Stopped)), "{answer:?}");
        }
        let after = within(writer.write(b"d".to_vec())).await;
        assert!(matches!(after, Err(WriteRefused::Stopped)), "{after:?}");
    }
}
