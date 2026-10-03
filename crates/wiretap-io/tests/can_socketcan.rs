//! Against a `vcan` interface, which only root can create, so these are
//! ignored unless asked for, as CI does after setting one up:
//!
//! ```sh
//! sudo modprobe vcan
//! sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0
//! cargo test -p wiretap-io --test can_socketcan -- --ignored --test-threads=1
//! ```
//!
//! vcan is multicast: in parallel, one test's frames would reach another's
//! reader. `WIRETAP_VCAN` names another interface than `vcan0`. The tests that
//! add, down or delete an interface make their own, with `ip`, or `sudo -n ip`
//! when not root. The other end of the bus is a plain socketcan socket.

#![cfg(all(feature = "can-socketcan", target_os = "linux"))]

mod support;

use std::{
    io,
    process::Command,
    time::{Duration, SystemTime},
};

use ::socketcan::{
    CanAnyFrame, CanDataFrame, CanFdFrame, CanFdSocket, CanRemoteFrame, EmbeddedFrame, ExtendedId,
    Frame, Socket, StandardId,
};
use support::within;
use wiretap_io::can::{
    socketcan::{self, Bitrates, SocketCanOptions},
    CanError, CanEvent, CanFrame, CanOptions, CanRead, CanTask, Direction, SendRefused,
    Unsupported,
};

const PATIENCE: Duration = Duration::from_secs(10);

fn vcan() -> String {
    std::env::var("WIRETAP_VCAN").unwrap_or_else(|_| "vcan0".to_owned())
}

fn sc(interface: &str, fd: bool) -> SocketCanOptions {
    SocketCanOptions {
        interface: interface.to_owned(),
        fd,
    }
}

fn can_options(own_frames: bool, reopen: Option<Duration>) -> CanOptions {
    let mut options = CanOptions::default();
    options.own_frames = own_frames;
    options.reopen = reopen;
    options
}

async fn open(interface: &str, fd: bool, options: CanOptions) -> CanTask {
    let mut task = socketcan::open(sc(interface, fd), options)
        .await
        .expect("the interface: see this file's header");
    assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
    task
}

async fn next(task: &mut CanTask) -> CanEvent {
    tokio::time::timeout(PATIENCE, task.next_event())
        .await
        .expect("an event in time")
        .expect("the task running")
}

async fn reads(task: &mut CanTask, count: usize) -> Vec<CanRead> {
    let mut reads = Vec::new();
    while reads.len() < count {
        match next(task).await {
            CanEvent::Read(batch) => reads.extend(batch),
            other => panic!("{other:?}"),
        }
    }
    reads
}

fn peer(interface: &str) -> CanFdSocket {
    let socket = CanFdSocket::open(interface).expect("the interface");
    socket.set_read_timeout(PATIENCE).unwrap();
    socket
}

fn standard(id: u16) -> StandardId {
    StandardId::new(id).unwrap()
}

fn classic(id: u16, data: &[u8]) -> CanDataFrame {
    CanDataFrame::new(standard(id), data).unwrap()
}

/// `ip` as root, else through `sudo -n`.
fn try_ip(args: &[&str]) -> bool {
    let ran = |command: &mut Command| command.status().is_ok_and(|s| s.success());
    ran(Command::new("ip").args(args)) || ran(Command::new("sudo").arg("-n").arg("ip").args(args))
}

fn ip(args: &[&str]) {
    assert!(
        try_ip(args),
        "ip {args:?} failed: this test needs vcan, and root or passwordless sudo"
    );
}

/// A vcan interface of the test's own, deleted when dropped.
struct Scratch(&'static str);

impl Scratch {
    fn new() -> Self {
        let scratch = Self("wiretap-e5");
        try_ip(&["link", "del", scratch.0]);
        scratch.add();
        scratch
    }

    fn add(&self) {
        ip(&["link", "add", "dev", self.0, "type", "vcan"]);
        ip(&["link", "set", "up", self.0]);
    }

    fn index(&self) -> String {
        std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.0)).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        try_ip(&["link", "del", self.0]);
    }
}

fn assert_kernel_stamped(read: &CanRead, before: SystemTime) {
    assert!(read.at >= before - Duration::from_millis(1) && read.at <= SystemTime::now());
    assert_eq!(read.device_us, None);
}

#[tokio::test]
async fn a_missing_interface_is_the_callers_open_error() {
    let error = within(socketcan::open(
        sc("wiretap-none", false),
        can_options(false, None),
    ))
    .await
    .err()
    .expect("the open should fail");
    assert!(
        matches!(&error, CanError::Open { device, .. } if device == "wiretap-none"),
        "{error:?}"
    );
}

#[test]
fn a_missing_interface_has_no_bitrates_and_one_that_isnt_can_reports_none() {
    assert!(socketcan::bitrates("wiretap-none").is_err());
    let none = Bitrates {
        nominal: None,
        data: None,
    };
    assert_eq!(socketcan::bitrates("lo").unwrap(), none);
}

#[test]
#[ignore = "needs vcan: see this file's header"]
fn a_vcan_interface_reports_no_bitrates() {
    assert_eq!(
        socketcan::bitrates(&vcan()).unwrap(),
        Bitrates {
            nominal: None,
            data: None
        }
    );
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn frames_on_the_bus_are_read_with_the_kernels_stamp_and_rtr_flagged() {
    let mut task = open(&vcan(), false, can_options(false, None)).await;
    let peer = peer(&vcan());
    let before = SystemTime::now();
    peer.write_frame(&classic(0x123, &[1, 2, 3])).unwrap();
    let extended = ExtendedId::new(0x18DA_F110).unwrap();
    peer.write_frame(&CanDataFrame::new(extended, &[0xAA; 8]).unwrap())
        .unwrap();
    peer.write_frame(&CanRemoteFrame::new_remote(standard(0x456), 4).unwrap())
        .unwrap();

    let reads = reads(&mut task, 3).await;
    let frames: Vec<CanFrame> = reads.iter().map(|r| r.frame.clone()).collect();
    assert_eq!(
        frames,
        [
            CanFrame::data(0, 0x123, false, false, false, vec![1, 2, 3]),
            CanFrame::data(0, 0x18DA_F110, true, false, false, vec![0xAA; 8]),
            CanFrame::remote(0, 0x456, false, 4),
        ]
    );
    for read in &reads {
        assert_eq!(read.direction, Direction::Rx);
        assert_kernel_stamped(read, before);
    }
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn frames_ready_together_come_in_one_read() {
    let mut options = can_options(false, None);
    options.events = 1;
    let mut task = socketcan::open(sc(&vcan(), false), options).await.unwrap();
    let peer = peer(&vcan());
    for id in 0..20 {
        peer.write_frame(&classic(id, &[id as u8])).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));

    let mut sizes = Vec::new();
    let mut ids = Vec::new();
    while ids.len() < 20 {
        let CanEvent::Read(batch) = next(&mut task).await else {
            panic!("a read");
        };
        sizes.push(batch.len());
        ids.extend(batch.iter().map(|r| r.frame.arb_id));
    }
    assert_eq!(ids, (0..20).collect::<Vec<u32>>());
    assert!(sizes.iter().any(|&n| n > 1), "{sizes:?}");
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn fd_frames_are_dropped_unless_fd_and_kept_with_their_flags_when_it_is() {
    let mut classic_task = open(&vcan(), false, can_options(false, None)).await;
    let mut fd_task = open(&vcan(), true, can_options(false, None)).await;
    let peer = peer(&vcan());
    let mut fd = CanFdFrame::new(standard(0x10), &[5; 12]).unwrap();
    fd.set_brs(true);
    peer.write_frame(&fd).unwrap();
    peer.write_frame(&classic(0x11, &[])).unwrap();

    let ids: Vec<u32> = reads(&mut classic_task, 1)
        .await
        .iter()
        .map(|r| r.frame.arb_id)
        .collect();
    assert_eq!(ids, [0x11]);
    let reads = reads(&mut fd_task, 2).await;
    assert_eq!(
        reads[0].frame,
        CanFrame::data(0, 0x10, false, true, true, vec![5; 12])
    );
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn a_send_reaches_the_bus_as_asked_with_fd_padded_to_a_length_code() {
    let task = open(&vcan(), true, can_options(false, None)).await;
    let writer = task.writer();
    let peer = peer(&vcan());

    writer
        .send(CanFrame::data(0, 0x20, false, true, true, vec![7; 13]))
        .await
        .unwrap()
        .unwrap();
    let CanAnyFrame::Fd(fd) = peer.read_frame().unwrap() else {
        panic!("an FD frame");
    };
    assert_eq!(fd.raw_id(), 0x20);
    assert_eq!(fd.data(), [&[7; 13][..], &[0; 3]].concat());
    assert!(fd.is_brs());

    writer
        .send(CanFrame::data(
            0,
            0x1ABC_DEF0,
            true,
            false,
            false,
            vec![1, 2],
        ))
        .await
        .unwrap()
        .unwrap();
    let CanAnyFrame::Normal(data) = peer.read_frame().unwrap() else {
        panic!("a classic frame");
    };
    assert!(data.is_extended());
    assert_eq!((data.raw_id(), data.data()), (0x1ABC_DEF0, &[1, 2][..]));

    writer
        .send(CanFrame::remote(0, 0x21, false, 5))
        .await
        .unwrap()
        .unwrap();
    let CanAnyFrame::Remote(remote) = peer.read_frame().unwrap() else {
        panic!("a remote frame");
    };
    assert_eq!((remote.raw_id(), remote.dlc()), (0x21, 5));
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn an_fd_send_on_a_classic_socket_is_refused() {
    let task = open(&vcan(), false, can_options(false, None)).await;
    let refused = task
        .writer()
        .send(CanFrame::data(0, 0x20, false, true, false, vec![0; 12]))
        .await
        .unwrap_err();
    assert_eq!(refused, SendRefused::Unsupported(Unsupported::Length(12)));
    let refused = task
        .writer()
        .send(CanFrame::data(0, 0x20, false, true, false, vec![0; 8]))
        .await
        .unwrap_err();
    assert_eq!(refused, SendRefused::Unsupported(Unsupported::Fd));
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn own_frames_come_back_as_tx_and_another_sockets_as_rx() {
    let mut own = open(&vcan(), false, can_options(true, None)).await;
    let other = open(&vcan(), false, can_options(true, None)).await;
    let before = SystemTime::now();
    let sent = CanFrame::data(0, 0x30, false, false, false, vec![3]);
    own.writer().send(sent.clone()).await.unwrap().unwrap();
    let theirs = CanFrame::data(0, 0x31, false, false, false, vec![4]);
    other.writer().send(theirs.clone()).await.unwrap().unwrap();

    let mut reads = reads(&mut own, 2).await;
    reads.sort_by_key(|r| r.frame.arb_id);
    assert_eq!(
        (&reads[0].frame, reads[0].direction),
        (&sent, Direction::Tx)
    );
    assert_eq!(
        (&reads[1].frame, reads[1].direction),
        (&theirs, Direction::Rx)
    );
    for read in &reads {
        assert_kernel_stamped(read, before);
    }
}

#[tokio::test]
#[ignore = "needs vcan: see this file's header"]
async fn without_own_frames_a_send_is_not_read_back() {
    let mut task = open(&vcan(), false, can_options(false, None)).await;
    let sent = CanFrame::data(0, 0x40, false, false, false, vec![]);
    task.writer().send(sent).await.unwrap().unwrap();
    peer(&vcan()).write_frame(&classic(0x41, &[])).unwrap();
    let ids: Vec<u32> = reads(&mut task, 1)
        .await
        .iter()
        .map(|r| r.frame.arb_id)
        .collect();
    assert_eq!(ids, [0x41]);
}

#[tokio::test]
#[ignore = "needs vcan and root or passwordless sudo: see this file's header"]
async fn a_deleted_interface_is_closed_and_reopened_by_name_under_its_new_index() {
    let scratch = Scratch::new();
    let index = scratch.index();
    let mut task = open(
        scratch.0,
        false,
        can_options(false, Some(Duration::from_millis(100))),
    )
    .await;

    ip(&["link", "del", scratch.0]);
    let CanEvent::Disconnected {
        error, consecutive, ..
    } = next(&mut task).await
    else {
        panic!("a loss");
    };
    assert!(matches!(error, CanError::Closed), "{error:?}");
    assert_eq!(consecutive, 1);

    scratch.add();
    assert_ne!(scratch.index(), index);
    loop {
        match next(&mut task).await {
            CanEvent::Connected(_) => break,
            CanEvent::Disconnected { error, .. } => {
                assert!(matches!(error, CanError::Open { .. }), "{error:?}")
            }
            other => panic!("only reopens while it is gone: {other:?}"),
        }
    }
    peer(scratch.0).write_frame(&classic(0x50, &[])).unwrap();
    assert_eq!(reads(&mut task, 1).await[0].frame.arb_id, 0x50);
}

#[tokio::test]
#[ignore = "needs vcan and root or passwordless sudo: see this file's header"]
async fn a_downed_interface_is_a_read_error_and_reads_resume_once_it_is_up() {
    let scratch = Scratch::new();
    let mut task = open(
        scratch.0,
        false,
        can_options(false, Some(Duration::from_millis(100))),
    )
    .await;

    ip(&["link", "set", "down", scratch.0]);
    let CanEvent::Disconnected {
        error, consecutive, ..
    } = next(&mut task).await
    else {
        panic!("a loss");
    };
    assert!(
        matches!(&error, CanError::Read(e) if e.kind() == io::ErrorKind::NetworkDown),
        "{error:?}"
    );
    assert_eq!(consecutive, 1);
    assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));

    ip(&["link", "set", "up", scratch.0]);
    peer(scratch.0).write_frame(&classic(0x60, &[])).unwrap();
    assert_eq!(reads(&mut task, 1).await[0].frame.arb_id, 0x60);
}

#[tokio::test]
#[ignore = "needs vcan and root or passwordless sudo: see this file's header"]
async fn without_reopen_a_downed_interface_ends_the_task() {
    let scratch = Scratch::new();
    let mut task = open(scratch.0, false, can_options(false, None)).await;
    ip(&["link", "set", "down", scratch.0]);
    let CanEvent::Disconnected {
        error, retry_in, ..
    } = next(&mut task).await
    else {
        panic!("a loss");
    };
    assert!(matches!(error, CanError::Read(_)), "{error:?}");
    assert_eq!(retry_in, None);
    assert!(task.next_event().await.is_none());
}
