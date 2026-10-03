#![cfg(feature = "modbus-task")]

mod support;

use std::time::{Duration, Instant};

use support::{within, Action, FakeServer};
use tokio::time::{sleep, timeout};
use wiretap_catalog::modbus::{FrameBackoff, PollItem, RegisterType};
use wiretap_io::modbus::{
    spawn, ItemId, ModbusTcp, PollEvent, PollTask, Poller, TaskEvent, TaskOptions, TcpOptions,
    TransportError, UnitSource,
};

fn quick() -> TcpOptions {
    TcpOptions {
        connect_timeout: Duration::from_millis(500),
        op_timeout: Duration::from_millis(200),
        ..TcpOptions::default()
    }
}

fn millis(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn options() -> TaskOptions {
    TaskOptions {
        reconnect_initial: millis(20),
        reconnect_max: millis(80),
        ..TaskOptions::default()
    }
}

fn item(start: u16, interval: Duration) -> PollItem<u16> {
    PollItem {
        register_type: RegisterType::Holding,
        start,
        count: 1,
        interval,
        device_address: 1,
        tag: start,
    }
}

fn poller(items: impl IntoIterator<Item = PollItem<u16>>) -> Poller<u16> {
    let now = Instant::now();
    Poller::new(items, UnitSource::Connection, FrameBackoff::default(), now)
}

fn start(server: &FakeServer, items: impl IntoIterator<Item = PollItem<u16>>) -> PollTask<u16> {
    start_with(server, items, options())
}

fn start_with(
    server: &FakeServer,
    items: impl IntoIterator<Item = PollItem<u16>>,
    options: TaskOptions,
) -> PollTask<u16> {
    spawn(
        ModbusTcp::new(server.endpoint(), quick()),
        poller(items),
        options,
    )
}

async fn next(task: &mut PollTask<u16>) -> TaskEvent<u16> {
    task.next_event().await.expect("the task is running")
}

/// The item and kind (`R`, `E` or `T`) of each event in a batch.
fn batch(event: TaskEvent<u16>) -> Vec<(usize, char)> {
    let TaskEvent::Batch(events) = event else {
        panic!("expected a batch, got {event:?}");
    };
    events
        .iter()
        .map(|event| match event {
            PollEvent::Read { item, .. } => (item.0, 'R'),
            PollEvent::Exception { item, .. } => (item.0, 'E'),
            PollEvent::Transport { item, .. } => (item.0, 'T'),
        })
        .collect()
}

fn disconnected(event: TaskEvent<u16>) -> (u32, Duration) {
    match event {
        TaskEvent::Disconnected {
            consecutive,
            retry_in,
            ..
        } => (consecutive, retry_in),
        other => panic!("expected a disconnect, got {other:?}"),
    }
}

async fn quiet_for(task: &mut PollTask<u16>, period: Duration) {
    if let Ok(event) = timeout(period, task.next_event()).await {
        panic!("expected nothing, got {event:?}");
    }
}

async fn until_closed(server: &FakeServer) {
    while server.open_connections() > 0 {
        sleep(millis(5)).await;
    }
}

#[tokio::test]
async fn it_connects_then_reports_each_step_as_one_batch() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, [item(1, millis(30)), item(2, millis(30))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await), [(0, 'R'), (1, 'R')]);
        assert_eq!(batch(next(&mut task).await), [(0, 'R'), (1, 'R')]);
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn a_connection_made_before_spawn_is_kept_and_reported() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        tcp.connect().await.unwrap();
        let mut task = spawn(tcp, poller([item(1, millis(30))]), options());
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await), [(0, 'R')]);
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn a_lost_steps_batch_comes_before_its_disconnect_and_then_everything_is_read() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Reply, Action::Close]);
        let mut task = start(
            &server,
            [item(1, millis(20)), item(2, Duration::from_secs(60))],
        );
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await), [(0, 'R'), (1, 'R')]);
        assert_eq!(batch(next(&mut task).await), [(0, 'T')]);
        let TaskEvent::Disconnected {
            error,
            consecutive: 1,
            retry_in,
        } = next(&mut task).await
        else {
            panic!("expected the first disconnect");
        };
        assert!(matches!(error, TransportError::Closed));
        assert_eq!(retry_in, millis(20));
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await), [(0, 'R'), (1, 'R')]);
    })
    .await
}

#[tokio::test]
async fn failed_connects_after_a_loss_count_on_from_it_and_back_off() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Close]);
        let mut task = start(&server, [item(1, millis(20))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        server.close().await;
        assert_eq!(batch(next(&mut task).await), [(0, 'T')]);

        let mut waits = Vec::new();
        let mut last: Option<(Instant, Duration)> = None;
        let waited_out = |last: Option<(Instant, Duration)>| {
            last.is_none_or(|(at, wait)| at.elapsed() + millis(2) >= wait)
        };
        for _ in 0..4 {
            let (consecutive, retry_in) = disconnected(next(&mut task).await);
            assert!(waited_out(last));
            last = Some((Instant::now(), retry_in));
            waits.push((consecutive, retry_in.as_millis()));
        }
        assert_eq!(waits, [(1, 20), (2, 40), (3, 80), (4, 80)]);
        server.reopen().await;
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert!(waited_out(last));
    })
    .await
}

#[tokio::test]
async fn a_connect_resets_the_count() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Close, Action::Close]);
        let mut task = start(&server, [item(1, millis(20))]);
        for _ in 0..2 {
            assert!(matches!(next(&mut task).await, TaskEvent::Connected));
            assert_eq!(batch(next(&mut task).await), [(0, 'T')]);
            assert_eq!(disconnected(next(&mut task).await), (1, millis(20)));
        }
    })
    .await
}

#[tokio::test]
async fn a_task_that_cannot_connect_backs_off_without_reading() {
    within(async {
        let server = FakeServer::start().await;
        server.close().await;
        let mut task = start(&server, [item(1, millis(20))]);
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(disconnected(next(&mut task).await));
        }
        assert_eq!(got, [(1, millis(20)), (2, millis(40)), (3, millis(80))]);
        assert!(server.seen().is_empty());
    })
    .await
}

#[tokio::test]
async fn with_a_connection_per_request_the_link_stays_up() {
    within(async {
        let server = FakeServer::start().await;
        let tcp = TcpOptions {
            reconnect_per_request: true,
            ..quick()
        };
        let conn = ModbusTcp::new(server.endpoint(), tcp);
        let mut task = spawn(conn, poller([item(1, millis(20))]), options());
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        for _ in 0..3 {
            assert_eq!(batch(next(&mut task).await), [(0, 'R')]);
        }
        assert!(server.connections() >= 3);
    })
    .await
}

#[tokio::test]
async fn pause_stops_reads_and_resume_reads_what_fell_due_once() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, [item(1, millis(20)), item(2, millis(20))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await).len(), 2);

        task.pause();
        quiet_for(&mut task, millis(120)).await;
        let paused = server.seen().len();
        assert_eq!(paused, 2);

        task.resume();
        assert_eq!(batch(next(&mut task).await), [(0, 'R'), (1, 'R')]);
        assert_eq!(server.seen().len(), paused + 2);
    })
    .await
}

#[tokio::test]
async fn retiring_the_last_item_ends_the_task_with_all_retired() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, [item(1, millis(20)), item(2, millis(20))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        assert_eq!(batch(next(&mut task).await).len(), 2);

        task.retire(ItemId(0));
        assert_eq!(batch(next(&mut task).await), [(1, 'R')]);
        task.retire(ItemId(1));
        assert!(matches!(next(&mut task).await, TaskEvent::AllRetired));
        assert!(task.next_event().await.is_none());
        until_closed(&server).await;
    })
    .await
}

#[tokio::test]
async fn a_poller_with_no_items_connects_and_idles() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, []);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        quiet_for(&mut task, millis(100)).await;
        assert!(server.seen().is_empty());
    })
    .await
}

#[tokio::test]
async fn a_full_event_queue_holds_the_task_back() {
    within(async {
        let server = FakeServer::start().await;
        let options = TaskOptions {
            events: 1,
            ..options()
        };
        let mut task = start_with(&server, [item(1, millis(5))], options);
        sleep(millis(100)).await;
        assert!(server.seen().len() <= 1);

        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        for _ in 0..5 {
            assert_eq!(batch(next(&mut task).await), [(0, 'R')]);
        }
    })
    .await
}

#[tokio::test]
async fn stop_returns_once_the_socket_is_closed() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, [item(1, millis(20))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        task.stop().await;
        until_closed(&server).await;
    })
    .await
}

#[tokio::test]
async fn stop_is_heard_while_the_event_queue_is_full() {
    within(async {
        let server = FakeServer::start().await;
        let options = TaskOptions {
            events: 1,
            ..options()
        };
        let task = start_with(&server, [item(1, millis(5))], options);
        sleep(millis(50)).await;
        task.stop().await;
        until_closed(&server).await;
    })
    .await
}

#[tokio::test]
async fn dropping_the_task_closes_its_connection() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, [item(1, millis(20))]);
        assert!(matches!(next(&mut task).await, TaskEvent::Connected));
        drop(task);
        until_closed(&server).await;
    })
    .await
}
