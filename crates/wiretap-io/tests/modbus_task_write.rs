#![cfg(all(feature = "modbus-task", feature = "modbus-write"))]

mod support;

use std::time::{Duration, Instant};

use support::{silent_addr, within, Action, FakeServer};
use tokio::time::{sleep, timeout};
use wiretap_catalog::modbus::{FrameBackoff, ModbusWrite, PollItem, RegisterType};
use wiretap_io::modbus::{
    spawn, ModbusTcp, PollTask, PollWriter, Poller, RequestError, TaskEvent, TaskOptions,
    TcpOptions, UnitSource, WriteOutcome, WriteRefused,
};

fn quick() -> TcpOptions {
    TcpOptions {
        connect_timeout: Duration::from_millis(300),
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

fn items(count: u16, interval: Duration) -> Vec<PollItem<()>> {
    (0..count)
        .map(|start| PollItem {
            register_type: RegisterType::Holding,
            start,
            count: 1,
            interval,
            device_address: 1,
            tag: (),
        })
        .collect()
}

fn start_on(endpoint: String, items: Vec<PollItem<()>>, options: TaskOptions) -> PollTask<()> {
    let poller = Poller::new(
        items,
        UnitSource::Connection,
        FrameBackoff::default(),
        Instant::now(),
    );
    spawn(ModbusTcp::new(endpoint, quick()), poller, options)
}

fn start(server: &FakeServer, items: Vec<PollItem<()>>) -> PollTask<()> {
    start_on(server.endpoint(), items, options())
}

async fn next(task: &mut PollTask<()>) -> TaskEvent<()> {
    task.next_event().await.expect("the task is running")
}

async fn connected(task: &mut PollTask<()>) {
    assert!(matches!(next(task).await, TaskEvent::Connected));
}

fn functions(server: &FakeServer) -> Vec<u8> {
    server.seen().iter().map(|s| s.function).collect()
}

async fn write_one(writer: &PollWriter, address: u16, value: u16) -> Result<(), WriteRefused> {
    let acknowledged = writer.write_registers(None, address, vec![value]).await?;
    acknowledged.expect("the device acknowledged");
    Ok(())
}

fn full(address: u16, value: u16) -> ModbusWrite {
    ModbusWrite::holding(address, value, 0xFFFF)
}

#[tokio::test]
async fn a_write_runs_on_the_tasks_connection_after_the_current_step() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Delay(millis(100))]);
        let mut task = start(&server, items(3, Duration::from_secs(60)));
        let writer = task.writer();
        connected(&mut task).await;
        sleep(millis(30)).await;

        write_one(&writer, 500, 7).await.unwrap();
        writer
            .write_coils(None, 9, vec![true])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(functions(&server), [0x03, 0x03, 0x03, 0x06, 0x05]);
        assert_eq!(server.holding(500), 7);
        assert!(server.coil(9));
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn a_write_queued_before_the_first_connect_runs_once_connected() {
    within(async {
        let server = FakeServer::start().await;
        let task = start(&server, items(1, Duration::from_secs(60)));
        write_one(&task.writer(), 500, 7).await.unwrap();
        assert_eq!(functions(&server)[0], 0x06);
    })
    .await
}

#[tokio::test]
async fn a_write_during_a_failing_connect_waits_for_it_then_is_refused() {
    within(async {
        let (_guard, silent) = silent_addr().await;
        let options = TaskOptions {
            reconnect_initial: Duration::from_secs(2),
            ..options()
        };
        let task = start_on(silent.to_string(), items(1, millis(20)), options);
        let began = Instant::now();
        let refused = write_one(&task.writer(), 500, 7).await;
        assert_eq!(refused, Err(WriteRefused::Disconnected));
        assert!(began.elapsed() >= millis(250));
    })
    .await
}

#[tokio::test]
async fn a_write_while_the_link_is_down_is_refused_at_once() {
    within(async {
        let server = FakeServer::start().await;
        server.close().await;
        let options = TaskOptions {
            reconnect_initial: Duration::from_secs(2),
            ..options()
        };
        let mut task = start_on(server.endpoint(), items(1, millis(20)), options);
        assert!(matches!(
            next(&mut task).await,
            TaskEvent::Disconnected { .. }
        ));
        let writer = task.writer();
        let began = Instant::now();
        assert_eq!(
            write_one(&writer, 500, 7).await,
            Err(WriteRefused::Disconnected)
        );
        let verified = writer.write_verified(None, vec![full(500, 7)]).await;
        assert_eq!(verified, Err(WriteRefused::Disconnected));
        let coils = writer.write_coils(None, 9, vec![true]).await;
        assert!(matches!(coils, Err(WriteRefused::Disconnected)));
        assert!(began.elapsed() < millis(100));
    })
    .await
}

#[tokio::test]
async fn writes_queued_when_the_link_drops_are_refused_and_never_run() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Stall]);
        let mut task = start(&server, items(1, Duration::from_secs(60)));
        let writer = task.writer();
        connected(&mut task).await;
        sleep(millis(30)).await;

        assert_eq!(
            write_one(&writer, 500, 7).await,
            Err(WriteRefused::Disconnected)
        );
        assert!(matches!(next(&mut task).await, TaskEvent::Batch(_)));
        assert!(matches!(
            next(&mut task).await,
            TaskEvent::Disconnected { .. }
        ));
        connected(&mut task).await;
        assert!(matches!(next(&mut task).await, TaskEvent::Batch(_)));
        assert!(!functions(&server).contains(&0x06));
    })
    .await
}

#[tokio::test]
async fn a_full_write_queue_refuses_at_once() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Delay(millis(120))]);
        let options = TaskOptions {
            writes: 1,
            ..options()
        };
        let mut task = start_on(
            server.endpoint(),
            items(1, Duration::from_secs(60)),
            options,
        );
        let writer = task.writer();
        connected(&mut task).await;
        sleep(millis(20)).await;

        let queued = tokio::spawn({
            let writer = writer.clone();
            async move { write_one(&writer, 500, 7).await }
        });
        sleep(millis(20)).await;
        assert_eq!(writer.queued(), 1);
        assert_eq!(
            write_one(&writer, 501, 8).await,
            Err(WriteRefused::QueueFull)
        );
        assert_eq!(queued.await.unwrap(), Ok(()));
        assert_eq!(writer.queued(), 0);
    })
    .await
}

#[tokio::test]
async fn writes_are_stopped_once_the_task_is_dropped() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Delay(millis(120))]);
        let mut task = start(&server, items(1, Duration::from_secs(60)));
        let writer = task.writer();
        connected(&mut task).await;
        sleep(millis(20)).await;

        let queued = tokio::spawn({
            let writer = writer.clone();
            async move { write_one(&writer, 500, 7).await }
        });
        sleep(millis(20)).await;
        drop(task);
        assert_eq!(queued.await.unwrap(), Err(WriteRefused::Stopped));
        assert_eq!(write_one(&writer, 500, 7).await, Err(WriteRefused::Stopped));
    })
    .await
}

#[tokio::test]
async fn a_write_that_loses_the_link_takes_it_down() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, Vec::new());
        let writer = task.writer();
        connected(&mut task).await;

        server.script([Action::Close]);
        let lost = writer.write_registers(None, 500, vec![7]).await.unwrap();
        let Err(RequestError::Transport(lost)) = lost else {
            panic!("expected a transport error, got {lost:?}");
        };
        assert_eq!(lost.to_string(), "connection closed by the device");
        let TaskEvent::Disconnected {
            error,
            consecutive: 1,
            ..
        } = next(&mut task).await
        else {
            panic!("expected the first disconnect");
        };
        assert_eq!(error.to_string(), lost.to_string());
        connected(&mut task).await;

        server.script([Action::Close]);
        let report = writer
            .write_verified(None, vec![full(500, 7)])
            .await
            .unwrap();
        assert!(report.transport_lost);
        assert!(matches!(
            next(&mut task).await,
            TaskEvent::Disconnected { consecutive: 1, .. }
        ));
        connected(&mut task).await;
    })
    .await
}

#[tokio::test]
async fn a_dropped_write_still_runs() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Delay(millis(100))]);
        let mut task = start(&server, items(1, Duration::from_secs(60)));
        let writer = task.writer();
        connected(&mut task).await;
        sleep(millis(20)).await;

        let abandoned = timeout(millis(10), write_one(&writer, 600, 9)).await;
        assert!(abandoned.is_err());
        while server.holding(600) != 9 {
            sleep(millis(5)).await;
        }
    })
    .await
}

#[tokio::test]
async fn a_write_is_served_while_the_event_queue_is_full() {
    within(async {
        let server = FakeServer::start().await;
        let options = TaskOptions {
            events: 1,
            ..options()
        };
        let task = start_on(server.endpoint(), items(1, millis(5)), options);
        sleep(millis(50)).await;
        write_one(&task.writer(), 500, 7).await.unwrap();
        assert_eq!(server.holding(500), 7);
    })
    .await
}

#[tokio::test]
async fn a_poller_with_no_items_serves_writes() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, Vec::new());
        connected(&mut task).await;
        write_one(&task.writer(), 500, 7).await.unwrap();
        assert_eq!(functions(&server), [0x06]);
    })
    .await
}

#[tokio::test]
async fn stop_finishes_the_batch_in_flight_and_refuses_the_queued_ones() {
    within(async {
        let server = FakeServer::start().await;
        let mut task = start(&server, Vec::new());
        let writer = task.writer();
        connected(&mut task).await;

        server.script([Action::Delay(millis(100))]);
        let in_flight = tokio::spawn({
            let writer = writer.clone();
            async move { writer.write_verified(None, vec![full(500, 7)]).await }
        });
        sleep(millis(20)).await;
        let queued = tokio::spawn({
            let writer = writer.clone();
            async move { write_one(&writer, 501, 8).await }
        });
        sleep(millis(10)).await;
        task.stop().await;

        let report = in_flight.await.unwrap().unwrap();
        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert_eq!(functions(&server), [0x06, 0x03]);
        assert_eq!(queued.await.unwrap(), Err(WriteRefused::Stopped));
        assert_eq!(write_one(&writer, 501, 8).await, Err(WriteRefused::Stopped));
    })
    .await
}
