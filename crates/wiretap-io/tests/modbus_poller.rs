#![cfg(feature = "modbus-tcp")]

mod support;

use std::time::{Duration, Instant, SystemTime};

use support::{within, Action, FakeServer};
use wiretap_catalog::modbus::{FrameBackoff, ModbusManifest, PollItem, RegisterType};
use wiretap_io::modbus::{
    Banks, ExceptionCode, ItemId, ModbusTcp, PollEvent, Poller, ReadData, StepEnd, TcpOptions,
    TransportError, UnitSource,
};

fn quick() -> TcpOptions {
    TcpOptions {
        connect_timeout: Duration::from_millis(500),
        op_timeout: Duration::from_millis(200),
        unit_id: 9,
        ..TcpOptions::default()
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn holding(start: u16, interval: u64, tag: &'static str) -> PollItem<&'static str> {
    PollItem {
        register_type: RegisterType::Holding,
        start,
        count: 2,
        interval: secs(interval),
        device_address: 4,
        tag,
    }
}

fn raw(units: UnitSource, t0: Instant) -> Poller<&'static str> {
    let items = [
        holding(10, 1, "a"),
        holding(20, 5, "b"),
        holding(30, 10, "c"),
    ];
    Poller::new(items, units, FrameBackoff::default(), t0)
}

fn addresses(server: &FakeServer) -> Vec<u16> {
    server.seen().iter().map(|s| s.address).collect()
}

/// `(item, kind)` for each event, where kind is `R`, `E` or `T`.
fn outline<T>(events: &[PollEvent<T>]) -> Vec<(usize, char)> {
    events
        .iter()
        .map(|event| match event {
            PollEvent::Read { item, .. } => (item.0, 'R'),
            PollEvent::Exception { item, .. } => (item.0, 'E'),
            PollEvent::Transport { item, .. } => (item.0, 'T'),
        })
        .collect()
}

#[tokio::test]
async fn nothing_due_does_nothing_and_does_not_connect() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0 + secs(1));

        let step = poller.step(&mut tcp, t0).await;
        assert!(step.events.is_empty());
        assert!(!step.connected);
        assert!(matches!(step.end, StepEnd::Done));
        assert_eq!(server.connections(), 0);
    })
    .await
}

#[tokio::test]
async fn due_items_are_read_in_list_order_on_one_connection() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);

        let step = poller.step(&mut tcp, t0).await;
        assert!(step.connected);
        assert!(matches!(step.end, StepEnd::Done));
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'R'), (2, 'R')]);
        assert_eq!(addresses(&server), [10, 20, 30]);
        let PollEvent::Read {
            tag,
            reading,
            signals,
            recovered,
            ..
        } = &step.events[1]
        else {
            unreachable!()
        };
        assert_eq!(*tag, "b");
        assert_eq!(reading.data, ReadData::Registers(vec![20, 21]));
        assert!(signals.is_empty());
        assert!(!recovered);

        let step = poller.step(&mut tcp, t0 + secs(1)).await;
        assert!(!step.connected);
        assert_eq!(outline(&step.events), [(0, 'R')]);
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn item_units_address_each_device_and_connection_units_send_none() {
    within(async {
        let server = FakeServer::start().await;
        let t0 = Instant::now();
        for (units, unit, seen) in [
            (UnitSource::Item, Some(4), 4),
            (UnitSource::Connection, None, 9),
        ] {
            let mut tcp = ModbusTcp::new(server.endpoint(), quick());
            let step = raw(units, t0).step(&mut tcp, t0).await;
            for event in &step.events {
                let PollEvent::Read { request, .. } = event else {
                    unreachable!()
                };
                assert_eq!(request.unit, unit);
            }
            assert!(server.seen().iter().rev().take(3).all(|s| s.unit == seen));
        }
    })
    .await
}

#[tokio::test]
async fn every_outcome_is_scheduled_from_the_steps_now() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);
        let late = t0 + secs(30);
        poller.step(&mut tcp, late).await;
        assert_eq!(poller.next_due(), Some(late + secs(1)));
        assert_eq!(poller.step(&mut tcp, late + secs(5)).await.events.len(), 2);
    })
    .await
}

#[tokio::test]
async fn a_failed_connect_reads_nothing_and_charges_no_item() {
    within(async {
        let server = FakeServer::start().await;
        server.close().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);

        let step = poller.step(&mut tcp, t0).await;
        assert!(step.events.is_empty());
        assert!(!step.connected);
        assert!(matches!(
            step.end,
            StepEnd::ConnectFailed(TransportError::Connect { .. })
        ));
        assert_eq!(poller.next_due(), Some(t0));

        server.reopen().await;
        let step = poller.step(&mut tcp, t0).await;
        assert!(step.connected);
        assert!(step.events.iter().all(|e| matches!(
            e,
            PollEvent::Read {
                recovered: false,
                ..
            }
        )));
    })
    .await
}

#[tokio::test]
async fn an_exception_backs_off_that_item_keeps_the_socket_and_carries_on() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Exception(0x02)]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);

        let step = poller.step(&mut tcp, t0).await;
        assert!(matches!(step.end, StepEnd::Done));
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'E'), (2, 'R')]);
        let PollEvent::Exception { code, retry_in, .. } = &step.events[1] else {
            unreachable!()
        };
        assert_eq!(*code, ExceptionCode::IllegalDataAddress);
        assert_eq!(*retry_in, secs(10));
        assert!(tcp.is_connected());

        let step = poller.step(&mut tcp, t0 + secs(9)).await;
        assert_eq!(outline(&step.events), [(0, 'R')]);
        let step = poller.step(&mut tcp, t0 + secs(10)).await;
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'R'), (2, 'R')]);
        assert!(matches!(
            step.events[1],
            PollEvent::Read {
                recovered: true,
                ..
            }
        ));
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn a_transport_error_ends_the_step_and_makes_every_item_due() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Close]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);

        let step = poller.step(&mut tcp, t0).await;
        assert!(matches!(step.end, StepEnd::Lost));
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'T')]);
        assert!(matches!(
            step.events[1],
            PollEvent::Transport { consecutive: 1, .. }
        ));
        assert!(!tcp.is_connected());
        assert_eq!(addresses(&server), [10, 20]);

        server.script([Action::Reply, Action::Close]);
        let step = poller.step(&mut tcp, t0).await;
        assert!(step.connected);
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'T')]);
        assert!(matches!(
            step.events[1],
            PollEvent::Transport { consecutive: 2, .. }
        ));

        let step = poller.step(&mut tcp, t0).await;
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'R'), (2, 'R')]);
        assert!(matches!(
            step.events[1],
            PollEvent::Read {
                recovered: true,
                ..
            }
        ));
    })
    .await
}

#[tokio::test]
async fn a_dropped_step_leaves_its_item_due() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Stall]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);

        let dropped =
            tokio::time::timeout(Duration::from_millis(50), poller.step(&mut tcp, t0)).await;
        assert!(dropped.is_err());
        assert!(!tcp.is_connected());
        assert_eq!(poller.next_due(), Some(t0));
        let step = poller.step(&mut tcp, t0).await;
        assert_eq!(outline(&step.events), [(0, 'R'), (1, 'R'), (2, 'R')]);
    })
    .await
}

#[tokio::test]
async fn a_retired_item_is_never_read_again() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = raw(UnitSource::Item, t0);
        assert_eq!(poller.item(ItemId(2)).tag, "c");

        poller.retire(ItemId(1));
        assert_eq!(poller.live_count(), 2);
        let step = poller.step(&mut tcp, t0).await;
        assert_eq!(outline(&step.events), [(0, 'R'), (2, 'R')]);

        poller.retire(ItemId(0));
        poller.retire(ItemId(2));
        assert_eq!(poller.live_count(), 0);
        assert_eq!(poller.next_due(), None);
    })
    .await
}

const MANIFEST: &str = r#"
[meta.modbus]
register_base = 0

[frame.modbus.relays]
register_number = 3
register_type = "coil"
length = 8
interval_ms = 1000

[[frame.modbus.relays.signals]]
name = "Relays"
start_bit = 0
bit_length = 8

[frame.modbus.parked]
register_number = 50
register_type = "holding"
length = 1
disabled = true

[frame.modbus.volts]
register_number = 7
register_type = "holding"
length = 1
interval_ms = 2000

[[frame.modbus.volts.signals]]
name = "Voltage"
start_bit = 0
bit_length = 16
factor = 0.1
unit = "V"
"#;

fn from_manifest(banks: Banks, t0: Instant) -> Poller<usize> {
    let manifest = ModbusManifest::parse(MANIFEST).unwrap();
    Poller::from_manifest(
        manifest,
        banks,
        UnitSource::Connection,
        FrameBackoff::default(),
        t0,
    )
}

#[tokio::test]
async fn a_manifest_poller_reads_register_frames_and_decodes_them() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = from_manifest(Banks::Registers, t0);
        assert_eq!(poller.live_count(), 1);
        assert_eq!(poller.item(ItemId(0)).tag, 2);
        assert_eq!(poller.manifest().unwrap().frames[2].name, "volts");

        let before = SystemTime::now();
        let step = poller.step(&mut tcp, t0).await;
        let PollEvent::Read { tag, signals, .. } = &step.events[0] else {
            unreachable!()
        };
        assert_eq!(*tag, 2);
        assert_eq!(signals[0].name, "Voltage");
        assert_eq!(signals[0].value.to_string(), "0.7");

        let (voltage, at) = poller.signal("Voltage").unwrap();
        assert_eq!(voltage.unit.as_deref(), Some("V"));
        assert!(at >= before && at <= SystemTime::now());
        assert!(poller.signal("Relays").is_none());
    })
    .await
}

#[tokio::test]
async fn every_bank_reads_coils_too_and_the_snapshot_keeps_each_reads_time() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let t0 = Instant::now();
        let mut poller = from_manifest(Banks::All, t0);
        assert_eq!(poller.live_count(), 2);

        poller.step(&mut tcp, t0).await;
        let first: Vec<_> = poller
            .signals()
            .map(|(s, at)| (s.name.clone(), at))
            .collect();
        let names: Vec<_> = first.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Relays", "Voltage"]);
        let (relays, _) = poller.signal("Relays").unwrap();
        assert_eq!(relays.value.to_string(), "170");

        let step = poller.step(&mut tcp, t0 + secs(1)).await;
        assert_eq!(outline(&step.events), [(0, 'R')]);
        let (_, relays_at) = poller.signal("Relays").unwrap();
        let (_, voltage_at) = poller.signal("Voltage").unwrap();
        assert!(relays_at > first[0].1);
        assert_eq!(voltage_at, first[1].1);
    })
    .await
}

#[test]
fn a_raw_poller_has_no_manifest_and_no_snapshot() {
    let item = PollItem {
        register_type: RegisterType::Holding,
        start: 0,
        count: 1,
        interval: secs(1),
        device_address: 1,
        tag: 0usize,
    };
    let poller = Poller::new(
        [item],
        UnitSource::Item,
        FrameBackoff::default(),
        Instant::now(),
    );
    assert!(poller.manifest().is_none());
    assert_eq!(poller.signals().count(), 0);
    assert!(poller.signal("Voltage").is_none());
}
