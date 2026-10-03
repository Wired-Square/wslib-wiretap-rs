#![cfg(feature = "modbus-tcp")]

mod support;

use std::time::{Duration, Instant, SystemTime};

use tokio::{net::TcpStream, time::sleep};

use support::{discrete_input, input_register, silent_addr, within, Action, FakeServer};
use wiretap_catalog::modbus::RegisterType;
use wiretap_io::modbus::{
    DeviceIdCode, ExceptionCode, ModbusTcp, ReadData, ReadRequest, RequestError, ResolveError,
    TcpOptions, TransportError,
};

fn quick() -> TcpOptions {
    TcpOptions {
        connect_timeout: Duration::from_millis(500),
        op_timeout: Duration::from_millis(200),
        ..TcpOptions::default()
    }
}

fn holding(start: u16, count: u16) -> ReadRequest {
    ReadRequest {
        register_type: RegisterType::Holding,
        start,
        count,
        unit: None,
    }
}

async fn read_words(tcp: &mut ModbusTcp, request: ReadRequest) -> Vec<u16> {
    match tcp.read(request).await.unwrap().data {
        ReadData::Registers(words) => words,
        other => panic!("expected registers, got {other:?}"),
    }
}

#[tokio::test]
async fn every_bank_reads_through_its_own_function() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let read = |register_type, start, count| ReadRequest {
            register_type,
            start,
            count,
            unit: None,
        };

        assert_eq!(read_words(&mut tcp, holding(10, 3)).await, [10, 11, 12]);
        let input = read_words(&mut tcp, read(RegisterType::Input, 7, 2)).await;
        assert_eq!(input, [input_register(7), input_register(8)]);

        let coils = tcp.read(read(RegisterType::Coil, 3, 10)).await.unwrap();
        let expected: Vec<bool> = (3u16..13).map(|n| n.is_multiple_of(2)).collect();
        assert_eq!(coils.data, ReadData::Coils(expected));

        let discrete = tcp.read(read(RegisterType::Discrete, 0, 5)).await.unwrap();
        let expected: Vec<bool> = (0..5).map(discrete_input).collect();
        assert_eq!(discrete.data, ReadData::Coils(expected));

        let functions: Vec<u8> = server.seen().iter().map(|s| s.function).collect();
        assert_eq!(functions, [0x03, 0x04, 0x01, 0x02]);
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn a_reading_carries_its_latency_and_completion_time() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        let before = SystemTime::now();
        let reading = tcp.read(holding(0, 1)).await.unwrap();
        assert!(reading.at >= before && reading.at <= SystemTime::now());
        assert!(reading.latency > Duration::ZERO);
    })
    .await
}

#[tokio::test]
async fn a_short_reply_is_returned_as_received() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Short(1)]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        assert_eq!(read_words(&mut tcp, holding(4, 3)).await, [4]);
    })
    .await
}

#[tokio::test]
async fn an_exception_keeps_the_socket() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Exception(0x02)]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());

        let error = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Exception {
                code: ExceptionCode::IllegalDataAddress,
                ..
            }
        ));
        assert!(error.device_replied());
        assert_eq!(error.to_string(), "Illegal Data Address");
        assert!(tcp.is_connected());

        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn an_op_timeout_drops_the_socket_and_the_next_request_reconnects() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Stall]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());

        let error = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Transport(TransportError::Timeout { after }) if after == quick().op_timeout
        ));
        assert!(!error.device_replied());
        assert_eq!(error.to_string(), "timed out after 200ms");
        assert!(!tcp.is_connected());

        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 2);
    })
    .await
}

#[tokio::test]
async fn a_peer_close_is_a_transport_error() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Close]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());

        let error = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Transport(TransportError::Closed)
        ));
        assert_eq!(error.to_string(), "connection closed by the device");
        assert!(!tcp.is_connected());
        tcp.read(holding(0, 1)).await.unwrap();
    })
    .await
}

/// tokio-modbus reports the EOF with the thread's stale errno; the connect in
/// between leaves EINPROGRESS, as a reconnect elsewhere did on the desktop.
#[tokio::test]
async fn a_device_that_hangs_up_between_reads_is_reported_as_closed() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::ReplyThenClose]);
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        tcp.read(holding(0, 1)).await.unwrap();
        while server.open_connections() > 0 {
            sleep(Duration::from_millis(1)).await;
        }
        let _other = TcpStream::connect(server.addr).await.unwrap();

        let error = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Transport(TransportError::Closed)
        ));
        assert_eq!(error.to_string(), "connection closed by the device");
    })
    .await
}

#[tokio::test]
async fn a_silent_endpoint_times_out_the_connect() {
    within(async {
        let (_guard, silent) = silent_addr().await;
        let mut tcp = ModbusTcp::new(silent.to_string(), quick());
        let started = Instant::now();

        let error = tcp.connect().await.unwrap_err();
        assert!(matches!(error, TransportError::ConnectTimeout { addr, .. } if addr == silent));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            error.to_string(),
            format!("connect to {silent} timed out after 500ms")
        );
        assert!(!tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_refused_connect_is_told_apart_from_a_resolve_failure() {
    within(async {
        let refused = {
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            server.local_addr().unwrap()
        };
        let mut tcp = ModbusTcp::new(refused.to_string(), quick());
        let error = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Transport(TransportError::Connect { addr, .. }) if addr == refused
        ));

        let mut tcp = ModbusTcp::new("127.0.0.1", quick());
        let error = tcp.connect().await.unwrap_err();
        assert!(matches!(
            &error,
            TransportError::Resolve { endpoint, reason: ResolveError::Io(_) } if endpoint == "127.0.0.1"
        ));
        assert!(error.to_string().starts_with("cannot resolve 127.0.0.1: "));
    })
    .await
}

/// `localhost` resolves to `::1` as well on most hosts, where nothing listens.
#[tokio::test]
async fn a_name_connects_through_whichever_of_its_addresses_answers() {
    within(async {
        let server = FakeServer::start().await;
        let endpoint = format!("localhost:{}", server.addr.port());
        let mut tcp = ModbusTcp::new(endpoint, quick());
        tcp.read(holding(0, 1)).await.unwrap();
    })
    .await
}

#[tokio::test]
async fn an_explicit_connect_is_kept_until_disconnect() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());
        assert!(!tcp.is_connected());
        tcp.connect().await.unwrap();
        tcp.connect().await.unwrap();
        assert!(tcp.is_connected());
        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 1);

        tcp.disconnect().await;
        assert!(!tcp.is_connected());
        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 2);
    })
    .await
}

#[tokio::test]
async fn an_idle_socket_is_replaced_before_the_next_request() {
    within(async {
        let server = FakeServer::start().await;
        let options = TcpOptions {
            idle_reconnect: Some(Duration::from_millis(100)),
            ..quick()
        };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        tcp.read(holding(0, 1)).await.unwrap();
        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 1);

        tokio::time::sleep(Duration::from_millis(150)).await;
        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 2);
        assert_eq!(server.seen().len(), 3);
    })
    .await
}

#[tokio::test]
async fn reconnect_per_request_closes_the_socket_after_each() {
    within(async {
        let server = FakeServer::start().await;
        let options = TcpOptions {
            reconnect_per_request: true,
            ..quick()
        };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        tcp.read(holding(0, 1)).await.unwrap();
        assert!(!tcp.is_connected());
        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 2);
    })
    .await
}

#[tokio::test]
async fn a_new_connection_settles_before_its_first_request() {
    within(async {
        let server = FakeServer::start().await;
        let settle = Duration::from_millis(150);
        let options = TcpOptions { settle, ..quick() };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        let started = Instant::now();
        let reading = tcp.read(holding(0, 1)).await.unwrap();
        assert!(started.elapsed() >= settle);
        assert!(reading.latency < settle);

        let started = Instant::now();
        tcp.read(holding(0, 1)).await.unwrap();
        assert!(started.elapsed() < settle);
    })
    .await
}

#[tokio::test]
async fn a_request_unit_overrides_the_default_for_that_request_only() {
    within(async {
        let server = FakeServer::start().await;
        let options = TcpOptions {
            unit_id: 7,
            ..quick()
        };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        tcp.read(holding(0, 1)).await.unwrap();
        tcp.read(ReadRequest {
            unit: Some(9),
            ..holding(0, 1)
        })
        .await
        .unwrap();
        tcp.read(holding(0, 1)).await.unwrap();

        let units: Vec<u8> = server.seen().iter().map(|s| s.unit).collect();
        assert_eq!(units, [7, 9, 7]);
    })
    .await
}

#[tokio::test]
async fn a_dropped_request_drops_its_socket() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Stall]);
        let options = TcpOptions {
            op_timeout: Duration::from_secs(5),
            ..quick()
        };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        let abandoned = tokio::time::timeout(Duration::from_millis(100), tcp.read(holding(0, 1)));
        assert!(abandoned.await.is_err());
        assert!(!tcp.is_connected());

        tcp.read(holding(0, 1)).await.unwrap();
        assert_eq!(server.connections(), 2);
    })
    .await
}

#[tokio::test]
async fn device_identification_returns_the_objects_as_sent() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = ModbusTcp::new(server.endpoint(), quick());

        let id = tcp
            .read_device_identification(Some(3), DeviceIdCode::Basic, 0)
            .await
            .unwrap();
        assert_eq!(id.conformity_level, 0x81);
        assert_eq!(
            id.objects,
            [(0x00, b"Wired Square".to_vec()), (0x01, b"FAKE-1".to_vec())]
        );
        assert!(!id.more_follows);

        let seen = server.seen();
        assert_eq!((seen[0].unit, seen[0].function), (3, 0x2B));
    })
    .await
}
