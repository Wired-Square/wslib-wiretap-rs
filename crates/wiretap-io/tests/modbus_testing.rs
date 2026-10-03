//! The `testing` fake device, as a consumer's test drives it.

#![cfg(feature = "testing")]

mod support;

use std::time::Duration;

use support::within;
use wiretap_catalog::modbus::RegisterType;
use wiretap_io::modbus::{
    testing::{self, device, Reply},
    ModbusTcp, ReadData, ReadRequest, RequestError, TcpOptions, TransportError,
};

fn connect(device: &testing::Device) -> ModbusTcp {
    let options = TcpOptions {
        connect_timeout: Duration::from_millis(500),
        op_timeout: Duration::from_millis(200),
        ..TcpOptions::default()
    };
    ModbusTcp::new(format!("127.0.0.1:{}", device.port), options)
}

fn holding(start: u16, count: u16) -> ReadRequest {
    ReadRequest {
        register_type: RegisterType::Holding,
        start,
        count,
        unit: Some(7),
    }
}

#[tokio::test]
async fn registers_hold_their_own_address_and_every_request_is_seen() {
    within(async {
        let device = device(testing::registers).await;
        let mut tcp = connect(&device);

        let reading = tcp.read(holding(5, 2)).await.unwrap();
        assert_eq!(reading.data, ReadData::Registers(vec![5, 6]));
        tcp.write_registers(None, 9, &[42]).await.unwrap();

        let seen: Vec<_> = device
            .requests()
            .iter()
            .map(|r| (r.connection, r.unit, r.function(), r.start()))
            .collect();
        assert_eq!(seen, [(1, 7, 0x03, 5), (1, 1, 0x06, 9)]);
    })
    .await
}

#[tokio::test]
async fn an_answer_can_refuse_stay_silent_or_hang_up() {
    within(async {
        let device = device(|request| match request.start() {
            1 => Reply::Exception(0x02),
            2 => Reply::Silent,
            3 => Reply::Drop,
            _ => testing::registers(request),
        })
        .await;
        let mut tcp = connect(&device);

        let refused = tcp.read(holding(1, 1)).await.unwrap_err();
        assert!(refused.device_replied(), "{refused:?}");
        let silent = tcp.read(holding(2, 1)).await.unwrap_err();
        assert!(matches!(
            silent,
            RequestError::Transport(TransportError::Timeout { .. })
        ));
        let dropped = tcp.read(holding(3, 1)).await.unwrap_err();
        assert!(!dropped.device_replied(), "{dropped:?}");
        assert!(tcp.read(holding(0, 1)).await.is_ok());

        let connections: Vec<_> = device.requests().iter().map(|r| r.connection).collect();
        assert_eq!(connections, [1, 1, 2, 3]);
    })
    .await
}

#[tokio::test]
async fn a_device_that_vanishes_refuses_the_next_connect() {
    within(async {
        let device = device(|_| Reply::Vanish).await;
        let mut tcp = connect(&device);

        assert!(tcp.read(holding(0, 1)).await.is_err());
        let refused = tcp.read(holding(0, 1)).await.unwrap_err();
        assert!(
            matches!(
                refused,
                RequestError::Transport(TransportError::Connect { .. })
            ),
            "{refused:?}"
        );
        assert_eq!(device.requests().len(), 1);
    })
    .await
}
