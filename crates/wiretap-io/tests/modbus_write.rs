#![cfg(feature = "modbus-write")]

mod support;

use std::time::{Duration, Instant};

use support::{within, Action, FakeServer};
use wiretap_catalog::modbus::{ModbusWrite, WriteBank};
use wiretap_io::modbus::{
    ExceptionCode, ModbusTcp, ReadbackKind, RequestError, TcpOptions, WriteOutcome, WriteReport,
};

fn quick() -> TcpOptions {
    TcpOptions {
        connect_timeout: Duration::from_millis(500),
        op_timeout: Duration::from_millis(200),
        ..TcpOptions::default()
    }
}

fn full(address: u16, value: u16) -> ModbusWrite {
    ModbusWrite::holding(address, value, 0xFFFF)
}

fn masked(address: u16, value: u16, mask: u16) -> ModbusWrite {
    ModbusWrite::holding(address, value, mask)
}

fn registers<const N: usize>(addresses: [u16; N]) -> Vec<(WriteBank, u16)> {
    addresses.map(|a| (WriteBank::Holding, a)).to_vec()
}

fn client(server: &FakeServer) -> ModbusTcp {
    ModbusTcp::new(server.endpoint(), quick())
}

/// `(function, address)` of every request the server saw.
fn requests(server: &FakeServer) -> Vec<(u8, u16)> {
    server
        .seen()
        .iter()
        .map(|s| (s.function, s.address))
        .collect()
}

fn readback(report: &WriteReport) -> Vec<(ReadbackKind, u16, Vec<u16>)> {
    report
        .readback
        .iter()
        .map(|r| (r.kind, r.start, r.words.clone()))
        .collect()
}

#[tokio::test]
async fn one_register_goes_out_as_fc06_and_several_as_fc16() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = client(&server);

        tcp.write_registers(None, 100, &[7]).await.unwrap();
        tcp.write_registers(None, 200, &[8, 9]).await.unwrap();

        assert_eq!(requests(&server), [(0x06, 100), (0x10, 200)]);
        assert_eq!(
            [
                server.holding(100),
                server.holding(200),
                server.holding(201)
            ],
            [7, 8, 9]
        );
    })
    .await
}

#[tokio::test]
async fn one_coil_goes_out_as_fc05_and_several_as_fc15() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = client(&server);

        tcp.write_coils(Some(4), 0, &[false]).await.unwrap();
        tcp.write_coils(
            None,
            10,
            &[false, true, false, true, true, false, false, true, true],
        )
        .await
        .unwrap();

        assert_eq!(requests(&server), [(0x05, 0), (0x0F, 10)]);
        assert_eq!(server.seen()[0].unit, 4);
        assert!(!server.coil(0));
        let coils: Vec<bool> = (10..19).map(|a| server.coil(a)).collect();
        assert_eq!(
            coils,
            [false, true, false, true, true, false, false, true, true]
        );
    })
    .await
}

#[tokio::test]
async fn a_rejected_write_is_an_exception_and_keeps_the_socket() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Exception(0x03)]);
        let mut tcp = client(&server);

        let error = tcp.write_registers(None, 5, &[1]).await.unwrap_err();
        assert!(matches!(
            error,
            RequestError::Exception {
                code: ExceptionCode::IllegalDataValue,
                ..
            }
        ));
        assert!(tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn contiguous_writes_go_out_as_runs_then_every_run_is_verified() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[full(10, 1), full(11, 2), full(20, 3)])
            .await;

        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert_eq!(
            requests(&server),
            [(0x10, 10), (0x06, 20), (0x03, 10), (0x03, 20)]
        );
        assert_eq!(report.written, registers([10, 11, 20]));
        assert_eq!(
            readback(&report),
            [
                (ReadbackKind::Verify, 10, vec![1, 2]),
                (ReadbackKind::Verify, 20, vec![3]),
            ]
        );
        assert!(!report.transport_lost);
        assert!(tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_mixed_batch_writes_each_bank_with_its_own_codes_then_verifies_it() {
    within(async {
        let server = FakeServer::start().await;
        let mut tcp = client(&server);
        let writes = [
            full(10, 1),
            ModbusWrite::coil(10, false),
            ModbusWrite::coil(11, true),
            ModbusWrite::coil(12, true),
            ModbusWrite::coil(20, false),
        ];

        let report = tcp.write_verified(None, &writes).await;

        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        // A coil run owns its coils, so there is no read before it.
        assert_eq!(
            requests(&server),
            [
                (0x06, 10),
                (0x0F, 10),
                (0x05, 20),
                (0x03, 10),
                (0x01, 10),
                (0x01, 20)
            ]
        );
        assert_eq!(server.holding(10), 1);
        let coils: Vec<bool> = [10, 11, 12, 20].map(|a| server.coil(a)).to_vec();
        assert_eq!(coils, [false, true, true, false]);
        assert_eq!(report.written, writes.map(|w| (w.bank, w.address)).to_vec());
        let verified: Vec<_> = report
            .readback
            .iter()
            .map(|r| (r.kind, r.bank, r.start, r.words.clone()))
            .collect();
        assert_eq!(
            verified,
            [
                (ReadbackKind::Verify, WriteBank::Holding, 10, vec![1]),
                (ReadbackKind::Verify, WriteBank::Coil, 10, vec![0, 1, 1]),
                (ReadbackKind::Verify, WriteBank::Coil, 20, vec![0]),
            ]
        );
    })
    .await
}

#[tokio::test]
async fn a_coil_that_did_not_change_is_unconfirmed_and_named_as_a_coil() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Ignore]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[full(5, 7), ModbusWrite::coil(5, true)])
            .await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Unconfirmed("coil 5: wrote 1, read 0".into())
        );
        assert!(!report.transport_lost);
    })
    .await
}

#[tokio::test]
async fn a_rejected_coil_write_fails_naming_the_coil() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Exception(0x02)]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[ModbusWrite::coil(8, true)])
            .await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Failed("coil 8: Illegal Data Address".into())
        );
        assert!(report.written.is_empty());
    })
    .await
}

#[tokio::test]
async fn a_masked_run_is_read_first_and_only_its_owned_bits_change() {
    within(async {
        let server = FakeServer::start().await;
        server.set_holding(30, 0xABCD);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[masked(30, 0x0012, 0x00FF), full(31, 5)])
            .await;

        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert_eq!([server.holding(30), server.holding(31)], [0xAB12, 5]);
        assert_eq!(requests(&server), [(0x03, 30), (0x10, 30), (0x03, 30)]);
        assert_eq!(
            readback(&report),
            [
                (ReadbackKind::BeforeWrite, 30, vec![0xABCD, 31]),
                (ReadbackKind::Verify, 30, vec![0xAB12, 5]),
            ]
        );
    })
    .await
}

#[tokio::test]
async fn an_exception_on_the_read_modify_write_read_fails_the_batch() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Exception(0x02)]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[masked(30, 1, 0x000F), full(40, 1)])
            .await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Failed("register 30: read-modify-write: Illegal Data Address".into())
        );
        assert_eq!(requests(&server), [(0x03, 30)]);
        assert!(report.written.is_empty() && report.readback.is_empty());
        assert!(!report.transport_lost);
        assert!(tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_transport_error_on_the_read_modify_write_read_fails_the_batch() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Stall]);
        let mut tcp = client(&server);

        let report = tcp.write_verified(None, &[masked(30, 1, 0x000F)]).await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Failed("register 30: read-modify-write: timed out after 200ms".into())
        );
        assert!(report.transport_lost);
        assert!(!tcp.is_connected());
        assert_eq!(server.connections(), 1);
    })
    .await
}

#[tokio::test]
async fn the_first_failing_run_stops_the_batch() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Exception(0x04)]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[full(10, 1), full(20, 2), full(30, 3)])
            .await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Failed("register 20: Server Device Failure".into())
        );
        assert_eq!(requests(&server), [(0x06, 10), (0x06, 20)]);
        assert_eq!(report.written, registers([10]));
        assert!(report.readback.is_empty());
        assert!(!report.transport_lost);
    })
    .await
}

#[tokio::test]
async fn a_lost_socket_on_a_write_ends_the_batch_without_reconnecting() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Close]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[full(10, 1), full(20, 2), full(30, 3)])
            .await;

        assert!(
            matches!(&report.outcome, WriteOutcome::Failed(d) if d.starts_with("register 20: "))
        );
        assert!(report.transport_lost);
        assert_eq!(report.written, registers([10]));
        assert_eq!(server.connections(), 1);
        assert!(!tcp.is_connected());

        let report = tcp.write_verified(None, &[full(30, 3)]).await;
        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert_eq!(server.connections(), 2);
    })
    .await
}

#[tokio::test]
async fn verify_carries_on_past_an_exception() {
    within(async {
        let server = FakeServer::start().await;
        server.script([
            Action::Reply,
            Action::Reply,
            Action::Exception(0x02),
            Action::Reply,
        ]);
        let mut tcp = client(&server);

        let report = tcp.write_verified(None, &[full(10, 1), full(20, 2)]).await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Unconfirmed("register 10: verify read: Illegal Data Address".into())
        );
        assert_eq!(requests(&server).len(), 4);
        assert_eq!(readback(&report), [(ReadbackKind::Verify, 20, vec![2])]);
        assert_eq!(report.written, registers([10, 20]));
        assert!(!report.transport_lost);
    })
    .await
}

#[tokio::test]
async fn a_lost_socket_stops_verify_without_reconnecting() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Reply, Action::Close]);
        let mut tcp = client(&server);

        let report = tcp.write_verified(None, &[full(10, 1), full(20, 2)]).await;

        assert!(matches!(
            &report.outcome,
            WriteOutcome::Unconfirmed(d) if d.starts_with("register 10: verify read: ")
        ));
        assert_eq!(requests(&server).len(), 3);
        assert!(report.transport_lost);
        assert_eq!(report.written, registers([10, 20]));
        assert_eq!(server.connections(), 1);
        assert!(!tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_mismatch_compares_only_the_owned_bits() {
    within(async {
        let server = FakeServer::start().await;
        server.set_holding(40, 0xFF00);
        // The read-modify-write read, then a write acknowledged but not applied.
        server.script([Action::Reply, Action::Ignore]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[masked(40, 0x0001, 0x000F)])
            .await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Unconfirmed("register 40: wrote 1, read 0".into())
        );
        assert!(!report.transport_lost);
    })
    .await
}

#[tokio::test]
async fn a_short_read_modify_write_read_is_zero_filled() {
    within(async {
        let server = FakeServer::start().await;
        server.set_holding(50, 0xFFFF);
        server.set_holding(51, 0xFFFF);
        server.script([Action::Short(1)]);
        let mut tcp = client(&server);

        let report = tcp
            .write_verified(None, &[masked(50, 1, 0x000F), masked(51, 2, 0x000F)])
            .await;

        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert_eq!([server.holding(50), server.holding(51)], [0xFFF1, 0x0002]);
        assert_eq!(report.readback[0].words, [0xFFFF]);
    })
    .await
}

#[tokio::test]
async fn a_short_verify_read_is_zero_filled_and_unconfirmed() {
    within(async {
        let server = FakeServer::start().await;
        server.script([Action::Reply, Action::Short(1)]);
        let mut tcp = client(&server);

        let report = tcp.write_verified(None, &[full(60, 0), full(61, 7)]).await;

        assert_eq!(
            report.outcome,
            WriteOutcome::Unconfirmed("register 61: wrote 7, read 0".into())
        );
        assert_eq!(readback(&report), [(ReadbackKind::Verify, 60, vec![0])]);
        assert!(!report.transport_lost);
        assert!(tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_batch_connects_and_settles_first_and_uses_its_unit() {
    within(async {
        let server = FakeServer::start().await;
        let settle = Duration::from_millis(150);
        let options = TcpOptions {
            settle,
            reconnect_per_request: true,
            ..quick()
        };
        let mut tcp = ModbusTcp::new(server.endpoint(), options);

        let started = Instant::now();
        let report = tcp
            .write_verified(Some(9), &[full(10, 1), full(20, 2)])
            .await;

        assert_eq!(report.outcome, WriteOutcome::Confirmed);
        assert!(started.elapsed() >= settle);
        assert!(server
            .seen()
            .iter()
            .all(|s| s.unit == 9 && s.connection == 1));
        assert!(!tcp.is_connected());
    })
    .await
}

#[tokio::test]
async fn a_batch_that_cannot_connect_fails_as_lost() {
    within(async {
        let refused = {
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            server.local_addr().unwrap()
        };
        let mut tcp = ModbusTcp::new(refused.to_string(), quick());

        let report = tcp.write_verified(None, &[full(10, 1)]).await;

        let connect_failed = format!("connect to {refused} failed: ");
        assert!(
            matches!(&report.outcome, WriteOutcome::Failed(d) if d.starts_with(&connect_failed))
        );
        assert!(report.transport_lost);
        assert!(report.written.is_empty() && report.readback.is_empty());
    })
    .await
}
