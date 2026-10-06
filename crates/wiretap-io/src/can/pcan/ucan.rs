//! The FD family's half: `pcan_usb_fd`'s start, stop and records over a pipe a
//! test can fake. Untested on a device; the sequence is the kernel driver's.

use std::{future::Future, io};

use wiretap_protocol::{
    bittiming::{calculate, Timing},
    can::ErrorState,
    pcan_usb_fd::{
        accept_all, bus_on, clock_set, command_list, decode_messages, encode_transmit, led_set,
        option, reset_mode, set_options, status, timing_fast, timing_slow, transfers, Command,
        FirmwareInfo, Frame, Message, CLOCK_80MHZ, CLOCK_HZ, DATA_BITTIMING, LED_DEVICE,
        NOMINAL_BITTIMING, USB_CALIBRATION,
    },
};

use super::{refused, serial_text, untimeable, BusWatch, PcanModel, PcanOptions};
use crate::can::{
    clock::{Received, Stamp},
    CanError, CanFrame, DeviceInfo, Direction,
};

/// The two vendor requests and the command endpoint.
pub(super) trait Pipe {
    fn info(&mut self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;

    fn driver_loaded(&mut self, loaded: bool) -> impl Future<Output = io::Result<()>> + Send;

    fn command(&mut self, transfer: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;

    /// Blocking, for a drop: no runtime may be left to wait in.
    fn driver_loaded_now(&mut self, loaded: bool) -> io::Result<()>;

    /// Blocking, as `driver_loaded_now`.
    fn command_now(&mut self, transfer: Vec<u8>) -> io::Result<()>;
}

/// The nominal timing, and the data phase's where CAN FD is asked for.
pub(super) fn timings(pcan: &PcanOptions) -> Result<(Timing, Option<Timing>), CanError> {
    let nominal = calculate(
        CLOCK_HZ,
        pcan.bitrate,
        pcan.sample_point,
        &NOMINAL_BITTIMING,
    )
    .ok_or_else(|| untimeable(pcan.bitrate, pcan.sample_point, CLOCK_HZ))?;
    let data = pcan
        .data
        .map(|(bitrate, sample_point)| {
            calculate(CLOCK_HZ, bitrate, sample_point, &DATA_BITTIMING)
                .ok_or_else(|| untimeable(bitrate, sample_point, CLOCK_HZ))
        })
        .transpose()?;
    Ok((nominal, data))
}

/// `INFO FW`, a read, so the device is left as it was.
pub(super) async fn identify(pipe: &mut impl Pipe) -> Result<FirmwareInfo, CanError> {
    let info = pipe.info().await.map_err(refused("INFO"))?;
    FirmwareInfo::from_bytes(&info).ok_or(CanError::Handshake("the firmware info is short"))
}

pub(super) fn device_info(firmware: &FirmwareInfo, model: PcanModel) -> DeviceInfo {
    let [major, minor, patch] = firmware.fw_version;
    DeviceInfo {
        buses: Some(model.channels()),
        fd: true,
        firmware: Some(format!("{major}.{minor}.{patch}")),
        serial: serial_text(firmware.serial_number()),
        hardware: Some(firmware.hw_version.to_string()),
        clock_hz: Some(CLOCK_HZ),
        ..DeviceInfo::default()
    }
}

/// The error counters cleared, the ISO choice where the firmware takes one, and
/// the mode: the end of `start`, and the whole of a restart.
pub(super) fn operational(firmware: &FirmwareInfo, channel: u8, listen_only: bool) -> Vec<Command> {
    bus_on(
        channel,
        listen_only,
        firmware.iso_switchable().then_some(true),
    )
}

/// The kernel driver's sequence after `INFO FW`, one command list per step.
pub(super) async fn start(
    pipe: &mut impl Pipe,
    firmware: &FirmwareInfo,
    channel: u8,
    (nominal, data): (Timing, Option<Timing>),
    listen_only: bool,
    high_speed: bool,
) -> Result<(), CanError> {
    pipe.driver_loaded(true).await.map_err(refused("DRVLD"))?;
    let steps = [
        ("CLK_SET", vec![clock_set(channel, CLOCK_80MHZ)]),
        ("LED_SET", vec![led_set(channel, LED_DEVICE)]),
        ("RESET_MODE", vec![reset_mode(channel)]),
        ("TIMING_SLOW", vec![timing_slow(channel, nominal)]),
    ]
    .into_iter()
    .chain(data.map(|data| ("TIMING_FAST", vec![timing_fast(channel, data)])))
    .chain([
        ("FILTER_STD", accept_all(channel)),
        ("SET_EN_OPTION", vec![reporting(channel, true)]),
        ("bus on", operational(firmware, channel, listen_only)),
    ]);
    for (name, commands) in steps {
        send(pipe, name, &commands, high_speed).await?;
    }
    Ok(())
}

/// Best effort: each step is tried whatever became of the one before.
pub(super) async fn stop(pipe: &mut impl Pipe, channel: u8, high_speed: bool) {
    for transfer in stopping(channel, high_speed) {
        let _ = pipe.command(transfer).await;
    }
    let _ = pipe.driver_loaded(false).await;
}

/// `CLR_DIS_OPTION` and `RESET_MODE`, a command list each.
fn stopping(channel: u8, high_speed: bool) -> Vec<Vec<u8>> {
    [reporting(channel, false), reset_mode(channel)]
        .into_iter()
        .flat_map(|command| {
            let list = command_list(&[command]);
            transfers(&list, high_speed)
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A started channel's pipe. Dropped before `stop`, as when the runtime shuts
/// down around its task, it stops the channel itself.
pub(super) struct OnBus<P: Pipe> {
    pub(super) pipe: P,
    pub(super) channel: u8,
    pub(super) high_speed: bool,
    stopped: bool,
}

impl<P: Pipe> OnBus<P> {
    pub(super) fn new(pipe: P, channel: u8, high_speed: bool) -> Self {
        Self {
            pipe,
            channel,
            high_speed,
            stopped: false,
        }
    }

    pub(super) async fn stop(mut self) {
        stop(&mut self.pipe, self.channel, self.high_speed).await;
        self.stopped = true;
    }
}

impl<P: Pipe> Drop for OnBus<P> {
    fn drop(&mut self) {
        if !self.stopped {
            for transfer in stopping(self.channel, self.high_speed) {
                let _ = self.pipe.command_now(transfer);
            }
            let _ = self.pipe.driver_loaded_now(false);
        }
    }
}

/// Error records and the calibration the kernel keeps its clock by.
fn reporting(channel: u8, on: bool) -> Command {
    set_options(channel, on, option::ERROR, USB_CALIBRATION)
}

async fn send(
    pipe: &mut impl Pipe,
    name: &'static str,
    commands: &[Command],
    high_speed: bool,
) -> Result<(), CanError> {
    transmit(pipe, commands, high_speed)
        .await
        .map_err(refused(name))
}

pub(super) async fn transmit(
    pipe: &mut impl Pipe,
    commands: &[Command],
    high_speed: bool,
) -> io::Result<()> {
    let list = command_list(commands);
    for transfer in transfers(&list, high_speed) {
        pipe.command(transfer.to_vec()).await?;
    }
    Ok(())
}

impl BusWatch {
    /// The kernel's: the counters from `ERROR`, the state from `STATUS`.
    fn ucan(&mut self, message: &Message) {
        match *message {
            Message::Error {
                channel,
                tx_err_cnt,
                rx_err_cnt,
                ..
            } if channel == self.now.bus => {
                self.now.tx_errors = Some(tx_err_cnt);
                self.now.rx_errors = Some(rx_err_cnt);
            }
            Message::Status { channel, flags, .. } if channel == self.now.bus => {
                let state = if flags & status::BUSOFF != 0 {
                    ErrorState::BusOff
                } else if flags & status::PASSIVE != 0 {
                    ErrorState::Passive
                } else if flags & status::WARNING != 0 {
                    ErrorState::Warning
                } else {
                    self.now.tx_errors = Some(0);
                    self.now.rx_errors = Some(0);
                    ErrorState::Active
                };
                self.set(state);
            }
            _ => {}
        }
    }
}

/// A buffer's frames, on whichever channel, stamped by the low 32 bits of the
/// device's µs clock; `bus` takes its channel's error and status records.
pub(super) fn incoming(buffer: &[u8], bus: &mut BusWatch) -> Vec<Received> {
    decode_messages(buffer)
        .into_iter()
        .filter_map(|message| match message {
            Message::CanRx { frame, ts_us } => Some(Received {
                frame: can_frame(frame),
                direction: Direction::Rx,
                stamp: Stamp::Counter(ts_us as u32),
                overflow: false,
            }),
            other => {
                bus.ucan(&other);
                None
            }
        })
        .collect()
}

fn can_frame(frame: Frame) -> CanFrame {
    if frame.rtr {
        return CanFrame::remote(frame.channel, frame.arb_id, frame.extended, frame.dlc);
    }
    let mut can = CanFrame::data(
        frame.channel,
        frame.arb_id,
        frame.extended,
        frame.fd,
        frame.brs,
        frame.data,
    );
    can.esi = frame.esi;
    can
}

pub(super) fn outgoing(frame: &CanFrame, channel: u8) -> Vec<u8> {
    encode_transmit(&Frame {
        channel,
        arb_id: frame.arb_id,
        extended: frame.extended,
        rtr: frame.rtr,
        fd: frame.fd,
        brs: frame.brs,
        esi: frame.esi,
        dlc: frame.dlc(),
        data: frame.data.clone(),
    })
}

#[cfg(test)]
mod tests {
    use wiretap_protocol::pcan_usb_fd::{
        filter_std, listen_only_mode, normal_mode, reset_error_counters, set_iso, END_OF_COLLECTION,
    };

    use std::time::Duration;

    use super::*;
    use crate::can::{pcan::PcanDevice, BusState};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Op {
        Info,
        DriverLoaded(bool),
        Command(Vec<u8>),
    }

    #[derive(Default)]
    struct FakePipe {
        log: Vec<Op>,
        info: Vec<u8>,
        broken: Option<(u16, io::ErrorKind)>,
    }

    impl Pipe for FakePipe {
        async fn info(&mut self) -> io::Result<Vec<u8>> {
            self.log.push(Op::Info);
            Ok(self.info.clone())
        }

        async fn driver_loaded(&mut self, loaded: bool) -> io::Result<()> {
            self.driver_loaded_now(loaded)
        }

        async fn command(&mut self, transfer: Vec<u8>) -> io::Result<()> {
            self.command_now(transfer)
        }

        fn driver_loaded_now(&mut self, loaded: bool) -> io::Result<()> {
            self.log.push(Op::DriverLoaded(loaded));
            Ok(())
        }

        fn command_now(&mut self, transfer: Vec<u8>) -> io::Result<()> {
            let opcode = u16::from_le_bytes([transfer[0], transfer[1]]) & 0x3ff;
            self.log.push(Op::Command(transfer));
            match self.broken {
                Some((broken, kind)) if broken == opcode => Err(kind.into()),
                _ => Ok(()),
            }
        }
    }

    impl Pipe for &mut FakePipe {
        async fn info(&mut self) -> io::Result<Vec<u8>> {
            (**self).info().await
        }

        async fn driver_loaded(&mut self, loaded: bool) -> io::Result<()> {
            (**self).driver_loaded(loaded).await
        }

        async fn command(&mut self, transfer: Vec<u8>) -> io::Result<()> {
            (**self).command(transfer).await
        }

        fn driver_loaded_now(&mut self, loaded: bool) -> io::Result<()> {
            (**self).driver_loaded_now(loaded)
        }

        fn command_now(&mut self, transfer: Vec<u8>) -> io::Result<()> {
            (**self).command_now(transfer)
        }
    }

    fn firmware(fw_major: u8, ser_no: u32) -> Vec<u8> {
        let mut b = vec![0u8; FirmwareInfo::SIZE];
        b[0..2].copy_from_slice(&36u16.to_le_bytes());
        b[2..4].copy_from_slice(&1u16.to_le_bytes());
        b[8] = 4;
        b[9..12].copy_from_slice(&[fw_major, 7, 1]);
        b[20..24].copy_from_slice(&ser_no.to_le_bytes());
        b
    }

    fn options(model: PcanModel, channel: u8, data: Option<(u32, Option<f32>)>) -> PcanOptions {
        let mut pcan = PcanOptions::new(
            PcanDevice {
                serial: None,
                bus: 1,
                address: 2,
                product: model.to_string(),
                model,
            },
            500_000,
        );
        pcan.channel = channel;
        pcan.data = data;
        pcan
    }

    fn list(commands: &[Command]) -> Op {
        Op::Command(command_list(commands))
    }

    #[tokio::test]
    async fn an_fd_start_sends_the_kernels_sequence_byte_for_byte() {
        for listen_only in [true, false] {
            let pcan = options(PcanModel::UsbProFd, 1, Some((2_000_000, None)));
            let (nominal, data) = timings(&pcan).unwrap();
            let mut pipe = FakePipe {
                info: firmware(2, 0x00AB_CDEF),
                ..FakePipe::default()
            };
            let info = identify(&mut pipe).await.unwrap();
            start(&mut pipe, &info, 1, (nominal, data), listen_only, true)
                .await
                .unwrap();
            let mode = if listen_only {
                listen_only_mode(1)
            } else {
                normal_mode(1)
            };
            let filters: Vec<u8> = (0..64u16)
                .flat_map(|row| filter_std(1, row, u32::MAX))
                .collect();
            assert_eq!(filters.len(), 512);
            assert_eq!(
                pipe.log,
                [
                    Op::Info,
                    Op::DriverLoaded(true),
                    list(&[[0x80, 0x10, 0, 0, 0, 0, 0, 0]]),
                    list(&[[0x86, 0x10, 0, 0, 0, 0, 0, 0]]),
                    list(&[[0x01, 0x10, 0, 0, 0, 0, 0, 0]]),
                    list(&[[0x04, 0x10, 96, 9, 19, 138, 0, 0]]),
                    list(&[[0x05, 0x10, 0, 4, 9, 28, 0, 0]]),
                    Op::Command(filters),
                    list(&[[0x0b, 0x10, 0x01, 0, 0, 0, 0x00, 0x80]]),
                    Op::Command(
                        [
                            reset_error_counters(1),
                            set_iso(1, true),
                            mode,
                            END_OF_COLLECTION
                        ]
                        .concat()
                    ),
                ]
            );
        }
    }

    #[tokio::test]
    async fn classic_timing_on_old_firmware_skips_the_data_phase_and_the_iso_switch() {
        let pcan = options(PcanModel::UsbFd, 0, None);
        let mut pipe = FakePipe::default();
        let info = FirmwareInfo::from_bytes(&firmware(1, 1)).unwrap();
        start(&mut pipe, &info, 0, timings(&pcan).unwrap(), false, true)
            .await
            .unwrap();
        assert!(!pipe
            .log
            .iter()
            .any(|op| matches!(op, Op::Command(c) if c[0] == 0x05)));
        assert_eq!(
            pipe.log.last(),
            Some(&list(&[reset_error_counters(0), normal_mode(0)]))
        );
    }

    #[tokio::test]
    async fn off_high_speed_every_list_goes_in_64_byte_transfers() {
        let mut pipe = FakePipe::default();
        let info = FirmwareInfo::from_bytes(&firmware(2, 1)).unwrap();
        let pcan = options(PcanModel::UsbFd, 0, None);
        start(&mut pipe, &info, 0, timings(&pcan).unwrap(), true, false)
            .await
            .unwrap();
        let lengths: Vec<usize> = pipe
            .log
            .iter()
            .filter_map(|op| match op {
                Op::Command(c) => Some(c.len()),
                _ => None,
            })
            .collect();
        assert_eq!(
            lengths,
            [16, 16, 16, 16, 64, 64, 64, 64, 64, 64, 64, 64, 16, 32]
        );
    }

    #[tokio::test]
    async fn a_probe_reads_only_the_firmware_info() {
        let mut pipe = FakePipe {
            info: firmware(3, 0x0012_ABCD),
            ..FakePipe::default()
        };
        let info = device_info(&identify(&mut pipe).await.unwrap(), PcanModel::UsbX6);
        assert_eq!(pipe.log, [Op::Info]);
        assert_eq!(
            info,
            DeviceInfo {
                buses: Some(2),
                fd: true,
                firmware: Some("3.7.1".into()),
                serial: Some("0012ABCD".into()),
                hardware: Some("4".into()),
                clock_hz: Some(80_000_000),
                ..DeviceInfo::default()
            }
        );

        let erased = FirmwareInfo::from_bytes(&firmware(3, u32::MAX)).unwrap();
        assert_eq!(device_info(&erased, PcanModel::UsbFd).serial, None);

        let mut short = FakePipe {
            info: vec![0; 20],
            ..FakePipe::default()
        };
        assert!(matches!(
            identify(&mut short).await,
            Err(CanError::Handshake(_))
        ));
    }

    #[test]
    fn a_rate_the_80_mhz_clock_cant_time_is_refused() {
        let slow = PcanOptions {
            bitrate: 100,
            ..options(PcanModel::UsbFd, 0, None)
        };
        assert!(matches!(timings(&slow), Err(CanError::Config(_))));
        let fast_data = options(PcanModel::UsbFd, 0, Some((30_000_000, None)));
        let Err(CanError::Config(reason)) = timings(&fast_data) else {
            panic!("a config error");
        };
        assert!(reason.starts_with("30000000 bit/s at a 75%"), "{reason}");
    }

    #[tokio::test]
    async fn a_refusal_names_its_step_and_stopping_tries_every_step() {
        let mut pipe = FakePipe {
            broken: Some((0x004, io::ErrorKind::TimedOut)),
            ..FakePipe::default()
        };
        let info = FirmwareInfo::from_bytes(&firmware(2, 1)).unwrap();
        let pcan = options(PcanModel::UsbFd, 0, None);
        let error = start(&mut pipe, &info, 0, timings(&pcan).unwrap(), true, true)
            .await
            .unwrap_err();
        assert!(matches!(&error, CanError::Read(e) if e.to_string().starts_with("TIMING_SLOW")));

        let mut pipe = FakePipe {
            broken: Some((0x00c, io::ErrorKind::ConnectionAborted)),
            ..FakePipe::default()
        };
        stop(&mut pipe, 1, true).await;
        assert_eq!(
            pipe.log,
            [
                list(&[[0x0c, 0x10, 0x01, 0, 0, 0, 0x00, 0x80]]),
                list(&[reset_mode(1)]),
                Op::DriverLoaded(false),
            ]
        );
    }

    #[tokio::test]
    async fn a_channel_dropped_unstopped_stops_itself_and_a_stopped_one_only_once() {
        let mut dropped = FakePipe::default();
        drop(OnBus::new(&mut dropped, 1, false));
        let mut stopped = FakePipe::default();
        OnBus::new(&mut stopped, 1, false).stop().await;
        assert!(!dropped.log.is_empty());
        assert_eq!(dropped.log, stopped.log);
    }

    fn can_rx(ts: u64, channel_dlc: u8, flags: u16, id: u32, data: &[u8]) -> Vec<u8> {
        let size = (28 + data.len()).next_multiple_of(4);
        let mut r = vec![0u8; size];
        r[0..2].copy_from_slice(&(size as u16).to_le_bytes());
        r[2..4].copy_from_slice(&1u16.to_le_bytes());
        r[4..8].copy_from_slice(&(ts as u32).to_le_bytes());
        r[8..12].copy_from_slice(&((ts >> 32) as u32).to_le_bytes());
        r[20] = channel_dlc;
        r[22..24].copy_from_slice(&flags.to_le_bytes());
        r[24..28].copy_from_slice(&id.to_le_bytes());
        r[28..28 + data.len()].copy_from_slice(data);
        r
    }

    #[test]
    fn frames_of_both_channels_become_reads_and_the_rest_are_dropped() {
        let status = {
            let mut s = vec![0u8; 16];
            s[0] = 16;
            s[2] = 3;
            s[12] = 0x80;
            s
        };
        let fd: Vec<u8> = (0..12).collect();
        let buffer = [
            can_rx(0x1_0000_0010, 0x20, 0, 0x123, &[0xaa, 0xbb]),
            status,
            can_rx(0x20, 0x91, 0x10 | 0x20 | 0x40, 0xfff, &fd),
            can_rx(0x30, 0x41, 0x02 | 0x01, 0x1fff_ffff, &[]),
        ]
        .concat();
        let seen: Vec<_> = incoming(&buffer, &mut BusWatch::new(0))
            .into_iter()
            .map(|r| {
                let Stamp::Counter(us) = r.stamp else {
                    panic!("a device stamp");
                };
                (r.frame, r.direction, us)
            })
            .collect();
        let mut fd_frame = CanFrame::data(1, 0x7ff, false, true, true, fd);
        fd_frame.esi = true;
        assert_eq!(
            seen,
            [
                (
                    CanFrame::data(0, 0x123, false, false, false, vec![0xaa, 0xbb]),
                    Direction::Rx,
                    0x10,
                ),
                (fd_frame, Direction::Rx, 0x20),
                (
                    CanFrame::remote(1, 0x1fff_ffff, true, 4),
                    Direction::Rx,
                    0x30
                ),
            ]
        );
    }

    #[test]
    fn a_send_is_the_frame_on_this_tasks_channel_with_its_terminator() {
        let mut frame = CanFrame::data(1, 0x7ff, false, true, true, (1..=9).collect());
        frame.esi = true;
        let bytes = outgoing(&frame, 1);
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[..4], &[32, 0, 0x00, 0x10]);
        assert_eq!(&bytes[12..20], &[0x91, 0, 0x70, 0, 0xff, 0x07, 0, 0]);
        assert_eq!(&bytes[20..32], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0]);
        assert_eq!(&bytes[32..], &[0; 4]);

        let remote = outgoing(&CanFrame::remote(0, 0x10, true, 3), 0);
        assert_eq!(&remote[12..20], &[0x30, 0, 0x03, 0, 0x10, 0, 0, 0]);
        assert_eq!(remote.len(), 28);
    }

    fn status_record(channel_flags: u8) -> Vec<u8> {
        let mut r = vec![0u8; 16];
        r[0] = 16;
        r[2] = 3;
        r[12] = channel_flags;
        r
    }

    fn error_record(channel: u8, tx: u8, rx: u8) -> Vec<u8> {
        let mut r = vec![0u8; 16];
        r[0] = 16;
        r[2] = 2;
        r[12] = channel;
        r[14] = tx;
        r[15] = rx;
        r
    }

    fn watched(bus: &mut BusWatch, records: &[&[u8]]) -> Vec<BusState> {
        assert!(incoming(&records.concat(), bus).is_empty());
        bus.reports()
    }

    fn on(state: ErrorState, counters: Option<(u8, u8)>) -> BusState {
        BusState {
            state,
            tx_errors: counters.map(|c| c.0),
            rx_errors: counters.map(|c| c.1),
            ..BusState::active(1)
        }
    }

    #[test]
    fn each_status_bit_is_its_state_on_this_tasks_channel() {
        let mut bus = BusWatch::new(1);
        for (flag, state) in [
            (status::WARNING, ErrorState::Warning),
            (status::PASSIVE, ErrorState::Passive),
            (status::BUSOFF | status::PASSIVE, ErrorState::BusOff),
        ] {
            assert_eq!(
                watched(&mut bus, &[&status_record(1 | flag)]),
                [on(state, None)]
            );
        }
    }

    #[test]
    fn counters_ride_on_the_next_change_and_an_empty_status_zeroes_them() {
        let mut bus = BusWatch::new(1);
        let other_channel: [&[u8]; 2] =
            [&error_record(0, 200, 200), &status_record(status::PASSIVE)];
        assert_eq!(watched(&mut bus, &other_channel), []);
        assert_eq!(watched(&mut bus, &[&error_record(1, 100, 5)]), []);
        let warning = status_record(1 | status::WARNING);
        assert_eq!(
            watched(&mut bus, &[&warning]),
            [on(ErrorState::Warning, Some((100, 5)))]
        );
        assert_eq!(watched(&mut bus, &[&warning]), []);
        assert_eq!(
            watched(&mut bus, &[&status_record(1)]),
            [on(ErrorState::Active, Some((0, 0)))]
        );
    }

    #[tokio::test]
    async fn a_status_while_bus_off_is_ignored_until_the_restart() {
        let mut bus = BusWatch::new(1);
        bus.restart_after = Duration::ZERO;
        watched(&mut bus, &[&status_record(1 | status::BUSOFF)]);
        let ignored: [&[u8]; 2] = [&status_record(1), &status_record(1 | status::WARNING)];
        assert_eq!(watched(&mut bus, &ignored), []);

        let mut pipe = FakePipe::default();
        let info = FirmwareInfo::from_bytes(&firmware(2, 1)).unwrap();
        let restart = operational(&info, 1, false);
        bus.recover(transmit(&mut pipe, &restart, true)).await;
        assert_eq!(
            pipe.log,
            [list(&[
                reset_error_counters(1),
                set_iso(1, true),
                normal_mode(1)
            ])]
        );
        assert_eq!(bus.reports(), [on(ErrorState::Active, Some((0, 0)))]);
        assert_eq!(
            watched(&mut bus, &[&status_record(1 | status::WARNING)]),
            [on(ErrorState::Warning, Some((0, 0)))]
        );
    }
}
