//! PEAK-System's USB adapters as a host, over nusb on macOS and Windows: the
//! classic PCAN-USB by `wiretap_protocol::pcan_usb`, and the CAN FD family —
//! PCAN-USB FD, PCAN-Chip USB, PCAN-USB Pro FD and PCAN-USB X6 — by
//! `pcan_usb_fd`. The FD family is untested: no device of it has met this code.
//! On Linux the kernel's `peak_usb` driver makes each a SocketCAN interface.
//!
//! The classic device's 16-bit tick counter wraps every 2.8 s, so each stamp is
//! unwrapped against the host time since the last one. Listen-only is refused
//! below revision 4, where the kernel quietly leaves the device acking.

#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(dead_code, reason = "only the tests build it here")
)]

use std::{fmt, future::Future, io, time::Duration};

use tokio::time::{sleep, timeout_at, Instant};
use wiretap_protocol::{
    bittiming::cia_sample_point,
    can::ErrorState,
    pcan_usb::{
        btr_for_bitrate, decode_message, error_flags, function, serial_number, ticks_to_us, Btr,
        Command, Frame, Record, ARGS_BYTES, BERR_MASK, CLOCK_HZ, PID, SILENT_MODE_FROM_REV,
        TICK_SCALE, TICK_SHIFT,
    },
    pcan_usb_fd::{self, PID_CHIP_USB, PID_USB_FD, PID_USB_PRO_FD, PID_USB_X6},
};

use super::{
    clock::{Received, Stamp},
    usb::refused,
    BusState, CanError, CanFrame, DeviceInfo, Direction,
};

mod basic;
mod ucan;
#[cfg(any(target_os = "macos", target_os = "windows"))]
mod usb;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub use usb::{devices, open, probe};

/// The adapter, which picks the protocol. The four FD models are untested: no
/// device of theirs has met this code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PcanModel {
    Usb,
    UsbFd,
    ChipUsb,
    UsbProFd,
    UsbX6,
}

impl PcanModel {
    const ALL: [Self; 5] = [
        Self::Usb,
        Self::UsbFd,
        Self::ChipUsb,
        Self::UsbProFd,
        Self::UsbX6,
    ];

    pub fn from_pid(pid: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|model| model.pid() == pid)
    }

    pub fn pid(self) -> u16 {
        match self {
            Self::Usb => PID,
            Self::UsbFd => PID_USB_FD,
            Self::ChipUsb => PID_CHIP_USB,
            Self::UsbProFd => PID_USB_PRO_FD,
            Self::UsbX6 => PID_USB_X6,
        }
    }

    /// Per USB device: an X6 is several of two each.
    pub fn channels(self) -> u8 {
        pcan_usb_fd::product(self.pid()).map_or(1, |p| p.channels)
    }

    /// The models but this one among those `present`, in a fixed order.
    fn others(self, present: impl IntoIterator<Item = Self>) -> Vec<Self> {
        let present: Vec<Self> = present.into_iter().collect();
        Self::ALL
            .into_iter()
            .filter(|model| *model != self && present.contains(model))
            .collect()
    }

    /// CAN FD, and the uCAN protocol that comes with it.
    pub fn fd(self) -> bool {
        self != Self::Usb
    }
}

impl fmt::Display for PcanModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = pcan_usb_fd::product(self.pid()).map_or("PCAN-USB", |p| p.name);
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcanDevice {
    /// The `%08X` serial `probe` reports, which survives a replug; bus and
    /// address don't.
    pub serial: Option<String>,
    pub bus: u8,
    pub address: u8,
    pub product: String,
    pub model: PcanModel,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PcanOptions {
    pub device: PcanDevice,
    pub channel: u8,
    pub bitrate: u32,
    /// Percent; `None` is CiA's for the bitrate.
    pub sample_point: Option<f32>,
    /// CAN FD's data rate and its sample point, `None` being CiA's.
    pub data: Option<(u32, Option<f32>)>,
}

impl PcanOptions {
    /// Channel 0, classic, at CiA's sample point.
    pub fn new(device: PcanDevice, bitrate: u32) -> Self {
        Self {
            device,
            channel: 0,
            bitrate,
            sample_point: None,
            data: None,
        }
    }
}

/// ISO 11898-1's arbitration-phase ceiling; the timing search goes higher.
const NOMINAL_BITRATE_MAX: u32 = 1_000_000;

/// What the model can't do, refused before the adapter is claimed.
fn check(pcan: &PcanOptions) -> Result<(), CanError> {
    let model = pcan.device.model;
    if pcan.bitrate > NOMINAL_BITRATE_MAX {
        return Err(CanError::Config(format!(
            "{} bit/s is above classic CAN's {NOMINAL_BITRATE_MAX}",
            pcan.bitrate
        )));
    }
    if pcan.data.is_some() && !model.fd() {
        return Err(CanError::Config(format!("the {model} has no CAN FD")));
    }
    if pcan.channel >= model.channels() {
        return Err(CanError::Config(format!(
            "channel {} is not on the {model}, which has {}",
            pcan.channel,
            model.channels()
        )));
    }
    Ok(())
}

fn untimeable(bitrate: u32, sample_point: Option<f32>, clock_hz: u32) -> CanError {
    let sample_point = sample_point.unwrap_or_else(|| cia_sample_point(bitrate));
    CanError::Config(format!(
        "{bitrate} bit/s at a {sample_point}% sample point can't be timed from the {clock_hz} Hz clock"
    ))
}

fn selector(device: &PcanDevice) -> String {
    match &device.serial {
        Some(serial) => format!("pcan {serial}"),
        None => format!("pcan {}:{}", device.bus, device.address),
    }
}

fn not_opened(device: &PcanDevice) -> impl Fn(io::Error) -> CanError {
    let device = selector(device);
    move |source| CanError::Open {
        device: device.clone(),
        source,
    }
}

fn serial_text(serial: Option<u32>) -> Option<String> {
    serial.map(|sn| format!("{sn:08X}"))
}

/// The command endpoints.
trait Commands {
    fn send(&mut self, command: Command) -> impl Future<Output = io::Result<()>> + Send;

    fn get(&mut self, function: u8) -> impl Future<Output = io::Result<[u8; ARGS_BYTES]>> + Send;

    /// Blocking, for a drop: no runtime may be left to wait in.
    fn send_now(&mut self, command: Command) -> io::Result<()>;
}

const STARTUP: Duration = Duration::from_millis(10);

fn timing(pcan: &PcanOptions) -> Result<Btr, CanError> {
    btr_for_bitrate(pcan.bitrate, pcan.sample_point)
        .ok_or_else(|| untimeable(pcan.bitrate, pcan.sample_point, CLOCK_HZ))
}

/// The kernel driver's sequence.
async fn start(
    usb: &mut impl Commands,
    btr: Btr,
    rev: u8,
    listen_only: bool,
) -> Result<DeviceInfo, CanError> {
    if listen_only && rev < SILENT_MODE_FROM_REV {
        return Err(CanError::Config(
            "the device has no listen-only mode".to_owned(),
        ));
    }
    let info = identify(usb, rev).await?;
    let silent =
        (rev >= SILENT_MODE_FROM_REV).then(|| ("SET_BUS", Command::set_silent(listen_only)));
    let sequence = bus_off()
        .into_iter()
        .chain([
            ("BITRATE", Command::set_bitrate(btr)),
            ("ERR_FR", Command::set_error_frames(BERR_MASK)),
        ])
        .chain(silent)
        .chain([
            ("EXT_VCC", Command::set_ext_vcc(false)),
            ("SET_BUS", Command::set_bus(true)),
        ]);
    for (name, command) in sequence {
        usb.send(command).await.map_err(refused(name))?;
    }
    sleep(STARTUP).await;
    Ok(info)
}

fn bus_off() -> [(&'static str, Command); 2] {
    [
        ("SET_BUS", Command::set_bus(false)),
        ("REGISTER", Command::set_sja1000_init(true)),
    ]
}

/// The kernel's `pcan_usb_restart_async`, and the settle `start` waits too.
async fn restart(usb: &mut impl Commands) -> io::Result<()> {
    usb.send(Command::set_bus(true)).await?;
    sleep(STARTUP).await;
    Ok(())
}

async fn stop(usb: &mut impl Commands) {
    for (_, command) in bus_off() {
        let _ = usb.send(command).await;
    }
}

/// A started channel's command pipe. Dropped before `stop`, as when the runtime
/// shuts down around its task, it takes the bus off itself.
struct OnBus<C: Commands> {
    usb: C,
    stopped: bool,
}

impl<C: Commands> OnBus<C> {
    fn new(usb: C) -> Self {
        Self {
            usb,
            stopped: false,
        }
    }

    async fn stop(mut self) {
        stop(&mut self.usb).await;
        self.stopped = true;
    }
}

impl<C: Commands> Drop for OnBus<C> {
    fn drop(&mut self) {
        if !self.stopped {
            for (_, command) in bus_off() {
                let _ = self.usb.send_now(command);
            }
        }
    }
}

/// `SN` alone, a read, so the device is left as it was.
async fn identify(usb: &mut impl Commands, rev: u8) -> Result<DeviceInfo, CanError> {
    let serial = usb.get(function::SN).await.map_err(refused("SN"))?;
    Ok(DeviceInfo {
        buses: Some(1),
        serial: serial_text(serial_number(&serial)),
        hardware: Some(rev.to_string()),
        clock_hz: Some(CLOCK_HZ),
        ..DeviceInfo::default()
    })
}

/// The 16-bit tick count carried on across wraps by host time.
#[derive(Default)]
struct Ticks {
    last: Option<(u16, Instant)>,
    total: u64,
}

impl Ticks {
    fn unwrap(&mut self, ts: u16, now: Instant) -> u64 {
        self.total = match self.last {
            Some((last, then)) => {
                let delta = ts.wrapping_sub(last);
                let elapsed = (now.saturating_duration_since(then).as_micros() << TICK_SHIFT)
                    / u128::from(TICK_SCALE);
                let wraps = (elapsed + 0x8000).saturating_sub(delta.into()) / 0x1_0000;
                self.total + wraps as u64 * 0x1_0000 + u64::from(delta)
            }
            None => u64::from(ts),
        };
        self.last = Some((ts, now));
        self.total
    }
}

/// As the kernel's `restart-ms`, which a consumer of this library has no way to
/// set or act on.
const RESTART_AFTER: Duration = Duration::from_secs(1);

/// The SJA1000's error-warning and error-passive limits.
const WARNING_LIMIT: u8 = 96;
const PASSIVE_LIMIT: u8 = 128;

/// The channel's bus as its records tell it, and the reports owed on it, one
/// per change of state: the firmware has no heartbeat to time a clear by. A
/// bus-off channel holds there until it is restarted.
struct BusWatch {
    now: BusState,
    restart_after: Duration,
    restart_at: Option<Instant>,
    reports: Vec<BusState>,
}

impl BusWatch {
    fn new(bus: u8) -> Self {
        Self {
            now: BusState::active(bus),
            restart_after: RESTART_AFTER,
            restart_at: None,
            reports: Vec::new(),
        }
    }

    fn set(&mut self, state: ErrorState) {
        if self.restart_at.is_some() || state == self.now.state {
            return;
        }
        self.now.state = state;
        if state == ErrorState::BusOff {
            self.restart_at = Some(Instant::now() + self.restart_after);
        }
        self.reports.push(self.now.clone());
    }

    fn classic(&mut self, record: &Record) {
        match *record {
            Record::BusEvent { rxerr, txerr, .. } => {
                self.now.tx_errors = Some(txerr);
                self.now.rx_errors = Some(rxerr);
                if txerr < WARNING_LIMIT && rxerr < WARNING_LIMIT {
                    self.set(ErrorState::Active);
                }
            }
            Record::Error { flags, .. } => {
                let passive = [self.now.tx_errors, self.now.rx_errors]
                    .into_iter()
                    .flatten()
                    .any(|count| count >= PASSIVE_LIMIT);
                self.set(if flags & error_flags::BUS_OFF != 0 {
                    ErrorState::BusOff
                } else if flags & error_flags::BUS_HEAVY != 0 && passive {
                    ErrorState::Passive
                } else if flags & (error_flags::BUS_HEAVY | error_flags::BUS_LIGHT) != 0 {
                    ErrorState::Warning
                } else {
                    ErrorState::Active
                });
            }
            _ => {}
        }
    }

    fn reports(&mut self) -> Vec<BusState> {
        std::mem::take(&mut self.reports)
    }

    fn restart_due(&self) -> bool {
        self.restart_at.is_some_and(|at| at <= Instant::now())
    }

    /// `receive`, or `None` at once while a report is owed or a restart is
    /// due, or when one falls due first.
    async fn wait<T>(&self, receive: impl Future<Output = T>) -> Option<T> {
        if !self.reports.is_empty() || self.restart_due() {
            return None;
        }
        match self.restart_at {
            Some(at) => timeout_at(at, receive).await.ok(),
            None => Some(receive.await),
        }
    }

    /// A restart the device refuses is tried again a wait later.
    async fn recover(&mut self, restart: impl Future<Output = io::Result<()>>) {
        if !self.restart_due() {
            return;
        }
        if restart.await.is_err() {
            self.restart_at = Some(Instant::now() + self.restart_after);
            return;
        }
        self.restart_at = None;
        self.now = BusState {
            tx_errors: Some(0),
            rx_errors: Some(0),
            ..BusState::active(self.now.bus)
        };
        self.reports.push(self.now.clone());
    }
}

/// A message's frames, stamped; every other stamped record still moves the
/// count on.
fn incoming(message: &[u8], ticks: &mut Ticks, bus: &mut BusWatch, now: Instant) -> Vec<Received> {
    decode_message(message)
        .into_iter()
        .filter_map(|record| {
            bus.classic(&record);
            let ts = match &record {
                Record::Frame { ticks, .. } | Record::Timestamp(ticks) => *ticks,
                Record::Error { ticks, .. } | Record::BusEvent { ticks, .. } => (*ticks)?,
            };
            let us = ticks_to_us(ticks.unwrap(ts, now));
            let Record::Frame { frame, .. } = record else {
                return None;
            };
            Some(Received {
                direction: if frame.srr {
                    Direction::Tx
                } else {
                    Direction::Rx
                },
                frame: can_frame(frame),
                stamp: Stamp::Counter(us as u32),
                overflow: false,
            })
        })
        .collect()
}

fn can_frame(frame: Frame) -> CanFrame {
    if frame.rtr {
        CanFrame::remote(0, frame.arb_id, frame.extended, frame.dlc)
    } else {
        CanFrame::data(0, frame.arb_id, frame.extended, false, false, frame.data)
    }
}

fn outgoing(frame: &CanFrame, srr: bool) -> Frame {
    Frame {
        arb_id: frame.arb_id,
        extended: frame.extended,
        rtr: frame.rtr,
        dlc: frame.dlc(),
        data: frame.data.clone(),
        srr,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::sync::mpsc;
    use wiretap_protocol::pcan_usb::{encode_transmit, number, COMMAND_BYTES};

    use super::*;
    use crate::can::{
        task::{self, Device},
        writer::Limits,
        CanEvent, CanOptions, CanTask,
    };

    #[derive(Default)]
    struct FakeUsb {
        log: Vec<[u8; COMMAND_BYTES]>,
        broken: Option<(u8, io::ErrorKind)>,
        erased: bool,
    }

    impl FakeUsb {
        fn fail(&self, function: u8) -> io::Result<()> {
            match self.broken {
                Some((broken, kind)) if broken == function => Err(kind.into()),
                _ => Ok(()),
            }
        }
    }

    impl Commands for FakeUsb {
        async fn send(&mut self, command: Command) -> io::Result<()> {
            self.log.push(command.to_bytes());
            self.fail(command.function)
        }

        async fn get(&mut self, function: u8) -> io::Result<[u8; ARGS_BYTES]> {
            self.log.push(Command::get(function).to_bytes());
            self.fail(function)?;
            let mut args = [0u8; ARGS_BYTES];
            if function == function::SN {
                let sn = if self.erased { u32::MAX } else { 0x0012_ABCD };
                args[..4].copy_from_slice(&sn.to_le_bytes());
            }
            Ok(args)
        }

        fn send_now(&mut self, _: Command) -> io::Result<()> {
            unreachable!("only a drop sends now")
        }
    }

    fn command(bytes: &[u8]) -> [u8; COMMAND_BYTES] {
        let mut b = [0u8; COMMAND_BYTES];
        b[..bytes.len()].copy_from_slice(bytes);
        b
    }

    fn device(model: PcanModel) -> PcanDevice {
        PcanDevice {
            serial: None,
            bus: 1,
            address: 2,
            product: model.to_string(),
            model,
        }
    }

    const BTR_500K: Btr = Btr {
        btr0: 0x00,
        btr1: 0x1c,
    };

    #[tokio::test]
    async fn a_start_sends_the_kernels_sequence_byte_for_byte() {
        for listen_only in [true, false] {
            let mut usb = FakeUsb::default();
            let btr = timing(&PcanOptions::new(device(PcanModel::Usb), 500_000)).unwrap();
            assert_eq!(btr, BTR_500K);
            let info = start(&mut usb, btr, 84, listen_only).await.unwrap();
            assert_eq!(
                usb.log,
                [
                    command(&[6, 1]),
                    command(&[3, 2, 0]),
                    command(&[9, 2, 0, 1]),
                    command(&[1, 2, 0x1c, 0x00]),
                    command(&[11, 2, 0x06]),
                    command(&[3, 3, listen_only.into()]),
                    command(&[10, 2, 0]),
                    command(&[3, 2, 1]),
                ]
            );
            assert_eq!(
                info,
                DeviceInfo {
                    buses: Some(1),
                    serial: Some("0012ABCD".into()),
                    hardware: Some("84".into()),
                    clock_hz: Some(8_000_000),
                    ..DeviceInfo::default()
                }
            );
        }
    }

    #[tokio::test]
    async fn an_early_revision_is_never_told_silent_mode() {
        let mut usb = FakeUsb::default();
        start(&mut usb, BTR_500K, 3, false).await.unwrap();
        assert!(!usb.log.iter().any(|c| c[..2] == [3, number::SILENT_MODE]));
        assert_eq!(usb.log.len(), 7);
    }

    #[tokio::test]
    async fn a_probe_sends_only_get_sn_and_an_erased_serial_is_none() {
        let mut usb = FakeUsb::default();
        let info = identify(&mut usb, 84).await.unwrap();
        assert_eq!(usb.log, [command(&[6, 1])]);
        assert_eq!(info.serial.as_deref(), Some("0012ABCD"));

        let mut erased = FakeUsb {
            erased: true,
            ..FakeUsb::default()
        };
        assert_eq!(identify(&mut erased, 84).await.unwrap().serial, None);
    }

    #[tokio::test]
    async fn what_the_device_cant_do_is_refused_before_a_command() {
        let untimeable = PcanOptions::new(device(PcanModel::Usb), 1_000);
        let CanError::Config(reason) = timing(&untimeable).unwrap_err() else {
            panic!("a config error");
        };
        assert!(
            reason.contains("1000 bit/s") && reason.contains("87.5%"),
            "{reason}"
        );

        let mut usb = FakeUsb::default();
        let error = start(&mut usb, BTR_500K, 3, true).await.unwrap_err();
        assert!(matches!(error, CanError::Config(_)), "{error:?}");
        assert!(usb.log.is_empty());
    }

    #[test]
    fn each_pid_is_its_model_with_its_name_and_channels() {
        let seen: Vec<_> = [0x000c, 0x0012, 0x0013, 0x0011, 0x0014]
            .into_iter()
            .map(|pid| {
                let model = PcanModel::from_pid(pid).unwrap();
                (model.to_string(), model.channels(), model.fd(), model.pid())
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("PCAN-USB".into(), 1, false, 0x000c),
                ("PCAN-USB FD".into(), 1, true, 0x0012),
                ("PCAN-Chip USB".into(), 1, true, 0x0013),
                ("PCAN-USB Pro FD".into(), 2, true, 0x0011),
                ("PCAN-USB X6".into(), 2, true, 0x0014),
            ]
        );
        assert_eq!(PcanModel::from_pid(0x000d), None);
    }

    #[test]
    fn a_serial_is_looked_for_in_each_other_model_plugged_in_once() {
        use PcanModel::*;
        assert_eq!(Usb.others([UsbX6, Usb, UsbFd, UsbX6]), [UsbFd, UsbX6]);
        assert_eq!(UsbFd.others([UsbFd]), []);
        assert_eq!(ChipUsb.others([]), []);
    }

    #[test]
    fn what_the_model_hasnt_got_is_refused_before_a_claim() {
        let config = |model, channel, data| {
            let mut pcan = PcanOptions::new(device(model), 500_000);
            pcan.channel = channel;
            pcan.data = data;
            match check(&pcan) {
                Err(CanError::Config(reason)) => Some(reason),
                Err(other) => panic!("{other:?}"),
                Ok(()) => None,
            }
        };
        assert_eq!(
            config(PcanModel::Usb, 0, Some((2_000_000, None))).as_deref(),
            Some("the PCAN-USB has no CAN FD")
        );
        assert_eq!(
            config(PcanModel::Usb, 1, None).as_deref(),
            Some("channel 1 is not on the PCAN-USB, which has 1")
        );
        assert_eq!(
            config(PcanModel::UsbFd, 1, Some((2_000_000, None))).as_deref(),
            Some("channel 1 is not on the PCAN-USB FD, which has 1")
        );
        assert_eq!(
            config(PcanModel::UsbProFd, 1, Some((2_000_000, None))),
            None
        );
        assert_eq!(
            config(PcanModel::UsbX6, 2, None).as_deref(),
            Some("channel 2 is not on the PCAN-USB X6, which has 2")
        );
    }

    #[test]
    fn a_nominal_bitrate_above_1_mbit_is_refused_before_a_claim() {
        let at = |model, bitrate| check(&PcanOptions::new(device(model), bitrate));
        assert!(at(PcanModel::Usb, 1_000_000).is_ok());
        for model in [PcanModel::Usb, PcanModel::UsbFd] {
            let Err(CanError::Config(reason)) = at(model, 2_000_000) else {
                panic!("2 Mbit/s taken on the {model}");
            };
            assert!(
                reason.contains("2000000 bit/s") && reason.contains("1000000"),
                "{reason}"
            );
        }
    }

    #[tokio::test]
    async fn a_device_gone_mid_start_is_closed_and_a_refusal_names_its_command() {
        let mut usb = FakeUsb {
            broken: Some((function::BITRATE, io::ErrorKind::ConnectionAborted)),
            ..FakeUsb::default()
        };
        let error = start(&mut usb, BTR_500K, 84, false).await.unwrap_err();
        assert!(matches!(error, CanError::Closed), "{error:?}");
        assert!(!usb.log.contains(&command(&[3, 2, 1])));

        usb.broken = Some((function::SN, io::ErrorKind::TimedOut));
        let error = start(&mut usb, BTR_500K, 84, false).await.unwrap_err();
        assert!(matches!(&error, CanError::Read(e) if e.to_string().starts_with("SN")));
    }

    #[tokio::test]
    async fn stopping_takes_the_bus_off_and_resets_the_controller() {
        let mut usb = FakeUsb {
            broken: Some((function::SET_BUS, io::ErrorKind::ConnectionAborted)),
            ..FakeUsb::default()
        };
        stop(&mut usb).await;
        assert_eq!(usb.log, [command(&[3, 2, 0]), command(&[9, 2, 0, 1])]);
    }

    fn message(records: &[&[u8]]) -> Vec<u8> {
        let mut m = vec![0x00, records.len() as u8];
        m.extend(records.concat());
        m
    }

    #[test]
    fn frames_become_reads_with_their_direction_and_the_rest_are_dropped() {
        let m = message(&[
            &[0x02, 0x60, 0x24, 0x00, 0x10, 0xaa, 0xbb],
            &[0xc0, 1, 0x10, 0x20],
            &[0x21, 0x81, 0x88, 0xd7, 0xc6, 0x30, 1, 0x80],
            &[0x13, 0xe0, 0xff, 0x40],
            &[0x43, 5, 0x80, 0, 7, 9],
        ]);
        let received = incoming(
            &m,
            &mut Ticks::default(),
            &mut BusWatch::new(0),
            Instant::now(),
        );
        let seen: Vec<_> = received
            .iter()
            .map(|r| {
                let Stamp::Counter(us) = r.stamp else {
                    panic!("a device stamp");
                };
                (r.frame.clone(), r.direction, us)
            })
            .collect();
        assert_eq!(
            seen,
            [
                (
                    CanFrame::data(0, 0x123, false, false, false, vec![0xaa, 0xbb]),
                    Direction::Rx,
                    ticks_to_us(0x1000) as u32,
                ),
                (
                    CanFrame::data(0, 0x18da_f110, true, false, false, vec![1]),
                    Direction::Tx,
                    ticks_to_us(0x1030) as u32,
                ),
                (
                    CanFrame::remote(0, 0x7ff, false, 3),
                    Direction::Rx,
                    ticks_to_us(0x1040) as u32,
                ),
            ]
        );
    }

    #[test]
    fn a_three_second_gap_unwraps_once_and_a_read_does_not() {
        let at = Instant::now();
        let mut ticks = Ticks::default();
        assert_eq!(ticks.unwrap(0xff00, at), 0xff00);
        assert_eq!(ticks.unwrap(0x0010, at), 0x1_0010);
        assert_eq!(ticks.unwrap(0x7000, at), 0x1_7000);

        let three_seconds = 70_312;
        let later = at + Duration::from_secs(3);
        let ts = (0x1_7000u64 + three_seconds) as u16;
        assert_eq!(ticks.unwrap(ts, later), 0x1_7000 + three_seconds);
        assert_eq!(
            ticks.unwrap(ts.wrapping_add(5), later),
            0x1_7000 + three_seconds + 5
        );
    }

    #[test]
    fn a_sync_moves_the_count_on_without_becoming_a_read() {
        let at = Instant::now();
        let mut ticks = Ticks::default();
        let sync = message(&[&[0x42, 4, 0, 0x00, 0xf0]]);
        let bus = &mut BusWatch::new(0);
        assert!(incoming(&sync, &mut ticks, bus, at).is_empty());
        let frame = message(&[&[0x00, 0x20, 0x00, 0x10, 0x00]]);
        let received = incoming(&frame, &mut ticks, bus, at + Duration::from_millis(20));
        assert!(
            matches!(received[0].stamp, Stamp::Counter(us) if u64::from(us) == ticks_to_us(0x1_0010))
        );
    }

    #[test]
    fn a_send_is_one_message_with_srr_only_when_echo_is_on() {
        let frame = CanFrame::data(0, 0x123, false, false, false, vec![1, 2, 3]);
        let plain = encode_transmit(&outgoing(&frame, false), 9);
        assert_eq!(&plain[..8], &[2, 1, 0x03, 0x60, 0x24, 1, 2, 3]);
        assert_eq!((plain[8], plain[63]), (0, 9));

        let echoed = encode_transmit(&outgoing(&frame, true), 10);
        assert_eq!(&echoed[..9], &[2, 1, 0x03, 0x61, 0x24, 1, 2, 3, 0x80]);

        let remote = encode_transmit(&outgoing(&CanFrame::remote(0, 0x10, true, 4), false), 0);
        assert_eq!(&remote[..7], &[2, 1, 0x34, 0x80, 0, 0, 0]);
    }

    fn error(flags: u8) -> Vec<u8> {
        vec![0x40, 1, flags]
    }

    fn bus_event(rxerr: u8, txerr: u8) -> Vec<u8> {
        vec![0x43, 5, 0x80, 0, rxerr, txerr]
    }

    fn watched(bus: &mut BusWatch, records: &[&[u8]]) -> Vec<BusState> {
        incoming(
            &message(records),
            &mut Ticks::default(),
            bus,
            Instant::now(),
        );
        bus.reports()
    }

    fn on(state: ErrorState, tx_errors: Option<u8>, rx_errors: Option<u8>) -> BusState {
        BusState {
            state,
            tx_errors,
            rx_errors,
            ..BusState::active(0)
        }
    }

    #[test]
    fn heavy_is_passive_past_a_count_of_127_and_else_warning_as_light_is() {
        use error_flags::{BUS_HEAVY, BUS_LIGHT};
        let mut bus = BusWatch::new(0);
        assert_eq!(watched(&mut bus, &[&bus_event(0, 100)]), []);
        assert_eq!(
            watched(&mut bus, &[&bus_event(0, 130), &error(BUS_HEAVY)]),
            [on(ErrorState::Passive, Some(130), Some(0))]
        );

        let mut bus = BusWatch::new(0);
        assert_eq!(
            watched(&mut bus, &[&bus_event(0, 100), &error(BUS_HEAVY)]),
            [on(ErrorState::Warning, Some(100), Some(0))]
        );
        assert_eq!(watched(&mut bus, &[&error(BUS_LIGHT)]), []);

        let mut bus = BusWatch::new(0);
        assert_eq!(
            watched(&mut bus, &[&error(BUS_LIGHT)]),
            [on(ErrorState::Warning, None, None)]
        );
    }

    #[test]
    fn an_error_without_bus_bits_or_both_counts_below_96_is_back_to_active() {
        use error_flags::{BUS_HEAVY, RXQOVR};
        let mut bus = BusWatch::new(0);
        watched(&mut bus, &[&bus_event(0, 100), &error(BUS_HEAVY)]);
        assert_eq!(
            watched(&mut bus, &[&error(RXQOVR)]),
            [on(ErrorState::Active, Some(100), Some(0))]
        );

        watched(&mut bus, &[&bus_event(130, 0), &error(BUS_HEAVY)]);
        assert_eq!(watched(&mut bus, &[&bus_event(100, 0)]), []);
        assert_eq!(
            watched(&mut bus, &[&bus_event(95, 0)]),
            [on(ErrorState::Active, Some(0), Some(95))]
        );
    }

    #[tokio::test]
    async fn bus_off_is_reported_once_and_held_until_a_restart_the_device_takes() {
        let mut bus = BusWatch::new(0);
        bus.restart_after = Duration::ZERO;
        let off = [on(ErrorState::BusOff, None, None)];
        assert_eq!(watched(&mut bus, &[&error(error_flags::BUS_OFF)]), off);
        assert_eq!(watched(&mut bus, &[&error(error_flags::BUS_OFF)]), []);
        assert_eq!(watched(&mut bus, &[&error(0), &bus_event(0, 0)]), []);
        assert!(bus.wait(std::future::pending::<()>()).await.is_none());

        let mut refusing = FakeUsb {
            broken: Some((function::SET_BUS, io::ErrorKind::TimedOut)),
            ..FakeUsb::default()
        };
        bus.recover(restart(&mut refusing)).await;
        assert_eq!(bus.reports(), []);

        let mut usb = FakeUsb::default();
        bus.recover(restart(&mut usb)).await;
        assert_eq!(usb.log, [command(&[3, 2, 1])]);
        assert_eq!(bus.reports(), [on(ErrorState::Active, Some(0), Some(0))]);
        bus.recover(restart(&mut usb)).await;
        assert_eq!(usb.log.len(), 1);
    }

    type Script = Result<Vec<u8>, CanError>;

    struct Bench {
        messages: Mutex<Option<mpsc::UnboundedReceiver<Script>>>,
        commands: Mutex<Vec<[u8; COMMAND_BYTES]>>,
        restart_after: Duration,
    }

    impl Commands for Arc<Bench> {
        async fn send(&mut self, command: Command) -> io::Result<()> {
            self.commands.lock().unwrap().push(command.to_bytes());
            Ok(())
        }

        async fn get(&mut self, _: u8) -> io::Result<[u8; ARGS_BYTES]> {
            unreachable!("only a start reads")
        }

        fn send_now(&mut self, command: Command) -> io::Result<()> {
            self.commands.lock().unwrap().push(command.to_bytes());
            Ok(())
        }
    }

    /// The classic `Device`'s glue over a scripted bulk-IN and a logged command pipe.
    struct Rigged {
        messages: Option<mpsc::UnboundedReceiver<Script>>,
        commands: OnBus<Arc<Bench>>,
        ticks: Ticks,
        bus: BusWatch,
    }

    impl Device for Rigged {
        type Config = Arc<Bench>;

        async fn open(bench: &Arc<Bench>, _: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
            let mut bus = BusWatch::new(0);
            bus.restart_after = bench.restart_after;
            let rigged = Self {
                messages: bench.messages.lock().unwrap().take(),
                commands: OnBus::new(bench.clone()),
                ticks: Ticks::default(),
                bus,
            };
            Ok((rigged, DeviceInfo::default()))
        }

        fn limits(&self) -> Limits {
            Limits {
                fd: false,
                brs: false,
                rtr: true,
                buses: Some(1),
            }
        }

        async fn read(&mut self) -> Result<Vec<Received>, CanError> {
            let messages = self.messages.as_mut().expect("one device open at a time");
            let Some(message) = self.bus.wait(messages.recv()).await else {
                return Ok(Vec::new());
            };
            let Some(message) = message else {
                return std::future::pending().await;
            };
            Ok(incoming(
                &message?,
                &mut self.ticks,
                &mut self.bus,
                Instant::now(),
            ))
        }

        async fn write(&mut self, _: &CanFrame) -> io::Result<()> {
            Ok(())
        }

        fn bus_reports(&mut self) -> Vec<BusState> {
            self.bus.reports()
        }

        async fn recover(&mut self) {
            self.bus.recover(restart(&mut self.commands.usb)).await;
        }

        async fn close(self) {
            *self.commands.usb.messages.lock().unwrap() = self.messages;
            self.commands.stop().await;
        }
    }

    fn bench(restart_after: Duration) -> (Arc<Bench>, mpsc::UnboundedSender<Script>) {
        let (script, messages) = mpsc::unbounded_channel();
        let bench = Bench {
            messages: Mutex::new(Some(messages)),
            commands: Mutex::default(),
            restart_after,
        };
        (Arc::new(bench), script)
    }

    async fn next(task: &mut CanTask) -> CanEvent {
        tokio::time::timeout(Duration::from_secs(5), task.next_event())
            .await
            .expect("an event in time")
            .expect("the task running")
    }

    async fn next_bus(task: &mut CanTask) -> BusState {
        match next(task).await {
            CanEvent::Bus(state) => state,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_bus_off_channel_is_restarted_in_place_after_the_wait_and_reported_active() {
        let (bench, script) = bench(Duration::from_millis(50));
        let options = CanOptions {
            reopen: None,
            ..CanOptions::default()
        };
        let mut task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        script
            .send(Ok(message(&[&error(error_flags::BUS_OFF)])))
            .unwrap();
        let since = std::time::Instant::now();
        assert_eq!(next_bus(&mut task).await.state, ErrorState::BusOff);
        assert_eq!(
            next_bus(&mut task).await,
            on(ErrorState::Active, Some(0), Some(0))
        );
        assert!(since.elapsed() >= Duration::from_millis(50));
        assert_eq!(*bench.commands.lock().unwrap(), [command(&[3, 2, 1])]);
    }

    #[tokio::test]
    async fn a_reopened_channel_starts_clean_of_a_bus_off() {
        let (bench, script) = bench(Duration::from_secs(60));
        let options = CanOptions {
            reopen: Some(Duration::from_millis(1)),
            ..CanOptions::default()
        };
        let mut task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        next(&mut task).await;
        script
            .send(Ok(message(&[&error(error_flags::BUS_OFF)])))
            .unwrap();
        assert_eq!(next_bus(&mut task).await.state, ErrorState::BusOff);
        script.send(Err(CanError::Closed)).unwrap();
        assert!(matches!(
            next(&mut task).await,
            CanEvent::Disconnected { .. }
        ));
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        script
            .send(Ok(message(&[&error(error_flags::BUS_LIGHT)])))
            .unwrap();
        assert_eq!(next_bus(&mut task).await.state, ErrorState::Warning);
        assert_eq!(*bench.commands.lock().unwrap(), bus_off_commands());
    }

    fn bus_off_commands() -> Vec<[u8; COMMAND_BYTES]> {
        bus_off().map(|(_, command)| command.to_bytes()).to_vec()
    }

    #[tokio::test]
    async fn a_stopped_channel_is_taken_off_the_bus_once() {
        let (bench, _script) = bench(Duration::from_secs(60));
        let mut task = task::open::<Rigged>(bench.clone(), CanOptions::default())
            .await
            .unwrap();
        next(&mut task).await;
        task.stop().await;
        assert_eq!(*bench.commands.lock().unwrap(), bus_off_commands());
    }

    #[test]
    fn a_runtime_shut_down_without_stop_still_takes_the_bus_off() {
        let (bench, _script) = bench(Duration::from_secs(60));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let task = runtime.block_on(async {
            let mut task = task::open::<Rigged>(bench.clone(), CanOptions::default())
                .await
                .unwrap();
            next(&mut task).await;
            task
        });
        drop(runtime);
        assert_eq!(*bench.commands.lock().unwrap(), bus_off_commands());
        drop(task);
    }
}
