//! gs_usb (candleLight) as a host: `wiretap_protocol::gs_usb` over nusb, one
//! channel per task, on macOS and Windows. On Linux the kernel's `gs_usb`
//! driver binds the adapter, and it is a SocketCAN interface instead; there
//! `devices` reads sysfs for the interface each channel became.
//!
//! The device's µs counter stamps each frame when `BT_CONST` offers
//! `HW_TIMESTAMP`; without it a frame takes its read's time.

#![cfg_attr(
    not(any(target_os = "macos", target_os = "windows")),
    allow(
        dead_code,
        reason = "only the tests and the Linux listing build it here"
    )
)]

use std::{future::Future, io, time::Duration};

use tokio::time::{timeout_at, Instant};
use wiretap_protocol::{
    can::{ErrorFrame, ErrorState},
    gs_usb::{
        bittiming_for_bitrate, calculate_bittiming, can_feature, can_mode, encode_host_frame,
        host_frame_timestamp, parse_host_frame, BittimingConstraints, Breq, BtConst,
        BtConstExtended, DeviceConfig, HostFrame, Mode, CLASSIC_FRAME_BYTES, FD_FRAME_BYTES,
        HOST_FORMAT, TIMESTAMP_BYTES,
    },
};

use super::{
    clock::{Received, Stamp},
    usb::refused,
    BusState, CanError, CanFrame, DeviceInfo, Direction,
};

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod usb;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub use usb::{devices, open, probe};
#[cfg(any(target_os = "linux", all(test, unix)))]
mod sysfs;
#[cfg(target_os = "linux")]
pub use sysfs::{devices, LinuxGsUsbDevice};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GsUsbDevice {
    /// Reopened by this where the device has one; bus and address change on a
    /// replug.
    pub serial: Option<String>,
    pub bus: u8,
    pub address: u8,
    pub product: String,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct GsUsbOptions {
    pub device: GsUsbDevice,
    pub channel: u8,
    pub bitrate: u32,
    /// Percent; `None` is 87.5.
    pub sample_point: Option<f32>,
    /// CAN FD's data rate and its sample point, `None` being 75.
    pub data: Option<(u32, Option<f32>)>,
    /// For firmware that won't report its clock.
    pub clock_hz: Option<u32>,
}

impl GsUsbOptions {
    /// Channel 0, classic, at the default sample point and the device's clock.
    pub fn new(device: GsUsbDevice, bitrate: u32) -> Self {
        Self {
            device,
            channel: 0,
            bitrate,
            sample_point: None,
            data: None,
            clock_hz: None,
        }
    }
}

/// Vendor requests to interface 0 on the default control endpoint.
trait Control {
    fn get(
        &self,
        request: Breq,
        value: u16,
        length: usize,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send;

    fn set(
        &self,
        request: Breq,
        value: u16,
        data: &[u8],
    ) -> impl Future<Output = io::Result<()>> + Send;
}

struct Started {
    info: DeviceInfo,
    fd: bool,
    timestamps: bool,
}

impl Started {
    /// One frame per transfer, and a packet multiple so the largest frame the
    /// channel sends can't overrun it.
    fn transfer_len(&self, packet: usize) -> usize {
        let frame = if self.fd {
            FD_FRAME_BYTES
        } else {
            CLASSIC_FRAME_BYTES
        };
        let stamp = if self.timestamps { TIMESTAMP_BYTES } else { 0 };
        (frame + stamp).next_multiple_of(packet)
    }
}

/// The kernel driver's sequence, with `DEVICE_CONFIG` to check the channel and
/// `HW_TIMESTAMP` wherever it is offered.
async fn start(
    usb: &impl Control,
    gs: &GsUsbOptions,
    listen_only: bool,
) -> Result<Started, CanError> {
    let channel = u16::from(gs.channel);
    usb.set(Breq::HostFormat, 1, &HOST_FORMAT.to_le_bytes())
        .await
        .map_err(refused("HOST_FORMAT"))?;
    let config = device_config(usb).await?;
    if gs.channel >= config.channels() {
        return Err(CanError::Config(format!(
            "channel {} is not on the device, which has {}",
            gs.channel,
            config.channels()
        )));
    }
    let bt = bt_const(usb, channel).await?;
    let offers = |feature| bt.feature & feature != 0;
    if gs.data.is_some() && !offers(can_feature::FD) {
        return Err(CanError::Config("the device has no CAN FD".to_owned()));
    }
    if listen_only && !offers(can_feature::LISTEN_ONLY) {
        return Err(CanError::Config(
            "the device has no listen-only mode".to_owned(),
        ));
    }

    usb.set(Breq::Mode, channel, &Mode::RESET.to_bytes())
        .await
        .map_err(refused("MODE"))?;
    let fclk = gs.clock_hz.unwrap_or(bt.fclk_can);
    let sample_point = gs.sample_point.unwrap_or(87.5);
    let nominal = if fclk == 0 {
        bittiming_for_bitrate(gs.bitrate)
    } else {
        calculate_bittiming(fclk, gs.bitrate, sample_point, &bt.nominal)
    }
    .ok_or_else(|| untimeable(gs.bitrate, sample_point, fclk, &bt.nominal))?;
    usb.set(Breq::Bittiming, channel, &nominal.to_bytes())
        .await
        .map_err(refused("BITTIMING"))?;

    let mut flags = if listen_only {
        can_mode::LISTEN_ONLY
    } else {
        can_mode::NORMAL
    };
    if let Some((bitrate, sample_point)) = gs.data {
        let ext = if offers(can_feature::BT_CONST_EXT) {
            usb.get(Breq::BtConstExt, channel, BtConstExtended::SIZE)
                .await
                .ok()
                .and_then(|ext| BtConstExtended::from_bytes(&ext))
        } else {
            None
        };
        let (fclk, constraints) = match ext {
            Some(ext) => (gs.clock_hz.unwrap_or(ext.fclk_can), ext.data),
            None => (fclk, bt.nominal),
        };
        let sample_point = sample_point.unwrap_or(75.0);
        let data = calculate_bittiming(fclk, bitrate, sample_point, &constraints)
            .ok_or_else(|| untimeable(bitrate, sample_point, fclk, &constraints))?;
        usb.set(Breq::DataBittiming, channel, &data.to_bytes())
            .await
            .map_err(refused("DATA_BITTIMING"))?;
        flags |= can_mode::FD;
    }
    let timestamps = offers(can_feature::HW_TIMESTAMP);
    if timestamps {
        flags |= can_mode::HW_TIMESTAMP;
    }
    usb.set(Breq::Mode, channel, &Mode::start(flags).to_bytes())
        .await
        .map_err(refused("MODE"))?;

    Ok(Started {
        info: info(&config, Some(&bt)),
        fd: gs.data.is_some(),
        timestamps,
    })
}

/// `DEVICE_CONFIG` and channel 0's `BT_CONST`: control-in only, so the device
/// is left as it was. Without `BT_CONST` there is no FD and no clock.
async fn identify(usb: &impl Control, deadline: Instant) -> Result<DeviceInfo, CanError> {
    let asked = async {
        let config = device_config(usb).await?;
        let bt = bt_const(usb, 0).await.ok();
        Ok(info(&config, bt.as_ref()))
    };
    timeout_at(deadline, asked)
        .await
        .unwrap_or_else(|_| Err(CanError::Read(io::ErrorKind::TimedOut.into())))
}

async fn device_config(usb: &impl Control) -> Result<DeviceConfig, CanError> {
    let config = usb
        .get(Breq::DeviceConfig, 1, DeviceConfig::SIZE)
        .await
        .map_err(refused("DEVICE_CONFIG"))?;
    DeviceConfig::from_bytes(&config).ok_or(CanError::Handshake("the DEVICE_CONFIG reply is short"))
}

async fn bt_const(usb: &impl Control, channel: u16) -> Result<BtConst, CanError> {
    let bt = usb
        .get(Breq::BtConst, channel, BtConst::SIZE)
        .await
        .map_err(refused("BT_CONST"))?;
    BtConst::from_bytes(&bt).ok_or(CanError::Handshake("the BT_CONST reply is short"))
}

fn info(config: &DeviceConfig, bt: Option<&BtConst>) -> DeviceInfo {
    DeviceInfo {
        buses: Some(config.channels()),
        fd: bt.is_some_and(|bt| bt.feature & can_feature::FD != 0),
        firmware: Some(config.sw_version.to_string()),
        hardware: Some(config.hw_version.to_string()),
        clock_hz: bt.map(|bt| bt.fclk_can),
        ..DeviceInfo::default()
    }
}

fn untimeable(
    bitrate: u32,
    sample_point: f32,
    fclk: u32,
    limits: &BittimingConstraints,
) -> CanError {
    CanError::Config(format!(
        "{bitrate} bit/s at a {sample_point}% sample point can't be timed from a {fclk} Hz clock \
         within the device's limits (tseg1 {}–{}, tseg2 {}–{}, sjw up to {}, brp {}–{} by {})",
        limits.tseg1_min,
        limits.tseg1_max,
        limits.tseg2_min,
        limits.tseg2_max,
        limits.sjw_max,
        limits.brp_min,
        limits.brp_max,
        limits.brp_inc,
    ))
}

/// A data frame, or `None` if it stops before its stamp on a stamped channel,
/// as the kernel drops it.
fn received(frame: HostFrame, bytes: &[u8], timestamps: bool) -> Option<Received> {
    let stamp = if timestamps {
        Stamp::Counter(host_frame_timestamp(bytes, frame.fd)?)
    } else {
        Stamp::Read
    };
    Some(Received {
        direction: if frame.is_rx() {
            Direction::Rx
        } else {
            Direction::Tx
        },
        overflow: frame.overflow,
        frame: can_frame(frame),
        stamp,
    })
}

fn can_frame(frame: HostFrame) -> CanFrame {
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

fn outgoing(frame: &CanFrame, echo_id: u32) -> Vec<u8> {
    encode_host_frame(&HostFrame {
        echo_id,
        dlc: frame.dlc(),
        ..HostFrame::transmit(
            frame.arb_id,
            frame.extended,
            frame.rtr,
            frame.fd,
            frame.brs,
            frame.bus,
            frame.data.clone(),
        )
    })
}

/// The kernel's `GS_MAX_TX_URBS`.
const ECHO_SLOTS: usize = 10;

/// A stuck-chip guard: candleLight repeats a report every 3 s while either
/// counter is non-zero, so this long with none is a clear bus.
const QUIET: Duration = Duration::from_secs(5);

/// The error-warning limit; candleLight reports back-to-active below it.
const WARNING_LIMIT: u8 = 96;

/// The channel's bus as its error frames tell it, and the reports owed on it.
/// `state` is the device's last word on it.
struct BusWatch {
    now: BusState,
    reported: (ErrorState, bool),
    quiet: Duration,
    quiet_at: Option<Instant>,
    reports: Vec<BusState>,
}

impl BusWatch {
    fn new(channel: u8) -> Self {
        Self {
            now: BusState::active(channel),
            reported: (ErrorState::Active, false),
            quiet: QUIET,
            quiet_at: None,
            reports: Vec::new(),
        }
    }

    /// A falling TEC, or a return to active, means sends are being ACKed.
    fn error(&mut self, error: ErrorFrame, tx_dropped: u32) {
        let now = &mut self.now;
        let counters_low = matches!(
            (error.tx_errors, error.rx_errors),
            (Some(tx), Some(rx)) if tx < WARNING_LIMIT && rx < WARNING_LIMIT
        );
        let back_to_active = error.state == Some(ErrorState::Active);
        let acked = matches!((error.tx_errors, now.tx_errors), (Some(new), Some(old)) if new < old);
        now.state = error
            .state
            .or(counters_low.then_some(ErrorState::Active))
            .unwrap_or(now.state);
        now.no_ack = error.no_ack || (now.no_ack && !back_to_active && !acked);
        now.tx_errors = error.tx_errors.or(now.tx_errors);
        now.rx_errors = error.rx_errors.or(now.rx_errors);
        self.quiet_at = Some(Instant::now() + self.quiet);
        self.report(error.tx_timeout, tx_dropped);
    }

    fn received_from_another_node(&mut self) {
        self.now.no_ack = false;
        self.report(false, 0);
    }

    fn clear(&mut self) {
        self.now = BusState::active(self.now.bus);
        self.quiet_at = None;
        self.report(false, 0);
    }

    fn report(&mut self, always: bool, tx_dropped: u32) {
        let seen = (self.now.state, self.now.no_ack);
        if always || seen != self.reported {
            self.reported = seen;
            self.reports.push(BusState {
                tx_dropped,
                ..self.now.clone()
            });
        }
    }
}

/// The bulk endpoints, one frame per transfer.
trait Transfers {
    /// Cancel-safe. An error is the device gone.
    fn receive(&mut self) -> impl Future<Output = Result<Vec<u8>, CanError>> + Send;

    fn send(&mut self, transfer: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
}

/// A started channel. Each send holds an echo slot until the device echoes it
/// from the bus, as the kernel's do, or a transmit timeout flushes them all;
/// with every slot held, a write reads until one is freed, keeping what else it
/// reads for the next read.
struct Frames<T> {
    transfers: T,
    channel: u8,
    timestamps: bool,
    echo_wait: Duration,
    awaiting_echo: [bool; ECHO_SLOTS],
    held: Vec<Received>,
    bus: BusWatch,
    lost: Option<CanError>,
}

impl<T: Transfers + Send> Frames<T> {
    fn new(transfers: T, channel: u8, timestamps: bool, echo_wait: Duration) -> Self {
        Self {
            transfers,
            channel,
            timestamps,
            echo_wait,
            awaiting_echo: [false; ECHO_SLOTS],
            held: Vec::new(),
            bus: BusWatch::new(channel),
            lost: None,
        }
    }

    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        if self.held.is_empty() && self.bus.reports.is_empty() {
            if let Some(error) = self.lost.take() {
                return Err(error);
            }
            let transfer = match self.bus.quiet_at {
                Some(at) => timeout_at(at, self.transfers.receive()).await.ok(),
                None => Some(self.transfers.receive().await),
            };
            match transfer {
                Some(transfer) => self.take(&transfer?),
                None => self.bus.clear(),
            }
        }
        Ok(std::mem::take(&mut self.held))
    }

    fn bus_reports(&mut self) -> Vec<BusState> {
        std::mem::take(&mut self.bus.reports)
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        if frame.bus != self.channel {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("this task sends on channel {}", self.channel),
            ));
        }
        if self.lost.is_some() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let slot = self.free_slot().await?;
        self.awaiting_echo[slot] = true;
        let sent = self.transfers.send(outgoing(frame, slot as u32)).await;
        if sent.is_err() {
            self.awaiting_echo[slot] = false;
        }
        sent
    }

    /// Echoes not back within `echo_wait` are taken as lost, and every slot is
    /// freed.
    async fn free_slot(&mut self) -> io::Result<usize> {
        let deadline = Instant::now() + self.echo_wait;
        loop {
            if let Some(slot) = self.awaiting_echo.iter().position(|awaiting| !awaiting) {
                return Ok(slot);
            }
            match timeout_at(deadline, self.transfers.receive()).await {
                Ok(Ok(transfer)) => self.take(&transfer),
                Ok(Err(error)) => {
                    self.lost = Some(error);
                    return Err(io::ErrorKind::NotConnected.into());
                }
                Err(_) => {
                    self.free_every_slot();
                    return Err(io::ErrorKind::TimedOut.into());
                }
            }
        }
    }

    /// `ECHO_ID_RX` is no slot, so a received frame frees none.
    fn take(&mut self, transfer: &[u8]) {
        let echo_id = transfer.first_chunk().map(|id| u32::from_le_bytes(*id));
        if let Some(awaiting) = echo_id.and_then(|id| self.awaiting_echo.get_mut(id as usize)) {
            *awaiting = false;
        }
        let Some(frame) = parse_host_frame(transfer) else {
            return;
        };
        if frame.error {
            if frame.channel == self.channel {
                let error = ErrorFrame::decode(frame.arb_id, &frame.data);
                let flushed = error.tx_timeout.then(|| self.free_every_slot());
                self.bus.error(error, flushed.unwrap_or(0));
            }
        } else if let Some(received) = received(frame, transfer, self.timestamps) {
            if received.direction == Direction::Rx {
                self.bus.received_from_another_node();
            }
            self.held.push(received);
        }
    }

    fn free_every_slot(&mut self) -> u32 {
        let held = self
            .awaiting_echo
            .iter()
            .filter(|&&awaiting| awaiting)
            .count();
        self.awaiting_echo = [false; ECHO_SLOTS];
        held as u32
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    };

    use tokio::sync::mpsc;
    use wiretap_protocol::gs_usb::{ECHO_ID_RX, HEADER_BYTES};

    use super::*;
    use crate::can::{
        task::{self, Device},
        writer::Limits,
        CanEvent, CanOptions, CanTask, SendRefused,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Request {
        Get(Breq, u16, usize),
        Set(Breq, u16, Vec<u8>),
    }

    struct FakeUsb {
        replies: Vec<(Breq, Vec<u8>)>,
        broken: Option<(Breq, io::ErrorKind)>,
        stalled: Option<Breq>,
        log: Mutex<Vec<Request>>,
    }

    impl FakeUsb {
        fn new(feature: u32, fclk: u32) -> Self {
            let mut bt = words(&[feature, fclk]);
            bt.extend(words(&[1, 16, 1, 8, 4, 1, 1024, 1]));
            let mut ext = bt.clone();
            ext.extend(words(&[1, 32, 1, 16, 16, 1, 32, 1]));
            Self {
                replies: vec![
                    (Breq::DeviceConfig, words(&[1 << 24, 7, 3])),
                    (Breq::BtConst, bt),
                    (Breq::BtConstExt, ext),
                ],
                broken: None,
                stalled: None,
                log: Mutex::default(),
            }
        }

        fn log(&self) -> Vec<Request> {
            self.log.lock().unwrap().clone()
        }

        fn fail(&self, request: Breq) -> io::Result<()> {
            match self.broken {
                Some((broken, kind)) if broken == request => Err(kind.into()),
                _ => Ok(()),
            }
        }
    }

    impl Control for FakeUsb {
        async fn get(&self, request: Breq, value: u16, length: usize) -> io::Result<Vec<u8>> {
            self.log
                .lock()
                .unwrap()
                .push(Request::Get(request, value, length));
            self.fail(request)?;
            if self.stalled == Some(request) {
                std::future::pending::<()>().await;
            }
            let (_, reply) = self.replies.iter().find(|(r, _)| *r == request).unwrap();
            Ok(reply.clone())
        }

        async fn set(&self, request: Breq, value: u16, data: &[u8]) -> io::Result<()> {
            self.log
                .lock()
                .unwrap()
                .push(Request::Set(request, value, data.to_vec()));
            self.fail(request)
        }
    }

    fn words(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn options(bitrate: u32) -> GsUsbOptions {
        let device = GsUsbDevice {
            serial: Some("0042".into()),
            bus: 1,
            address: 2,
            product: "candleLight".into(),
        };
        GsUsbOptions::new(device, bitrate)
    }

    const CLASSIC_FEATURES: u32 = can_feature::LISTEN_ONLY
        | can_feature::HW_TIMESTAMP
        | can_feature::PAD_PKTS_TO_MAX_PKT_SIZE;

    #[tokio::test]
    async fn a_classic_start_sends_the_kernels_sequence_byte_for_byte() {
        let usb = FakeUsb::new(CLASSIC_FEATURES, 48_000_000);
        let started = start(&usb, &options(500_000), true).await.unwrap();
        assert_eq!(
            usb.log(),
            [
                Request::Set(Breq::HostFormat, 1, vec![0xEF, 0xBE, 0, 0]),
                Request::Get(Breq::DeviceConfig, 1, 12),
                Request::Get(Breq::BtConst, 0, 40),
                Request::Set(Breq::Mode, 0, vec![0; 8]),
                Request::Set(Breq::Bittiming, 0, words(&[0, 13, 2, 2, 6])),
                Request::Set(Breq::Mode, 0, words(&[1, 0x11])),
            ],
            "padding is offered and never asked for"
        );
        assert_eq!(
            started.info,
            DeviceInfo {
                buses: Some(2),
                fd: false,
                firmware: Some("7".into()),
                hardware: Some("3".into()),
                clock_hz: Some(48_000_000),
                ..DeviceInfo::default()
            }
        );
        assert!(!started.fd && started.timestamps);
        assert_eq!(
            started.transfer_len(64),
            64,
            "a stamped classic frame is 24"
        );
    }

    async fn probed(usb: &FakeUsb, within: Duration) -> Result<DeviceInfo, CanError> {
        tokio::time::timeout(
            Duration::from_secs(5),
            identify(usb, Instant::now() + within),
        )
        .await
        .expect("the probe should keep its deadline")
    }

    #[tokio::test]
    async fn a_probe_only_reads_device_config_and_bt_const() {
        let usb = FakeUsb::new(can_feature::FD, 80_000_000);
        let info = probed(&usb, Duration::from_secs(2)).await.unwrap();
        assert_eq!(
            usb.log(),
            [
                Request::Get(Breq::DeviceConfig, 1, 12),
                Request::Get(Breq::BtConst, 0, 40),
            ]
        );
        assert_eq!(
            info,
            DeviceInfo {
                buses: Some(2),
                fd: true,
                firmware: Some("7".into()),
                hardware: Some("3".into()),
                clock_hz: Some(80_000_000),
                ..DeviceInfo::default()
            }
        );
    }

    #[tokio::test]
    async fn a_probe_without_bt_const_has_no_fd_and_no_clock() {
        let mut failed = FakeUsb::new(can_feature::FD, 80_000_000);
        failed.broken = Some((Breq::BtConst, io::ErrorKind::ConnectionReset));
        let mut short = FakeUsb::new(can_feature::FD, 80_000_000);
        short.replies[1].1.truncate(8);
        for usb in [failed, short] {
            let info = probed(&usb, Duration::from_secs(2)).await.unwrap();
            assert_eq!((info.buses, info.fd, info.clock_hz), (Some(2), false, None));
        }
    }

    #[tokio::test]
    async fn a_short_device_config_fails_the_probe_as_a_handshake() {
        let mut usb = FakeUsb::new(0, 48_000_000);
        usb.replies[0].1.truncate(8);
        let error = probed(&usb, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(error, CanError::Handshake(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_stalled_device_is_a_timed_out_read_at_the_deadline() {
        let mut usb = FakeUsb::new(0, 48_000_000);
        usb.stalled = Some(Breq::BtConst);
        let asked = std::time::Instant::now();
        let error = probed(&usb, Duration::from_millis(100)).await.unwrap_err();
        assert!(matches!(&error, CanError::Read(e) if e.kind() == io::ErrorKind::TimedOut));
        assert!(asked.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn an_fd_start_times_the_data_phase_from_bt_const_ext() {
        let usb = FakeUsb::new(can_feature::FD | can_feature::BT_CONST_EXT, 80_000_000);
        let fd = GsUsbOptions {
            channel: 1,
            data: Some((2_000_000, None)),
            ..options(500_000)
        };
        let started = start(&usb, &fd, false).await.unwrap();
        assert_eq!(
            usb.log()[2..],
            [
                Request::Get(Breq::BtConst, 1, 40),
                Request::Set(Breq::Mode, 1, vec![0; 8]),
                Request::Set(Breq::Bittiming, 1, words(&[0, 13, 2, 2, 10])),
                Request::Get(Breq::BtConstExt, 1, 72),
                Request::Set(Breq::DataBittiming, 1, words(&[0, 14, 5, 5, 2])),
                Request::Set(Breq::Mode, 1, words(&[1, 0x100])),
            ]
        );
        assert!(started.fd && started.info.fd && !started.timestamps);
        assert_eq!(started.transfer_len(64), 128, "an FD frame is 76");
        assert_eq!(started.transfer_len(512), 512);
    }

    #[tokio::test]
    async fn a_clock_that_isnt_reported_falls_back_to_the_48_mhz_table() {
        let usb = FakeUsb::new(0, 0);
        start(&usb, &options(125_000), false).await.unwrap();
        assert_eq!(
            usb.log()[4],
            Request::Set(Breq::Bittiming, 0, words(&[0, 13, 2, 1, 24]))
        );
    }

    #[tokio::test]
    async fn what_the_device_cant_do_is_refused_before_the_channel_starts() {
        let fd = GsUsbOptions {
            data: Some((2_000_000, None)),
            ..options(500_000)
        };
        let other_channel = GsUsbOptions {
            channel: 2,
            ..options(500_000)
        };
        let cases = [
            (FakeUsb::new(0, 48_000_000), fd, false),
            (FakeUsb::new(0, 48_000_000), options(500_000), true),
            (FakeUsb::new(0, 48_000_000), other_channel, false),
            (FakeUsb::new(0, 48_000_000), options(7_000_000), false),
        ];
        for (usb, gs, listen_only) in cases {
            let error = start(&usb, &gs, listen_only).await.err().unwrap();
            assert!(matches!(error, CanError::Config(_)), "{error:?}");
            let started = usb
                .log()
                .iter()
                .any(|r| matches!(r, Request::Set(Breq::Mode, _, d) if d[0] == 1));
            assert!(!started);
        }
    }

    #[tokio::test]
    async fn a_bitrate_outside_the_devices_limits_is_refused_with_them_named() {
        let mut usb = FakeUsb::new(0, 48_000_000);
        usb.replies[1].1 = words(&[0, 48_000_000, 1, 16, 1, 8, 4, 1, 2, 1]);
        let error = start(&usb, &options(500_000), false).await.err().unwrap();
        let CanError::Config(reason) = error else {
            panic!("{error:?}");
        };
        assert!(
            reason.contains("500000 bit/s") && reason.contains("brp 1–2 by 1"),
            "{reason}"
        );
        assert!(
            !usb.log()
                .contains(&Request::Set(Breq::Bittiming, 0, words(&[0, 13, 2, 2, 6]))),
            "the 48 MHz table is only for a device that reports no clock"
        );
    }

    #[tokio::test]
    async fn a_device_gone_mid_start_is_closed_and_a_refusal_names_its_request() {
        let mut usb = FakeUsb::new(0, 48_000_000);
        usb.broken = Some((Breq::Bittiming, io::ErrorKind::ConnectionAborted));
        let error = start(&usb, &options(500_000), false).await.err().unwrap();
        assert!(matches!(error, CanError::Closed));
        usb.broken = Some((Breq::BtConst, io::ErrorKind::ConnectionReset));
        let error = start(&usb, &options(500_000), false).await.err().unwrap();
        assert!(matches!(&error, CanError::Read(e) if e.to_string().starts_with("BT_CONST")));
    }

    fn host(echo_id: u32, arb_id: u32, fd: bool, len: usize) -> HostFrame {
        HostFrame {
            echo_id,
            ..HostFrame::transmit(arb_id, false, false, fd, fd, 0, vec![0xAB; len])
        }
    }

    fn transfer(frame: &HostFrame, stamp: Option<u32>) -> Vec<u8> {
        let mut bytes = encode_host_frame(frame);
        bytes.extend(stamp.into_iter().flat_map(u32::to_le_bytes));
        bytes
    }

    fn incoming(bytes: &[u8], timestamps: bool) -> Option<Received> {
        received(parse_host_frame(bytes)?, bytes, timestamps)
    }

    fn counter(stamp: &Stamp) -> Option<u32> {
        match stamp {
            Stamp::Counter(ts) => Some(*ts),
            _ => None,
        }
    }

    #[test]
    fn a_stamped_classic_transfer_is_one_frame_with_its_stamp() {
        let bytes = transfer(&host(ECHO_ID_RX, 0x1, false, 2), Some(100));
        assert_eq!(bytes.len(), 24);
        let received = incoming(&bytes, true).unwrap();
        assert_eq!((received.frame.arb_id, received.frame.data.len()), (0x1, 2));
        assert!(!received.frame.fd && !received.overflow);
        assert_eq!(received.direction, Direction::Rx);
        assert_eq!(counter(&received.stamp), Some(100));

        let echo = incoming(&transfer(&host(0, 0x4, false, 1), Some(400)), true).unwrap();
        assert_eq!(echo.direction, Direction::Tx);
        assert_eq!(counter(&echo.stamp), Some(400));
    }

    #[test]
    fn a_stamped_fd_transfer_is_one_frame_with_its_stamp() {
        let bytes = transfer(&host(ECHO_ID_RX, 0x2, true, 12), Some(200));
        assert_eq!(bytes.len(), 80);
        let received = incoming(&bytes, true).unwrap();
        assert!(received.frame.fd && received.frame.brs);
        assert_eq!(
            (received.frame.arb_id, received.frame.data.len()),
            (0x2, 12)
        );
        assert_eq!(counter(&received.stamp), Some(200));
    }

    #[test]
    fn a_stampless_transfer_takes_the_reads_time() {
        for (fd, len) in [(false, CLASSIC_FRAME_BYTES), (true, FD_FRAME_BYTES)] {
            let bytes = transfer(&host(ECHO_ID_RX, 0x1, fd, 8), None);
            assert_eq!(bytes.len(), len);
            let received = incoming(&bytes, false).unwrap();
            assert_eq!(received.frame.fd, fd);
            assert!(matches!(received.stamp, Stamp::Read));
        }
    }

    #[test]
    fn a_frame_that_stops_at_its_data_is_taken_only_on_a_stampless_channel() {
        let bytes = transfer(&host(ECHO_ID_RX, 0x1, false, 2), None);
        let short = &bytes[..HEADER_BYTES + 2];
        assert_eq!(incoming(short, false).unwrap().frame.data.len(), 2);
        assert!(
            incoming(short, true).is_none(),
            "the kernel counts it as a length error"
        );
    }

    /// The first packet of a full FD frame was what padding turned into a
    /// phantom classic frame with the FD frame's id.
    #[test]
    fn a_truncated_transfer_is_nothing() {
        let bytes = transfer(&host(ECHO_ID_RX, 0x2, true, 64), Some(200));
        assert!(incoming(&bytes[..64], true).is_none());
        assert!(incoming(&bytes[..HEADER_BYTES - 1], true).is_none());
    }

    #[test]
    fn an_overflow_is_carried_on_the_frame_after_the_loss() {
        let flagged = HostFrame {
            overflow: true,
            ..host(ECHO_ID_RX, 0x5, false, 8)
        };
        let received = incoming(&transfer(&flagged, Some(500)), true).unwrap();
        assert!(received.overflow);
        assert_eq!(received.frame.arb_id, 0x5);
    }

    #[test]
    fn a_send_is_encoded_on_its_channel_and_echo_id_with_an_rtrs_own_code() {
        let remote = outgoing(&CanFrame::remote(1, 0x123, false, 5), 0);
        let back = parse_host_frame(&remote).unwrap();
        assert!(back.rtr);
        assert_eq!((back.channel, back.dlc), (1, 5));

        let fd = outgoing(&CanFrame::data(0, 0x10, true, true, true, vec![7; 12]), 3);
        assert_eq!(fd.len(), FD_FRAME_BYTES);
        let back = parse_host_frame(&fd).unwrap();
        assert!(back.extended && back.fd && back.brs);
        assert_eq!((back.echo_id, back.dlc, back.data), (3, 9, vec![7; 12]));
    }

    type FromDevice = Result<Vec<u8>, CanError>;

    /// The device's side of the bulk endpoints, across reopens: what it was
    /// sent, and what it hands the host.
    struct Bench {
        sent: Mutex<Vec<HostFrame>>,
        echoes: bool,
        replies: AtomicBool,
        most_held: AtomicUsize,
        echo_wait: Duration,
        quiet: Duration,
        to_host: mpsc::UnboundedSender<FromDevice>,
        from_device: Mutex<Option<mpsc::UnboundedReceiver<FromDevice>>>,
    }

    impl Bench {
        fn new(echoes: bool, echo_wait: Duration) -> Arc<Self> {
            Self::quiet_after(QUIET, echoes, echo_wait)
        }

        fn quiet_after(quiet: Duration, echoes: bool, echo_wait: Duration) -> Arc<Self> {
            let (to_host, from_device) = mpsc::unbounded_channel();
            Arc::new(Self {
                sent: Mutex::default(),
                echoes,
                replies: AtomicBool::new(false),
                most_held: AtomicUsize::new(0),
                echo_wait,
                quiet,
                to_host,
                from_device: Mutex::new(Some(from_device)),
            })
        }

        fn frames(self: &Arc<Self>) -> Frames<FakeBulk> {
            let from_device = self.from_device.lock().unwrap().take();
            let bulk = FakeBulk {
                bench: self.clone(),
                from_device: from_device.expect("one device open at a time"),
            };
            let mut frames = Frames::new(bulk, 0, false, self.echo_wait);
            frames.bus.quiet = self.quiet;
            frames
        }

        fn sent(&self) -> Vec<(u32, u32)> {
            let sent = self.sent.lock().unwrap();
            sent.iter().map(|f| (f.arb_id, f.echo_id)).collect()
        }

        fn echo(&self, slot: u32) {
            let sent = self.sent.lock().unwrap();
            let frame = sent.iter().rev().find(|f| f.echo_id == slot).unwrap();
            self.to_host.send(Ok(encode_host_frame(frame))).unwrap();
        }

        fn receive(&self, arb_id: u32) {
            let frame = encode_host_frame(&host(ECHO_ID_RX, arb_id, false, 1));
            self.to_host.send(Ok(frame)).unwrap();
        }

        fn error(&self, (class, data): (u32, [u8; 8])) {
            let frame = HostFrame {
                echo_id: ECHO_ID_RX,
                error: true,
                ..HostFrame::transmit(class, false, false, false, false, 0, data.to_vec())
            };
            self.to_host.send(Ok(encode_host_frame(&frame))).unwrap();
        }
    }

    struct FakeBulk {
        bench: Arc<Bench>,
        from_device: mpsc::UnboundedReceiver<FromDevice>,
    }

    impl Transfers for FakeBulk {
        async fn receive(&mut self) -> Result<Vec<u8>, CanError> {
            self.from_device
                .recv()
                .await
                .expect("the bench holds a sender")
        }

        async fn send(&mut self, transfer: Vec<u8>) -> io::Result<()> {
            let frame = parse_host_frame(&transfer).unwrap();
            let reply = REPLY | frame.arb_id;
            self.bench.sent.lock().unwrap().push(frame);
            if self.bench.echoes {
                self.bench.to_host.send(Ok(transfer)).unwrap();
            }
            if self.bench.replies.load(Ordering::SeqCst) {
                self.bench.receive(reply);
            }
            Ok(())
        }
    }

    struct Rigged(Frames<FakeBulk>);

    impl Device for Rigged {
        type Config = Arc<Bench>;

        async fn open(bench: &Arc<Bench>, _: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
            Ok((Self(bench.frames()), DeviceInfo::default()))
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
            self.0.read().await
        }

        async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
            let written = self.0.write(frame).await;
            let held = self.0.held.len();
            self.0
                .transfers
                .bench
                .most_held
                .fetch_max(held, Ordering::SeqCst);
            written
        }

        fn bus_reports(&mut self) -> Vec<BusState> {
            self.0.bus_reports()
        }

        async fn close(self) {
            *self.0.transfers.bench.from_device.lock().unwrap() =
                Some(self.0.transfers.from_device);
        }
    }

    const REPLY: u32 = 0x400;

    fn classic(arb_id: u32) -> CanFrame {
        CanFrame::data(0, arb_id, false, false, false, vec![arb_id as u8])
    }

    async fn filled(bench: &Arc<Bench>) -> Frames<FakeBulk> {
        let mut frames = bench.frames();
        for id in 0..10 {
            frames.write(&classic(id)).await.unwrap();
        }
        frames
    }

    async fn soon<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .expect("in time")
    }

    #[tokio::test]
    async fn ten_sends_without_echoes_fill_the_slots_and_the_eleventh_times_out_freeing_them() {
        let bench = Bench::new(false, Duration::from_millis(50));
        let mut frames = filled(&bench).await;
        let slots: Vec<(u32, u32)> = (0..10).map(|id| (id, id)).collect();
        assert_eq!(bench.sent(), slots);

        let asked = std::time::Instant::now();
        let error = soon(frames.write(&classic(10))).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(asked.elapsed() >= Duration::from_millis(50));
        assert_eq!(
            bench.sent().len(),
            10,
            "the eleventh never reached the device"
        );

        frames.write(&classic(11)).await.unwrap();
        assert_eq!(bench.sent().last(), Some(&(11, 0)));
    }

    #[tokio::test]
    async fn an_echo_frees_its_slot_and_what_a_waiting_write_reads_comes_in_the_next_read() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = filled(&bench).await;
        bench.receive(0x70);
        bench.echo(3);
        soon(frames.write(&classic(10))).await.unwrap();
        assert_eq!(bench.sent().last(), Some(&(10, 3)));

        let read = frames.read().await.unwrap();
        let seen: Vec<(u32, Direction)> =
            read.iter().map(|r| (r.frame.arb_id, r.direction)).collect();
        assert_eq!(seen, [(0x70, Direction::Rx), (3, Direction::Tx)]);
    }

    #[tokio::test]
    async fn a_device_gone_while_a_write_waits_is_the_next_reads_loss_after_what_it_read() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = filled(&bench).await;
        bench.receive(0x70);
        bench.to_host.send(Err(CanError::Closed)).unwrap();
        let error = soon(frames.write(&classic(10))).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(frames.read().await.unwrap()[0].frame.arb_id, 0x70);
        assert!(matches!(frames.read().await, Err(CanError::Closed)));
    }

    #[tokio::test]
    async fn a_flood_through_the_task_reaches_the_device_in_order_with_none_lost() {
        let bench = Bench::new(true, Duration::from_secs(60));
        let task = task::open::<Rigged>(bench.clone(), CanOptions::default())
            .await
            .unwrap();
        let writer = task.writer();
        let mut answers = Vec::new();
        for id in 0..1_000 {
            answers.push(soon(writer.send_when_ready(classic(id))).await.unwrap());
        }
        for answer in answers {
            soon(answer).await.unwrap().unwrap();
        }
        let sent = bench.sent();
        assert!(sent.iter().map(|&(id, _)| id).eq(0..1_000));
        assert!(sent.iter().all(|&(_, slot)| slot < ECHO_SLOTS as u32));
        task.stop().await;
    }

    async fn settle(until: impl Fn() -> bool) {
        for _ in 0..10_000 {
            if until() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("never settled");
    }

    #[tokio::test]
    async fn with_every_slot_held_the_queue_backs_up_until_the_waiting_send_times_out() {
        let bench = Bench::new(false, Duration::from_millis(100));
        let options = CanOptions {
            writes: 1,
            ..CanOptions::default()
        };
        let task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        let writer = task.writer();
        for id in 0..10 {
            soon(writer.send(classic(id))).await.unwrap().unwrap();
        }
        let waiting = tokio::spawn(writer.submit(classic(10)).unwrap());
        settle(|| writer.queued() == 0).await;
        let queued = tokio::spawn(writer.submit(classic(11)).unwrap());
        assert_eq!(
            writer.submit(classic(12)).err(),
            Some(SendRefused::QueueFull)
        );

        let timed_out = soon(waiting).await.unwrap().unwrap().unwrap_err();
        assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
        soon(queued).await.unwrap().unwrap().unwrap();
        assert_eq!(bench.sent().last(), Some(&(11, 0)));
        task.stop().await;
    }

    #[tokio::test]
    async fn a_reopened_device_starts_with_every_slot_free() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let options = CanOptions {
            reopen: Some(Duration::from_millis(1)),
            ..CanOptions::default()
        };
        let mut task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        assert!(matches!(
            task.next_event().await,
            Some(CanEvent::Connected(_))
        ));
        let writer = task.writer();
        for id in 0..10 {
            soon(writer.send(classic(id))).await.unwrap().unwrap();
        }
        bench.to_host.send(Err(CanError::Closed)).unwrap();
        assert!(matches!(
            soon(task.next_event()).await,
            Some(CanEvent::Disconnected { .. })
        ));
        assert!(matches!(
            soon(task.next_event()).await,
            Some(CanEvent::Connected(_))
        ));
        soon(writer.send(classic(10))).await.unwrap().unwrap();
        assert_eq!(bench.sent().last(), Some(&(10, 0)));
        task.stop().await;
    }

    #[tokio::test]
    async fn a_flood_of_sends_still_delivers_the_replies_read_meanwhile() {
        let bench = Bench::new(true, Duration::from_secs(60));
        bench.replies.store(true, Ordering::SeqCst);
        let options = CanOptions {
            writes: 500,
            ..CanOptions::default()
        };
        let mut task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        let writer = task.writer();
        let answers: Vec<_> = (0..500)
            .map(|id| writer.submit(classic(id)).unwrap())
            .collect();
        assert!(matches!(
            soon(task.next_event()).await,
            Some(CanEvent::Connected(_))
        ));
        let mut replies = Vec::new();
        while replies.len() < 500 {
            let Some(CanEvent::Read(reads)) = soon(task.next_event()).await else {
                panic!("a read");
            };
            if replies.is_empty() {
                assert!(bench.sent().len() < 500, "a reply before the flood ends");
            }
            replies.extend(reads.iter().map(|r| r.frame.arb_id));
        }
        assert!(replies.iter().copied().eq((0..500).map(|id| REPLY | id)));
        assert!(bench.most_held.load(Ordering::SeqCst) <= ECHO_SLOTS + 2);
        for answer in answers {
            soon(answer).await.unwrap().unwrap();
        }
        task.stop().await;
    }

    /// The CANable 2.5's on a bus with nothing to ACK, 2026-10-03.
    const BEFORE_ANY_CLASS: (u32, [u8; 8]) = (0, [0, 0, 0, 0, 0, 0, 8, 0]);
    const TX_TIMEOUT: (u32, [u8; 8]) = (0x25, [0, 0x20, 0, 0, 0, 0x10, 0x80, 0]);
    const PASSIVE_NO_ACK: (u32, [u8; 8]) = (0x24, [0, 0x20, 0, 0, 0, 0, 0x80, 0]);

    fn passive(tx_dropped: u32) -> BusState {
        BusState {
            state: ErrorState::Passive,
            no_ack: true,
            tx_dropped,
            tx_errors: Some(128),
            rx_errors: Some(0),
            ..BusState::active(0)
        }
    }

    #[tokio::test]
    async fn a_tx_timeout_frees_every_held_slot_so_the_next_send_goes_at_once() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = filled(&bench).await;
        bench.error(TX_TIMEOUT);
        soon(frames.write(&classic(10))).await.unwrap();
        assert_eq!(bench.sent().last(), Some(&(10, 0)));
        assert_eq!(frames.bus_reports(), [passive(10)]);
    }

    #[tokio::test]
    async fn an_error_frame_is_no_frame_and_is_reported_on_a_change_or_a_tx_timeout() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = bench.frames();
        let cases = [
            (BEFORE_ANY_CLASS, vec![]),
            (PASSIVE_NO_ACK, vec![passive(0)]),
            (PASSIVE_NO_ACK, vec![]),
            (TX_TIMEOUT, vec![passive(0)]),
            (PASSIVE_NO_ACK, vec![]),
        ];
        for (error, reported) in cases {
            bench.error(error);
            assert!(soon(frames.read()).await.unwrap().is_empty());
            assert_eq!(frames.bus_reports(), reported);
        }
    }

    #[tokio::test]
    async fn an_idle_passive_bus_heartbeat_reports_nothing_new() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = bench.frames();
        let heartbeat = (0x04, [0, 0x20, 0, 0, 0, 0, 0x80, 0]);
        for (error, reported) in [
            (PASSIVE_NO_ACK, vec![passive(0)]),
            (heartbeat, vec![]),
            (heartbeat, vec![]),
        ] {
            bench.error(error);
            soon(frames.read()).await.unwrap();
            assert_eq!(frames.bus_reports(), reported);
        }
    }

    #[tokio::test]
    async fn a_decaying_tec_acks_then_warns_then_is_back_to_active() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = bench.frames();
        let on = |state, no_ack, tec| BusState {
            state,
            no_ack,
            tx_errors: Some(tec),
            rx_errors: Some(0),
            ..BusState::active(0)
        };
        for (error, reported) in [
            (PASSIVE_NO_ACK, vec![passive(0)]),
            (
                (0x04, [0, 0x08, 0, 0, 0, 0, 127, 0]),
                vec![on(ErrorState::Warning, false, 127)],
            ),
            ((0x04, [0, 0x08, 0, 0, 0, 0, 110, 0]), vec![]),
            (
                (0x04, [0, 0x40, 0, 0, 0, 0, 95, 0]),
                vec![on(ErrorState::Active, false, 95)],
            ),
        ] {
            bench.error(error);
            soon(frames.read()).await.unwrap();
            assert_eq!(frames.bus_reports(), reported);
        }
    }

    #[tokio::test]
    async fn five_seconds_without_an_error_frame_is_a_full_clear_once() {
        let bench = Bench::quiet_after(Duration::from_millis(50), false, Duration::from_secs(60));
        let mut frames = bench.frames();
        let since = std::time::Instant::now();
        bench.error(PASSIVE_NO_ACK);
        soon(frames.read()).await.unwrap();
        assert_eq!(frames.bus_reports(), [passive(0)]);

        assert!(soon(frames.read()).await.unwrap().is_empty());
        assert!(since.elapsed() >= Duration::from_millis(50));
        assert_eq!(frames.bus_reports(), [BusState::active(0)]);
        let again = tokio::time::timeout(Duration::from_millis(200), frames.read()).await;
        assert!(again.is_err(), "nothing more once clear");
    }

    #[tokio::test]
    async fn a_frame_from_another_node_clears_no_ack_but_not_passive_and_an_echo_neither() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let mut frames = bench.frames();
        bench.error(PASSIVE_NO_ACK);
        soon(frames.read()).await.unwrap();
        assert_eq!(frames.bus_reports(), [passive(0)]);

        frames.write(&classic(1)).await.unwrap();
        bench.echo(0);
        assert_eq!(
            soon(frames.read()).await.unwrap()[0].direction,
            Direction::Tx
        );
        assert_eq!(frames.bus_reports(), []);
        bench.receive(0x70);
        assert_eq!(
            soon(frames.read()).await.unwrap()[0].direction,
            Direction::Rx
        );
        let acked = BusState {
            no_ack: false,
            ..passive(0)
        };
        assert_eq!(frames.bus_reports(), [acked]);
    }

    async fn bus_event(task: &mut CanTask) -> BusState {
        match soon(task.next_event()).await {
            Some(CanEvent::Bus(state)) => state,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn through_the_task_a_tx_timeout_is_one_bus_event_until_quiet_clears_it() {
        let bench = Bench::quiet_after(Duration::from_millis(50), false, Duration::from_secs(60));
        let mut task = task::open::<Rigged>(bench.clone(), CanOptions::default())
            .await
            .unwrap();
        assert!(matches!(
            task.next_event().await,
            Some(CanEvent::Connected(_))
        ));
        let writer = task.writer();
        for id in 0..10 {
            soon(writer.send(classic(id))).await.unwrap().unwrap();
        }
        bench.error(TX_TIMEOUT);
        assert_eq!(bus_event(&mut task).await, passive(10));
        bench.error(PASSIVE_NO_ACK);
        soon(writer.send(classic(10))).await.unwrap().unwrap();
        assert_eq!(bench.sent().last(), Some(&(10, 0)));
        assert_eq!(bus_event(&mut task).await, BusState::active(0));
        task.stop().await;
    }

    #[tokio::test]
    async fn a_reopened_device_starts_with_a_clear_bus() {
        let bench = Bench::new(false, Duration::from_secs(60));
        let options = CanOptions {
            reopen: Some(Duration::from_millis(1)),
            ..CanOptions::default()
        };
        let mut task = task::open::<Rigged>(bench.clone(), options).await.unwrap();
        assert!(matches!(
            task.next_event().await,
            Some(CanEvent::Connected(_))
        ));
        bench.error(PASSIVE_NO_ACK);
        assert_eq!(bus_event(&mut task).await, passive(0));
        bench.to_host.send(Err(CanError::Closed)).unwrap();
        assert!(matches!(
            soon(task.next_event()).await,
            Some(CanEvent::Disconnected { .. })
        ));
        assert!(matches!(
            soon(task.next_event()).await,
            Some(CanEvent::Connected(_))
        ));
        bench.error(PASSIVE_NO_ACK);
        assert_eq!(bus_event(&mut task).await, passive(0));
        task.stop().await;
    }
}
