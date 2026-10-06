//! A PEAK adapter bound to PEAK's own driver (`PCAN_USB`) on Windows, which
//! nusb can't open, through `PCANBasic.dll`: classic CAN on the first channel.
//! The DLL is loaded at open and sits behind `Api`, so all but the loading
//! runs on every platform against a fake. Constants are `PCANBasic.h`'s, as
//! PCAN-Basic 4.9 has them.

#![cfg_attr(
    not(target_os = "windows"),
    allow(dead_code, reason = "only Windows opens it; the tests build it here")
)]

use std::{io, sync::Arc, time::Duration};

use tokio::{
    task::{spawn_blocking, JoinHandle},
    time::{sleep, Instant},
};
use wiretap_protocol::{can::ErrorState, pcan_usb::CLOCK_HZ};

use super::{check, not_opened, timing, BusWatch, PcanDevice, PcanOptions};
use crate::can::{
    clock::{Received, Stamp},
    task::Device,
    writer::Limits,
    BusState, CanError, CanFrame, CanOptions, DeviceInfo, Direction,
};

#[cfg(target_os = "windows")]
mod dll;
#[cfg(target_os = "windows")]
pub(super) use dll::{open, probe};

const NONEBUS: u16 = 0x00;
const DEVICE_USB: u8 = 0x05;
const ON: u32 = 1;

mod parameter {
    pub const RECEIVE_EVENT: u8 = 0x03;
    pub const LISTEN_ONLY: u8 = 0x08;
    pub const ALLOW_STATUS_FRAMES: u8 = 0x1e;
    pub const ATTACHED_CHANNELS_COUNT: u8 = 0x2a;
    pub const ATTACHED_CHANNELS: u8 = 0x2b;
    pub const ALLOW_ECHO_FRAMES: u8 = 0x2c;
}

mod status {
    pub const OK: u32 = 0;
    pub const XMTFULL: u32 = 0x01;
    pub const OVERRUN: u32 = 0x02;
    pub const BUSLIGHT: u32 = 0x04;
    pub const BUSHEAVY: u32 = 0x08;
    pub const BUSOFF: u32 = 0x10;
    pub const QRCVEMPTY: u32 = 0x20;
    pub const QOVERRUN: u32 = 0x40;
    pub const QXMTFULL: u32 = 0x80;
    /// A value, not flags: `HWINUSE`, `NETINUSE`, `ILLHW`, `ILLNET` and
    /// `ILLCLIENT` share these bits.
    pub const HANDLE_FIELD: u32 = 0x1c00;
    pub const HWINUSE: u32 = 0x0400;
    pub const ILLHW: u32 = 0x1400;
    pub const BUSPASSIVE: u32 = 0x4_0000;
    pub const NOT_FAILURES: u32 =
        QRCVEMPTY | OVERRUN | QOVERRUN | BUSLIGHT | BUSHEAVY | BUSOFF | BUSPASSIVE;
}

mod msgtype {
    pub const RTR: u8 = 0x01;
    pub const EXTENDED: u8 = 0x02;
    pub const ECHO: u8 = 0x20;
    pub const ERRFRAME: u8 = 0x40;
    pub const STATUS: u8 = 0x80;
}

/// `TPCANMsg`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Msg {
    id: u32,
    msgtype: u8,
    len: u8,
    data: [u8; 8],
}

/// `TPCANTimestamp`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Timestamp {
    millis: u32,
    millis_overflow: u16,
    micros: u16,
}

impl Timestamp {
    fn us(self) -> u64 {
        let millis = u64::from(self.millis) + (u64::from(self.millis_overflow) << 32);
        u64::from(self.micros) + 1000 * millis
    }
}

/// `PCANBasic.dll`'s calls, and the event its receive wake-up sets.
pub(super) trait Api: Send + Sync + 'static {
    fn initialize(&self, channel: u16, btr0btr1: u16) -> u32;
    fn uninitialize(&self, channel: u16) -> u32;
    fn read(&self, channel: u16, msg: &mut Msg, timestamp: &mut Timestamp) -> u32;
    fn write(&self, channel: u16, msg: &Msg) -> u32;
    fn get_value(&self, channel: u16, parameter: u8, buffer: &mut [u8]) -> u32;
    fn set_value(&self, channel: u16, parameter: u8, buffer: &[u8]) -> u32;
    fn get_status(&self, channel: u16) -> u32;
    /// `PCAN_RECEIVE_EVENT`, set to the event `wait` waits on.
    fn watch(&self, channel: u16) -> u32;
    /// Blocks until the event is set or `timeout` passes.
    fn wait(&self, timeout: Duration);
}

/// One `TPCANChannelInformation`, of what `pick` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attached {
    handle: u16,
    device_type: u8,
    name: String,
    device_id: u32,
}

const CHANNEL_INFORMATION_BYTES: usize = 52;

fn attached_channels(buffer: &[u8]) -> Vec<Attached> {
    buffer
        .as_chunks::<CHANNEL_INFORMATION_BYTES>()
        .0
        .iter()
        .map(|info| {
            let name = &info[8..41];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            Attached {
                handle: u16::from_le_bytes([info[0], info[1]]),
                device_type: info[2],
                name: String::from_utf8_lossy(&name[..end]).into_owned(),
                device_id: u32::from_le_bytes(info[44..48].try_into().unwrap()),
            }
        })
        .collect()
}

fn attached(api: &impl Api) -> Result<Vec<Attached>, CanError> {
    let mut count = [0u8; 4];
    called(
        "PCAN_ATTACHED_CHANNELS_COUNT",
        api.get_value(NONEBUS, parameter::ATTACHED_CHANNELS_COUNT, &mut count),
    )?;
    let mut buffer = vec![0u8; u32::from_le_bytes(count) as usize * CHANNEL_INFORMATION_BYTES];
    if !buffer.is_empty() {
        called(
            "PCAN_ATTACHED_CHANNELS",
            api.get_value(NONEBUS, parameter::ATTACHED_CHANNELS, &mut buffer),
        )?;
    }
    Ok(attached_channels(&buffer))
}

/// PCAN-Basic can't see a USB serial, so a lone USB channel is the device, and
/// among several the one whose device id the selector's serial names, in hex.
fn pick(channels: &[Attached], device: &PcanDevice) -> Result<u16, CanError> {
    let usb: Vec<&Attached> = channels
        .iter()
        .filter(|c| c.device_type == DEVICE_USB)
        .collect();
    let device_id = device
        .serial
        .as_deref()
        .and_then(|serial| u32::from_str_radix(serial, 16).ok());
    match usb[..] {
        [] => Err(not_opened(device)(io::Error::new(
            io::ErrorKind::NotFound,
            "PEAK's driver has no USB channel attached",
        ))),
        [only] => Ok(only.handle),
        _ => device_id
            .and_then(|id| usb.iter().find(|c| c.device_id == id))
            .map(|c| c.handle)
            .ok_or_else(|| {
                let candidates: Vec<String> = usb
                    .iter()
                    .map(|c| format!("{} {:#x} with device id {:X}", c.name, c.handle, c.device_id))
                    .collect();
                CanError::Config(format!(
                    "PEAK's driver has several USB channels, and the selector's serial names no device id among them: {}",
                    candidates.join(", ")
                ))
            }),
    }
}

/// What PEAK's driver doesn't take that nusb would.
fn check_basic(pcan: &PcanOptions) -> Result<(), CanError> {
    if pcan.data.is_some() {
        return Err(CanError::Config(
            "CAN FD isn't opened through PEAK's driver: bind WinUSB to the adapter for it".into(),
        ));
    }
    if pcan.channel != 0 {
        return Err(CanError::Config(
            "only channel 0 is opened through PEAK's driver".into(),
        ));
    }
    Ok(())
}

/// The SJA1000 pair as PCAN-Basic's `Btr0Btr1` word.
fn btr0btr1(pcan: &PcanOptions) -> Result<u16, CanError> {
    let btr = timing(pcan)?;
    Ok(u16::from_be_bytes([btr.btr0, btr.btr1]))
}

/// A call's status as `refused` maps a USB request's: the adapter gone is
/// `Closed`, anything else names the call.
fn called(call: &str, status: u32) -> Result<(), CanError> {
    if status == status::OK {
        return Ok(());
    }
    Err(match status & status::HANDLE_FIELD {
        status::ILLHW => CanError::Closed,
        status::HWINUSE => CanError::Read(io::Error::new(
            io::ErrorKind::ResourceBusy,
            format!("{call}: another program holds the adapter (PCAN-View?)"),
        )),
        _ => CanError::Read(io::Error::other(format!(
            "{call}: PCAN-Basic error {status:#x}"
        ))),
    })
}

/// A read's or `CAN_GetStatus`'s status: bus state and lost frames are news,
/// anything else ends the read.
fn reported(call: &str, status: u32) -> Result<u32, CanError> {
    if status & !status::NOT_FAILURES != 0 {
        called(call, status)?;
    }
    Ok(status)
}

fn bus_state(status: u32) -> ErrorState {
    if status & status::BUSOFF != 0 {
        ErrorState::BusOff
    } else if status & status::BUSPASSIVE != 0 {
        ErrorState::Passive
    } else if status & (status::BUSLIGHT | status::BUSHEAVY) != 0 {
        ErrorState::Warning
    } else {
        ErrorState::Active
    }
}

fn overflowed(status: u32) -> bool {
    status & (status::OVERRUN | status::QOVERRUN) != 0
}

/// A status or error frame is no read.
fn incoming(msg: &Msg) -> Option<(CanFrame, Direction)> {
    if msg.msgtype & (msgtype::STATUS | msgtype::ERRFRAME) != 0 {
        return None;
    }
    let extended = msg.msgtype & msgtype::EXTENDED != 0;
    let arb_id = msg.id & if extended { 0x1fff_ffff } else { 0x7ff };
    let len = msg.len.min(8);
    let frame = if msg.msgtype & msgtype::RTR != 0 {
        CanFrame::remote(0, arb_id, extended, len)
    } else {
        CanFrame::data(
            0,
            arb_id,
            extended,
            false,
            false,
            msg.data[..len.into()].to_vec(),
        )
    };
    let direction = if msg.msgtype & msgtype::ECHO != 0 {
        Direction::Tx
    } else {
        Direction::Rx
    };
    Some((frame, direction))
}

fn outgoing(frame: &CanFrame) -> Msg {
    let mut data = [0u8; 8];
    let len = frame.data.len().min(8);
    data[..len].copy_from_slice(&frame.data[..len]);
    let extended = if frame.extended { msgtype::EXTENDED } else { 0 };
    let rtr = if frame.rtr { msgtype::RTR } else { 0 };
    Msg {
        id: frame.arb_id,
        msgtype: extended | rtr,
        len: frame.dlc(),
        data,
    }
}

/// A started channel, uninitialised when dropped: by `close`, or by a runtime
/// shut down around its task.
struct Started<A: Api> {
    api: Arc<A>,
    handle: u16,
    btr0btr1: u16,
    listen_only: bool,
    own_frames: bool,
}

impl<A: Api> Started<A> {
    /// Listen-only is set, either way, before `CAN_Initialize`, so an earlier
    /// open in this process can't leave it on; the rest after it.
    fn initialize(&self) -> Result<(), CanError> {
        let api = &*self.api;
        let on = ON.to_le_bytes();
        called(
            "PCAN_LISTEN_ONLY",
            api.set_value(
                self.handle,
                parameter::LISTEN_ONLY,
                &u32::from(self.listen_only).to_le_bytes(),
            ),
        )?;
        called("CAN_Initialize", api.initialize(self.handle, self.btr0btr1))?;
        called(
            "PCAN_ALLOW_STATUS_FRAMES",
            api.set_value(self.handle, parameter::ALLOW_STATUS_FRAMES, &on),
        )?;
        if self.own_frames {
            called(
                "PCAN_ALLOW_ECHO_FRAMES",
                api.set_value(self.handle, parameter::ALLOW_ECHO_FRAMES, &on),
            )?;
        }
        called("PCAN_RECEIVE_EVENT", api.watch(self.handle))
    }

    fn restart(&self) -> io::Result<()> {
        self.api.uninitialize(self.handle);
        self.initialize().map_err(io::Error::other)
    }
}

impl<A: Api> Drop for Started<A> {
    fn drop(&mut self) {
        self.api.uninitialize(self.handle);
    }
}

/// A read with nothing queued waits this long at most for the receive event,
/// so a quiet bus still has its status and the adapter's presence polled.
const WAKE_BOUND: Duration = Duration::from_millis(100);
/// Frames taken per read, so a status that never empties the queue can't hold
/// the task.
const DRAIN_MAX: usize = 256;
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const WRITE_RETRY: Duration = Duration::from_millis(1);

struct Basic<A: Api> {
    started: Started<A>,
    waiter: Option<JoinHandle<()>>,
    overflow: bool,
    bus: BusWatch,
}

impl<A: Api> Basic<A> {
    /// Until the queue is empty, then the bus's status.
    fn drain(&mut self) -> Result<Vec<Received>, CanError> {
        let Started { api, handle, .. } = &self.started;
        let mut received = Vec::new();
        for _ in 0..DRAIN_MAX {
            let mut msg = Msg::default();
            let mut timestamp = Timestamp::default();
            let status = reported("CAN_Read", api.read(*handle, &mut msg, &mut timestamp))?;
            self.overflow |= overflowed(status);
            if status & status::QRCVEMPTY != 0 {
                break;
            }
            let Some((frame, direction)) = incoming(&msg) else {
                continue;
            };
            received.push(Received {
                frame,
                direction,
                stamp: Stamp::Counter(timestamp.us() as u32),
                overflow: std::mem::take(&mut self.overflow),
            });
        }
        let status = reported("CAN_GetStatus", api.get_status(*handle))?;
        self.overflow |= overflowed(status);
        self.bus.set(bus_state(status));
        Ok(received)
    }
}

/// Cancel-safe: a wait cut short is picked up by the next.
async fn woken<A: Api>(waiter: &mut Option<JoinHandle<()>>, api: &Arc<A>) {
    let waiting = waiter.get_or_insert_with(|| {
        let api = api.clone();
        spawn_blocking(move || api.wait(WAKE_BOUND))
    });
    let _ = waiting.await;
    *waiter = None;
}

impl<A: Api> Device for Basic<A> {
    type Config = (Arc<A>, PcanOptions);

    async fn open(
        (api, pcan): &(Arc<A>, PcanOptions),
        options: &CanOptions,
    ) -> Result<(Self, DeviceInfo), CanError> {
        check(pcan)?;
        check_basic(pcan)?;
        let started = Started {
            btr0btr1: btr0btr1(pcan)?,
            handle: pick(&attached(&**api)?, &pcan.device)?,
            api: api.clone(),
            listen_only: options.listen_only,
            own_frames: options.own_frames,
        };
        started.initialize()?;
        let device = Self {
            started,
            waiter: None,
            overflow: false,
            bus: BusWatch::new(0),
        };
        Ok((device, device_info()))
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
        let received = self.drain()?;
        if !received.is_empty() {
            return Ok(received);
        }
        let woken = woken(&mut self.waiter, &self.started.api);
        if self.bus.wait(woken).await.is_none() {
            return Ok(received);
        }
        self.drain()
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        let msg = outgoing(frame);
        let deadline = Instant::now() + WRITE_TIMEOUT;
        let Started { api, handle, .. } = &self.started;
        loop {
            let status = api.write(*handle, &msg);
            if status & (status::XMTFULL | status::QXMTFULL) == 0 {
                return called("CAN_Write", status).map_err(io::Error::other);
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            sleep(WRITE_RETRY).await;
        }
    }

    fn bus_reports(&mut self) -> Vec<BusState> {
        self.bus.reports()
    }

    async fn recover(&mut self) {
        let started = &self.started;
        self.bus.recover(async { started.restart() }).await;
    }

    async fn close(self) {}
}

fn device_info() -> DeviceInfo {
    DeviceInfo {
        buses: Some(1),
        clock_hz: Some(CLOCK_HZ),
        ..DeviceInfo::default()
    }
}

/// `pcan::probe`'s answer without touching the channel.
fn identify(api: &impl Api, device: &PcanDevice) -> Result<DeviceInfo, CanError> {
    pick(&attached(api)?, device)?;
    Ok(device_info())
}

/// The service PEAK-Drivers binds to its USB adapters.
pub(super) fn is_pcan_usb(driver: Option<&str>) -> bool {
    driver.is_some_and(|driver| driver.eq_ignore_ascii_case("PCAN_USB"))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        mem::{offset_of, size_of},
        sync::Mutex,
    };

    use super::*;
    use crate::can::{pcan::PcanModel, task, CanEvent, CanTask};

    #[test]
    fn the_structs_are_laid_out_as_pcanbasic_h_has_them() {
        assert_eq!(size_of::<Msg>(), 16);
        assert_eq!(
            [
                offset_of!(Msg, id),
                offset_of!(Msg, msgtype),
                offset_of!(Msg, len),
                offset_of!(Msg, data)
            ],
            [0, 4, 5, 6]
        );
        assert_eq!(size_of::<Timestamp>(), 8);
        assert_eq!(
            [
                offset_of!(Timestamp, millis),
                offset_of!(Timestamp, millis_overflow),
                offset_of!(Timestamp, micros)
            ],
            [0, 4, 6]
        );
    }

    #[test]
    fn a_timestamp_is_whole_microseconds_across_the_millis_overflow() {
        let at = |millis, millis_overflow, micros| {
            Timestamp {
                millis,
                millis_overflow,
                micros,
            }
            .us()
        };
        assert_eq!(at(1234, 0, 567), 1_234_567);
        assert_eq!(at(0, 1, 0), 1000 << 32);
        assert_eq!(at(u32::MAX, 0, 999), u64::from(u32::MAX) * 1000 + 999);
    }

    fn information(handle: u16, device_type: u8, name: &str, device_id: u32) -> Vec<u8> {
        let mut info = vec![0xee; CHANNEL_INFORMATION_BYTES];
        info[..2].copy_from_slice(&handle.to_le_bytes());
        info[2] = device_type;
        info[8..41].fill(0);
        info[8..8 + name.len()].copy_from_slice(name.as_bytes());
        info[44..48].copy_from_slice(&device_id.to_le_bytes());
        info
    }

    fn channel(handle: u16, device_type: u8, device_id: u32) -> Attached {
        Attached {
            handle,
            device_type,
            name: "PCAN-USB".into(),
            device_id,
        }
    }

    #[test]
    fn channel_information_is_52_bytes_with_the_name_at_8_and_the_device_id_at_44() {
        let buffer = [
            information(0x51, 5, "PCAN-USB", 0xff),
            information(0x41, 4, "PCAN-PCI", 7),
        ]
        .concat();
        assert_eq!(
            attached_channels(&buffer),
            [
                channel(0x51, 5, 0xff),
                Attached {
                    name: "PCAN-PCI".into(),
                    ..channel(0x41, 4, 7)
                }
            ]
        );
    }

    fn device(serial: Option<&str>) -> PcanDevice {
        PcanDevice {
            serial: serial.map(str::to_owned),
            bus: 0,
            address: 8,
            product: "PCAN-USB".into(),
            model: PcanModel::Usb,
        }
    }

    #[test]
    fn the_lone_usb_channel_is_taken_else_the_device_id_the_serial_names() {
        let pci = channel(0x41, 4, 1);
        let lone = [pci.clone(), channel(0x51, 5, 0xff)];
        assert_eq!(pick(&lone, &device(None)).unwrap(), 0x51);
        assert_eq!(pick(&lone, &device(Some("12"))).unwrap(), 0x51);

        let two = [channel(0x51, 5, 0xff), channel(0x52, 5, 0x12), pci];
        assert_eq!(pick(&two, &device(Some("12"))).unwrap(), 0x52);
        for unnamed in [None, Some("13"), Some("zz")] {
            let Err(CanError::Config(reason)) = pick(&two, &device(unnamed)) else {
                panic!("several and none named is refused");
            };
            assert!(
                reason
                    .ends_with("PCAN-USB 0x51 with device id FF, PCAN-USB 0x52 with device id 12"),
                "{reason}"
            );
        }

        let error = pick(&[channel(0x41, 4, 1)], &device(None)).unwrap_err();
        assert!(
            matches!(&error, CanError::Open { source, .. } if source.kind() == io::ErrorKind::NotFound),
            "{error:?}"
        );
    }

    #[test]
    fn btr0btr1_is_peaks_preset_word() {
        for (bitrate, preset) in [(500_000, 0x001c), (250_000, 0x011c), (125_000, 0x031c)] {
            let pcan = PcanOptions::new(device(None), bitrate);
            assert_eq!(btr0btr1(&pcan).unwrap(), preset, "{bitrate}");
        }
    }

    #[test]
    fn only_the_service_pcan_usb_is_peaks_driver_in_any_case() {
        assert!(is_pcan_usb(Some("PCAN_USB")));
        assert!(is_pcan_usb(Some("pcan_usb")));
        assert!(!is_pcan_usb(Some("WinUSB")));
        assert!(!is_pcan_usb(None));
    }

    #[test]
    fn bus_bits_are_the_worst_state_and_overrun_is_either_queue() {
        use status::*;
        assert_eq!(bus_state(OK), ErrorState::Active);
        assert_eq!(bus_state(BUSLIGHT), ErrorState::Warning);
        assert_eq!(bus_state(BUSHEAVY | QRCVEMPTY), ErrorState::Warning);
        assert_eq!(bus_state(BUSPASSIVE | BUSHEAVY), ErrorState::Passive);
        assert_eq!(bus_state(BUSOFF | BUSPASSIVE), ErrorState::BusOff);
        assert!(overflowed(OVERRUN) && overflowed(QOVERRUN | QRCVEMPTY));
        assert!(!overflowed(QRCVEMPTY | BUSOFF));
    }

    #[test]
    fn illhw_is_the_adapter_gone_and_hwinuse_names_the_other_program() {
        use status::*;
        assert!(reported("CAN_Read", QRCVEMPTY | BUSOFF | QOVERRUN).is_ok());
        assert!(matches!(reported("CAN_Read", ILLHW), Err(CanError::Closed)));
        let Err(CanError::Read(busy)) = called("CAN_Initialize", HWINUSE) else {
            panic!("in use is a refusal");
        };
        assert_eq!(busy.kind(), io::ErrorKind::ResourceBusy);
        assert_eq!(
            busy.to_string(),
            "CAN_Initialize: another program holds the adapter (PCAN-View?)"
        );
        let Err(CanError::Read(client)) = reported("CAN_Read", 0x1c00) else {
            panic!("ILLCLIENT is no ILLHW");
        };
        assert_eq!(client.to_string(), "CAN_Read: PCAN-Basic error 0x1c00");
    }

    #[test]
    fn msgtype_bits_are_the_frames_flags_and_status_frames_are_no_reads() {
        let msg = |id, msgtype, len, data: &[u8]| {
            let mut m = Msg {
                id,
                msgtype,
                len,
                data: [0; 8],
            };
            m.data[..data.len()].copy_from_slice(data);
            m
        };
        let rx = |frame| Some((frame, Direction::Rx));
        assert_eq!(
            incoming(&msg(0x123, 0, 2, &[0xaa, 0xbb])),
            rx(CanFrame::data(
                0,
                0x123,
                false,
                false,
                false,
                vec![0xaa, 0xbb]
            ))
        );
        assert_eq!(
            incoming(&msg(0x18da_f110, 0x03, 4, &[])),
            rx(CanFrame::remote(0, 0x18da_f110, true, 4))
        );
        assert_eq!(
            incoming(&msg(0x10, 0x20, 1, &[7])),
            Some((
                CanFrame::data(0, 0x10, false, false, false, vec![7]),
                Direction::Tx
            ))
        );
        assert_eq!(incoming(&msg(0, 0x80, 4, &[0, 0, 0, 8])), None);
        assert_eq!(incoming(&msg(0, 0x40, 0, &[])), None);

        let sent = outgoing(&CanFrame::data(
            0,
            0x18da_f110,
            true,
            false,
            false,
            vec![1, 2, 3],
        ));
        assert_eq!(sent, msg(0x18da_f110, 0x02, 3, &[1, 2, 3]));
        let remote = outgoing(&CanFrame::remote(0, 0x7ff, false, 5));
        assert_eq!(remote, msg(0x7ff, 0x01, 5, &[]));
    }

    #[derive(Debug, Clone, PartialEq)]
    enum Call {
        Set(u8, u32),
        Initialize(u16, u16),
        Watch(u16),
        Uninitialize(u16),
    }

    #[derive(Default)]
    struct Fake {
        attached: Mutex<Vec<u8>>,
        calls: Mutex<Vec<Call>>,
        initialize: Mutex<VecDeque<u32>>,
        reads: Mutex<VecDeque<(u32, Msg, Timestamp)>>,
        status: Mutex<u32>,
        writes: Mutex<VecDeque<u32>>,
        written: Mutex<Vec<Msg>>,
    }

    impl Fake {
        fn with_one_usb_channel() -> Arc<Self> {
            let fake = Self::default();
            *fake.attached.lock().unwrap() = information(0x51, DEVICE_USB, "PCAN-USB", 0xff);
            Arc::new(fake)
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        fn queue(&self, status: u32, msg: Msg, us: u64) {
            let timestamp = Timestamp {
                millis: (us / 1000) as u32,
                millis_overflow: 0,
                micros: (us % 1000) as u16,
            };
            self.reads
                .lock()
                .unwrap()
                .push_back((status, msg, timestamp));
        }
    }

    impl Api for Fake {
        fn initialize(&self, channel: u16, btr0btr1: u16) -> u32 {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Initialize(channel, btr0btr1));
            self.initialize
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(status::OK)
        }

        fn uninitialize(&self, channel: u16) -> u32 {
            self.calls.lock().unwrap().push(Call::Uninitialize(channel));
            status::OK
        }

        fn read(&self, _: u16, msg: &mut Msg, timestamp: &mut Timestamp) -> u32 {
            let Some((status, queued, at)) = self.reads.lock().unwrap().pop_front() else {
                return status::QRCVEMPTY;
            };
            (*msg, *timestamp) = (queued, at);
            status
        }

        fn write(&self, _: u16, msg: &Msg) -> u32 {
            self.written.lock().unwrap().push(*msg);
            self.writes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(status::OK)
        }

        fn get_value(&self, channel: u16, parameter: u8, buffer: &mut [u8]) -> u32 {
            assert_eq!(channel, NONEBUS);
            let attached = self.attached.lock().unwrap();
            match parameter {
                parameter::ATTACHED_CHANNELS_COUNT => {
                    let count = (attached.len() / CHANNEL_INFORMATION_BYTES) as u32;
                    buffer.copy_from_slice(&count.to_le_bytes());
                }
                parameter::ATTACHED_CHANNELS => buffer.copy_from_slice(&attached),
                _ => unreachable!(),
            }
            status::OK
        }

        fn set_value(&self, _: u16, parameter: u8, buffer: &[u8]) -> u32 {
            let value = u32::from_le_bytes(buffer.try_into().unwrap());
            self.calls.lock().unwrap().push(Call::Set(parameter, value));
            status::OK
        }

        fn get_status(&self, _: u16) -> u32 {
            *self.status.lock().unwrap()
        }

        fn watch(&self, channel: u16) -> u32 {
            self.calls.lock().unwrap().push(Call::Watch(channel));
            status::OK
        }

        fn wait(&self, _: Duration) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn options(listen_only: bool, own_frames: bool) -> CanOptions {
        CanOptions {
            listen_only,
            own_frames,
            reopen: Some(Duration::from_millis(1)),
            ..CanOptions::default()
        }
    }

    async fn opened(fake: &Arc<Fake>, options: CanOptions) -> Result<CanTask, CanError> {
        let pcan = PcanOptions::new(device(None), 500_000);
        task::open::<Basic<Fake>>((fake.clone(), pcan), options).await
    }

    async fn next(task: &mut CanTask) -> CanEvent {
        tokio::time::timeout(Duration::from_secs(5), task.next_event())
            .await
            .expect("an event in time")
            .expect("the task running")
    }

    const STARTED: [Call; 4] = [
        Call::Set(parameter::LISTEN_ONLY, 0),
        Call::Initialize(0x51, 0x001c),
        Call::Set(parameter::ALLOW_STATUS_FRAMES, ON),
        Call::Watch(0x51),
    ];

    #[tokio::test]
    async fn listen_only_is_set_either_way_before_initialize_and_echo_after_it_and_stop_uninitializes(
    ) {
        let fake = Fake::with_one_usb_channel();
        let mut task = opened(&fake, options(true, true)).await.unwrap();
        let CanEvent::Connected(info) = next(&mut task).await else {
            panic!("connected");
        };
        assert_eq!(info, device_info());
        task.stop().await;
        assert_eq!(
            fake.calls(),
            [
                Call::Set(parameter::LISTEN_ONLY, ON),
                Call::Initialize(0x51, 0x001c),
                Call::Set(parameter::ALLOW_STATUS_FRAMES, ON),
                Call::Set(parameter::ALLOW_ECHO_FRAMES, ON),
                Call::Watch(0x51),
                Call::Uninitialize(0x51),
            ]
        );

        let fake = Fake::with_one_usb_channel();
        opened(&fake, options(false, false))
            .await
            .unwrap()
            .stop()
            .await;
        assert_eq!(
            fake.calls(),
            [&STARTED[..], &[Call::Uninitialize(0x51)]].concat()
        );
    }

    #[tokio::test]
    async fn fd_and_a_second_channel_are_refused_before_a_call() {
        let fake = Fake::with_one_usb_channel();
        for (channel, data) in [(0, Some((2_000_000, None))), (1, None)] {
            let mut pcan = PcanOptions::new(device(None), 500_000);
            pcan.device.model = PcanModel::UsbProFd;
            pcan.channel = channel;
            pcan.data = data;
            let error = task::open::<Basic<Fake>>((fake.clone(), pcan), options(false, false))
                .await
                .err()
                .expect("refused");
            assert!(matches!(error, CanError::Config(_)), "{error:?}");
        }
        assert_eq!(fake.calls(), []);
    }

    #[tokio::test]
    async fn an_adapter_in_use_elsewhere_is_named_at_open() {
        let fake = Fake::with_one_usb_channel();
        fake.initialize.lock().unwrap().push_back(status::HWINUSE);
        let error = opened(&fake, options(false, false))
            .await
            .err()
            .expect("refused");
        assert!(error
            .to_string()
            .contains("another program holds the adapter"));
    }

    fn data(id: u32, msgtype: u8, byte: u8) -> Msg {
        Msg {
            id,
            msgtype,
            len: 1,
            data: [byte, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[tokio::test]
    async fn the_queue_is_drained_with_echoes_as_sends_and_an_overrun_flags_the_next_frame() {
        let fake = Fake::with_one_usb_channel();
        let mut task = opened(&fake, options(false, true)).await.unwrap();
        next(&mut task).await;
        fake.queue(status::OK, data(0x100, 0, 1), 1_000);
        fake.queue(status::OK, data(0, msgtype::STATUS, 0), 1_500);
        fake.queue(status::OK, data(0x101, msgtype::ECHO, 2), 2_000);
        fake.queue(status::QOVERRUN | status::QRCVEMPTY, Msg::default(), 0);
        fake.queue(status::OK, data(0x102, 0, 3), 3_250);
        let mut seen = Vec::new();
        while seen.len() < 3 {
            let CanEvent::Read(reads) = next(&mut task).await else {
                panic!("a read");
            };
            seen.extend(
                reads
                    .into_iter()
                    .map(|r| (r.frame.arb_id, r.direction, r.overflow, r.device_us)),
            );
        }
        assert_eq!(
            seen,
            [
                (0x100, Direction::Rx, false, Some(1_000)),
                (0x101, Direction::Tx, false, Some(2_000)),
                (0x102, Direction::Rx, true, Some(3_250)),
            ]
        );
    }

    #[tokio::test]
    async fn each_change_of_bus_status_is_reported() {
        let fake = Fake::with_one_usb_channel();
        let mut task = opened(&fake, options(false, false)).await.unwrap();
        next(&mut task).await;
        *fake.status.lock().unwrap() = status::BUSHEAVY;
        let CanEvent::Bus(state) = next(&mut task).await else {
            panic!("a bus report");
        };
        assert_eq!(state.state, ErrorState::Warning);
        *fake.status.lock().unwrap() = status::BUSPASSIVE | status::BUSHEAVY;
        let CanEvent::Bus(state) = next(&mut task).await else {
            panic!("a bus report");
        };
        assert_eq!(state.state, ErrorState::Passive);
    }

    #[tokio::test]
    async fn illhw_is_a_loss_that_reopens_the_channel() {
        let fake = Fake::with_one_usb_channel();
        let mut task = opened(&fake, options(false, false)).await.unwrap();
        next(&mut task).await;
        fake.queue(status::ILLHW, Msg::default(), 0);
        let CanEvent::Disconnected { error, .. } = next(&mut task).await else {
            panic!("a loss");
        };
        assert!(matches!(error, CanError::Closed), "{error:?}");
        assert!(matches!(next(&mut task).await, CanEvent::Connected(_)));
        let twice = [&STARTED[..], &[Call::Uninitialize(0x51)], &STARTED[..]].concat();
        assert_eq!(fake.calls(), twice);
    }

    #[tokio::test]
    async fn a_bus_off_channel_is_reinitialized_in_place() {
        let fake = Fake::with_one_usb_channel();
        let (mut basic, _) = Basic::<Fake>::open(
            &(fake.clone(), PcanOptions::new(device(None), 500_000)),
            &options(false, false),
        )
        .await
        .unwrap();
        basic.bus.restart_after = Duration::ZERO;
        *fake.status.lock().unwrap() = status::BUSOFF;
        basic.drain().unwrap();
        assert_eq!(basic.bus_reports()[0].state, ErrorState::BusOff);
        *fake.status.lock().unwrap() = status::OK;
        fake.calls.lock().unwrap().clear();
        basic.recover().await;
        assert_eq!(
            fake.calls(),
            [&[Call::Uninitialize(0x51)], &STARTED[..]].concat()
        );
        assert_eq!(basic.bus_reports()[0].state, ErrorState::Active);
    }

    #[tokio::test]
    async fn a_full_transmit_queue_is_retried_and_a_send_is_one_msg() {
        let fake = Fake::with_one_usb_channel();
        let task = opened(&fake, options(false, false)).await.unwrap();
        fake.writes
            .lock()
            .unwrap()
            .extend([status::QXMTFULL, status::OK]);
        let frame = CanFrame::data(0, 0x123, false, false, false, vec![9]);
        task.writer().send(frame).await.unwrap().unwrap();
        assert_eq!(*fake.written.lock().unwrap(), [data(0x123, 0, 9); 2]);
    }

    #[test]
    fn a_runtime_shut_down_without_stop_still_uninitializes() {
        let fake = Fake::with_one_usb_channel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let task = runtime.block_on(async {
            let mut task = opened(&fake, options(false, false)).await.unwrap();
            next(&mut task).await;
            task
        });
        drop(runtime);
        assert_eq!(fake.calls().last(), Some(&Call::Uninitialize(0x51)));
        drop(task);
    }
}
