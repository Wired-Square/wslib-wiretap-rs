//! GVRET as a host: `wiretap_protocol::gvret`'s host end, driven over a link.
//! A device that has answered a keepalive is `Unresponsive` once ten asks in a
//! row go unanswered; one that never answers is never dropped.

use std::{future, io, mem, time::Duration};

use tokio::{
    net::TcpStream,
    time::{sleep, sleep_until, timeout_at, Instant},
};
use wiretap_protocol::gvret::{
    encode_transmit_into, DeviceDecoder, DeviceMessage, REQ_DEV_INFO, REQ_KEEPALIVE, REQ_NUM_BUSES,
    SYNC,
};

#[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
use crate::serial::{blocking, LineSettings};

use super::{
    clock::{Received, Stamp},
    task::{self, Device},
    writer::Limits,
    CanError, CanFrame, CanOptions, CanTask, DeviceInfo, Direction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Link {
    /// `endpoint` is `host:port`, resolved on every connect.
    Tcp {
        endpoint: String,
        connect_timeout: Duration,
    },
    /// Opened read-write and exclusive, as `serial-write` opens a port.
    #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
    Serial { path: String, line: LineSettings },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GvretOptions {
    /// How long to wait for the bus count; silence is `DeviceInfo::buses: None`.
    pub probe_timeout: Duration,
    /// How often to ask whether the device is alive; `None` never asks.
    pub keepalive: Option<Duration>,
}

impl Default for GvretOptions {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_millis(1500),
            keepalive: Some(Duration::from_millis(250)),
        }
    }
}

/// Connects and runs the handshake now, on the caller's task, then spawns the
/// task that reads the device. Panics outside a tokio runtime.
pub async fn open(
    link: Link,
    gvret: GvretOptions,
    options: CanOptions,
) -> Result<CanTask, CanError> {
    task::open::<Gvret>(Config { link, gvret }, options).await
}

/// Syncs, asks for the device info and the bus count, and closes the link, all
/// within `timeout`. No frame, bus setup or keepalive is sent. Silence is
/// `buses: None`; a close or a read error is `Err`. Panics outside a tokio
/// runtime.
pub async fn probe(link: Link, timeout: Duration) -> Result<DeviceInfo, CanError> {
    let deadline = Instant::now() + timeout;
    let mut gvret = Gvret::new(Wire::open(&link, Some(deadline)).await?, None);
    let asked = timeout_at(deadline, gvret.handshake(timeout)).await;
    let info = mem::take(&mut gvret.info);
    gvret.close().await;
    asked.unwrap_or(Ok(())).map(|()| info)
}

const SETTLE: Duration = Duration::from_millis(100);
const UNANSWERED_LIMIT: u32 = 10;

struct Config {
    link: Link,
    gvret: GvretOptions,
}

struct Gvret {
    wire: Wire,
    decoder: DeviceDecoder,
    /// Bytes the link hasn't taken yet, so a cancelled read loses none.
    outbound: Vec<u8>,
    /// Frames read during the handshake, for the first read.
    early: Vec<Received>,
    keepalive: Option<Keepalive>,
    info: DeviceInfo,
}

struct Keepalive {
    every: Duration,
    next: Instant,
    answered: bool,
    unanswered: u32,
}

impl Device for Gvret {
    type Config = Config;

    async fn open(config: &Config, _: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
        let wire = Wire::open(&config.link, None).await?;
        let mut gvret = Self::new(wire, config.gvret.keepalive);
        gvret.handshake(config.gvret.probe_timeout).await?;
        let info = gvret.info.clone();
        Ok((gvret, info))
    }

    fn limits(&self) -> Limits {
        Limits {
            fd: false,
            brs: false,
            rtr: false,
            // Some firmware answers 0; refusing every bus would stop it sending at all.
            buses: self.info.buses.filter(|&n| n > 0),
        }
    }

    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        if !self.early.is_empty() {
            return Ok(mem::take(&mut self.early));
        }
        loop {
            let next_ask = self.keepalive.as_ref().map(|k| k.next);
            tokio::select! {
                biased;
                () = until(next_ask) => self.ask_keepalive()?,
                bytes = self.wire.read(&mut self.outbound) => {
                    let frames = self.decode(&bytes?);
                    if !frames.is_empty() {
                        return Ok(frames);
                    }
                }
            }
        }
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        encode_transmit_into(
            &mut self.outbound,
            frame.arb_id,
            frame.extended,
            frame.bus,
            &frame.data,
        );
        self.flush().await
    }

    async fn close(self) {
        self.wire.close().await;
    }
}

impl Gvret {
    fn new(wire: Wire, keepalive: Option<Duration>) -> Self {
        Self {
            wire,
            decoder: DeviceDecoder::new(),
            outbound: Vec::new(),
            early: Vec::new(),
            keepalive: keepalive.map(|every| Keepalive {
                every,
                next: Instant::now(),
                answered: false,
                unanswered: 0,
            }),
            info: DeviceInfo::default(),
        }
    }

    /// A close or a read error is the caller's error; silence is not.
    async fn handshake(&mut self, probe_timeout: Duration) -> Result<(), CanError> {
        self.outbound.extend_from_slice(&SYNC);
        self.flush().await.map_err(CanError::Read)?;
        sleep(SETTLE).await;
        self.outbound.extend_from_slice(&REQ_DEV_INFO);
        self.ask_keepalive()?;
        self.outbound.extend_from_slice(&REQ_NUM_BUSES);
        self.flush().await.map_err(CanError::Read)?;

        let deadline = Instant::now() + probe_timeout;
        while self.info.buses.is_none() {
            let Ok(bytes) = timeout_at(deadline, self.wire.read(&mut self.outbound)).await else {
                break;
            };
            let frames = self.decode(&bytes?);
            self.early.extend(frames);
        }
        self.info.keepalive = self.keepalive.as_ref().is_some_and(|k| k.answered);
        Ok(())
    }

    /// The frames in `bytes`; the replies go into `info`.
    fn decode(&mut self, bytes: &[u8]) -> Vec<Received> {
        let mut frames = Vec::new();
        for message in self.decoder.feed(bytes) {
            match message {
                DeviceMessage::Frame {
                    ts_us,
                    bus,
                    arb_id,
                    extended,
                    data,
                    ..
                } => frames.push(Received {
                    frame: CanFrame::data(bus, arb_id, extended, data.len() > 8, false, data),
                    direction: Direction::Rx,
                    stamp: Stamp::Counter(ts_us),
                    overflow: false,
                }),
                DeviceMessage::Keepalive => {
                    if let Some(k) = &mut self.keepalive {
                        k.answered = true;
                        k.unanswered = 0;
                    }
                }
                DeviceMessage::NumBuses(n) => self.info.buses = Some(n),
                DeviceMessage::DevInfo { build, .. } => {
                    self.info.firmware = Some(build.to_string());
                }
                _ => {}
            }
        }
        frames
    }

    fn ask_keepalive(&mut self) -> Result<(), CanError> {
        let Some(k) = &mut self.keepalive else {
            return Ok(());
        };
        if k.answered && k.unanswered >= UNANSWERED_LIMIT {
            return Err(CanError::Unresponsive);
        }
        k.unanswered = k.unanswered.saturating_add(1);
        k.next = Instant::now() + k.every;
        self.outbound.extend_from_slice(&REQ_KEEPALIVE);
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.wire.flush(&mut self.outbound).await
    }
}

enum Wire {
    Tcp(TcpStream),
    #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
    Serial(blocking::Port),
}

impl Wire {
    /// With a `deadline`, a connect gets no longer than is left, and a serial
    /// open runs on the blocking pool.
    async fn open(link: &Link, deadline: Option<Instant>) -> Result<Self, CanError> {
        match link {
            Link::Tcp {
                endpoint,
                connect_timeout,
            } => {
                let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
                let budget = left.map_or(*connect_timeout, |left| left.min(*connect_timeout));
                let stream = crate::net::connect(endpoint, budget)
                    .await
                    .map_err(CanError::Connect)?;
                let _ = stream.set_nodelay(true);
                Ok(Self::Tcp(stream))
            }
            #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
            Link::Serial { path, line } => match deadline {
                Some(deadline) => super::port::open_before(path, *line, deadline).await,
                None => super::port::open(path, *line),
            }
            .map(Self::Serial),
        }
    }

    /// Cancel-safe: pushes `outbound` while it waits, and returns at least a byte.
    async fn read(&mut self, outbound: &mut Vec<u8>) -> Result<Vec<u8>, CanError> {
        match self {
            Self::Tcp(stream) => loop {
                tokio::select! {
                    biased;
                    ready = stream.writable(), if !outbound.is_empty() => {
                        ready.map_err(CanError::Read)?;
                        let _ = push(stream, outbound);
                    }
                    ready = stream.readable() => {
                        ready.map_err(CanError::Read)?;
                        let mut buf = [0; 4096];
                        match stream.try_read(&mut buf) {
                            Ok(0) => return Err(CanError::Closed),
                            Ok(n) => return Ok(buf[..n].to_vec()),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(e) => return Err(CanError::Read(e)),
                        }
                    }
                }
            },
            #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
            Self::Serial(port) => super::port::read(port, outbound).await,
        }
    }

    /// A failed write drops what was pending: the next read decides the link.
    async fn flush(&mut self, outbound: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => {
                while !outbound.is_empty() {
                    stream.writable().await?;
                    push(stream, outbound)?;
                }
                Ok(())
            }
            #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
            Self::Serial(port) => port.write(outbound).await,
        }
    }

    async fn close(self) {
        #[cfg(all(feature = "can-gvret-serial", not(target_os = "ios")))]
        if let Self::Serial(port) = self {
            port.close().await;
        }
    }
}

fn push(stream: &TcpStream, outbound: &mut Vec<u8>) -> io::Result<()> {
    match stream.try_write(outbound) {
        Ok(n) => {
            outbound.drain(..n);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => {
            outbound.clear();
            Err(e)
        }
    }
}

async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => future::pending().await,
    }
}

#[allow(dead_code)]
fn futures_are_send(link: Link) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&probe(link.clone(), Duration::ZERO));
    is_send(&open(link, GvretOptions::default(), CanOptions::default()));
}
