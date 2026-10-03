//! SLCAN as a host: `wiretap_protocol::slcan` over a serial port. The protocol
//! carries no timestamp, so a frame takes its read's time.
//!
//! Each command waits for its answer: `\r`, a bell, or a reply line. Opening
//! counts silence as taken, since not every firmware answers; a probe needs an
//! answer to `V`, `v` or `N`.

use std::{io, mem, time::Duration};

use tokio::time::{timeout, timeout_at, Instant};
use wiretap_protocol::{
    slcan::{
        bitrate_command, data_bitrate_command, encode_frame_into, parse_version, Frame, Line,
        LineDecoder, Version, BELL, CLOSE, DATA_BITRATES, MODE_NORMAL, MODE_SILENT,
        NOMINAL_BITRATES, OPEN, QUERY_HW_VERSION, QUERY_SERIAL, QUERY_VERSION,
    },
    ARB_MASK_EXT, ARB_MASK_STD,
};

use crate::serial::{blocking::Port, LineSettings};

use super::{
    clock::{Received, Stamp},
    port,
    task::{self, Device},
    writer::Limits,
    CanError, CanFrame, CanOptions, CanTask, DeviceInfo, Direction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlcanOptions {
    /// Opened read-write and exclusive, as `serial-write` opens a port.
    pub path: String,
    pub line: LineSettings,
    /// One of `wiretap_protocol::slcan::NOMINAL_BITRATES`.
    pub bitrate: u32,
    /// CAN FD's data rate, one of `DATA_BITRATES`, which needs the Elmue firmware.
    pub data_bitrate: Option<u32>,
}

/// Opens the port and starts the device now, on the caller's task, then spawns
/// the task that reads it. Panics outside a tokio runtime.
pub async fn open(slcan: SlcanOptions, options: CanOptions) -> Result<CanTask, CanError> {
    task::open::<Slcan>(slcan, options).await
}

/// Opens the port, asks `V`, `v` and `N`, and closes it, all within `timeout`.
/// The channel is never opened and nothing else is sent. Panics outside a tokio
/// runtime.
pub async fn probe(
    path: &str,
    line: LineSettings,
    timeout: Duration,
) -> Result<DeviceInfo, CanError> {
    let deadline = Instant::now() + timeout;
    let mut slcan = Slcan::new(port::open_before(path, line, deadline).await?, false);
    let mut heard = Heard::default();
    let asked = timeout_at(deadline, slcan.identify(&mut heard, true)).await;
    slcan.port.close().await;
    asked.unwrap_or(Ok(()))?;
    if !heard.answered {
        return Err(CanError::Handshake("no answer to V, v or N"));
    }
    Ok(DeviceInfo {
        buses: Some(1),
        fd: heard.version.elmue,
        firmware: heard.version.firmware,
        hardware: heard.hardware,
        serial: heard.serial,
        ..DeviceInfo::default()
    })
}

/// A freshly plugged USB device can drop what it is sent before this.
const SETTLE: Duration = Duration::from_millis(200);
const ANSWER_TIMEOUT: Duration = Duration::from_millis(100);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

struct Slcan {
    port: Port,
    decoder: LineDecoder,
    /// Whether the decoder holds part of a line, so a `\r` ends it rather
    /// than answering a command.
    mid_line: bool,
    outbound: Vec<u8>,
    /// Read past a command's answer, for the next answer or the first read.
    unread: Vec<u8>,
    fd: bool,
}

enum Answer {
    Taken,
    Refused,
    Reply(String),
    Silent,
}

/// What the device said to `V`, `v` and `N`.
#[derive(Default)]
struct Heard {
    answered: bool,
    version: Version,
    hardware: Option<String>,
    serial: Option<String>,
}

impl Heard {
    /// The reply line, if the answer was one.
    fn hear(&mut self, answer: Answer) -> Option<String> {
        self.answered |= !matches!(answer, Answer::Silent);
        match answer {
            Answer::Reply(reply) => Some(reply),
            _ => None,
        }
    }
}

impl Device for Slcan {
    type Config = SlcanOptions;

    async fn open(
        config: &SlcanOptions,
        options: &CanOptions,
    ) -> Result<(Self, DeviceInfo), CanError> {
        let bitrate = command(config.bitrate, bitrate_command, &NOMINAL_BITRATES)?;
        let data_bitrate = config
            .data_bitrate
            .map(|bps| Ok((bps, command(bps, data_bitrate_command, &DATA_BITRATES)?)))
            .transpose()?;
        let port = port::open(&config.path, config.line)?;
        let mut slcan = Self::new(port, data_bitrate.is_some());
        let info = slcan
            .start(config.bitrate, bitrate, data_bitrate, options.listen_only)
            .await?;
        Ok((slcan, info))
    }

    fn limits(&self) -> Limits {
        Limits {
            fd: self.fd,
            brs: self.fd,
            rtr: true,
            buses: Some(1),
        }
    }

    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        let bytes = match mem::take(&mut self.unread) {
            unread if unread.is_empty() => port::read(&mut self.port, &mut self.outbound).await?,
            unread => unread,
        };
        Ok(self
            .decoder
            .feed(&bytes)
            .into_iter()
            .filter_map(|line| match line {
                Line::Frame(frame) => Some(received(frame)),
                Line::Reply(_) => None,
            })
            .collect())
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        let frame = if frame.rtr {
            Frame::remote(frame.arb_id, frame.extended, frame.dlc())
        } else {
            Frame::data(
                frame.arb_id,
                frame.extended,
                frame.fd,
                frame.brs,
                frame.data.clone(),
            )
        };
        encode_frame_into(&mut self.outbound, &frame);
        self.port.write(&mut self.outbound).await
    }

    async fn close(mut self) {
        self.outbound.extend_from_slice(CLOSE.as_bytes());
        let _ = timeout(CLOSE_TIMEOUT, self.port.write(&mut self.outbound)).await;
        self.port.close().await;
    }
}

impl Slcan {
    fn new(port: Port, fd: bool) -> Self {
        Self {
            port,
            decoder: LineDecoder::new(),
            mid_line: false,
            outbound: Vec::new(),
            unread: Vec::new(),
            fd,
        }
    }

    async fn start(
        &mut self,
        bps: u32,
        bitrate: &str,
        data_bitrate: Option<(u32, &str)>,
        listen_only: bool,
    ) -> Result<DeviceInfo, CanError> {
        let mut heard = Heard::default();
        self.identify(&mut heard, false).await?;
        let Heard {
            version, serial, ..
        } = heard;
        if data_bitrate.is_some() && !version.elmue {
            return Err(CanError::Config(
                "CAN FD needs the Elmue firmware".to_owned(),
            ));
        }

        if let Answer::Refused = self.ask(bitrate).await? {
            return Err(CanError::Config(format!("the device refused {bps} bit/s")));
        }
        if let Some((bps, data_bitrate)) = data_bitrate {
            if let Answer::Refused = self.ask(data_bitrate).await? {
                return Err(CanError::Config(format!(
                    "the device refused a data rate of {bps} bit/s"
                )));
            }
        }
        // A device without modes refuses `M0` and runs as it would anyway.
        let mode = if listen_only {
            MODE_SILENT
        } else {
            MODE_NORMAL
        };
        let refused = matches!(self.ask(mode).await?, Answer::Refused);
        if refused && listen_only {
            return Err(CanError::Config(
                "the device refused silent mode".to_owned(),
            ));
        }
        if let Answer::Refused = self.ask(OPEN).await? {
            return Err(CanError::Handshake(
                "the device refused to open the channel",
            ));
        }
        Ok(DeviceInfo {
            buses: Some(1),
            fd: version.elmue,
            hardware: board_and_mcu(version.board.as_deref(), version.mcu.as_deref()),
            firmware: version.firmware,
            serial,
            ..DeviceInfo::default()
        })
    }

    /// Settles, closes a channel left open, and asks `V`, then `v` if `V` named
    /// no board or MCU and `hardware` is set, then `N`. Fills `heard` as the
    /// answers come, so a deadline keeps what came before it.
    async fn identify(&mut self, heard: &mut Heard, hardware: bool) -> Result<(), CanError> {
        let settled = Instant::now() + SETTLE;
        while self.read_before(settled).await?.is_some() {}
        // Lawicel's firmware refuses `C` on a closed channel, which is fine.
        self.ask(CLOSE).await?;
        if let Some(reply) = heard.hear(self.ask(QUERY_VERSION).await?) {
            heard.version = parse_version(&reply);
            let version = &heard.version;
            heard.hardware = board_and_mcu(version.board.as_deref(), version.mcu.as_deref());
        }
        if hardware && heard.hardware.is_none() {
            let reply = heard.hear(self.ask(QUERY_HW_VERSION).await?);
            heard.hardware = reply.and_then(|reply| unechoed('v', &reply));
        }
        let reply = heard.hear(self.ask(QUERY_SERIAL).await?);
        heard.serial = reply.and_then(|reply| unechoed('N', &reply));
        Ok(())
    }

    async fn ask(&mut self, command: &str) -> Result<Answer, CanError> {
        self.outbound.extend_from_slice(command.as_bytes());
        self.port
            .write(&mut self.outbound)
            .await
            .map_err(CanError::Read)?;
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        let mut bytes = mem::take(&mut self.unread);
        loop {
            if let Some((answer, used)) = self.answer(&bytes) {
                self.unread = bytes.split_off(used);
                return Ok(answer);
            }
            match self.read_before(deadline).await? {
                Some(read) => bytes = read,
                None => return Ok(Answer::Silent),
            }
        }
    }

    /// The first answer in `bytes`, and how many bytes it took. Frames before
    /// it are from before the channel was set up, and are dropped.
    fn answer(&mut self, bytes: &[u8]) -> Option<(Answer, usize)> {
        for (at, &byte) in bytes.iter().enumerate() {
            let answer = match byte {
                BELL => Some(Answer::Refused),
                b'\r' if !self.mid_line => Some(Answer::Taken),
                _ => None,
            };
            self.mid_line = match byte {
                b'\r' | b'\n' | BELL => false,
                b if b.is_ascii() && !b.is_ascii_control() => true,
                _ => self.mid_line,
            };
            let reply = self
                .decoder
                .feed(&[byte])
                .into_iter()
                .find_map(|line| match line {
                    Line::Reply(reply) => Some(Answer::Reply(reply)),
                    Line::Frame(_) => None,
                });
            if let Some(answer) = reply.or(answer) {
                return Some((answer, at + 1));
            }
        }
        None
    }

    /// `None` once `deadline` has passed.
    async fn read_before(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, CanError> {
        timeout_at(deadline, port::read(&mut self.port, &mut self.outbound))
            .await
            .ok()
            .transpose()
    }
}

/// The command for `bps`, or `Config` naming the rates there are.
fn command(
    bps: u32,
    lookup: fn(u32) -> Option<&'static str>,
    table: &[(u32, &str)],
) -> Result<&'static str, CanError> {
    lookup(bps).ok_or_else(|| {
        let rates: Vec<String> = table.iter().map(|(rate, _)| rate.to_string()).collect();
        CanError::Config(format!(
            "{bps} bit/s is not an SLCAN rate; it takes {}",
            rates.join(", ")
        ))
    })
}

fn board_and_mcu(board: Option<&str>, mcu: Option<&str>) -> Option<String> {
    match (board, mcu) {
        (Some(board), Some(mcu)) => Some(format!("{board} {mcu}")),
        (board, mcu) => board.or(mcu).map(str::to_owned),
    }
}

fn received(frame: Frame) -> Received {
    let mask = if frame.extended {
        ARB_MASK_EXT
    } else {
        ARB_MASK_STD
    };
    let arb_id = frame.arb_id & mask;
    let frame = if frame.rtr {
        CanFrame::remote(0, arb_id, frame.extended, frame.dlc)
    } else {
        CanFrame::data(0, arb_id, frame.extended, frame.fd, frame.brs, frame.data)
    };
    Received {
        frame,
        direction: Direction::Rx,
        stamp: Stamp::Read,
        overflow: false,
    }
}

/// The reply without the command letter a device echoes, if anything is left.
fn unechoed(command: char, reply: &str) -> Option<String> {
    let rest = reply.strip_prefix(command).unwrap_or(reply);
    (!rest.is_empty()).then(|| rest.to_owned())
}

#[allow(dead_code)]
fn futures_are_send(slcan: SlcanOptions) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&probe(&slcan.path, slcan.line, Duration::ZERO));
    is_send(&open(slcan, CanOptions::default()));
}
