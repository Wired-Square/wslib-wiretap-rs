//! SocketCAN on Linux: one raw socket per interface for classic and FD frames,
//! each stamped with the kernel's receive time. The interface's bitrate is set
//! outside, with privilege; [`bitrates`] reads it.
//!
//! A read is this module's own `recvmsg`, because socketcan doesn't pass up
//! `MSG_CONFIRM`, which is how the kernel marks the socket's own frames.

use std::{
    io, mem,
    os::fd::{AsRawFd, RawFd},
    ptr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use socketcan::{
    CanAnyFrame, CanDataFrame, CanFdFrame, CanFdSocket, CanInterface, CanRemoteFrame,
    EmbeddedFrame, ExtendedId, Id, Socket, SocketOptions, StandardId,
};
use tokio::io::{unix::AsyncFd, Interest};
use wiretap_protocol::socketcan::{parse_frame, FD_FRAME_BYTES};

use super::{
    clock::{Received, Stamp},
    task::{self, Device},
    writer::Limits,
    CanError, CanFrame, CanOptions, CanTask, DeviceInfo, Direction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketCanOptions {
    /// Reopened by name after a loss, so an adapter that comes back under the
    /// same name is found again.
    pub interface: String,
    /// Without it, FD frames are dropped and FD sends refused.
    pub fd: bool,
}

/// An interface's configured rates, `None` where it reports none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitrates {
    pub nominal: Option<u32>,
    pub data: Option<u32>,
}

/// Opens the socket now, on the caller's task, then spawns the task that reads
/// it. Panics outside a tokio runtime.
pub async fn open(sc: SocketCanOptions, options: CanOptions) -> Result<CanTask, CanError> {
    let config = Config {
        sc,
        kept: Arc::default(),
    };
    task::open::<SocketCan>(config, options).await
}

/// One netlink round trip; a netlink failure is `Err`, not `None`.
pub fn bitrates(interface: &str) -> io::Result<Bitrates> {
    let details = CanInterface::open(interface)?
        .details()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Bitrates {
        nominal: details.can.bit_timing.map(|t| t.bitrate),
        data: details.can.data_bit_timing.map(|t| t.bitrate),
    })
}

const BATCH: usize = 64;

type Raw = AsyncFd<CanFdSocket>;
type Kept = Arc<Mutex<Option<Raw>>>;

struct Config {
    sc: SocketCanOptions,
    /// The socket a read error left open, for the reopen to retry.
    kept: Kept,
}

struct SocketCan {
    socket: Raw,
    fd: bool,
    kept: Kept,
    keep: bool,
    /// An error read after a batch's frames, for the next read.
    pending: Option<CanError>,
}

impl Device for SocketCan {
    type Config = Config;

    async fn open(config: &Config, options: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
        let kept = config.kept.lock().unwrap_or_else(|e| e.into_inner()).take();
        let socket = match kept {
            Some(socket) => socket,
            None => {
                bind(&config.sc.interface, options.own_frames).map_err(|source| CanError::Open {
                    device: config.sc.interface.clone(),
                    source,
                })?
            }
        };
        let device = Self {
            socket,
            fd: config.sc.fd,
            kept: config.kept.clone(),
            keep: false,
            pending: None,
        };
        let info = DeviceInfo {
            buses: Some(1),
            fd: config.sc.fd,
            ..DeviceInfo::default()
        };
        Ok((device, info))
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
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        // A downed or deleted interface raises only EPOLLERR, which
        // `readable()` never wakes on.
        let mut guard = self
            .socket
            .ready(Interest::READABLE | Interest::ERROR)
            .await
            .map_err(CanError::Read)?;
        let mut received = Vec::new();
        for _ in 0..BATCH {
            let mut bytes = [0; FD_FRAME_BYTES];
            match guard.try_io(|socket| receive(socket.as_raw_fd(), &mut bytes)) {
                Ok(Ok((len, at, own))) => {
                    received.extend(incoming(&bytes[..len], at, own, self.fd))
                }
                Ok(Err(error)) => {
                    let error = self.lost(error);
                    if received.is_empty() {
                        return Err(error);
                    }
                    self.pending = Some(error);
                    break;
                }
                Err(_would_block) => break,
            }
        }
        Ok(received)
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        let frame = outgoing(frame).ok_or(io::ErrorKind::InvalidInput)?;
        self.socket
            .async_io(Interest::WRITABLE, |socket| socket.write_frame(&frame))
            .await
    }

    async fn close(self) {
        if self.keep {
            *self.kept.lock().unwrap_or_else(|e| e.into_inner()) = Some(self.socket);
        }
    }
}

impl SocketCan {
    /// A gone interface takes a new socket, by name; any other error keeps
    /// this one.
    fn lost(&mut self, error: io::Error) -> CanError {
        match error.raw_os_error() {
            Some(libc::ENODEV | libc::ENXIO) => CanError::Closed,
            _ => {
                self.keep = true;
                CanError::Read(error)
            }
        }
    }
}

fn bind(interface: &str, own_frames: bool) -> io::Result<Raw> {
    let socket = CanFdSocket::open(interface)?;
    socket.set_nonblocking(true)?;
    socket.set_recv_timestamp(true)?;
    socket.set_recv_own_msgs(own_frames)?;
    AsyncFd::new(socket)
}

/// Error frames are dropped, and FD frames unless `fd`.
fn incoming(bytes: &[u8], at: SystemTime, own: bool, fd: bool) -> Option<Received> {
    let raw = parse_frame(bytes)?;
    if raw.error || (raw.fd && !fd) {
        return None;
    }
    let mut frame = if raw.rtr {
        CanFrame::remote(0, raw.arb_id, raw.extended, raw.data.len() as u8)
    } else {
        CanFrame::data(0, raw.arb_id, raw.extended, raw.fd, raw.brs, raw.data)
    };
    frame.esi = raw.esi;
    Some(Received {
        frame,
        direction: if own { Direction::Tx } else { Direction::Rx },
        stamp: Stamp::Kernel(at),
        overflow: false,
    })
}

/// `None` for what `Limits` lets through but a frame can't hold: an RTR code
/// over 8.
fn outgoing(frame: &CanFrame) -> Option<CanAnyFrame> {
    let id: Id = if frame.extended {
        ExtendedId::new(frame.arb_id)?.into()
    } else {
        StandardId::new(u16::try_from(frame.arb_id).ok()?)?.into()
    };
    Some(if frame.rtr {
        CanRemoteFrame::new_remote(id, frame.dlc().into())?.into()
    } else if frame.fd {
        let mut fd = CanFdFrame::new(id, &frame.data)?;
        fd.set_brs(frame.brs);
        fd.into()
    } else {
        CanDataFrame::new(id, &frame.data)?.into()
    })
}

#[repr(C, align(8))]
struct Control([u8; 64]);

/// One `recvmsg` into `bytes`: its length, its `SO_TIMESTAMPNS`, and whether
/// the kernel marked it as this socket's own. A missing stamp is `InvalidData`,
/// as socketcan has it.
fn receive(fd: RawFd, bytes: &mut [u8]) -> io::Result<(usize, SystemTime, bool)> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = Control([0; 64]);
    // SAFETY: every pointer in `msg` outlives the call, and the cmsg walk stays
    // within the `msg_controllen` the kernel wrote back.
    unsafe {
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control.0.len() as _;
        let len = libc::recvmsg(fd, &mut msg, 0);
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut at = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_TIMESTAMPNS
            {
                let ts: libc::timespec = ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                at = Some(kernel_time(ts.tv_sec, ts.tv_nsec));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        let at = at.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no SO_TIMESTAMPNS control message received",
            )
        })?;
        Ok((len as usize, at, msg.msg_flags & libc::MSG_CONFIRM != 0))
    }
}

#[allow(dead_code)]
fn futures_are_send(sc: SocketCanOptions) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&open(sc, CanOptions::default()));
}

/// A kernel clock set before the epoch is clamped to it, as socketcan does.
/// `secs` is generic because naming `libc::time_t` is deprecated on musl.
fn kernel_time(secs: impl TryInto<u64>, nanos: libc::c_long) -> SystemTime {
    secs.try_into().map_or(UNIX_EPOCH, |secs| {
        UNIX_EPOCH + Duration::new(secs, nanos as u32)
    })
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    /// The cmsg walk, on a socket any Linux can open: a UDP datagram to itself.
    #[test]
    fn a_datagram_comes_with_its_kernel_stamp() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let on: libc::c_int = 1;
        // SAFETY: a valid fd and an int option of the size given.
        let set = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPNS,
                ptr::from_ref(&on).cast(),
                mem::size_of_val(&on) as _,
            )
        };
        assert_eq!(set, 0);
        let before = SystemTime::now();
        socket
            .send_to(b"frame", socket.local_addr().unwrap())
            .unwrap();
        let mut bytes = [0; 16];
        let (len, at, own) = receive(socket.as_raw_fd(), &mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"frame");
        assert!(at >= before - Duration::from_millis(1) && at <= SystemTime::now());
        assert!(!own);
    }

    #[test]
    fn a_stamp_before_the_epoch_is_clamped_to_it() {
        assert_eq!(kernel_time(-5, 0), UNIX_EPOCH);
        assert_eq!(kernel_time(2, 7), UNIX_EPOCH + Duration::new(2, 7));
    }

    #[test]
    fn without_a_stamp_the_read_is_invalid_data() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"x", socket.local_addr().unwrap()).unwrap();
        let error = receive(socket.as_raw_fd(), &mut [0; 16]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_error_frame_and_an_unwanted_fd_frame_are_dropped() {
        use wiretap_protocol::socketcan::{encode_frame, Frame};
        let at = SystemTime::now();
        let fd = encode_frame(&Frame::new(0x10, false, false, true, true, vec![1; 12]));
        assert!(incoming(&fd, at, false, false).is_none());
        let kept = incoming(&fd, at, true, true).unwrap();
        assert_eq!(
            kept.frame,
            CanFrame::data(0, 0x10, false, true, true, vec![1; 12])
        );
        assert_eq!(kept.direction, Direction::Tx);
        let error = Frame {
            error: true,
            ..Frame::new(0x10, false, false, false, false, vec![])
        };
        assert!(incoming(&encode_frame(&error), at, false, true).is_none());
    }

    #[test]
    fn an_fd_send_is_padded_to_a_length_code_and_keeps_its_brs() {
        let frame = outgoing(&CanFrame::data(0, 0x10, false, true, true, vec![7; 13])).unwrap();
        let CanAnyFrame::Fd(fd) = frame else {
            panic!("an FD frame");
        };
        assert_eq!(fd.data(), [&[7; 13][..], &[0; 3]].concat());
        assert!(fd.is_brs());
        let remote = outgoing(&CanFrame::remote(0, 0x10, false, 5)).unwrap();
        assert!(matches!(remote, CanAnyFrame::Remote(r) if r.dlc() == 5));
        assert!(outgoing(&CanFrame::remote(0, 0x10, false, 9)).is_none());
    }
}
