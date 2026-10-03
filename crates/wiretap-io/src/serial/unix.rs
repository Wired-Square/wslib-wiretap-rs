//! WireTAP-Server's `SerialLine`: `O_RDONLY`, so no write path exists, and raw
//! termios with software and hardware flow control cleared explicitly —
//! `cfmakeraw` leaves `IXOFF` as the port had it, and with it set the kernel
//! would put an XOFF on the wire. `VMIN = 1`, so a read with nothing there is
//! `WouldBlock` rather than zero: zero is the line gone.

use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
};

use nix::{
    fcntl::OFlag,
    sys::termios::{self, BaudRate, ControlFlags, FlushArg, InputFlags, SetArg},
};
use tokio::io::{unix::AsyncFd, Interest};

use super::{check, LineSettings, Parity, SerialError, SerialOptions};

nix::ioctl_none_bad!(tiocexcl, nix::libc::TIOCEXCL);

pub(super) struct Port {
    fd: AsyncFd<File>,
    buf: Vec<u8>,
}

impl Port {
    pub(super) fn open(
        path: &str,
        line: LineSettings,
        options: &SerialOptions,
    ) -> Result<Self, SerialError> {
        check(line)?;
        let speed = baud(line.baud).ok_or(SerialError::UnsupportedBaud(line.baud))?;
        let failed = |source| SerialError::Open {
            path: path.to_owned(),
            source,
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_NOCTTY | OFlag::O_NONBLOCK).bits())
            .open(path)
            .map_err(failed)?;
        configure(&file, line, speed, options.exclusive).map_err(|e| failed(e.into()))?;
        Ok(Self {
            fd: AsyncFd::new(file).map_err(failed)?,
            buf: vec![0; options.read_buffer.max(1)],
        })
    }

    /// Cancel-safe.
    pub(super) async fn read(&mut self) -> Result<Vec<u8>, SerialError> {
        let buf = &mut self.buf;
        match self
            .fd
            .async_io(Interest::READABLE, |mut file| file.read(buf))
            .await
        {
            Ok(0) => Err(SerialError::Closed),
            Ok(n) => Ok(self.buf[..n].to_vec()),
            Err(e) => Err(SerialError::Read(e)),
        }
    }

    pub(super) async fn close(self) {}
}

fn configure(file: &File, line: LineSettings, speed: BaudRate, exclusive: bool) -> nix::Result<()> {
    if exclusive {
        // SAFETY: TIOCEXCL takes no argument, and `file` is an open descriptor.
        unsafe { tiocexcl(file.as_raw_fd()) }?;
    }
    let mut t = termios::tcgetattr(file)?;
    termios::cfmakeraw(&mut t);
    termios::cfsetspeed(&mut t, speed)?;
    t.input_flags &= !(InputFlags::IXON | InputFlags::IXOFF | InputFlags::IXANY);
    t.control_flags |= ControlFlags::CLOCAL | ControlFlags::CREAD;
    t.control_flags &= !(ControlFlags::CSIZE
        | ControlFlags::PARENB
        | ControlFlags::PARODD
        | ControlFlags::CSTOPB
        | ControlFlags::CRTSCTS);
    t.control_flags |= match line.data_bits {
        5 => ControlFlags::CS5,
        6 => ControlFlags::CS6,
        7 => ControlFlags::CS7,
        _ => ControlFlags::CS8,
    };
    t.control_flags |= match line.parity {
        Parity::None => ControlFlags::empty(),
        Parity::Even => ControlFlags::PARENB,
        Parity::Odd => ControlFlags::PARENB | ControlFlags::PARODD,
    };
    if line.stop_bits == 2 {
        t.control_flags |= ControlFlags::CSTOPB;
    }
    termios::tcsetattr(file, SetArg::TCSANOW, &t)?;
    // Whatever arrived before the line was configured isn't this open's.
    termios::tcflush(file, FlushArg::TCIFLUSH)
}

/// macOS has no termios constant above 230 400 baud.
fn baud(rate: u32) -> Option<BaudRate> {
    Some(match rate {
        50 => BaudRate::B50,
        75 => BaudRate::B75,
        110 => BaudRate::B110,
        134 => BaudRate::B134,
        150 => BaudRate::B150,
        200 => BaudRate::B200,
        300 => BaudRate::B300,
        600 => BaudRate::B600,
        1200 => BaudRate::B1200,
        1800 => BaudRate::B1800,
        2400 => BaudRate::B2400,
        4800 => BaudRate::B4800,
        9600 => BaudRate::B9600,
        19200 => BaudRate::B19200,
        38400 => BaudRate::B38400,
        57600 => BaudRate::B57600,
        115200 => BaudRate::B115200,
        230400 => BaudRate::B230400,
        #[cfg(target_os = "linux")]
        460800 => BaudRate::B460800,
        #[cfg(target_os = "linux")]
        500000 => BaudRate::B500000,
        #[cfg(target_os = "linux")]
        576000 => BaudRate::B576000,
        #[cfg(target_os = "linux")]
        921600 => BaudRate::B921600,
        #[cfg(target_os = "linux")]
        1000000 => BaudRate::B1000000,
        #[cfg(target_os = "linux")]
        1152000 => BaudRate::B1152000,
        #[cfg(target_os = "linux")]
        1500000 => BaudRate::B1500000,
        #[cfg(target_os = "linux")]
        2000000 => BaudRate::B2000000,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(baud: u32) -> LineSettings {
        LineSettings {
            baud,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
        }
    }

    #[test]
    fn standard_rates_map_to_their_kernel_constant() {
        assert_eq!(baud(9600), Some(BaudRate::B9600));
        assert_eq!(baud(115200), Some(BaudRate::B115200));
        assert_eq!(baud(230400), Some(BaudRate::B230400));
        assert_eq!(baud(9601), None);
        assert_eq!(baud(0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_maps_rates_above_230400() {
        assert_eq!(baud(460800), Some(BaudRate::B460800));
        assert_eq!(baud(921600), Some(BaudRate::B921600));
        assert_eq!(baud(2000000), Some(BaudRate::B2000000));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_rates_above_230400_before_opening() {
        for rate in [460800, 921600, 2000000] {
            let refused = Port::open("/nonexistent", line(rate), &SerialOptions::default());
            assert!(matches!(refused, Err(SerialError::UnsupportedBaud(r)) if r == rate));
        }
    }

    #[test]
    fn a_rate_with_no_constant_is_refused_before_opening() {
        let refused = Port::open("/nonexistent", line(9601), &SerialOptions::default());
        assert!(matches!(refused, Err(SerialError::UnsupportedBaud(9601))));
    }
}
