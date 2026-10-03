use std::{
    io,
    time::{Duration, SystemTime},
};

use tokio::time::{sleep, timeout, Instant};
use tokio_modbus::{
    client::{tcp::attach_slave, Context},
    prelude::{Client, ReadCode, Request, Response, SlaveContext},
    ProtocolError, Slave,
};

use super::{
    DeviceIdCode, DeviceIdentification, ExceptionCode, ReadData, ReadRequest, Reading,
    RequestError, TransportError,
};
use wiretap_catalog::modbus::RegisterType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOptions {
    /// Covers resolving and every address tried, one at a time, each getting an
    /// even share of what remains. An IP literal endpoint gets all of it.
    pub connect_timeout: Duration,
    /// Applies to every request.
    pub op_timeout: Duration,
    /// Wait after each (re)connect.
    pub settle: Duration,
    pub reconnect_per_request: bool,
    /// Before a request, a socket idle longer than this is replaced. Cheap
    /// stacks close idle connections after 30–120 s.
    pub idle_reconnect: Option<Duration>,
    /// Used when a request names none.
    pub unit_id: u8,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            op_timeout: Duration::from_secs(10),
            settle: Duration::ZERO,
            reconnect_per_request: false,
            idle_reconnect: None,
            unit_id: 1,
        }
    }
}

pub struct ModbusTcp {
    endpoint: String,
    pub(super) options: TcpOptions,
    link: Option<Link>,
}

/// Owned by the request in flight, so dropping its future drops the socket.
pub(super) struct Link {
    ctx: Context,
    last_used: Instant,
}

impl ModbusTcp {
    /// Doesn't connect. The first request, or `connect`, does.
    pub fn new(endpoint: impl Into<String>, options: TcpOptions) -> Self {
        Self {
            endpoint: endpoint.into(),
            options,
            link: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), TransportError> {
        if self.link.is_none() {
            self.link = Some(open(&self.endpoint, &self.options).await?);
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.link.is_some()
    }

    pub async fn disconnect(&mut self) {
        if let Some(mut link) = self.link.take() {
            let _ = timeout(self.options.op_timeout, link.ctx.disconnect()).await;
        }
    }

    pub async fn read(&mut self, request: ReadRequest) -> Result<Reading, RequestError> {
        let ReadRequest {
            register_type,
            start,
            count,
            unit,
        } = request;
        let wire = match register_type {
            RegisterType::Coil => Request::ReadCoils(start, count),
            RegisterType::Discrete => Request::ReadDiscreteInputs(start, count),
            RegisterType::Holding => Request::ReadHoldingRegisters(start, count),
            RegisterType::Input => Request::ReadInputRegisters(start, count),
        };
        let (data, latency) = self
            .call(unit, wire, |response| match response {
                Response::ReadCoils(mut bits) | Response::ReadDiscreteInputs(mut bits) => {
                    bits.truncate(count.into());
                    Some(ReadData::Coils(bits))
                }
                Response::ReadHoldingRegisters(words) | Response::ReadInputRegisters(words) => {
                    Some(ReadData::Registers(words))
                }
                _ => None,
            })
            .await?;
        Ok(Reading {
            data,
            latency,
            at: SystemTime::now(),
        })
    }

    pub async fn read_device_identification(
        &mut self,
        unit: Option<u8>,
        code: DeviceIdCode,
        object: u8,
    ) -> Result<DeviceIdentification, RequestError> {
        let read_code = match code {
            DeviceIdCode::Basic => ReadCode::Basic,
            DeviceIdCode::Regular => ReadCode::Regular,
            DeviceIdCode::Extended => ReadCode::Extended,
            DeviceIdCode::Specific => ReadCode::Specific,
        };
        let request = Request::ReadDeviceIdentification(read_code, object);
        let (identification, _) = self
            .call(unit, request, |response| match response {
                Response::ReadDeviceIdentification(r) => Some(DeviceIdentification {
                    conformity_level: r.conformity_level.value(),
                    objects: r
                        .device_id_objects
                        .into_iter()
                        .map(|o| (o.id, o.value.to_vec()))
                        .collect(),
                    more_follows: r.more_follows,
                    next_object_id: r.next_object_id,
                }),
                _ => None,
            })
            .await?;
        Ok(identification)
    }

    pub(super) async fn call<T>(
        &mut self,
        unit: Option<u8>,
        request: Request<'_>,
        extract: impl FnOnce(Response) -> Option<T>,
    ) -> Result<(T, Duration), RequestError> {
        let mut link = self.acquire().await?;
        let result = link
            .exchange(self.unit(unit), request, self.options.op_timeout, extract)
            .await;
        if !matches!(result, Err(RequestError::Transport(_))) {
            self.release(link);
        }
        result
    }

    pub(super) fn unit(&self, unit: Option<u8>) -> u8 {
        unit.unwrap_or(self.options.unit_id)
    }

    pub(super) async fn acquire(&mut self) -> Result<Link, TransportError> {
        let idle_limit = self.options.idle_reconnect;
        match self.link.take() {
            Some(link) if !idle_limit.is_some_and(|idle| link.last_used.elapsed() > idle) => {
                Ok(link)
            }
            _ => open(&self.endpoint, &self.options).await,
        }
    }

    pub(super) fn release(&mut self, link: Link) {
        if !self.options.reconnect_per_request {
            self.link = Some(link);
        }
    }
}

/// Borrows the endpoint and options rather than the connection, which is
/// `Send` but not `Sync`.
async fn open(endpoint: &str, options: &TcpOptions) -> Result<Link, TransportError> {
    let stream = crate::net::connect(endpoint, options.connect_timeout).await?;
    if !options.settle.is_zero() {
        sleep(options.settle).await;
    }
    Ok(Link {
        ctx: attach_slave(stream, Slave(options.unit_id)),
        last_used: Instant::now(),
    })
}

impl Link {
    pub(super) async fn exchange<T>(
        &mut self,
        unit: u8,
        request: Request<'_>,
        op_timeout: Duration,
        extract: impl FnOnce(Response) -> Option<T>,
    ) -> Result<(T, Duration), RequestError> {
        self.ctx.set_slave(Slave(unit));
        let sent = Instant::now();
        let reply = timeout(op_timeout, self.ctx.call(request)).await;
        let latency = sent.elapsed();
        self.last_used = Instant::now();
        let transport = match reply {
            Ok(Ok(Ok(response))) => match extract(response) {
                Some(value) => return Ok((value, latency)),
                None => TransportError::Protocol("unexpected response".into()),
            },
            Ok(Ok(Err(code))) => {
                return Err(RequestError::Exception {
                    code: ExceptionCode::from_code(code.into()),
                    latency,
                })
            }
            Ok(Err(tokio_modbus::Error::Transport(e))) if closed_by_peer(&e) => {
                TransportError::Closed
            }
            Ok(Err(tokio_modbus::Error::Transport(e))) => TransportError::Io(e),
            Ok(Err(tokio_modbus::Error::Protocol(e))) => TransportError::Protocol(match e {
                ProtocolError::HeaderMismatch { message, .. } => message,
                ProtocolError::FunctionCodeMismatch { request, .. } => {
                    format!("reply does not match function {request}")
                }
            }),
            Err(_) => TransportError::Timeout { after: op_timeout },
        };
        Err(transport.into())
    }
}

/// tokio-modbus reports a clean EOF as `io::Error::last_os_error()`, a stale
/// errno: the EAGAIN or EINPROGRESS of an earlier syscall on the same thread.
fn closed_by_peer(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    matches!(
        e.kind(),
        UnexpectedEof
            | ConnectionReset
            | ConnectionAborted
            | BrokenPipe
            | NotConnected
            | WouldBlock
    ) || e.raw_os_error() == Some(EINPROGRESS)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
const EINPROGRESS: i32 = 36;
#[cfg(target_os = "linux")]
const EINPROGRESS: i32 = 115;
#[cfg(target_os = "windows")]
const EINPROGRESS: i32 = 10036;

#[allow(dead_code)]
fn futures_are_send(mut tcp: ModbusTcp, request: ReadRequest) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&tcp);
    is_send(&tcp.connect());
    is_send(&tcp.disconnect());
    is_send(&tcp.read(request));
    is_send(&tcp.read_device_identification(None, DeviceIdCode::Basic, 0));
}
