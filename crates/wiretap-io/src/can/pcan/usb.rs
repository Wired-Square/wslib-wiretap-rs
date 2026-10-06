use std::{
    future::{Future, IntoFuture},
    io,
    time::Duration,
};

use nusb::{
    transfer::{
        Bulk, Completion, ControlIn, ControlOut, ControlType, EndpointDirection, In, Out, Recipient,
    },
    DeviceInfo as UsbDevice, Endpoint, Interface, MaybeFuture, Speed,
};
use tokio::time::{timeout, timeout_at, Instant};
use wiretap_protocol::{
    pcan_usb::{
        device_rev, encode_transmit, function, serial_number, Command, ARGS_BYTES, EP_COMMAND_IN,
        EP_COMMAND_OUT, EP_MESSAGE_IN, EP_MESSAGE_OUT, MESSAGE_BYTES, SELF_RECEPTION_FROM_REV, VID,
    },
    pcan_usb_fd::{
        driver_loaded, is_can_interface, request, Command as UcanCommand, FirmwareInfo, FCT_DRVLD,
        INFO_FW, RX_BUFFER_BYTES,
    },
};

use super::{
    check, identify, incoming, outgoing, restart, serial_text, start, timing, ucan, BusWatch,
    Commands, OnBus, PcanDevice, PcanModel, PcanOptions, Ticks,
};
use crate::can::{
    clock::Received,
    task::{self, Device},
    usb::bus,
    writer::Limits,
    BusState, CanError, CanFrame, CanOptions, CanTask, DeviceInfo,
};

/// The PEAK adapters plugged in now, classic and FD. The classic adapter has no
/// USB serial string, so there `serial` is usually `None` until a `probe`
/// reads it.
pub fn devices() -> io::Result<Vec<PcanDevice>> {
    Ok(nusb::list_devices()
        .wait()?
        .filter_map(|found| {
            Some(PcanDevice {
                serial: found.serial_number().map(str::to_owned),
                bus: bus(&found),
                address: found.device_address(),
                product: found.product_string().unwrap_or_default().to_owned(),
                model: model(&found)?,
            })
        })
        .collect())
}

/// Claims the adapter and starts its channel now, on the caller's task, then
/// spawns the task that reads it. A serial is found whatever its model, whose
/// protocol and limits then apply. Panics outside a tokio runtime.
pub async fn open(pcan: PcanOptions, options: CanOptions) -> Result<CanTask, CanError> {
    in_any_model(&pcan.device, |model| {
        let mut pcan = pcan.clone();
        pcan.device.model = model;
        open_as(pcan, options.clone())
    })
    .await
}

async fn open_as(pcan: PcanOptions, options: CanOptions) -> Result<CanTask, CanError> {
    if pcan.device.model.fd() {
        task::open::<Ucan>(pcan, options).await
    } else {
        task::open::<Classic>(pcan, options).await
    }
}

/// Claims the adapter, reads who it is and releases it, all within `timeout`:
/// the classic adapter's serial number, or the FD family's firmware info. The
/// bus is never touched, and a serial is found whatever its model. Panics
/// outside a tokio runtime.
pub async fn probe(device: &PcanDevice, timeout: Duration) -> Result<DeviceInfo, CanError> {
    let deadline = Instant::now() + timeout;
    let probed = in_any_model(device, |model| {
        let device = PcanDevice {
            model,
            ..device.clone()
        };
        async move {
            if model.fd() {
                probe_as::<UcanClaim>(&device, deadline).await
            } else {
                probe_as::<ClassicClaim>(&device, deadline).await
            }
        }
    });
    timeout_at(deadline, probed)
        .await
        .unwrap_or_else(|_| Err(not_opened(device)(io::ErrorKind::TimedOut.into())))
}

async fn probe_as<C: Claim>(
    device: &PcanDevice,
    deadline: Instant,
) -> Result<DeviceInfo, CanError> {
    let mut claimed = timeout_at(deadline, claim::<C>(device))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        .map_err(not_opened(device))?;
    timeout_at(deadline, claimed.identify())
        .await
        .unwrap_or_else(|_| Err(CanError::Read(io::ErrorKind::TimedOut.into())))
}

/// The selector's model first. Past a refusal or a miss there, a serial is
/// looked for among the other models plugged in, and tried as the one holding it.
async fn in_any_model<T, F: Future<Output = Result<T, CanError>>>(
    device: &PcanDevice,
    attempt: impl Fn(PcanModel) -> F,
) -> Result<T, CanError> {
    let first = attempt(device.model).await;
    let missed = match &first {
        Err(CanError::Config(_)) => true,
        Err(CanError::Open { source, .. }) => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    };
    if device.serial.is_none() || !missed {
        return first;
    }
    let Ok(listed) = nusb::list_devices().await else {
        return first;
    };
    let present: Vec<PcanModel> = listed.filter_map(|found| model(&found)).collect();
    for other in device.model.others(present) {
        let device = PcanDevice {
            model: other,
            ..device.clone()
        };
        let holds = if other.fd() {
            claim::<UcanClaim>(&device).await.is_ok()
        } else {
            claim::<ClassicClaim>(&device).await.is_ok()
        };
        if holds {
            return attempt(other).await;
        }
    }
    first
}

/// Command writes and sends alike: a device whose queue is full stops taking
/// them.
const TIMEOUT: Duration = Duration::from_secs(1);
/// Windows ignores nusb's own, so the wait is tokio's.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
/// Each blocking transfer a drop makes.
const DROP_TIMEOUT: Duration = Duration::from_millis(100);
const IN_FLIGHT: usize = 4;

struct Classic {
    commands: OnBus<CommandPipe>,
    message_in: Endpoint<Bulk, In>,
    message_out: Endpoint<Bulk, Out>,
    srr: bool,
    sequence: u8,
    ticks: Ticks,
    bus: BusWatch,
}

impl Device for Classic {
    type Config = PcanOptions;

    async fn open(
        pcan: &PcanOptions,
        options: &CanOptions,
    ) -> Result<(Self, DeviceInfo), CanError> {
        check(pcan)?;
        let btr = timing(pcan)?;
        let ClassicClaim {
            mut commands,
            message_in: mut bulk_in,
            message_out,
            rev,
        } = claim(&pcan.device)
            .await
            .map_err(not_opened(&pcan.device))?;
        let info = start(&mut commands, btr, rev, options.listen_only).await?;
        let transfer = MESSAGE_BYTES.next_multiple_of(bulk_in.max_packet_size());
        for _ in 0..IN_FLIGHT {
            bulk_in.submit(bulk_in.allocate(transfer));
        }
        let device = Self {
            commands: OnBus::new(commands),
            message_in: bulk_in,
            message_out,
            srr: options.own_frames && rev >= SELF_RECEPTION_FROM_REV,
            sequence: 0,
            ticks: Ticks::default(),
            bus: BusWatch::new(0),
        };
        Ok((device, info))
    }

    fn limits(&self) -> Limits {
        Limits {
            fd: false,
            brs: false,
            rtr: true,
            buses: Some(1),
        }
    }

    /// Any bulk-IN error is the device gone.
    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        let Some(completion) = self.bus.wait(self.message_in.next_complete()).await else {
            return Ok(Vec::new());
        };
        if completion.status.is_err() {
            return Err(CanError::Closed);
        }
        let received = incoming(
            &completion.buffer[..completion.actual_len],
            &mut self.ticks,
            &mut self.bus,
            Instant::now(),
        );
        self.message_in.submit(completion.buffer);
        Ok(received)
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        let message = encode_transmit(&outgoing(frame, self.srr), self.sequence);
        self.sequence = self.sequence.wrapping_add(1);
        self.message_out.submit(message.to_vec().into());
        bounded(&mut self.message_out).await.map(drop)
    }

    fn bus_reports(&mut self) -> Vec<BusState> {
        self.bus.reports()
    }

    async fn recover(&mut self) {
        self.bus.recover(restart(&mut self.commands.usb)).await;
    }

    async fn close(self) {
        self.commands.stop().await;
    }
}

struct Ucan {
    started: ucan::OnBus<UcanPipe>,
    data_in: Endpoint<Bulk, In>,
    data_out: Endpoint<Bulk, Out>,
    fd: bool,
    restart: Vec<UcanCommand>,
    bus: BusWatch,
}

impl Device for Ucan {
    type Config = PcanOptions;

    async fn open(
        pcan: &PcanOptions,
        options: &CanOptions,
    ) -> Result<(Self, DeviceInfo), CanError> {
        check(pcan)?;
        let timings = ucan::timings(pcan)?;
        let not_opened = not_opened(&pcan.device);
        let UcanClaim {
            mut pipe,
            firmware,
            model,
            high_speed,
        } = claim(&pcan.device).await.map_err(&not_opened)?;
        let endpoints = firmware.endpoints();
        let mut data_in = pipe
            .interface
            .endpoint::<Bulk, In>(endpoints.data_in)
            .map_err(|e| not_opened(e.into()))?;
        let data_out = pipe
            .interface
            .endpoint::<Bulk, Out>(endpoints.data_out[usize::from(pcan.channel)])
            .map_err(|e| not_opened(e.into()))?;
        ucan::start(
            &mut pipe,
            &firmware,
            pcan.channel,
            timings,
            options.listen_only,
            high_speed,
        )
        .await?;
        let transfer = RX_BUFFER_BYTES.next_multiple_of(data_in.max_packet_size());
        for _ in 0..IN_FLIGHT {
            data_in.submit(data_in.allocate(transfer));
        }
        let device = Self {
            started: ucan::OnBus::new(pipe, pcan.channel, high_speed),
            data_in,
            data_out,
            fd: pcan.data.is_some(),
            restart: ucan::operational(&firmware, pcan.channel, options.listen_only),
            bus: BusWatch::new(pcan.channel),
        };
        Ok((device, ucan::device_info(&firmware, model)))
    }

    fn limits(&self) -> Limits {
        Limits {
            fd: self.fd,
            brs: self.fd,
            rtr: true,
            buses: Some(self.started.channel + 1),
        }
    }

    /// Any bulk-IN error is the device gone.
    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        let Some(completion) = self.bus.wait(self.data_in.next_complete()).await else {
            return Ok(Vec::new());
        };
        if completion.status.is_err() {
            return Err(CanError::Closed);
        }
        let received = ucan::incoming(&completion.buffer[..completion.actual_len], &mut self.bus);
        self.data_in.submit(completion.buffer);
        Ok(received)
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        let channel = self.started.channel;
        if frame.bus != channel {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("this task sends on channel {channel}"),
            ));
        }
        self.data_out.submit(ucan::outgoing(frame, channel).into());
        bounded(&mut self.data_out).await.map(drop)
    }

    fn bus_reports(&mut self) -> Vec<BusState> {
        self.bus.reports()
    }

    async fn recover(&mut self) {
        let started = &mut self.started;
        let restart = ucan::transmit(&mut started.pipe, &self.restart, started.high_speed);
        self.bus.recover(restart).await;
    }

    async fn close(self) {
        self.started.stop().await;
    }
}

struct CommandPipe {
    out: Endpoint<Bulk, Out>,
    reply: Endpoint<Bulk, In>,
}

impl Commands for CommandPipe {
    async fn send(&mut self, command: Command) -> io::Result<()> {
        self.out.submit(command.to_bytes().to_vec().into());
        bounded(&mut self.out).await.map(drop)
    }

    async fn get(&mut self, function: u8) -> io::Result<[u8; ARGS_BYTES]> {
        self.send(Command::get(function)).await?;
        self.reply
            .submit(self.reply.allocate(self.reply.max_packet_size()));
        let reply = bounded(&mut self.reply).await?;
        Command::from_bytes(&reply.buffer[..reply.actual_len])
            .map(|reply| reply.args)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a short reply"))
    }

    fn send_now(&mut self, command: Command) -> io::Result<()> {
        send_blocking(&mut self.out, command.to_bytes().to_vec())
    }
}

/// `command` is `None` until the firmware info has said where it is.
struct UcanPipe {
    interface: Interface,
    command: Option<Endpoint<Bulk, Out>>,
}

impl ucan::Pipe for UcanPipe {
    async fn info(&mut self) -> io::Result<Vec<u8>> {
        let asked = self.interface.control_in(
            ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Other,
                request: request::INFO,
                value: INFO_FW,
                index: 0,
                length: FirmwareInfo::SIZE as u16,
            },
            CONTROL_TIMEOUT,
        );
        within_control_timeout(asked.into_future()).await
    }

    async fn driver_loaded(&mut self, loaded: bool) -> io::Result<()> {
        let told = self.tell_driver_loaded(loaded, CONTROL_TIMEOUT);
        within_control_timeout(told.into_future()).await
    }

    async fn command(&mut self, transfer: Vec<u8>) -> io::Result<()> {
        let out = self.command.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        out.submit(transfer.into());
        bounded(out).await.map(drop)
    }

    fn driver_loaded_now(&mut self, loaded: bool) -> io::Result<()> {
        Ok(self.tell_driver_loaded(loaded, DROP_TIMEOUT).wait()?)
    }

    fn command_now(&mut self, transfer: Vec<u8>) -> io::Result<()> {
        let out = self.command.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        send_blocking(out, transfer)
    }
}

impl UcanPipe {
    fn tell_driver_loaded(
        &self,
        loaded: bool,
        timeout: Duration,
    ) -> impl MaybeFuture<Output = Result<(), nusb::transfer::TransferError>> {
        self.interface.control_out(
            ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Other,
                request: request::FCT,
                value: FCT_DRVLD,
                index: 0,
                data: &driver_loaded(loaded),
            },
            timeout,
        )
    }
}

async fn within_control_timeout<T>(
    transfer: impl Future<Output = Result<T, nusb::transfer::TransferError>>,
) -> io::Result<T> {
    timeout(CONTROL_TIMEOUT, transfer)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(io::Error::from)
}

/// Windows ignores nusb's own timeouts, so the wait is tokio's.
async fn bounded<D: EndpointDirection>(endpoint: &mut Endpoint<Bulk, D>) -> io::Result<Completion> {
    let completion = match timeout(TIMEOUT, endpoint.next_complete()).await {
        Ok(completion) => completion,
        Err(_) => {
            endpoint.cancel_all();
            let completion = endpoint.next_complete().await;
            if completion.status.is_err() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            completion
        }
    };
    completion.status.map_err(io::Error::from)?;
    Ok(completion)
}

/// A send a task dropped mid-way left pending is cancelled first.
fn send_blocking(endpoint: &mut Endpoint<Bulk, Out>, transfer: Vec<u8>) -> io::Result<()> {
    endpoint.cancel_all();
    while endpoint.pending() > 0 {
        endpoint
            .wait_next_complete(DROP_TIMEOUT)
            .ok_or(io::ErrorKind::TimedOut)?;
    }
    endpoint.submit(transfer.into());
    let completion = endpoint
        .wait_next_complete(DROP_TIMEOUT)
        .ok_or(io::ErrorKind::TimedOut)?;
    Ok(completion.status?)
}

/// An adapter claimed, by family.
trait Claim: Sized + Send {
    fn attach(found: &UsbDevice) -> impl Future<Output = io::Result<Self>> + Send;

    /// As `%08X`.
    fn serial(&mut self) -> impl Future<Output = Option<String>> + Send;

    fn identify(&mut self) -> impl Future<Output = Result<DeviceInfo, CanError>> + Send;
}

struct ClassicClaim {
    commands: CommandPipe,
    message_in: Endpoint<Bulk, In>,
    message_out: Endpoint<Bulk, Out>,
    rev: u8,
}

impl Claim for ClassicClaim {
    async fn attach(found: &UsbDevice) -> io::Result<Self> {
        let interface = found.open().await?.claim_interface(0).await?;
        Ok(Self {
            commands: CommandPipe {
                out: interface.endpoint(EP_COMMAND_OUT)?,
                reply: interface.endpoint(EP_COMMAND_IN)?,
            },
            message_in: interface.endpoint(EP_MESSAGE_IN)?,
            message_out: interface.endpoint(EP_MESSAGE_OUT)?,
            rev: device_rev(found.device_version()),
        })
    }

    async fn serial(&mut self) -> Option<String> {
        let args = self.commands.get(function::SN).await.ok()?;
        serial_text(serial_number(&args))
    }

    async fn identify(&mut self) -> Result<DeviceInfo, CanError> {
        identify(&mut self.commands, self.rev).await
    }
}

/// The firmware info is read as the adapter is claimed: it names the
/// endpoints.
struct UcanClaim {
    pipe: UcanPipe,
    firmware: FirmwareInfo,
    model: PcanModel,
    high_speed: bool,
}

impl Claim for UcanClaim {
    async fn attach(found: &UsbDevice) -> io::Result<Self> {
        let model = model(found).ok_or(io::ErrorKind::NotFound)?;
        let device = found.open().await?;
        let number = device
            .active_configuration()
            .ok()
            .and_then(|config| {
                config
                    .interface_alt_settings()
                    .filter(|alt| alt.alternate_setting() == 0)
                    .find(|alt| {
                        let endpoints: Vec<u8> = alt.endpoints().map(|e| e.address()).collect();
                        is_can_interface(model.pid(), alt.interface_number(), &endpoints)
                    })
                    .map(|alt| alt.interface_number())
            })
            .unwrap_or(0);
        let mut pipe = UcanPipe {
            interface: device.claim_interface(number).await?,
            command: None,
        };
        let firmware = ucan::identify(&mut pipe)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        pipe.command = Some(pipe.interface.endpoint(firmware.endpoints().command_out)?);
        Ok(Self {
            pipe,
            firmware,
            model,
            high_speed: found.speed() == Some(Speed::High),
        })
    }

    async fn serial(&mut self) -> Option<String> {
        serial_text(self.firmware.serial_number())
    }

    async fn identify(&mut self) -> Result<DeviceInfo, CanError> {
        Ok(ucan::device_info(&self.firmware, self.model))
    }
}

async fn attach<C: Claim>(found: &UsbDevice) -> io::Result<C> {
    use crate::can::usb::{bound_driver, foreign_driver};
    let remedy = "install PEAK-Drivers, or bind WinUSB to it";
    C::attach(found)
        .await
        .map_err(|e| foreign_driver(e, bound_driver(found), remedy))
}

/// Among the selector's model, by serial number where the selector has one —
/// the USB string first, then each adapter's own — else by bus and address.
async fn claim<C: Claim>(device: &PcanDevice) -> io::Result<C> {
    let adapters: Vec<UsbDevice> = nusb::list_devices()
        .await?
        .filter(|found| model(found) == Some(device.model))
        .collect();
    let Some(wanted) = &device.serial else {
        let found = adapters
            .iter()
            .find(|found| bus(found) == device.bus && found.device_address() == device.address)
            .ok_or(io::ErrorKind::NotFound)?;
        return attach(found).await;
    };
    if let Some(found) = adapters
        .iter()
        .find(|found| found.serial_number() == Some(wanted))
    {
        return attach(found).await;
    }
    for found in &adapters {
        let Ok(mut claimed) = C::attach(found).await else {
            continue;
        };
        if claimed.serial().await.as_deref() == Some(wanted) {
            return Ok(claimed);
        }
    }
    Err(io::ErrorKind::NotFound.into())
}

fn model(found: &UsbDevice) -> Option<PcanModel> {
    (found.vendor_id() == VID)
        .then(|| PcanModel::from_pid(found.product_id()))
        .flatten()
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

#[allow(dead_code)]
fn futures_are_send(pcan: PcanOptions) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&probe(&pcan.device, Duration::ZERO));
    is_send(&open(pcan, CanOptions::default()));
}
