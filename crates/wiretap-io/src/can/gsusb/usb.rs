use std::{future::IntoFuture, io, time::Duration};

use nusb::{
    descriptors::TransferType,
    transfer::{
        Bulk, ControlIn, ControlOut, ControlType, Direction as UsbDirection, In, Out, Recipient,
    },
    DeviceInfo as UsbDevice, Endpoint, Interface, MaybeFuture,
};
use tokio::time::{timeout, timeout_at, Instant};
use wiretap_protocol::gs_usb::{Breq, DEVICES};

use super::{identify, start, Control, Frames, GsUsbDevice, GsUsbOptions, OnBus, Transfers};
use crate::can::{
    clock::Received,
    task::{self, Device},
    usb::bus,
    writer::Limits,
    BusState, CanError, CanFrame, CanOptions, CanTask, DeviceInfo,
};

/// The gs_usb adapters plugged in now.
pub fn devices() -> io::Result<Vec<GsUsbDevice>> {
    Ok(nusb::list_devices()
        .wait()?
        .filter(is_gs_usb)
        .map(|found| GsUsbDevice {
            serial: found.serial_number().map(str::to_owned),
            bus: bus(&found),
            address: found.device_address(),
            product: found.product_string().unwrap_or_default().to_owned(),
        })
        .collect())
}

/// Claims the adapter and starts its channel now, on the caller's task, then
/// spawns the task that reads it. Panics outside a tokio runtime.
pub async fn open(gs: GsUsbOptions, options: CanOptions) -> Result<CanTask, CanError> {
    task::open::<GsUsb>(gs, options).await
}

/// Claims the adapter, reads `DEVICE_CONFIG` and `BT_CONST`, and releases it,
/// all within `timeout`. The channel is never started. Panics outside a tokio
/// runtime.
pub async fn probe(device: &GsUsbDevice, timeout: Duration) -> Result<DeviceInfo, CanError> {
    let deadline = Instant::now() + timeout;
    let (interface, serial) = timeout_at(deadline, claim(device))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        .map_err(|source| CanError::Open {
            device: selector(device),
            source,
        })?;
    let info = identify(&interface, deadline).await?;
    Ok(DeviceInfo { serial, ..info })
}

const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
/// The reset a drop sends, blocking.
const DROP_TIMEOUT: Duration = Duration::from_millis(100);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const IN_FLIGHT: usize = 30;

struct GsUsb {
    control: OnBus<Interface>,
    frames: Frames<Endpoints>,
    fd: bool,
}

struct Endpoints {
    bulk_in: Endpoint<Bulk, In>,
    bulk_out: Endpoint<Bulk, Out>,
}

impl Device for GsUsb {
    type Config = GsUsbOptions;

    async fn open(gs: &GsUsbOptions, options: &CanOptions) -> Result<(Self, DeviceInfo), CanError> {
        let not_opened = |source| CanError::Open {
            device: selector(&gs.device),
            source,
        };
        let (interface, serial) = claim(&gs.device).await.map_err(not_opened)?;
        let (in_address, out_address) = bulk_endpoints(&interface);
        let mut bulk_in = interface
            .endpoint::<Bulk, In>(in_address)
            .map_err(|e| not_opened(e.into()))?;
        let bulk_out = interface
            .endpoint::<Bulk, Out>(out_address)
            .map_err(|e| not_opened(e.into()))?;
        let started = start(&interface, gs, options.listen_only).await?;
        let transfer = started.transfer_len(bulk_in.max_packet_size());
        for _ in 0..IN_FLIGHT {
            bulk_in.submit(bulk_in.allocate(transfer));
        }
        let endpoints = Endpoints { bulk_in, bulk_out };
        let device = Self {
            control: OnBus::new(interface, gs.channel),
            frames: Frames::new(endpoints, gs.channel, started.timestamps, WRITE_TIMEOUT),
            fd: started.fd,
        };
        Ok((
            device,
            DeviceInfo {
                serial,
                ..started.info
            },
        ))
    }

    fn limits(&self) -> Limits {
        Limits {
            fd: self.fd,
            brs: self.fd,
            rtr: true,
            buses: Some(self.frames.channel + 1),
        }
    }

    async fn read(&mut self) -> Result<Vec<Received>, CanError> {
        self.frames.read().await
    }

    async fn write(&mut self, frame: &CanFrame) -> io::Result<()> {
        self.frames.write(frame).await
    }

    fn bus_reports(&mut self) -> Vec<BusState> {
        self.frames.bus_reports()
    }

    async fn close(self) {
        self.control.reset().await;
    }
}

impl Transfers for Endpoints {
    /// Any bulk-IN error is the device gone.
    async fn receive(&mut self) -> Result<Vec<u8>, CanError> {
        let completion = self.bulk_in.next_complete().await;
        if completion.status.is_err() {
            return Err(CanError::Closed);
        }
        let transfer = completion.buffer[..completion.actual_len].to_vec();
        self.bulk_in.submit(completion.buffer);
        Ok(transfer)
    }

    /// A device whose queue is full stops taking frames, so a send is bounded.
    async fn send(&mut self, transfer: Vec<u8>) -> io::Result<()> {
        self.bulk_out.submit(transfer.into());
        let sent = timeout(WRITE_TIMEOUT, self.bulk_out.next_complete()).await;
        match sent {
            Ok(completion) => completion.status.map_err(io::Error::from),
            Err(_) => {
                self.bulk_out.cancel_all();
                let completion = self.bulk_out.next_complete().await;
                completion
                    .status
                    .map_err(|_| io::ErrorKind::TimedOut.into())
            }
        }
    }
}

impl Control for Interface {
    async fn get(&self, request: Breq, value: u16, length: usize) -> io::Result<Vec<u8>> {
        let asked = self.control_in(
            ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Interface,
                request: request as u8,
                value,
                index: 0,
                length: length as u16,
            },
            CONTROL_TIMEOUT,
        );
        // Windows ignores nusb's timeout and waits 5 s.
        timeout(CONTROL_TIMEOUT, asked.into_future())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::from)
    }

    async fn set(&self, request: Breq, value: u16, data: &[u8]) -> io::Result<()> {
        let told = self.control_out(vendor_out(request, value, data), CONTROL_TIMEOUT);
        timeout(CONTROL_TIMEOUT, told.into_future())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(io::Error::from)
    }

    fn set_now(&self, request: Breq, value: u16, data: &[u8]) -> io::Result<()> {
        let told = self.control_out(vendor_out(request, value, data), DROP_TIMEOUT);
        Ok(told.wait()?)
    }
}

fn vendor_out(request: Breq, value: u16, data: &[u8]) -> ControlOut<'_> {
    ControlOut {
        control_type: ControlType::Vendor,
        recipient: Recipient::Interface,
        request: request as u8,
        value,
        index: 0,
        data,
    }
}

/// By serial number where both have one, else by bus and address.
async fn claim(device: &GsUsbDevice) -> io::Result<(Interface, Option<String>)> {
    let found = nusb::list_devices()
        .await?
        .filter(is_gs_usb)
        .find(|found| match (&device.serial, found.serial_number()) {
            (Some(wanted), Some(serial)) => wanted == serial,
            _ => bus(found) == device.bus && found.device_address() == device.address,
        })
        .ok_or(io::ErrorKind::NotFound)?;
    let interface = found.open().await?.claim_interface(0).await?;
    Ok((interface, found.serial_number().map(str::to_owned)))
}

fn is_gs_usb(found: &UsbDevice) -> bool {
    DEVICES.contains(&(found.vendor_id(), found.product_id()))
}

fn selector(device: &GsUsbDevice) -> String {
    match &device.serial {
        Some(serial) => format!("gs_usb {serial}"),
        None => format!("gs_usb {}:{}", device.bus, device.address),
    }
}

/// gs_usb's usual `0x81` and `0x02` where the descriptor doesn't say.
fn bulk_endpoints(interface: &Interface) -> (u8, u8) {
    let mut found = (0x81, 0x02);
    for endpoint in interface.descriptor().iter().flat_map(|d| d.endpoints()) {
        if endpoint.transfer_type() == TransferType::Bulk {
            match endpoint.direction() {
                UsbDirection::In => found.0 = endpoint.address(),
                UsbDirection::Out => found.1 = endpoint.address(),
            }
        }
    }
    found
}

#[allow(dead_code)]
fn futures_are_send(gs: GsUsbOptions) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&probe(&gs.device, Duration::ZERO));
    is_send(&open(gs, CanOptions::default()));
}
