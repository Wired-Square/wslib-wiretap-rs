use std::{ffi::c_void, io, ptr, sync::Arc, time::Duration};

use libloading::Library;

use super::{identify, parameter, Api, Basic, Msg, Timestamp};
use crate::can::{
    pcan::{not_opened, PcanDevice, PcanOptions},
    task, CanError, CanOptions, CanTask, DeviceInfo,
};

pub(in crate::can::pcan) async fn open(
    pcan: PcanOptions,
    options: CanOptions,
) -> Result<CanTask, CanError> {
    let dll = Dll::load().map_err(not_opened(&pcan.device))?;
    task::open::<Basic<Dll>>((Arc::new(dll), pcan), options).await
}

pub(in crate::can::pcan) fn probe(device: &PcanDevice) -> Result<DeviceInfo, CanError> {
    identify(&Dll::load().map_err(not_opened(device))?, device)
}

type Handle = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
}

/// An auto-reset Win32 event.
struct Event(Handle);

// SAFETY: a Win32 event handle may be waited on and set from any thread.
unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl Event {
    fn new() -> io::Result<Self> {
        // SAFETY: no attributes and no name, both of which may be null.
        let handle = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: the handle is this event's own, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// The calls, each the signature `PCANBasic.h` declares, valid while `_library`
/// is loaded.
struct Dll {
    initialize: unsafe extern "system" fn(u16, u16, u8, u32, u16) -> u32,
    uninitialize: unsafe extern "system" fn(u16) -> u32,
    read: unsafe extern "system" fn(u16, *mut Msg, *mut Timestamp) -> u32,
    write: unsafe extern "system" fn(u16, *mut Msg) -> u32,
    get_value: unsafe extern "system" fn(u16, u8, *mut c_void, u32) -> u32,
    set_value: unsafe extern "system" fn(u16, u8, *mut c_void, u32) -> u32,
    get_status: unsafe extern "system" fn(u16) -> u32,
    event: Event,
    _library: Library,
}

impl Dll {
    fn load() -> io::Result<Self> {
        let missing = |e: libloading::Error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{e}: install PEAK-Drivers (PCAN-Basic)"),
            )
        };
        // SAFETY: PCANBasic.dll runs no initialiser with preconditions, each
        // type is the symbol's in PCANBasic.h, and the pointers are kept only
        // beside the library they came from.
        unsafe {
            let library = Library::new("PCANBasic.dll").map_err(missing)?;
            Ok(Self {
                initialize: symbol(&library, b"CAN_Initialize\0").map_err(missing)?,
                uninitialize: symbol(&library, b"CAN_Uninitialize\0").map_err(missing)?,
                read: symbol(&library, b"CAN_Read\0").map_err(missing)?,
                write: symbol(&library, b"CAN_Write\0").map_err(missing)?,
                get_value: symbol(&library, b"CAN_GetValue\0").map_err(missing)?,
                set_value: symbol(&library, b"CAN_SetValue\0").map_err(missing)?,
                get_status: symbol(&library, b"CAN_GetStatus\0").map_err(missing)?,
                event: Event::new()?,
                _library: library,
            })
        }
    }
}

unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, libloading::Error> {
    library.get::<T>(name).map(|symbol| *symbol)
}

// SAFETY, for every call: the library is loaded for as long as `self` lives,
// and each pointer and length is a live buffer of that length.
impl Api for Dll {
    fn initialize(&self, channel: u16, btr0btr1: u16) -> u32 {
        unsafe { (self.initialize)(channel, btr0btr1, 0, 0, 0) }
    }

    fn uninitialize(&self, channel: u16) -> u32 {
        unsafe { (self.uninitialize)(channel) }
    }

    fn read(&self, channel: u16, msg: &mut Msg, timestamp: &mut Timestamp) -> u32 {
        unsafe { (self.read)(channel, msg, timestamp) }
    }

    fn write(&self, channel: u16, msg: &Msg) -> u32 {
        let mut msg = *msg;
        unsafe { (self.write)(channel, &mut msg) }
    }

    fn get_value(&self, channel: u16, parameter: u8, buffer: &mut [u8]) -> u32 {
        let len = buffer.len() as u32;
        unsafe { (self.get_value)(channel, parameter, buffer.as_mut_ptr().cast(), len) }
    }

    fn set_value(&self, channel: u16, parameter: u8, buffer: &[u8]) -> u32 {
        let mut buffer = buffer.to_vec();
        let len = buffer.len() as u32;
        unsafe { (self.set_value)(channel, parameter, buffer.as_mut_ptr().cast(), len) }
    }

    fn get_status(&self, channel: u16) -> u32 {
        unsafe { (self.get_status)(channel) }
    }

    fn watch(&self, channel: u16) -> u32 {
        self.set_value(
            channel,
            parameter::RECEIVE_EVENT,
            &(self.event.0 as usize).to_ne_bytes(),
        )
    }

    fn wait(&self, timeout: Duration) {
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: the event lives as long as `self`.
        unsafe { WaitForSingleObject(self.event.0, millis) };
    }
}
