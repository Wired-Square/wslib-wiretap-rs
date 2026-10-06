# wiretap-io

Device I/O for WireTAP — the part of the [`wslib-wiretap-rs`](../../) workspace that
opens sockets and serial ports. Every transport sits behind its own feature, so
an app compiles only the ones it uses.

## What's here

| Feature | Brings |
| --- | --- |
| `modbus-tcp` | `modbus::ModbusTcp`: one connection to a `host:port`, reads of every bank (FC01–04) and device identification (FC43/14), whose `vendor`, `product_code` and `revision` read as text. And `modbus::Poller`, whose `step` reads whatever is due over a connection it is lent, decoding catalogue frames into a snapshot |
| `modbus-write` | its write methods: `write_registers` (FC06/16), `write_coils` (FC05/15) and `write_verified`, the batch write-verify of catalogue `ModbusWrite`s: a holding run read-modify-written and read back by FC03, a coil run written whole and read back by FC01. Implies `modbus-tcp` |
| `modbus-task` | `modbus::spawn`: one task per connection that owns it and a `Poller`, emits each step as a batch of events, and reconnects with backoff. With `modbus-write` as well, a `PollWriter` sends writes over that task's connection. Implies `modbus-tcp` |
| `testing` | `modbus::testing::device`: a Modbus TCP device on loopback for a consumer's tests, answering each request with a closure, and `registers`, the answer that holds each register at its own address. Implies `modbus-tcp`; for dev-dependencies |
| `serial` | `serial::open`: a read-only serial port. It opens the path at once, so a missing adapter is the caller's error unless `wait_for_device` leaves it to the task, then spawns a task that emits each read's bytes with the wall clock it returned at, and reopens the line every second after a loss (or ends, with `reopen: None`) |
| `serial-ports` | `serial::ports`: every port the OS lists, as a `PortInfo` with its path and, for a USB port, the VID, PID, serial number, manufacturer and product. Implies `serial` |
| `serial-write` | `Access::ReadWrite`, and a `SerialWriter` whose writes the task serves between reads, and while it waits on a full event queue. Implies `serial-ports` |
| `can` | what every CAN transport shares: `can::CanFrame`, `CanRead` and its stamp, `CanOptions`, the `CanEvent`s a `CanTask` emits, and a `CanWriter` whose sends it serves between reads. Each transport is its own `can-*` feature, implying this one |
| `can-gvret` | `can::gvret::open`: a GVRET device over TCP, such as an ESP32-RET or WireTAP-Server's GVRET end. It connects and runs the handshake at once, so a dead device is the caller's error, then spawns the `CanTask` that reads it. And `probe`, which asks what the device is without a task |
| `can-gvret-serial` | `gvret::Link::Serial`: the same device over a serial port, such as an M2 or an ESP32-RET on USB. Implies `can-gvret` and `serial-write` |
| `can-slcan` | `can::slcan::open`: an SLCAN adapter on a serial port, such as a CANable, with CAN FD on the Elmue firmware. It opens the port and starts the channel at once, so a dead adapter is the caller's error. Implies `can` and `serial-write` |
| `can-gsusb` | `can::gsusb::open`: a gs_usb adapter over USB on macOS and Windows, such as a CANable or a candleLight, one channel per task, with CAN FD where the device has it. It claims the adapter and starts the channel at once, so a missing adapter is the caller's error. And `devices`, the adapters plugged in, and `probe`, which reads one without starting it. Implies `can` |
| `can-pcan` | `can::pcan::open`: a PEAK-System adapter over USB on macOS and Windows, one channel per task: the classic PCAN-USB, and the CAN FD PCAN-USB FD, PCAN-Chip USB, PCAN-USB Pro FD and PCAN-USB X6. **The four FD models are untested**: no device of theirs has met this code. It claims the adapter and starts the channel at once, so a missing adapter is the caller's error. And `devices`, the adapters plugged in, and `probe`, which reads one without starting it. Implies `can` |
| `can-socketcan` | `can::socketcan::open`: a SocketCAN interface on Linux, classic and FD, stamped by the kernel. It opens the socket at once, so a missing interface is the caller's error. And `bitrates`, the interface's configured rates. Implies `can` |

There are **no default features**. Modbus, `can` and `can-gvret` build only for Windows,
macOS, Linux and iOS, serial, `can-gvret-serial` and `can-slcan` only for Windows, macOS and Linux,
`can-gsusb` only for Windows and macOS, bar its Linux `devices`, `can-pcan` only for Windows and
macOS, and `can-socketcan` only for Linux; elsewhere, such as Android, their features compile to nothing. On Linux the kernel's `gs_usb`
driver makes a gs_usb adapter a SocketCAN interface, and its `peak_usb` driver a PEAK one.

The crate never builds a runtime, and never spawns without `modbus-task`, `testing`,
`serial` or a `can-*` transport: every method is an `async fn` on the caller's task, and every future
is `Send`. `spawn` and `serial::open` use the ambient tokio runtime. No
tokio-modbus, nix, serialport, nusb or socketcan type appears in its API, so an app drops its own
tokio-modbus dependency and an upgrade of any of them is an ordinary release of
this library.

The connection is lazy and resolves the endpoint on every connect, trying each
address it resolves to within one `connect_timeout`. `tcp_endpoint(host, port)`,
in `modbus` and `can`, builds an endpoint, bracketing an IPv6 literal. A transport error drops the
socket and the next request reconnects; a Modbus exception keeps it; dropping a
request's future mid-flight drops the socket too. There is no retry and no
backoff in the connection or the poller — when to try again is the caller's
call, or the task's.

## Using it

```toml
wiretap-io = { git = "https://github.com/Wired-Square/wslib-wiretap-rs.git", tag = "v0.1.0", features = ["modbus-tcp"] }
```

```rust
use wiretap_io::modbus::{ModbusTcp, ReadRequest, TcpOptions};

let mut tcp = ModbusTcp::new("inverter.local:502", TcpOptions::default());
let reading = tcp.read(ReadRequest::for_frame(&manifest, frame)).await?;
```

**Staying read-only.** `modbus-write` is strictly additive — no other feature
turns it on — but Cargo unions a crate's features across the whole build graph,
so another dependency can switch it on for you. A consumer that must not carry a
write path checks for it in CI:

```sh
! cargo tree -e features -i wiretap-io | grep -q modbus-write
```

**Serial.** Read-only on Linux and macOS, the port is opened `O_RDONLY`, raw,
with flow control off, and read through the tokio reactor; without
`serial-write` no write path is compiled in, and without it or `serial-ports`
serialport isn't built.
`exclusive`, on by default, sets `TIOCEXCL`, so a second reader's open fails
while the line is held (root bypasses it). A rate with no termios constant is
`UnsupportedBaud`, which on macOS is every rate above 230 400. On Windows, and
for `ReadWrite` everywhere, serialport opens the port read-write and reads it
on the blocking pool with a 50 ms timeout; `exclusive` there is serialport's
`TIOCEXCL` and `flock`, and a Windows port is always exclusive. On Windows
`serial` alone builds serialport. The task's events are bounded: when
the queue is full it waits, and bytes queue in the kernel instead.

**Serial writes.** Every write is answered: `ReadOnly` on a read-only port,
`Disconnected` at once while the line is down, `QueueFull`, or `Stopped`.
Otherwise it runs as `write_all` then `flush`, and its own error comes back in
the `Ok`; a failed write leaves the line up, and the next read decides.

```rust
use wiretap_io::serial::{self, LineSettings, Parity, SerialEvent, SerialOptions};

let line = LineSettings { baud: 9600, data_bits: 8, parity: Parity::None, stop_bits: 1 };
let mut task = serial::open("/dev/ttyUSB0", line, SerialOptions::default())?;
while let Some(event) = task.next_event().await {
    if let SerialEvent::Read { bytes, at } = event {
        tap.push(&bytes, at);
    }
}
```

```rust
let options = SerialOptions { access: Access::ReadWrite, ..SerialOptions::default() };
let task = serial::open("/dev/ttyUSB0", line, options)?;
let writer = task.writer();
writer.write(request).await??;
```

**Port listing.** `serial::ports` is one `serialport::available_ports`, mapped
field for field and not filtered, so macOS lists each port as `tty.*` and
`cu.*`. On Linux serialport reads udev where another dependency turns on its
`libudev` feature, and otherwise scans `/sys/class/tty`; where that is missing,
as in a minimal container, the list is empty. The two can list different ports
on one host.

**CAN.** One `CanFrame` for every transport, `wiretap_protocol::can`'s: the payload is a length, not a
code, and an RTR keeps its code for `dlc()`. A device with its own µs counter
has it unwrapped into `device_us` and, by default (`TimeMapping::Mapped`),
mapped onto the wall clock by the lowest offset over a 60 s window, so a stamp
is never later than the read that delivered it. A counter that jumps back is a
device reset and re-anchors, and one that stays put for a second of wall clock
falls back to the read's time, as `TimeMapping::Host` always does. No stamp is
earlier than one the task has already handed out. A read's `overflow` says the
device dropped frames before it; only gs_usb reports that, and the other
transports leave it false. Only gs_usb and PEAK emit `CanEvent::Bus`, and `CanEvent` is
`#[non_exhaustive]`. Every send is answered:
`ListenOnly` and `Unsupported` before it is queued, then `Disconnected`,
`QueueFull` or `Stopped` as for serial writes, and otherwise once the device
has taken the frame.

**GVRET.** Over TCP, `open` resolves the endpoint on every connect, as Modbus
does, and a failed connect is `CanError::Connect` with Modbus's
`TransportError`, so a DNS failure stays distinct. It then sends `E7 E7`, waits 100 ms, then asks for the device info, a keepalive
and the bus count, waiting up to `probe_timeout` (1.5 s) for the count. The
count is `DeviceInfo::buses`, or `None` if the device stayed silent, and then
no bus is refused; a close or a read error during the probe is `Err`. Frames the
device sends during the handshake come in the first `Read`, stamped by its µs
counter. Every `keepalive` (250 ms) the task asks `F1 09`: once the device has
answered one, ten unanswered in a row is `Unresponsive`, and a device that never
answers keeps running, with `DeviceInfo::keepalive: false`. A send is
`encode_transmit`'s bytes, unchanged; GVRET has no FD, BRS or RTR flag, so
those and anything over 8 bytes are refused. Listen-only is the library
refusing sends: GVRET can't tell the device.

Over a serial port (`can-gvret-serial`), `Link::Serial` opens the path through
serialport, read-write and exclusive, as `serial-write` does, and every
`LineSettings` field is honoured. The handshake, keepalive and sends are the
same bytes as over TCP. A missing path is `CanError::Open`, and settings the
port can't take are `Config`. A read waits at most 50 ms, and a send or a
keepalive ask waits for the read in flight. An unplug is `Closed` if the read
returns zero bytes and `Read` if it fails; which one each OS gives is unknown
without hardware.

`gvret::probe` runs the same handshake without the keepalive ask, `E7 E7`, the
100 ms settle, then `F1 07` and `F1 0C`, and closes the link, all within its one
`timeout`. It never sends a frame, a bus setup or a keepalive, and drops the
frames it reads. A TCP connect gets the lesser of `connect_timeout` and what is
left, and a serial open runs on the blocking pool, so neither outlasts it. The
bus count is unclamped, and silence to the deadline is `Ok` with `buses: None`
and whatever `DEV_INFO` said; a close or a read error is `Err`. `E7 E7` puts a
serial console into binary mode, which no probe can avoid.

```rust
use wiretap_io::can::{gvret::{self, GvretOptions, Link}, CanEvent, CanOptions};

let link = Link::Tcp { endpoint: "esp32-ret.local:23".into(), connect_timeout: Duration::from_secs(5) };
// or, with `can-gvret-serial`:
let link = Link::Serial { path: "/dev/ttyACM0".into(), line: LineSettings { baud: 1_000_000, data_bits: 8, parity: Parity::None, stop_bits: 1 } };
let mut task = gvret::open(link, GvretOptions::default(), CanOptions::default()).await?;
while let Some(event) = task.next_event().await {
    if let CanEvent::Read(reads) = event {
        capture.extend(reads);
    }
}
```

**SLCAN.** `slcan::open` opens the path as `Link::Serial` does, honouring every
`LineSettings` field, and checks the bitrate first: one SLCAN can't name is
`Config`, listing the ones it can. After a 200 ms settle, it sends `C`, asks `V`
and `N` for `DeviceInfo`'s firmware and serial (and Elmue's board and MCU as
`hardware`), then `S<n>`, `Y<n>` when `data_bitrate` is set, `M1` under
`listen_only` or `M0`, and `O`. Each waits up
to 100 ms for its answer, and silence counts as taken, since not every firmware
answers. A bell on `S`, `Y` or `M1` is `Config`, and on `O` is `Handshake`; a
bell on `C` or `M0` is not an error. CAN FD needs the Elmue firmware, which only
its `V` reply identifies (`DeviceInfo::fd`): without it a `data_bitrate` is
`Config`, and FD sends are refused unless `data_bitrate` is set. SLCAN carries
no timestamp, so a frame takes its read's time and `device_us` is `None`. It
has one bus, 0, so `DeviceInfo::buses` is `Some(1)`. Sends are
`encode_frame`'s lines, RTR included, and the adapter's own `z` replies are
skipped. `stop`, and every loss, sends `C` first, bounded by 1 s. Serial loss is
as for GVRET over a serial port.

```rust
use wiretap_io::can::{slcan::{self, SlcanOptions}, CanOptions};

let slcan = SlcanOptions {
    path: "/dev/ttyACM0".into(),
    line: LineSettings { baud: 115_200, data_bits: 8, parity: Parity::None, stop_bits: 1 },
    bitrate: 500_000,
    data_bitrate: Some(2_000_000),
};
let mut task = slcan::open(slcan, CanOptions::default()).await?;
```

`slcan::probe` opens the port on the blocking pool, so a stalled open can't
outlast its one `timeout`, then settles, sends `C` and asks `V`, `v` (only when
`V` named no board or MCU) and `N`, each as `open` does. It never sends `O`, a
rate, a mode or a frame, and closes the port without writing `C` again.
`DeviceInfo::hardware` is the `v` reply, or Elmue's board and MCU. A bell or a
bare `\r` counts as an answer; silence to all three is `Handshake`. A deadline
that passes keeps the answers so far, and one that passes during the open is
`Open` with `TimedOut`. The worst case under silence is 600 ms; 2 s suits.

**gs_usb.** `gsusb::open` finds the adapter by serial number, or by bus and
address where either side has none, and claims its interface 0; since bus and
address change on a replug, only an adapter with a serial number comes back on
a reopen. It then runs the kernel driver's start: `HOST_FORMAT`,
`DEVICE_CONFIG` (a channel the device hasn't got is `Config`), `BT_CONST`, a
`MODE` reset, `BITTIMING` within the device's own limits (a bitrate they can't
time is `Config`, naming them), or from the 48 MHz table when the device
reports no clock, and for FD `BT_CONST_EXT` and `DATA_BITTIMING`. `MODE`
starts the channel with `LISTEN_ONLY` under `listen_only` (a device without it
is `Config`), and with `HW_TIMESTAMP` wherever `BT_CONST` offers it; packet
padding is never asked for, as the kernel never asks. FD on a device without
it is `Config`. With `HW_TIMESTAMP` each frame is stamped by the device's µs
counter, mapped as GVRET's is; without it a frame takes its read's time. Four
bulk-IN transfers stay in flight, each sized for the largest frame the channel
can send rounded up to the packet, and each holds one frame, ended by its short
packet. The device's echoes of this task's sends are `Tx` reads with
`own_frames`. Error frames are no reads: they feed `CanEvent::Bus`, the
bus's whole state (error state, `no_ack`, the counters), emitted on a change
and on every transmit timeout. `state` is what the device last reported, and
`no_ack` clears on a frame from another node, a falling transmit error count or
a return to active; 5 s with no error frame clears both. A frame flagged `OVERFLOW` is read
with `overflow` set: the device dropped frames before it, which the kernel
counts as `rx_over_errors`. A send goes on the task's channel,
so it must name that channel as its bus, and waits up to 1 s for the device to
take it. As in the kernel, at most ten sends are on the device before it echoes
them from the bus, each under its own echo id; the next waits up to 1 s for an
echo, so the send queue backs up meanwhile, and past that it fails `TimedOut`
and the ten are taken as lost. A transmit timeout, the firmware flushing its
queue, frees them all at once, its `Bus` counting them in `tx_dropped`. Any
bulk-IN error is `Closed`. `stop`, and every loss, resets the channel first,
bounded by 1 s. Windows compiles and is untested at runtime.

`gsusb::probe` claims the adapter as `open` does, and within its one `timeout`
reads `DEVICE_CONFIG` and channel 0's `BT_CONST`, then releases it. It sends no
control-out request and makes no bulk transfer, so the device is left as it was.
`DeviceInfo` gets the channel count, FD, the software and hardware versions and
the CAN clock; a failed `BT_CONST` leaves FD off and the clock `None`. A deadline
that passes while claiming is `Open` with `TimedOut`, and after it `Read`.

On Linux, `gsusb::devices` reads sysfs instead, as a `LinuxGsUsbDevice` per
`can*` interface on a gs_usb adapter, with its name and whether it is up, then
one per adapter the driver hasn't bound. There is no `open` or `probe`: the
interface is `socketcan::open`'s.

```rust
use wiretap_io::can::{gsusb::{self, GsUsbOptions}, CanOptions};

let device = gsusb::devices()?.remove(0);
let mut gs = GsUsbOptions::new(device, 500_000);
gs.data = Some((2_000_000, None));
let mut task = gsusb::open(gs, CanOptions::default()).await?;
```

**PEAK.** `pcan::devices` lists every PEAK adapter it knows as a
`PcanDevice`, whose `model` (a `PcanModel`) picks the protocol: the classic
PCAN-USB speaks its own, and the four FD models PEAK's uCAN. `pcan::open` finds
the adapter by serial number, or by bus and address where the selector has
none. A serial is looked for among the selector's model first, then, past a
miss or a refusal, among each other model plugged in; the model found is the
one whose protocol and limits apply, and the one a reopen uses. The classic
adapter has no USB serial string, so a serial is matched against each
adapter's `SN` reply, and an FD adapter's against the `ser_no` of
its firmware info, both as `%08X`; only a selector with one comes back on a
reopen, and an erased serial (`FFFFFFFF`) reads as none and matches nothing.
What the model hasn't got is `Config` before the claim: `data` or a `channel`
past 0 on the classic adapter, a `channel` past the model's on an FD one. So is
a bitrate the clock can't time within 5%, the sample point being CiA's unless
given, as the kernel's `can_calc_bittiming` has it.

On the classic PCAN-USB `open` claims interface 0 and runs the kernel driver's
start: `SN`, bus off and the controller reset, `BITRATE`, `ERR_FR`, silent mode
under `listen_only` (below revision 4, which has none, that is `Config`),
`EXT_VCC` off, bus on, and 10 ms for the device to settle. Four 64-byte bulk-IN
transfers stay in flight. Each frame is stamped by the device's 16-bit tick
counter, unwrapped against the host time between records and mapped as GVRET's
is. Error and bus-event records feed `CanEvent::Bus` on a change of state, as
the kernel maps them, except that `BUS_LIGHT` is `Warning`; sync records are
dropped. With `own_frames`, from
revision 41, each send asks the device to hand it back, and those are `Tx`
reads; before 41 nothing comes back. A send is one 64-byte message, bounded by
1 s, on bus 0. Any bulk-IN error is `Closed`. `stop`, and every loss, takes the
bus off and resets the controller, each bounded by 1 s.

On the FD family — **untested: no device of it has met this code, and every
byte of it is the kernel driver's** — `open` claims the CAN interface (0 on the
PCAN-USB FD, else the one on PCAN-USB Pro's endpoints), reads the firmware info
(`INFO FW`, a vendor request), whose endpoints win over the defaults from type
2, and runs the kernel driver's start, one command list per step: `DRVLD` 1,
the 80 MHz clock, the LED to the device, `RESET_MODE`, the nominal timing, the
data timing where `data` asks for CAN FD, all 64 filter rows open, error and
calibration records on, then the error counters cleared, ISO CAN FD from
firmware 2.0, and normal or listen-only mode. Off a high-speed link each list
goes in 64-byte transfers. Four 2048-byte bulk-IN transfers stay in flight.
Each frame is stamped by the low 32 bits of the device's µs clock and mapped as
GVRET's is. The channel's status records feed `CanEvent::Bus` on a change of
state, with the counters of its last error record, as the kernel's do; every
other record is dropped. `own_frames` hands nothing back. A
send is one transfer on the channel's data endpoint, bounded by 1 s, on the
task's own channel only. Any bulk-IN error is `Closed`. `stop`, and every loss,
turns error and calibration records off, resets the channel and sends `DRVLD`
0, each best effort.

On either family `CanEvent::Bus` has `no_ack` false and `tx_dropped` 0, and a
bus-off channel ignores what the device reports until, 1 s later, the task
restarts it in place, as the kernel does with `restart-ms`, and reports it
`Active` with its counters zeroed: bus on on the classic adapter, the error
counters cleared and the mode on an FD one. A reopen starts clean.

`pcan::probe` claims the adapter as `open` does, and within its one `timeout`
reads `SN` or the firmware info, then releases it; the bus is never touched.
On the classic adapter `DeviceInfo` has the serial as `%08X`, the revision
(`bcdDevice >> 8`) as `hardware` and the 8 MHz clock; on an FD one the serial,
`hw_version` as `hardware`, the firmware as `a.b.c`, the model's channels, `fd`
and the 80 MHz clock.

```rust
use wiretap_io::can::{pcan::{self, PcanOptions}, CanOptions};

let device = pcan::devices()?.remove(0);
let mut pcan = PcanOptions::new(device, 500_000);
if pcan.device.model.fd() {
    pcan.data = Some((2_000_000, None));
}
let mut task = pcan::open(pcan, CanOptions::default()).await?;
```

**SocketCAN.** `socketcan::open` binds one raw socket to the interface by
name, for classic and FD frames alike, and stamps each frame with the kernel's
receive time (`SO_TIMESTAMPNS`), unmapped, with `device_us` `None`. A read that
comes without the stamp is lost, as `Read` with `InvalidData`, never stamped
with the host's clock. Each read drains what else is ready, up to 64 frames.
Error frames are never asked for, RTR frames arrive flagged, and with `fd:
false` FD frames are dropped and FD sends refused. The interface is bus 0, and
`DeviceInfo::buses` is `Some(1)`. An FD send is padded with zeros to the next
length code, with BRS as the frame says. With `own_frames`, the socket asks for
its own frames back (`CAN_RAW_RECV_OWN_MSGS`), and the kernel's `MSG_CONFIRM`
makes them `Tx` reads, stamped when they came back; another socket's frames
stay `Rx`. Listen-only is the library refusing sends: a socket can't tell the
interface. A deleted interface (`ENODEV`, `ENXIO`) is `Closed`, and the reopen
binds a new socket by name, so an adapter that comes back under the same name,
brought up, is found again under its new index. Any other read error, such as
`ENETDOWN` from `ip link set down`, is `Read`, and the reopen retries the same
socket. With `wait_for_device`, an interface missing at open (`ENODEV`) is
waited for as after a loss. Bringing an interface up and setting its bitrate
need `CAP_NET_ADMIN`, and stay the consumer's; `bitrates` reads the rates in one
netlink round trip, `None` where the interface reports none (as `vcan` does),
and a netlink failure is `Err`.

```rust
use wiretap_io::can::{socketcan::{self, SocketCanOptions}, CanOptions};

let rates = socketcan::bitrates("can0")?;
let sc = SocketCanOptions { interface: "can0".into(), fd: true };
let mut task = socketcan::open(sc, CanOptions::default()).await?;
```
