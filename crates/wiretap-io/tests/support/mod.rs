//! A fake Modbus TCP server on loopback, hand-rolled rather than tokio-modbus's
//! `server` feature: the tests need replies no conforming server sends — a
//! short read, a stall, a dropped connection, a write acknowledged but not
//! applied — scripted per request.

#![allow(dead_code)]

use std::{
    collections::VecDeque,
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

/// What the server does with one request. Unscripted requests get `Reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Reply,
    Exception(u8),
    /// Never answer, and keep the connection open.
    Stall,
    Close,
    /// Answer a register read with only this many words.
    Short(u16),
    /// Acknowledge a write without applying it.
    Ignore,
    /// Answer as `Reply` does, this much later.
    Delay(Duration),
    /// Answer as `Reply` does, then close.
    ReplyThenClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    pub connection: usize,
    pub unit: u8,
    pub function: u8,
    pub address: u16,
}

pub struct FakeServer {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    accepting: Mutex<Option<JoinHandle<()>>>,
}

struct State {
    holding: Vec<u16>,
    coils: Vec<bool>,
    script: VecDeque<Action>,
    seen: Vec<Seen>,
    connections: usize,
    open: usize,
}

pub fn input_register(address: u16) -> u16 {
    address.wrapping_add(0x1000)
}

pub fn discrete_input(address: u16) -> bool {
    address.is_multiple_of(3)
}

impl FakeServer {
    /// Holding register `n` starts as `n`; coil `n` as `n` is even.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            holding: (0..=u16::MAX).collect(),
            coils: (0..=u16::MAX).map(|n| n.is_multiple_of(2)).collect(),
            script: VecDeque::new(),
            seen: Vec::new(),
            connections: 0,
            open: 0,
        }));
        let accepting = Mutex::new(Some(accept(listener, state.clone())));
        Self {
            addr,
            state,
            accepting,
        }
    }

    /// Stop listening, so a connect is refused. Open connections are kept.
    pub async fn close(&self) {
        let accepting = self.accepting.lock().unwrap().take();
        if let Some(accepting) = accepting {
            accepting.abort();
            let _ = accepting.await;
        }
    }

    /// Listen again on the same address.
    pub async fn reopen(&self) {
        let listener = TcpListener::bind(self.addr).await.unwrap();
        *self.accepting.lock().unwrap() = Some(accept(listener, self.state.clone()));
    }

    /// Connections the client hasn't closed yet.
    pub fn open_connections(&self) -> usize {
        self.state.lock().unwrap().open
    }

    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    pub fn script(&self, actions: impl IntoIterator<Item = Action>) {
        self.state.lock().unwrap().script.extend(actions);
    }

    pub fn connections(&self) -> usize {
        self.state.lock().unwrap().connections
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    pub fn holding(&self, address: u16) -> u16 {
        self.state.lock().unwrap().holding[address as usize]
    }

    pub fn set_holding(&self, address: u16, value: u16) {
        self.state.lock().unwrap().holding[address as usize] = value;
    }

    pub fn coil(&self, address: u16) -> bool {
        self.state.lock().unwrap().coils[address as usize]
    }
}

fn accept(listener: TcpListener, state: Arc<Mutex<State>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let connection = {
                let mut state = state.lock().unwrap();
                state.connections += 1;
                state.open += 1;
                state.connections
            };
            let state = state.clone();
            tokio::spawn(async move {
                serve(stream, connection, &state).await;
                state.lock().unwrap().open -= 1;
            });
        }
    })
}

async fn serve(mut stream: TcpStream, connection: usize, state: &Mutex<State>) {
    loop {
        let mut header = [0u8; 7];
        if stream.read_exact(&mut header).await.is_err() {
            return;
        }
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        let mut pdu = vec![0u8; length.saturating_sub(1)];
        if stream.read_exact(&mut pdu).await.is_err() {
            return;
        }
        let unit = header[6];
        let (action, reply) = {
            let mut state = state.lock().unwrap();
            state.seen.push(Seen {
                connection,
                unit,
                function: pdu[0],
                address: word(&pdu, 1),
            });
            let action = state.script.pop_front().unwrap_or(Action::Reply);
            (action, state.respond(&pdu, action))
        };
        match action {
            Action::Stall => std::future::pending::<()>().await,
            Action::Close => return,
            Action::Delay(delay) => sleep(delay).await,
            _ => {}
        }
        let mut adu = header[..4].to_vec();
        adu.extend((reply.len() as u16 + 1).to_be_bytes());
        adu.push(unit);
        adu.extend(reply);
        if stream.write_all(&adu).await.is_err() || action == Action::ReplyThenClose {
            return;
        }
    }
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn pack(bits: impl Iterator<Item = bool>) -> Vec<u8> {
    let bits: Vec<bool> = bits.collect();
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (i, _) in bits.iter().enumerate().filter(|(_, &on)| on) {
        bytes[i / 8] |= 1 << (i % 8);
    }
    bytes
}

impl State {
    fn respond(&mut self, pdu: &[u8], action: Action) -> Vec<u8> {
        let function = pdu[0];
        if let Action::Exception(code) = action {
            return vec![function | 0x80, code];
        }
        let address = word(pdu, 1);
        let apply = action != Action::Ignore;
        let span = |count: u16| address..address + count;
        match function {
            0x01 | 0x02 => {
                let count = word(pdu, 3);
                let bytes = if function == 0x01 {
                    pack(span(count).map(|a| self.coils[a as usize]))
                } else {
                    pack(span(count).map(discrete_input))
                };
                [vec![function, bytes.len() as u8], bytes].concat()
            }
            0x03 | 0x04 => {
                let count = match action {
                    Action::Short(n) => n,
                    _ => word(pdu, 3),
                };
                let mut reply = vec![function, (count * 2) as u8];
                for a in span(count) {
                    let value = if function == 0x03 {
                        self.holding[a as usize]
                    } else {
                        input_register(a)
                    };
                    reply.extend(value.to_be_bytes());
                }
                reply
            }
            0x05 => {
                if apply {
                    self.coils[address as usize] = pdu[3] == 0xFF;
                }
                pdu.to_vec()
            }
            0x06 => {
                if apply {
                    self.holding[address as usize] = word(pdu, 3);
                }
                pdu.to_vec()
            }
            0x0F => {
                let count = word(pdu, 3);
                if apply {
                    for (i, a) in span(count).enumerate() {
                        self.coils[a as usize] = pdu[6 + i / 8] & (1 << (i % 8)) != 0;
                    }
                }
                pdu[..5].to_vec()
            }
            0x10 => {
                let count = word(pdu, 3);
                if apply {
                    for (i, a) in span(count).enumerate() {
                        self.holding[a as usize] = word(pdu, 6 + i * 2);
                    }
                }
                pdu[..5].to_vec()
            }
            0x2B => {
                let mut reply = vec![0x2B, 0x0E, pdu[2], 0x81, 0x00, 0x00, 2];
                for (id, value) in [(0x00, &b"Wired Square"[..]), (0x01, b"FAKE-1")] {
                    reply.extend([id, value.len() as u8]);
                    reply.extend(value);
                }
                reply
            }
            _ => vec![function | 0x80, 0x01],
        }
    }
}

/// A loopback address a connect hangs on, as against a host that drops the SYN:
/// a listener that never accepts, with its backlog full. Keep the
/// returned guard alive for as long as the address must stay silent.
pub async fn silent_addr() -> (impl Sized, SocketAddr) {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = socket.local_addr().unwrap();
    let listener = socket.listen(1).unwrap();
    let mut filler = Vec::new();
    let silent = loop {
        match timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => filler.push(stream),
            Ok(Err(_)) => break unaliased_loopback(addr.port()).await,
            Err(_) => break addr,
        }
        assert!(filler.len() < 64, "the backlog never filled");
    };
    ((listener, filler), silent)
}

/// macOS (seen on Darwin 27) resets a connect to a full backlog, but leaves a
/// SYN to an unconfigured loopback address unanswered. Linux answers all of 127/8.
async fn unaliased_loopback(port: u16) -> SocketAddr {
    let addr = SocketAddr::from(([127, 0, 0, 2], port));
    let answered = timeout(Duration::from_millis(100), TcpStream::connect(addr)).await;
    assert!(
        answered.is_err(),
        "no silent address here: {addr} answered {answered:?}"
    );
    addr
}

/// Every test runs under this, so a hang fails instead of stalling the suite.
pub async fn within<F: Future>(test: F) -> F::Output {
    timeout(Duration::from_secs(5), test)
        .await
        .expect("test timed out")
}
