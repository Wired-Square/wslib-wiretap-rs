use std::time::{Duration, SystemTime};

use tokio_modbus::prelude::{Request, Response};
use wiretap_catalog::modbus::{group_contiguous, ModbusWrite, WriteBank};

use super::{tcp::Link, ModbusTcp, RequestError, TransportError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReport {
    pub outcome: WriteOutcome,
    /// Every read-modify-write and verify read, in the order they ran.
    pub readback: Vec<Readback>,
    /// Targets of the runs the device accepted, for flash wear.
    pub written: Vec<(WriteBank, u16)>,
    /// The socket dropped during this batch.
    pub transport_lost: bool,
}

/// The detail names the registers involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Confirmed,
    Unconfirmed(String),
    Failed(String),
}

/// The words as received: a short reply stays short, and a coil reads as 0 or 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readback {
    pub kind: ReadbackKind,
    pub bank: WriteBank,
    pub start: u16,
    pub words: Vec<u16>,
    pub at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadbackKind {
    BeforeWrite,
    Verify,
}

impl ModbusTcp {
    /// FC06 for one register, FC16 for several.
    pub async fn write_registers(
        &mut self,
        unit: Option<u8>,
        start: u16,
        values: &[u16],
    ) -> Result<Duration, RequestError> {
        let (_, latency) = self
            .call(unit, register_write(start, values.to_vec()), acknowledged)
            .await?;
        Ok(latency)
    }

    /// FC05 for one coil, FC15 for several.
    pub async fn write_coils(
        &mut self,
        unit: Option<u8>,
        start: u16,
        values: &[bool],
    ) -> Result<Duration, RequestError> {
        let (_, latency) = self
            .call(unit, coil_write(start, values.to_vec()), acknowledged)
            .await?;
        Ok(latency)
    }

    /// Runs from `group_contiguous`, each read-modify-written where a mask
    /// leaves register bits alone (a coil run owns its coils outright), written
    /// in order, then every run read back and its owned bits compared. The
    /// whole batch holds one connection and never reconnects mid-way, and a
    /// report always comes back.
    pub async fn write_verified(
        &mut self,
        unit: Option<u8>,
        writes: &[ModbusWrite],
    ) -> WriteReport {
        self.write_verified_keeping_loss(unit, writes).await.0
    }

    /// With the error that dropped the socket, when `transport_lost`.
    pub(super) async fn write_verified_keeping_loss(
        &mut self,
        unit: Option<u8>,
        writes: &[ModbusWrite],
    ) -> (WriteReport, Option<TransportError>) {
        let mut report = WriteReport {
            outcome: WriteOutcome::Confirmed,
            readback: Vec::new(),
            written: Vec::new(),
            transport_lost: false,
        };
        let mut link = match self.acquire().await {
            Ok(link) => link,
            Err(e) => {
                report.outcome = WriteOutcome::Failed(e.to_string());
                report.transport_lost = true;
                return (report, Some(e));
            }
        };
        let mut batch = Batch {
            link: &mut link,
            unit: self.unit(unit),
            op_timeout: self.options.op_timeout,
            report: &mut report,
            lost: None,
        };
        let runs = group_contiguous(writes);
        if batch.write(&runs).await {
            batch.verify(&runs).await;
        }
        let lost = batch.lost;
        report.transport_lost = lost.is_some();
        if lost.is_none() {
            self.release(link);
        }
        (report, lost)
    }
}

fn register_write(start: u16, values: Vec<u16>) -> Request<'static> {
    match values[..] {
        [value] => Request::WriteSingleRegister(start, value),
        _ => Request::WriteMultipleRegisters(start, values.into()),
    }
}

fn coil_write(start: u16, values: Vec<bool>) -> Request<'static> {
    match values[..] {
        [value] => Request::WriteSingleCoil(start, value),
        _ => Request::WriteMultipleCoils(start, values.into()),
    }
}

fn acknowledged(response: Response) -> Option<()> {
    matches!(
        response,
        Response::WriteSingleRegister(..)
            | Response::WriteMultipleRegisters(..)
            | Response::WriteSingleCoil(..)
            | Response::WriteMultipleCoils(..)
    )
    .then_some(())
}

fn read_back_request(bank: WriteBank, start: u16, count: u16) -> Request<'static> {
    match bank {
        WriteBank::Holding => Request::ReadHoldingRegisters(start, count),
        WriteBank::Coil => Request::ReadCoils(start, count),
    }
}

/// A coil read's padding bits past `count` are dropped.
fn words(response: Response, count: u16) -> Option<Vec<u16>> {
    match response {
        Response::ReadHoldingRegisters(words) => Some(words),
        Response::ReadCoils(bits) => {
            Some(bits.into_iter().take(count.into()).map(u16::from).collect())
        }
        _ => None,
    }
}

fn describe(w: &ModbusWrite) -> String {
    format!("{} {}", w.bank.noun(), w.address)
}

/// Missing words read as 0, as the catalogue decoders treat a short block.
fn word_at(words: &[u16], index: usize) -> u16 {
    words.get(index).copied().unwrap_or(0)
}

struct Batch<'a> {
    link: &'a mut Link,
    unit: u8,
    op_timeout: Duration,
    report: &'a mut WriteReport,
    lost: Option<TransportError>,
}

impl Batch<'_> {
    async fn read_back(
        &mut self,
        kind: ReadbackKind,
        run: &[ModbusWrite],
    ) -> Result<Vec<u16>, RequestError> {
        let ModbusWrite {
            bank,
            address: start,
            ..
        } = run[0];
        let count = run.len() as u16;
        let (words, _) = self
            .link
            .exchange(
                self.unit,
                read_back_request(bank, start, count),
                self.op_timeout,
                |response| words(response, count),
            )
            .await?;
        self.report.readback.push(Readback {
            kind,
            bank,
            start,
            words: words.clone(),
            at: SystemTime::now(),
        });
        Ok(words)
    }

    fn fail(&mut self, first: &ModbusWrite, step: &str, e: RequestError) -> bool {
        self.report.outcome = WriteOutcome::Failed(format!("{}: {step}{e}", describe(first)));
        if let RequestError::Transport(error) = e {
            self.lost = Some(error);
        }
        false
    }

    async fn register_values(&mut self, run: &[ModbusWrite]) -> Result<Vec<u16>, RequestError> {
        // A full mask takes nothing from `current`, so a run of them needs no read.
        let current = if run.iter().all(|w| w.mask == 0xFFFF) {
            Vec::new()
        } else {
            self.read_back(ReadbackKind::BeforeWrite, run).await?
        };
        Ok(run
            .iter()
            .enumerate()
            .map(|(i, w)| (word_at(&current, i) & !w.mask) | (w.value & w.mask))
            .collect())
    }

    /// Stops at the first failing run, and says whether every run went out.
    async fn write(&mut self, runs: &[Vec<ModbusWrite>]) -> bool {
        for run in runs {
            let first = &run[0];
            let request = match first.bank {
                WriteBank::Coil => coil_write(
                    first.address,
                    run.iter().map(|w| w.value & w.mask != 0).collect(),
                ),
                WriteBank::Holding => match self.register_values(run).await {
                    Ok(values) => register_write(first.address, values),
                    Err(e) => return self.fail(first, "read-modify-write: ", e),
                },
            };
            if let Err(e) = self
                .link
                .exchange(self.unit, request, self.op_timeout, acknowledged)
                .await
            {
                return self.fail(first, "", e);
            }
            self.report
                .written
                .extend(run.iter().map(|w| (w.bank, w.address)));
        }
        true
    }

    /// Carries on past an exception; only a lost socket stops it.
    async fn verify(&mut self, runs: &[Vec<ModbusWrite>]) {
        let mut problems = Vec::new();
        for run in runs {
            match self.read_back(ReadbackKind::Verify, run).await {
                Ok(words) => {
                    for (i, w) in run.iter().enumerate() {
                        let (wrote, read) = (w.value & w.mask, word_at(&words, i) & w.mask);
                        if wrote != read {
                            problems.push(format!("{}: wrote {wrote}, read {read}", describe(w)));
                        }
                    }
                }
                Err(e) => {
                    problems.push(format!("{}: verify read: {e}", describe(&run[0])));
                    if let RequestError::Transport(error) = e {
                        self.lost = Some(error);
                        break;
                    }
                }
            }
        }
        if !problems.is_empty() {
            self.report.outcome = WriteOutcome::Unconfirmed(problems.join("; "));
        }
    }
}

#[allow(dead_code)]
fn futures_are_send(mut tcp: ModbusTcp, writes: &[ModbusWrite]) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&tcp.write_registers(None, 0, &[]));
    is_send(&tcp.write_coils(None, 0, &[]));
    is_send(&tcp.write_verified(None, writes));
}
