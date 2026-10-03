use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime},
};

use wiretap_catalog::modbus::{
    decode_coil_frame, decode_frame, DecodedSignal, FrameBackoff, ItemSchedule, ModbusManifest,
    PollItem,
};

use super::{
    ExceptionCode, ModbusTcp, ReadData, ReadRequest, Reading, RequestError, TransportError,
};

/// Position in the list the poller was built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(pub usize);

/// Which unit each read is addressed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitSource {
    /// The item's `device_address`.
    Item,
    /// `unit: None`, so [`TcpOptions::unit_id`](super::TcpOptions::unit_id).
    Connection,
}

/// Which banks [`Poller::from_manifest`] schedules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Banks {
    Registers,
    All,
}

/// Reads what is due over a connection the caller lends it, and records each
/// outcome. It doesn't own the connection, doesn't sleep and doesn't retry.
pub struct Poller<T> {
    schedule: ItemSchedule<T>,
    units: UnitSource,
    catalogue: Option<Catalogue>,
}

struct Catalogue {
    manifest: ModbusManifest,
    frame_of_item: Vec<usize>,
    cache: BTreeMap<String, (DecodedSignal, SystemTime)>,
}

#[derive(Debug)]
pub struct Step<T> {
    /// In the order the reads ran.
    pub events: Vec<PollEvent<T>>,
    /// This step opened the socket.
    pub connected: bool,
    pub end: StepEnd,
}

#[derive(Debug)]
pub enum StepEnd {
    /// Every due item was tried.
    Done,
    /// Nothing was read, and no item was charged.
    ConnectFailed(TransportError),
    /// The last event is the `Transport` that dropped the socket.
    Lost,
}

#[derive(Debug)]
pub enum PollEvent<T> {
    Read {
        item: ItemId,
        tag: T,
        request: ReadRequest,
        reading: Reading,
        /// Empty for a raw poller.
        signals: Vec<DecodedSignal>,
        /// It had been failing.
        recovered: bool,
    },
    Exception {
        item: ItemId,
        tag: T,
        request: ReadRequest,
        code: ExceptionCode,
        latency: Duration,
        /// The backoff applied.
        retry_in: Duration,
    },
    Transport {
        item: ItemId,
        tag: T,
        request: ReadRequest,
        error: TransportError,
        /// This item's run of transport errors.
        consecutive: u32,
    },
}

impl<T: Clone> Poller<T> {
    /// Raw reads: no decode, no snapshot. Every item is due at `now`.
    pub fn new(
        items: impl IntoIterator<Item = PollItem<T>>,
        units: UnitSource,
        backoff: FrameBackoff,
        now: Instant,
    ) -> Self {
        Self {
            schedule: ItemSchedule::new(items, now, backoff),
            units,
            catalogue: None,
        }
    }

    /// Reads every due item in list order, recording each outcome at `now`
    /// before the next read starts, so dropping the future loses only the
    /// event list. Connects first if something is due and `conn` has no
    /// socket; stops at the first transport error, making every item due.
    pub async fn step(&mut self, conn: &mut ModbusTcp, now: Instant) -> Step<T> {
        let mut step = Step {
            events: Vec::new(),
            connected: false,
            end: StepEnd::Done,
        };
        let due = self.schedule.due(now);
        if due.is_empty() {
            return step;
        }
        if !conn.is_connected() {
            if let Err(error) = conn.connect().await {
                step.end = StepEnd::ConnectFailed(error);
                return step;
            }
            step.connected = true;
        }
        for id in due {
            let item = ItemId(id);
            let tag = self.schedule.item(id).tag.clone();
            let request = self.request(id);
            let event = match conn.read(request).await {
                Ok(reading) => PollEvent::Read {
                    recovered: self.schedule.record_read(id, now),
                    signals: self.decode(id, &reading),
                    item,
                    tag,
                    request,
                    reading,
                },
                Err(RequestError::Exception { code, latency }) => PollEvent::Exception {
                    retry_in: self.schedule.record_exception(id, now),
                    item,
                    tag,
                    request,
                    code,
                    latency,
                },
                Err(RequestError::Transport(error)) => {
                    step.end = StepEnd::Lost;
                    PollEvent::Transport {
                        consecutive: self.schedule.record_transport_error(id, now),
                        item,
                        tag,
                        request,
                        error,
                    }
                }
            };
            step.events.push(event);
            if matches!(step.end, StepEnd::Lost) {
                break;
            }
        }
        step
    }
}

impl<T> Poller<T> {
    /// Panics if `id` is out of range.
    pub fn item(&self, id: ItemId) -> &PollItem<T> {
        self.schedule.item(id.0)
    }

    /// Never read `id` again. Panics if it is out of range.
    pub fn retire(&mut self, id: ItemId) {
        self.schedule.retire(id.0);
    }

    pub fn live_count(&self) -> usize {
        self.schedule.live_count()
    }

    /// `None` once every item is retired.
    pub fn next_due(&self) -> Option<Instant> {
        self.schedule.next_due()
    }

    fn request(&self, id: usize) -> ReadRequest {
        let request = ReadRequest::from(self.schedule.item(id));
        match self.units {
            UnitSource::Item => request,
            UnitSource::Connection => ReadRequest {
                unit: None,
                ..request
            },
        }
    }

    fn decode(&mut self, id: usize, reading: &Reading) -> Vec<DecodedSignal> {
        let Some(catalogue) = &mut self.catalogue else {
            return Vec::new();
        };
        let frame = &catalogue.manifest.frames[catalogue.frame_of_item[id]];
        let signals = match &reading.data {
            ReadData::Registers(words) => decode_frame(frame, words, &catalogue.manifest.meta),
            ReadData::Coils(bits) => decode_coil_frame(frame, bits),
        };
        for signal in &signals {
            let cached = (signal.clone(), reading.at);
            catalogue.cache.insert(signal.name.clone(), cached);
        }
        signals
    }
}

impl Poller<usize> {
    /// One item per enabled frame in `banks`, tagged by frame index. Reads are
    /// decoded and cached.
    pub fn from_manifest(
        manifest: ModbusManifest,
        banks: Banks,
        units: UnitSource,
        backoff: FrameBackoff,
        now: Instant,
    ) -> Self {
        let items: Vec<_> = manifest
            .poll_items(|index, _| index)
            .into_iter()
            .filter(|item| banks == Banks::All || item.register_type.is_register_bank())
            .collect();
        let frame_of_item = items.iter().map(|item| item.tag).collect();
        Self {
            schedule: ItemSchedule::new(items, now, backoff),
            units,
            catalogue: Some(Catalogue {
                manifest,
                frame_of_item,
                cache: BTreeMap::new(),
            }),
        }
    }

    /// `None` unless the poller was built by [`Self::from_manifest`].
    pub fn manifest(&self) -> Option<&ModbusManifest> {
        self.catalogue.as_ref().map(|catalogue| &catalogue.manifest)
    }

    /// The snapshot: the last decoded value of every signal seen, ordered by
    /// name, with the wall-clock time of the read it came from.
    pub fn signals(&self) -> impl Iterator<Item = (&DecodedSignal, SystemTime)> {
        self.catalogue
            .iter()
            .flat_map(|catalogue| catalogue.cache.values())
            .map(|(signal, at)| (signal, *at))
    }

    pub fn signal(&self, name: &str) -> Option<(&DecodedSignal, SystemTime)> {
        let (signal, at) = self.catalogue.as_ref()?.cache.get(name)?;
        Some((signal, *at))
    }
}

#[allow(dead_code)]
fn futures_are_send(mut poller: Poller<usize>, mut tcp: ModbusTcp) {
    fn is_send<T: Send>(_: &T) {}
    is_send(&poller.step(&mut tcp, Instant::now()));
}
