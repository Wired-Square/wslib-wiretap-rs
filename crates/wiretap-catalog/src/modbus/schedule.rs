//! Which register frames are due, on a clock the caller owns.
//!
//! Sans-io: every call takes `now`, and nothing here sleeps, reads or keeps a
//! socket. A consumer asks [`PollSchedule::due`], performs those reads, and
//! reports each outcome back through a `record_*` call.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::{decode_frame, DecodedSignal, ItemSchedule, ModbusManifest};

/// How far a frame backs off after repeated Modbus exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameBackoff {
    /// Longest delay between reads of a failing frame. A frame the device
    /// rejects is still read this often, since the same catalogue may meet
    /// hardware that implements it.
    pub ceiling: Duration,
}

impl Default for FrameBackoff {
    fn default() -> Self {
        Self {
            ceiling: Duration::from_secs(600),
        }
    }
}

impl FrameBackoff {
    /// `interval × 2^failures`, capped at the ceiling.
    pub fn delay(&self, interval: Duration, failures: u32) -> Duration {
        2u32.checked_pow(failures)
            .and_then(|factor| interval.checked_mul(factor))
            .map_or(self.ceiling, |wait| wait.min(self.ceiling))
    }
}

/// Per-frame poll schedule and last-known values for a [`ModbusManifest`].
///
/// Only enabled register-bank frames are scheduled. Frame indices are
/// positions in `manifest().frames`.
#[derive(Debug, Clone)]
pub struct PollSchedule {
    manifest: ModbusManifest,
    items: ItemSchedule<usize>,
    item_of_frame: Vec<Option<usize>>,
    cache: BTreeMap<String, DecodedSignal>,
}

impl PollSchedule {
    /// Every scheduled frame is due at `now`.
    pub fn new(manifest: ModbusManifest, now: Instant, backoff: FrameBackoff) -> Self {
        let items: Vec<_> = manifest
            .poll_items(|index, _| index)
            .into_iter()
            .filter(|item| item.register_type.is_register_bank())
            .collect();
        let mut item_of_frame = vec![None; manifest.frames.len()];
        for (id, item) in items.iter().enumerate() {
            item_of_frame[item.tag] = Some(id);
        }
        Self {
            manifest,
            items: ItemSchedule::new(items, now, backoff),
            item_of_frame,
            cache: BTreeMap::new(),
        }
    }

    pub fn manifest(&self) -> &ModbusManifest {
        &self.manifest
    }

    fn item(&self, frame: usize) -> usize {
        self.item_of_frame[frame].expect("frame is scheduled")
    }

    /// Indices of the frames due at `now`, in manifest order.
    pub fn due(&self, now: Instant) -> Vec<usize> {
        self.items
            .due(now)
            .into_iter()
            .map(|id| self.items.item(id).tag)
            .collect()
    }

    /// The earliest instant any frame falls due; `None` if nothing is scheduled.
    pub fn next_due(&self) -> Option<Instant> {
        self.items.next_due()
    }

    /// Decode a successful read of `frame`, cache it, and return its signals.
    ///
    /// Panics if `frame` is not a scheduled frame.
    pub fn record_registers(
        &mut self,
        frame: usize,
        now: Instant,
        regs: &[u16],
    ) -> Vec<DecodedSignal> {
        let id = self.item(frame);
        self.items.record_read(id, now);
        let decoded = decode_frame(&self.manifest.frames[frame], regs, &self.manifest.meta);
        for sig in &decoded {
            self.cache.insert(sig.name.clone(), sig.clone());
        }
        decoded
    }

    /// Back `frame` off after a Modbus exception, returning the delay applied.
    ///
    /// Panics if `frame` is not a scheduled frame.
    pub fn record_exception(&mut self, frame: usize, now: Instant) -> Duration {
        let id = self.item(frame);
        self.items.record_exception(id, now)
    }

    /// Make every frame due at `now`, so nothing is skipped after a reconnect.
    /// Cached values and backoff counts are kept.
    pub fn record_transport_error(&mut self, now: Instant) {
        self.items.make_all_due(now);
    }

    /// The last decoded value of every signal seen, ordered by name.
    pub fn cached(&self) -> impl Iterator<Item = &DecodedSignal> {
        self.cache.values()
    }

    pub fn cached_signal(&self, name: &str) -> Option<&DecodedSignal> {
        self.cache.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    const FIXTURE: &str = r#"
[meta.modbus]
register_base = 0

[frame.modbus.telemetry]
register_number = 100
register_type = "input"
length = 2
interval_ms = 2000

[[frame.modbus.telemetry.signals]]
name = "Voltage"
start_bit = 0
bit_length = 16
factor = 0.1
unit = "V"

[[frame.modbus.telemetry.signals]]
name = "Load"
start_bit = 16
bit_length = 16
unit = "%"

[frame.modbus.ratings]
register_number = 200
register_type = "holding"
length = 1
interval_ms = 600000

[[frame.modbus.ratings.signals]]
name = "Rated_VA"
start_bit = 0
bit_length = 16
unit = "VA"

[frame.modbus.parked]
register_number = 300
register_type = "input"
length = 1
disabled = true

[frame.modbus.relays]
register_number = 10
register_type = "coil"
length = 8

[frame.modbus.alarms]
register_number = 20
register_type = "discrete"
length = 8
"#;

    fn schedule(t0: Instant) -> PollSchedule {
        let manifest = ModbusManifest::parse(FIXTURE).expect("fixture parses");
        PollSchedule::new(manifest, t0, FrameBackoff::default())
    }

    fn index(s: &PollSchedule, name: &str) -> usize {
        s.manifest()
            .frames
            .iter()
            .position(|f| f.name == name)
            .unwrap_or_else(|| panic!("frame {name} present"))
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn every_scheduled_frame_is_due_at_construction() {
        let t0 = Instant::now();
        let s = schedule(t0);
        let mut due = s.due(t0);
        due.sort_unstable();
        let mut expected = vec![index(&s, "telemetry"), index(&s, "ratings")];
        expected.sort_unstable();
        assert_eq!(due, expected);
        assert_eq!(s.next_due(), Some(t0));
    }

    #[test]
    fn coil_discrete_and_disabled_frames_are_never_due() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.record_transport_error(t0 + secs(3600));
        let due = s.due(t0 + secs(3600));
        for name in ["parked", "relays", "alarms"] {
            assert!(!due.contains(&index(&s, name)), "{name} scheduled");
        }
    }

    #[test]
    fn each_frame_is_due_on_its_own_interval() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let (tel, rat) = (index(&s, "telemetry"), index(&s, "ratings"));
        s.record_registers(tel, t0, &[0, 0]);
        s.record_registers(rat, t0, &[0]);

        assert!(s.due(t0 + Duration::from_millis(1999)).is_empty());
        assert_eq!(s.due(t0 + secs(2)), vec![tel]);
        assert_eq!(s.next_due(), Some(t0 + secs(2)));
        assert!(s.due(t0 + secs(600)).contains(&rat));
    }

    #[test]
    fn a_frame_not_due_still_contributes_its_cached_values() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let (tel, rat) = (index(&s, "telemetry"), index(&s, "ratings"));
        s.record_registers(rat, t0, &[1500]);
        s.record_registers(tel, t0, &[2301, 40]);
        s.record_registers(tel, t0 + secs(2), &[2302, 41]);

        assert_eq!(s.cached_signal("Rated_VA").unwrap().value, dec!(1500));
        let voltage = s.cached_signal("Voltage").unwrap();
        assert_eq!(voltage.value, dec!(230.2));
        assert_eq!(voltage.unit.as_deref(), Some("V"));
        let names: Vec<_> = s.cached().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["Load", "Rated_VA", "Voltage"]);
    }

    #[test]
    fn recording_registers_returns_that_frames_signals_with_units() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let decoded = s.record_registers(index(&s, "telemetry"), t0, &[2301, 40]);
        let got: Vec<_> = decoded
            .iter()
            .map(|d| (d.name.as_str(), d.value, d.unit.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("Voltage", dec!(230.1), Some("V")),
                ("Load", dec!(40), Some("%"))
            ]
        );
    }

    #[test]
    fn an_exception_doubles_the_interval_per_failure_up_to_the_ceiling() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let tel = index(&s, "telemetry");
        let delays: Vec<_> = (0..10).map(|_| s.record_exception(tel, t0)).collect();
        assert_eq!(
            delays,
            [4, 8, 16, 32, 64, 128, 256, 512, 600, 600].map(secs)
        );
        assert_eq!(s.due(t0 + secs(599)), vec![index(&s, "ratings")]);
        assert!(s.due(t0 + secs(600)).contains(&tel));
    }

    #[test]
    fn backoff_saturates_rather_than_overflowing() {
        let backoff = FrameBackoff::default();
        assert_eq!(backoff.delay(secs(2), 40), backoff.ceiling);
        assert_eq!(backoff.delay(Duration::MAX, 1), backoff.ceiling);
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let rat = index(&s, "ratings");
        for _ in 0..100 {
            assert_eq!(s.record_exception(rat, t0), secs(600));
        }
    }

    #[test]
    fn the_ceiling_is_the_callers_choice() {
        let t0 = Instant::now();
        let manifest = ModbusManifest::parse(FIXTURE).unwrap();
        let backoff = FrameBackoff { ceiling: secs(5) };
        let mut s = PollSchedule::new(manifest, t0, backoff);
        let tel = index(&s, "telemetry");
        assert_eq!(s.record_exception(tel, t0), secs(4));
        assert_eq!(s.record_exception(tel, t0), secs(5));
    }

    #[test]
    fn a_success_resets_the_backoff() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let tel = index(&s, "telemetry");
        s.record_exception(tel, t0);
        s.record_exception(tel, t0);
        s.record_registers(tel, t0 + secs(8), &[0, 0]);
        assert_eq!(s.record_exception(tel, t0 + secs(10)), secs(4));
    }

    #[test]
    fn a_transport_error_makes_everything_due_and_keeps_the_cache() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let (tel, rat) = (index(&s, "telemetry"), index(&s, "ratings"));
        s.record_registers(tel, t0, &[2301, 40]);
        s.record_registers(rat, t0, &[1500]);

        let t1 = t0 + secs(1);
        s.record_transport_error(t1);
        assert_eq!(s.due(t1).len(), 2);
        assert_eq!(s.next_due(), Some(t1));
        assert_eq!(s.cached().count(), 3);
    }

    #[test]
    fn a_manifest_with_nothing_to_poll_has_no_next_due() {
        let manifest = ModbusManifest::parse(
            "[frame.modbus.relays]\nregister_number = 1\nregister_type = \"coil\"\nlength = 1\n",
        )
        .unwrap();
        let t0 = Instant::now();
        let s = PollSchedule::new(manifest, t0, FrameBackoff::default());
        assert_eq!(s.next_due(), None);
        assert!(s.due(t0).is_empty());
    }

    #[test]
    fn a_consumer_loop_records_while_iterating_due_frames() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let mut reads = 0;
        for frame in s.due(t0) {
            let regs = vec![0u16; usize::from(s.manifest().frames[frame].length)];
            if s.manifest().frames[frame].name == "ratings" {
                s.record_exception(frame, t0);
            } else {
                s.record_registers(frame, t0, &regs);
            }
            reads += 1;
        }
        assert_eq!(reads, 2);
        assert!(s.due(t0).is_empty());
    }
}
