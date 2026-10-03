//! Which reads are due, for any list of reads, on a clock the caller owns.
//!
//! The layer under [`PollSchedule`](super::PollSchedule): no catalogue, no
//! decode, any bank. Items are addressed by their position in the list given to
//! [`ItemSchedule::new`]. When to retire one is the caller's policy.

use std::time::{Duration, Instant};

use super::{FrameBackoff, ModbusFrame, ModbusManifest, RegisterType};

/// One read on its own interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollItem<T> {
    pub register_type: RegisterType,
    /// Protocol-level (0-based) start address.
    pub start: u16,
    pub count: u16,
    pub interval: Duration,
    pub device_address: u8,
    /// The caller's own data, carried and never read here.
    pub tag: T,
}

#[derive(Debug, Clone)]
struct Entry<T> {
    item: PollItem<T>,
    next_due: Instant,
    exceptions: u32,
    transport_errors: u32,
    retired: bool,
}

/// Per-item poll schedule with exception backoff and transport-error counts.
#[derive(Debug, Clone)]
pub struct ItemSchedule<T> {
    backoff: FrameBackoff,
    entries: Vec<Entry<T>>,
}

impl<T> ItemSchedule<T> {
    /// Every item is due at `now`.
    pub fn new(
        items: impl IntoIterator<Item = PollItem<T>>,
        now: Instant,
        backoff: FrameBackoff,
    ) -> Self {
        let entries = items
            .into_iter()
            .map(|item| Entry {
                item,
                next_due: now,
                exceptions: 0,
                transport_errors: 0,
                retired: false,
            })
            .collect();
        Self { backoff, entries }
    }

    /// Panics if `id` is out of range.
    pub fn item(&self, id: usize) -> &PollItem<T> {
        &self.entries[id].item
    }

    fn live(&self) -> impl Iterator<Item = (usize, &Entry<T>)> {
        self.entries.iter().enumerate().filter(|(_, e)| !e.retired)
    }

    /// Ids of the live items due at `now`, in list order.
    pub fn due(&self, now: Instant) -> Vec<usize> {
        self.live()
            .filter(|(_, e)| e.next_due <= now)
            .map(|(id, _)| id)
            .collect()
    }

    /// The earliest instant any live item falls due; `None` if none is left.
    pub fn next_due(&self) -> Option<Instant> {
        self.live().map(|(_, e)| e.next_due).min()
    }

    /// Reschedule `id` a full interval on, returning whether it had been failing.
    pub fn record_read(&mut self, id: usize, now: Instant) -> bool {
        let e = &mut self.entries[id];
        let was_failing = e.exceptions > 0 || e.transport_errors > 0;
        e.exceptions = 0;
        e.transport_errors = 0;
        e.next_due = now + e.item.interval;
        was_failing
    }

    /// Back `id` off after a Modbus exception, returning the delay applied.
    pub fn record_exception(&mut self, id: usize, now: Instant) -> Duration {
        let e = &mut self.entries[id];
        e.exceptions = e.exceptions.saturating_add(1);
        e.transport_errors = 0;
        let delay = self.backoff.delay(e.item.interval, e.exceptions);
        e.next_due = now + delay;
        delay
    }

    /// Count a transport error against `id` and make every item due at `now`,
    /// returning `id`'s consecutive transport errors. Exception counts are kept.
    pub fn record_transport_error(&mut self, id: usize, now: Instant) -> u32 {
        let e = &mut self.entries[id];
        e.transport_errors = e.transport_errors.saturating_add(1);
        let count = e.transport_errors;
        self.make_all_due(now);
        count
    }

    /// Make every item due at `now`, as after a reconnect.
    pub fn make_all_due(&mut self, now: Instant) {
        self.entries.iter_mut().for_each(|e| e.next_due = now);
    }

    /// Never schedule `id` again.
    pub fn retire(&mut self, id: usize) {
        self.entries[id].retired = true;
    }

    pub fn live_count(&self) -> usize {
        self.live().count()
    }
}

impl ModbusManifest {
    /// One item per enabled frame, in any bank, tagged by `tag(index, frame)`.
    pub fn poll_items<T>(&self, mut tag: impl FnMut(usize, &ModbusFrame) -> T) -> Vec<PollItem<T>> {
        self.frames
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.disabled)
            .map(|(i, f)| PollItem {
                register_type: f.register_type,
                start: self.protocol_address(f),
                count: f.length,
                interval: Duration::from_millis(f.interval_ms),
                device_address: f.device_address,
                tag: tag(i, f),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn item(interval: u64, tag: &'static str) -> PollItem<&'static str> {
        PollItem {
            register_type: RegisterType::Coil,
            start: 0,
            count: 8,
            interval: secs(interval),
            device_address: 1,
            tag,
        }
    }

    fn schedule(t0: Instant) -> ItemSchedule<&'static str> {
        ItemSchedule::new(
            [item(1, "fast"), item(10, "slow"), item(5, "mid")],
            t0,
            FrameBackoff::default(),
        )
    }

    #[test]
    fn every_item_is_due_at_construction_in_list_order() {
        let t0 = Instant::now();
        let s = schedule(t0);
        assert_eq!(s.due(t0), [0, 1, 2]);
        assert_eq!(s.next_due(), Some(t0));
        assert_eq!(s.item(1).tag, "slow");
    }

    #[test]
    fn a_read_schedules_the_next_one_a_full_interval_on() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        let t1 = t0 + Duration::from_millis(300);
        for id in s.due(t0) {
            s.record_read(id, t1);
        }
        assert!(s.due(t1 + Duration::from_millis(999)).is_empty());
        assert_eq!(s.due(t1 + secs(1)), [0]);
        assert_eq!(s.next_due(), Some(t1 + secs(1)));
    }

    #[test]
    fn an_exception_backs_off_only_that_item() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        assert_eq!(s.record_exception(0, t0), secs(2));
        assert_eq!(s.record_exception(0, t0), secs(4));
        s.record_read(2, t0);
        assert_eq!(s.due(t0 + secs(3)), [1]);
    }

    #[test]
    fn a_read_after_failures_reports_the_recovery_and_resets_both_counts() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        assert!(!s.record_read(0, t0));

        s.record_exception(0, t0);
        assert!(s.record_read(0, t0));
        assert_eq!(s.record_exception(0, t0), secs(2));

        s.record_transport_error(1, t0);
        assert!(s.record_read(1, t0));
        assert_eq!(s.record_transport_error(1, t0), 1);
    }

    #[test]
    fn a_transport_error_counts_per_item_and_makes_everything_due() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        for id in s.due(t0) {
            s.record_read(id, t0);
        }
        let t1 = t0 + secs(1);
        assert_eq!(s.record_transport_error(2, t1), 1);
        assert_eq!(s.record_transport_error(2, t1), 2);
        assert_eq!(s.record_transport_error(1, t1), 1);
        assert_eq!(s.due(t1), [0, 1, 2]);
    }

    #[test]
    fn an_exception_breaks_a_run_of_transport_errors() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.record_transport_error(0, t0);
        s.record_exception(0, t0);
        assert_eq!(s.record_transport_error(0, t0), 1);
    }

    #[test]
    fn exception_backoff_survives_a_transport_error() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.record_exception(0, t0);
        s.record_exception(0, t0);
        s.record_transport_error(1, t0);
        assert_eq!(s.due(t0), [0, 1, 2]);
        assert_eq!(s.record_exception(0, t0), secs(8));
    }

    #[test]
    fn making_all_due_needs_no_item() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        for id in s.due(t0) {
            s.record_read(id, t0);
        }
        s.make_all_due(t0 + secs(1));
        assert_eq!(s.due(t0 + secs(1)), [0, 1, 2]);
    }

    #[test]
    fn a_retired_item_is_never_due_and_the_count_says_when_none_are_left() {
        let t0 = Instant::now();
        let mut s = schedule(t0);
        s.retire(0);
        s.retire(2);
        s.make_all_due(t0);
        assert_eq!(s.due(t0), [1]);
        assert_eq!(s.live_count(), 1);

        s.record_read(1, t0);
        assert_eq!(s.next_due(), Some(t0 + secs(10)));
        s.retire(1);
        assert_eq!(s.live_count(), 0);
        assert_eq!(s.next_due(), None);
        assert!(s.due(t0 + secs(3600)).is_empty());
    }

    #[test]
    fn manifest_items_cover_every_enabled_frame_in_any_bank() {
        let manifest = ModbusManifest::parse(
            r#"
[meta.modbus]
register_base = 1

[node.inverter]
device_address = 3

[frame.modbus.a_voltage]
register_number = 30101
register_type = "input"
length = 2
interval_ms = 2000
node_address = 3

[frame.modbus.b_parked]
register_number = 40001
register_type = "holding"
length = 1
disabled = true

[frame.modbus.c_relays]
register_number = 11
register_type = "coil"
length = 8
"#,
        )
        .unwrap();
        assert_eq!(
            manifest.poll_items(|i, f| (i, f.register_number)),
            [
                PollItem {
                    register_type: RegisterType::Input,
                    start: 100,
                    count: 2,
                    interval: secs(2),
                    device_address: 3,
                    tag: (0, 30101),
                },
                PollItem {
                    register_type: RegisterType::Coil,
                    start: 10,
                    count: 8,
                    interval: secs(5),
                    device_address: 1,
                    tag: (2, 11),
                },
            ]
        );
    }
}
