//! Stamps a read's frames. A device's µs counter is unwrapped and mapped onto
//! the wall clock by the lowest `read time − counter` seen over a window of
//! device time: a frame can't arrive before it happened, so each read's offset
//! bounds the true one from above, and a mapped stamp is never later than its
//! read. The window lets the offset follow the device crystal's drift.

use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{CanFrame, CanRead, Direction, TimeMapping};

pub(crate) enum Stamp {
    /// The device has no clock: the frame takes its read's time.
    #[cfg_attr(
        not(any(
            all(feature = "can-slcan", not(target_os = "ios")),
            all(
                feature = "can-gsusb",
                any(test, target_os = "macos", target_os = "windows")
            )
        )),
        allow(dead_code, reason = "SLCAN and gs_usb construct it")
    )]
    Read,
    /// The device's raw µs counter.
    #[cfg_attr(
        not(any(
            feature = "can-gvret",
            all(
                any(feature = "can-gsusb", feature = "can-pcan"),
                any(test, target_os = "macos", target_os = "windows")
            )
        )),
        allow(
            dead_code,
            reason = "with no transport compiled in, only the tests construct it"
        )
    )]
    Counter(u32),
    /// Passed through unmapped and unfloored.
    #[cfg_attr(
        not(all(feature = "can-socketcan", target_os = "linux")),
        allow(dead_code, reason = "SocketCAN constructs it")
    )]
    Kernel(SystemTime),
}

pub(crate) struct Received {
    pub frame: CanFrame,
    pub direction: Direction,
    pub stamp: Stamp,
    pub overflow: bool,
}

const HALF_RANGE: u32 = 1 << 31;
const STUCK_AFTER_US: i64 = 1_000_000;

#[derive(Clone, Copy)]
struct Counter {
    raw: u32,
    unwrapped: u64,
}

pub(crate) struct DeviceClock {
    mapping: TimeMapping,
    floor: i64,
    counter: Option<Counter>,
    moved_at: i64,
    /// `(device µs, offset)`, offsets rising front to back, so the front is
    /// the window's lowest.
    envelope: VecDeque<(u64, i64)>,
}

impl DeviceClock {
    pub fn new(mapping: TimeMapping) -> Self {
        Self {
            mapping,
            floor: i64::MIN,
            counter: None,
            moved_at: 0,
            envelope: VecDeque::new(),
        }
    }

    /// For a new connection; the floor holds across it.
    pub fn reset(&mut self) {
        self.counter = None;
        self.envelope.clear();
    }

    pub fn stamp(&mut self, read_at: SystemTime, received: Vec<Received>) -> Vec<CanRead> {
        let read_us = micros(read_at);
        let before = self.counter.map(|c| c.raw);
        let device_us: Vec<Option<u64>> = received
            .iter()
            .map(|r| match r.stamp {
                Stamp::Counter(raw) => Some(self.unwrap(raw)),
                _ => None,
            })
            .collect();
        let last = device_us.iter().rev().flatten().next().copied();
        let offset = last.and_then(|last| self.offset(read_us, before, last));
        received
            .into_iter()
            .zip(device_us)
            .map(|(r, device_us)| {
                let at = match (r.stamp, device_us.zip(offset)) {
                    (Stamp::Kernel(at), _) => micros(at),
                    (_, Some((us, offset))) => self.floored((us as i64 + offset).min(read_us)),
                    _ => self.floored(read_us),
                };
                CanRead {
                    device_us,
                    overflow: r.overflow,
                    ..CanRead::new(r.frame, r.direction, from_micros(at))
                }
            })
            .collect()
    }

    /// A jump back of up to half the range is a device reset, and re-anchors.
    fn unwrap(&mut self, raw: u32) -> u64 {
        let unwrapped = match self.counter {
            Some(c) if raw.wrapping_sub(c.raw) < HALF_RANGE => {
                c.unwrapped + u64::from(raw.wrapping_sub(c.raw))
            }
            Some(_) => {
                self.envelope.clear();
                u64::from(raw)
            }
            None => u64::from(raw),
        };
        self.counter = Some(Counter { raw, unwrapped });
        unwrapped
    }

    /// `None` stamps the read with host time: under `Host`, or while the
    /// counter hasn't moved for a second of wall clock.
    fn offset(&mut self, read_us: i64, before: Option<u32>, last: u64) -> Option<i64> {
        let TimeMapping::Mapped { window } = self.mapping else {
            return None;
        };
        if before != self.counter.map(|c| c.raw) {
            self.moved_at = read_us;
        }
        if read_us - self.moved_at >= STUCK_AFTER_US {
            self.envelope.clear();
            return None;
        }
        let offset = read_us - last as i64;
        while self.envelope.back().is_some_and(|&(_, o)| o >= offset) {
            self.envelope.pop_back();
        }
        self.envelope.push_back((last, offset));
        let window = window.as_micros() as u64;
        while self
            .envelope
            .front()
            .is_some_and(|&(us, _)| us + window < last)
        {
            self.envelope.pop_front();
        }
        self.envelope.front().map(|&(_, o)| o)
    }

    fn floored(&mut self, us: i64) -> i64 {
        self.floor = self.floor.max(us);
        self.floor
    }
}

fn micros(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_micros() as i64,
        Err(before) => -(before.duration().as_micros() as i64),
    }
}

fn from_micros(us: i64) -> SystemTime {
    let magnitude = Duration::from_micros(us.unsigned_abs());
    if us >= 0 {
        UNIX_EPOCH + magnitude
    } else {
        UNIX_EPOCH - magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH_US: i64 = 1_790_000_000_000_000;
    const MAPPED: TimeMapping = TimeMapping::Mapped {
        window: Duration::from_secs(60),
    };

    fn at(us: i64) -> SystemTime {
        from_micros(EPOCH_US + us)
    }

    fn since_epoch(read: &CanRead) -> i64 {
        micros(read.at) - EPOCH_US
    }

    fn read(clock: &mut DeviceClock, read_us: i64, stamps: Vec<Stamp>) -> Vec<CanRead> {
        let received = stamps
            .into_iter()
            .map(|stamp| Received {
                frame: CanFrame::data(0, 0x100, false, false, false, vec![1]),
                direction: Direction::Rx,
                stamp,
                overflow: false,
            })
            .collect();
        clock.stamp(at(read_us), received)
    }

    fn counters(clock: &mut DeviceClock, read_us: i64, counters: &[u32]) -> Vec<i64> {
        let counters = counters.iter().map(|&c| Stamp::Counter(c)).collect();
        read(clock, read_us, counters)
            .iter()
            .map(since_epoch)
            .collect()
    }

    #[test]
    fn frames_in_one_read_are_spread_by_device_time_and_never_later_than_it() {
        let mut clock = DeviceClock::new(MAPPED);
        assert_eq!(counters(&mut clock, 10_000, &[5_000]), [10_000]);
        let reads = read(
            &mut clock,
            20_500,
            [8_000, 9_000, 15_000].map(Stamp::Counter).into(),
        );
        let stamps: Vec<i64> = reads.iter().map(since_epoch).collect();
        assert_eq!(stamps, [13_000, 14_000, 20_000]);
        assert_eq!(reads[2].device_us, Some(15_000));
    }

    #[test]
    fn a_stamp_is_never_later_than_its_read() {
        let mut clock = DeviceClock::new(MAPPED);
        let mut seed = 7u64;
        let mut read_us = 0;
        for i in 1..10_000i64 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let latency = (seed >> 33) as i64 % 20_000;
            let happened = i * 1_000;
            read_us = (happened + latency).max(read_us);
            let stamps = [happened as u32 - 500, happened as u32];
            for stamp in counters(&mut clock, read_us, &stamps) {
                assert!(stamp <= read_us, "{stamp} after its read at {read_us}");
            }
        }
    }

    #[test]
    fn the_counter_unwraps_past_two_to_the_thirty_two() {
        let mut clock = DeviceClock::new(MAPPED);
        let start = u32::MAX - 999;
        counters(&mut clock, 0, &[start]);
        let reads = read(&mut clock, 3_000, vec![Stamp::Counter(1_000)]);
        assert_eq!(reads[0].device_us, Some((1 << 32) + 1_000));
        assert_eq!(since_epoch(&reads[0]), 2_000);
    }

    #[test]
    fn a_jump_back_is_a_reset_and_re_anchors() {
        let mut clock = DeviceClock::new(MAPPED);
        counters(&mut clock, 0, &[50_000_000]);
        counters(&mut clock, 1_000_000, &[51_000_000]);
        let reads = read(&mut clock, 2_000_000, vec![Stamp::Counter(200)]);
        assert_eq!(reads[0].device_us, Some(200));
        assert_eq!(since_epoch(&reads[0]), 2_000_000);
        assert_eq!(counters(&mut clock, 2_100_000, &[100_000]), [2_099_800]);
    }

    /// The lower envelope over a 60 s window lags a crystal 100 ppm slow by at
    /// most 6 ms, plus the quickest read's latency.
    #[test]
    fn drift_of_a_hundred_ppm_over_an_hour_stays_within_one_windows_error() {
        const MIN_LATENCY: i64 = 500;
        const WINDOW_ERROR: i64 = 6_000;
        for ppm in [100i64, -100] {
            let mut clock = DeviceClock::new(MAPPED);
            let start = u32::MAX as i64 - 1_000_000_000;
            let mut seed = 1u64;
            for i in 0..360_000i64 {
                let happened = i * 10_000;
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let latency = if i % 5 == 0 {
                    MIN_LATENCY
                } else {
                    MIN_LATENCY + (seed >> 33) as i64 % 2_500
                };
                let device = start + happened + happened * ppm / 1_000_000;
                let [stamp] = counters(&mut clock, happened + latency, &[device as u32])[..] else {
                    unreachable!()
                };
                let error = stamp - happened;
                assert!(
                    error.abs() <= WINDOW_ERROR + MIN_LATENCY,
                    "{ppm} ppm, at {happened} µs: {error} µs out",
                );
            }
        }
    }

    #[test]
    fn the_wall_clock_stepping_back_never_takes_a_stamp_back() {
        for mapping in [MAPPED, TimeMapping::Host] {
            let mut clock = DeviceClock::new(mapping);
            let [first] = counters(&mut clock, 10_000_000, &[1_000])[..] else {
                unreachable!()
            };
            let [second] = counters(&mut clock, 5_000_000, &[11_000])[..] else {
                unreachable!()
            };
            assert_eq!(second, first);
            let unstamped = read(&mut clock, 4_000_000, vec![Stamp::Read]);
            assert_eq!(since_epoch(&unstamped[0]), first);
        }
    }

    #[test]
    fn a_counter_stuck_at_zero_is_stamped_as_host_after_a_second() {
        let mut clock = DeviceClock::new(MAPPED);
        for i in 0..=10 {
            counters(&mut clock, i * 100_000, &[0, 0]);
        }
        assert_eq!(counters(&mut clock, 1_100_000, &[0, 0]), [1_100_000; 2]);
        assert_eq!(counters(&mut clock, 1_150_000, &[0]), [1_150_000]);
        assert_eq!(
            counters(&mut clock, 1_200_000, &[1_000, 50_000]),
            [1_151_000, 1_200_000]
        );
        assert_eq!(counters(&mut clock, 1_300_000, &[150_000]), [1_300_000]);
    }

    #[test]
    fn host_mapping_stamps_the_read_and_keeps_the_counter() {
        let mut clock = DeviceClock::new(TimeMapping::Host);
        counters(&mut clock, 0, &[u32::MAX]);
        let reads = read(
            &mut clock,
            7_000,
            vec![Stamp::Counter(1_000), Stamp::Counter(3_000)],
        );
        assert!(reads.iter().all(|r| since_epoch(r) == 7_000));
        assert_eq!(reads[1].device_us, Some((1 << 32) + 3_000));
    }

    #[test]
    fn a_kernel_stamp_passes_through_in_whole_microseconds() {
        let mut clock = DeviceClock::new(MAPPED);
        counters(&mut clock, 10_000_000, &[1]);
        let kernel = at(1_000) + Duration::from_nanos(999);
        let reads = read(&mut clock, 10_000_001, vec![Stamp::Kernel(kernel)]);
        assert_eq!(since_epoch(&reads[0]), 1_000);
        assert_eq!(reads[0].device_us, None);
    }

    #[test]
    fn a_reset_keeps_the_floor() {
        let mut clock = DeviceClock::new(MAPPED);
        counters(&mut clock, 10_000_000, &[1]);
        clock.reset();
        assert_eq!(counters(&mut clock, 9_000_000, &[500]), [10_000_000]);
    }
}
