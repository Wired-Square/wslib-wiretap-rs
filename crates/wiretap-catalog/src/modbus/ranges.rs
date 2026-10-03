//! Poll items from address ranges, for a device with no catalogue yet.
//!
//! Each range is chunked to the smaller of the block size and the bank's
//! per-read limit. Ranges are never merged.

use std::time::Duration;

use super::{PollItem, RegisterType, MAX_REGISTERS_PER_READ};

/// One contiguous span of addresses to poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRange {
    pub register_type: RegisterType,
    /// Protocol-level (0-based) first address.
    pub start: u16,
    /// Last address, inclusive.
    pub end: u16,
    /// Overrides [`RangeSpec::interval`].
    pub interval: Option<Duration>,
    /// Overrides [`RangeSpec::device_address`].
    pub device_address: Option<u8>,
}

/// A catalogue-free poll plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeSpec {
    pub ranges: Vec<RegisterRange>,
    pub device_address: u8,
    pub interval: Duration,
    /// Addresses per request, clamped to the bank's per-read limit.
    pub block_size: u16,
    pub max_registers: u32,
}

impl Default for RangeSpec {
    fn default() -> Self {
        Self {
            ranges: Vec::new(),
            device_address: 1,
            interval: Duration::from_secs(1),
            block_size: MAX_REGISTERS_PER_READ,
            max_registers: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    #[error("no register ranges given")]
    NoRanges,
    #[error("block size must be at least 1")]
    ZeroBlockSize,
    #[error("poll interval must be greater than zero")]
    ZeroInterval,
    #[error("range {start}..{end} is inverted: start must be <= end")]
    Inverted { start: u16, end: u16 },
    #[error("range spec covers {total} registers, over the max_registers limit of {limit}")]
    TooManyRegisters { total: u32, limit: u32 },
}

/// Split each range into items no larger than one request, each tagged `tag`.
pub fn chunk_ranges<T: Clone>(spec: &RangeSpec, tag: T) -> Result<Vec<PollItem<T>>, RangeError> {
    if spec.ranges.is_empty() {
        return Err(RangeError::NoRanges);
    }
    if spec.block_size == 0 {
        return Err(RangeError::ZeroBlockSize);
    }
    if spec.interval.is_zero()
        || spec
            .ranges
            .iter()
            .any(|r| r.interval == Some(Duration::ZERO))
    {
        return Err(RangeError::ZeroInterval);
    }

    let mut total: u32 = 0;
    for r in &spec.ranges {
        if r.start > r.end {
            return Err(RangeError::Inverted {
                start: r.start,
                end: r.end,
            });
        }
        total = total.saturating_add(u32::from(r.end - r.start) + 1);
    }
    if total > spec.max_registers {
        return Err(RangeError::TooManyRegisters {
            total,
            limit: spec.max_registers,
        });
    }

    let mut items = Vec::new();
    for r in &spec.ranges {
        let block = spec.block_size.min(r.register_type.max_per_read());
        items.extend(
            chunk_walk(r.start, r.end, block).map(|(start, count)| PollItem {
                register_type: r.register_type,
                start,
                count,
                interval: r.interval.unwrap_or(spec.interval),
                device_address: r.device_address.unwrap_or(spec.device_address),
                tag: tag.clone(),
            }),
        );
    }
    Ok(items)
}

/// `(start, count)` spans of at most `block` covering `start..=end`, ascending.
/// Needs `start <= end` and `block >= 1`.
pub(super) fn chunk_walk(start: u16, end: u16, block: u16) -> impl Iterator<Item = (u16, u16)> {
    let mut next = Some(start);
    std::iter::from_fn(move || {
        let pos = next?;
        // Not `end - pos + 1`, which is 65 536 for the whole address space.
        let count = (end - pos).min(block - 1) + 1;
        next = pos.checked_add(count).filter(|&n| n <= end);
        Some((pos, count))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(ranges: Vec<RegisterRange>) -> RangeSpec {
        RangeSpec {
            ranges,
            ..Default::default()
        }
    }

    fn range(register_type: RegisterType, start: u16, end: u16) -> RegisterRange {
        RegisterRange {
            register_type,
            start,
            end,
            interval: None,
            device_address: None,
        }
    }

    fn spans(s: &RangeSpec) -> Vec<(u16, u16)> {
        chunk_ranges(s, ())
            .unwrap()
            .iter()
            .map(|p| (p.start, p.count))
            .collect()
    }

    #[test]
    fn splits_a_holding_range_into_125_register_blocks() {
        assert_eq!(
            spans(&spec(vec![range(RegisterType::Holding, 0, 999)])),
            [
                (0, 125),
                (125, 125),
                (250, 125),
                (375, 125),
                (500, 125),
                (625, 125),
                (750, 125),
                (875, 125),
            ]
        );
    }

    #[test]
    fn a_partial_final_block_keeps_only_the_remaining_registers() {
        assert_eq!(
            spans(&spec(vec![range(RegisterType::Holding, 0, 159)])),
            [(0, 125), (125, 35)]
        );
    }

    #[test]
    fn coils_use_the_2000_per_read_ceiling() {
        let mut s = spec(vec![range(RegisterType::Coil, 0, 2999)]);
        s.block_size = 2000;
        assert_eq!(spans(&s), [(0, 2000), (2000, 1000)]);
    }

    #[test]
    fn an_oversized_block_clamps_to_the_protocol_maximum() {
        let mut s = spec(vec![range(RegisterType::Holding, 0, 499)]);
        s.block_size = 500;
        assert_eq!(spans(&s), [(0, 125), (125, 125), (250, 125), (375, 125)]);
    }

    #[test]
    fn ranges_are_never_merged() {
        let s = spec(vec![
            range(RegisterType::Holding, 0, 9),
            range(RegisterType::Holding, 10, 19),
        ]);
        assert_eq!(spans(&s), [(0, 10), (10, 10)]);
    }

    #[test]
    fn every_item_carries_the_callers_tag() {
        let items =
            chunk_ranges(&spec(vec![range(RegisterType::Holding, 0, 199)]), "sweep").unwrap();
        assert!(items.iter().all(|p| p.tag == "sweep"));
    }

    #[test]
    fn a_range_may_override_the_interval_and_slave() {
        let mut s = spec(vec![RegisterRange {
            interval: Some(Duration::from_millis(250)),
            device_address: Some(7),
            ..range(RegisterType::Input, 0, 3)
        }]);
        s.interval = Duration::from_secs(5);
        s.device_address = 1;
        let items = chunk_ranges(&s, ()).unwrap();
        assert_eq!(items[0].interval, Duration::from_millis(250));
        assert_eq!(items[0].device_address, 7);
    }

    #[test]
    fn an_inverted_range_is_rejected() {
        let err = chunk_ranges(&spec(vec![range(RegisterType::Holding, 100, 50)]), ());
        assert_eq!(
            err,
            Err(RangeError::Inverted {
                start: 100,
                end: 50
            })
        );
    }

    #[test]
    fn a_range_over_the_register_cap_is_rejected() {
        let err = chunk_ranges(&spec(vec![range(RegisterType::Holding, 0, 9999)]), ());
        assert_eq!(
            err,
            Err(RangeError::TooManyRegisters {
                total: 10000,
                limit: 4096
            })
        );
    }

    #[test]
    fn a_range_ending_at_the_top_of_the_address_space_terminates() {
        let mut s = spec(vec![range(RegisterType::Holding, 65400, 65535)]);
        s.max_registers = 65535;
        assert_eq!(spans(&s), [(65400, 125), (65525, 11)]);
    }

    #[test]
    fn the_whole_address_space_chunks_without_overflowing() {
        let mut s = spec(vec![range(RegisterType::Holding, 0, 65535)]);
        s.max_registers = 65536;
        let spans = spans(&s);
        assert_eq!(spans.len(), 525);
        assert!(spans.iter().all(|&(_, count)| count > 0));
        assert_eq!(spans.iter().map(|&(_, c)| u32::from(c)).sum::<u32>(), 65536);
        assert_eq!(spans.last(), Some(&(65500, 36)));
    }

    #[test]
    fn a_single_address_at_the_top_of_the_address_space_is_one_item() {
        let s = spec(vec![range(RegisterType::Coil, 65535, 65535)]);
        assert_eq!(spans(&s), [(65535, 1)]);
    }

    #[test]
    fn many_single_register_blocks_are_not_capped() {
        let mut s = spec(vec![range(RegisterType::Holding, 0, 8191)]);
        s.max_registers = 65535;
        s.block_size = 1;
        assert_eq!(chunk_ranges(&s, ()).unwrap().len(), 8192);
    }

    #[test]
    fn an_empty_spec_is_rejected() {
        assert_eq!(chunk_ranges(&spec(vec![]), ()), Err(RangeError::NoRanges));
    }

    #[test]
    fn a_zero_block_size_is_rejected() {
        let mut s = spec(vec![range(RegisterType::Holding, 0, 9)]);
        s.block_size = 0;
        assert_eq!(chunk_ranges(&s, ()), Err(RangeError::ZeroBlockSize));
    }

    #[test]
    fn a_zero_interval_is_rejected() {
        let mut s = spec(vec![range(RegisterType::Holding, 0, 9)]);
        s.interval = Duration::ZERO;
        assert_eq!(chunk_ranges(&s, ()), Err(RangeError::ZeroInterval));

        let mut s = spec(vec![range(RegisterType::Holding, 0, 9)]);
        s.ranges[0].interval = Some(Duration::ZERO);
        assert_eq!(chunk_ranges(&s, ()), Err(RangeError::ZeroInterval));
    }
}
