//! A register sweep's plan, for a device with no catalogue: which read is next,
//! and what the answers found.
//!
//! The caller does the I/O. It asks [`RegisterSweep::next_step`] for a read, issues
//! it, and hands back what the device did. A refused chunk is bisected down to
//! single addresses, after a few retries if the refusal was Busy (0x06) or
//! Acknowledge (0x05), which mean "later". A silent one is marked absent whole,
//! since a timeout says nothing about which address was at fault; a gateway's
//! 0x0A or 0x0B is silence relayed, so it counts as silence too.

use super::ranges::chunk_walk;
use super::{ExceptionCode, RangeError, RegisterType};

/// Limits on a [`RegisterSweep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepLimits {
    /// Refuse a sweep wider than this.
    pub max_registers: u32,
    /// Stop after this many reads, across every pass.
    pub max_requests: u32,
    /// Stop after this many silent reads in a row; 0 never stops.
    pub max_consecutive_silent: u32,
    /// Passes over the range; 0 counts as 1.
    pub passes: u32,
}

impl Default for SweepLimits {
    fn default() -> Self {
        Self {
            max_registers: 4096,
            max_requests: 2000,
            max_consecutive_silent: 3,
            passes: 1,
        }
    }
}

/// One read to issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadSpan {
    pub start: u16,
    pub count: u16,
}

/// What the device did with the last [`ReadSpan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// `values` is how many came back.
    Answered {
        values: u16,
    },
    Refused {
        code: ExceptionCode,
    },
    /// Nothing usable: a timeout or a transport error.
    Silent,
}

/// What the sweep wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepStep {
    Read(ReadSpan),
    /// Pass `n` (2-based) starts at the next [`RegisterSweep::next_step`]; the caller may pause first.
    Pass(u32),
    Done(SweepEnd),
}

/// Why a sweep stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SweepEnd {
    Complete,
    /// `swept` of `total` addresses were resolved in the pass it stopped in.
    OutOfRequests {
        swept: u32,
        total: u32,
    },
    /// That many silent reads in a row.
    Silent {
        consecutive: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SweepProgress {
    /// Addresses resolved in this pass; reaches `total` when the pass completes.
    pub swept: u32,
    pub total: u32,
    /// Values answered, summed over every pass.
    pub found: u32,
    pub requests: u32,
    /// 1-based.
    pub pass: u32,
    pub passes: u32,
}

/// A contiguous run of addresses, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressBlock {
    pub start: u16,
    pub end: u16,
}

impl AddressBlock {
    /// Up to 65 536, so not a `u16`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        u32::from(self.end) - u32::from(self.start) + 1
    }

    /// `addresses` sorted, deduplicated and joined into runs.
    pub fn runs(addresses: impl IntoIterator<Item = u16>) -> Vec<AddressBlock> {
        let mut addresses: Vec<u16> = addresses.into_iter().collect();
        addresses.sort_unstable();
        addresses.dedup();
        let mut runs: Vec<AddressBlock> = Vec::new();
        for a in addresses {
            match runs.last_mut() {
                Some(run) if a == run.end + 1 => run.end = a,
                _ => runs.push(AddressBlock { start: a, end: a }),
            }
        }
        runs
    }

    /// The addresses in `start..=end` outside `blocks`, which must be sorted,
    /// disjoint and within `start..=end`.
    pub fn gaps(blocks: &[AddressBlock], start: u16, end: u16) -> Vec<AddressBlock> {
        let mut gaps = Vec::new();
        let mut push = |from: u16, to: u16| {
            if from <= to {
                gaps.push(AddressBlock {
                    start: from,
                    end: to,
                });
            }
        };
        let mut cursor = start;
        for b in blocks {
            if let Some(before) = b.start.checked_sub(1) {
                push(cursor, before);
            }
            match b.end.checked_add(1) {
                Some(next) => cursor = next,
                None => return gaps,
            }
        }
        push(cursor, end);
        gaps
    }
}

/// How many times [`RegisterSweep`] re-offers a span refused Busy or
/// Acknowledge before bisecting it.
pub const DEFAULT_BUSY_RETRIES: u32 = 3;

fn is_busy(outcome: ReadOutcome) -> bool {
    matches!(outcome, ReadOutcome::Refused { code } if matches!(code.code(), 0x05 | 0x06))
}

fn relayed_silence_as_silent(outcome: ReadOutcome) -> ReadOutcome {
    match outcome {
        ReadOutcome::Refused { code } if matches!(code.code(), 0x0A | 0x0B) => ReadOutcome::Silent,
        other => other,
    }
}

/// A register sweep's plan: which read is next, and what the answers found.
///
/// A busy span is re-offered at once; waiting between tries is the caller's job.
#[derive(Debug, Clone)]
pub struct RegisterSweep {
    start: u16,
    end: u16,
    chunk: u16,
    limits: SweepLimits,
    stack: Vec<ReadSpan>,
    outstanding: Option<ReadSpan>,
    pass_pending: bool,
    ended: Option<SweepEnd>,
    pass: u32,
    swept: u32,
    silent_run: u32,
    busy_retries: u32,
    busy_run: u32,
    requests: u32,
    found: u32,
    found_in_pass_1: Vec<u16>,
}

impl RegisterSweep {
    /// `chunk_size` is clamped to `register_type.max_per_read()`.
    pub fn new(
        register_type: RegisterType,
        start: u16,
        end: u16,
        chunk_size: u16,
        limits: SweepLimits,
    ) -> Result<Self, RangeError> {
        if start > end {
            return Err(RangeError::Inverted { start, end });
        }
        if chunk_size == 0 {
            return Err(RangeError::ZeroBlockSize);
        }
        let total = u32::from(end - start) + 1;
        if total > limits.max_registers {
            return Err(RangeError::TooManyRegisters {
                total,
                limit: limits.max_registers,
            });
        }
        let mut sweep = Self {
            start,
            end,
            chunk: chunk_size.min(register_type.max_per_read()),
            limits: SweepLimits {
                passes: limits.passes.max(1),
                ..limits
            },
            stack: Vec::new(),
            outstanding: None,
            pass_pending: false,
            ended: None,
            pass: 0,
            swept: 0,
            silent_run: 0,
            busy_retries: DEFAULT_BUSY_RETRIES,
            busy_run: 0,
            requests: 0,
            found: 0,
            found_in_pass_1: Vec::new(),
        };
        sweep.start_pass();
        Ok(sweep)
    }

    /// Re-offer a span refused Busy or Acknowledge up to `retries` times before
    /// bisecting it, in place of [`DEFAULT_BUSY_RETRIES`].
    pub fn with_busy_retries(mut self, retries: u32) -> Self {
        self.busy_retries = retries;
        self
    }

    /// The same [`SweepStep::Read`] until it is reported.
    pub fn next_step(&mut self) -> SweepStep {
        if let Some(end) = self.ended {
            return SweepStep::Done(end);
        }
        if let Some(span) = self.outstanding {
            return SweepStep::Read(span);
        }
        if self.pass_pending {
            self.pass_pending = false;
            self.start_pass();
        }
        let Some(&span) = self.stack.last() else {
            if self.pass < self.limits.passes {
                self.pass_pending = true;
                return SweepStep::Pass(self.pass + 1);
            }
            return self.end(SweepEnd::Complete);
        };
        if self.requests >= self.limits.max_requests {
            return self.end(SweepEnd::OutOfRequests {
                swept: self.swept,
                total: self.total(),
            });
        }
        self.stack.pop();
        self.outstanding = Some(span);
        SweepStep::Read(span)
    }

    /// Panics without an outstanding [`SweepStep::Read`].
    pub fn report(&mut self, outcome: ReadOutcome) {
        let span = self
            .outstanding
            .take()
            .expect("report without an outstanding read");
        self.requests += 1;
        if is_busy(outcome) && self.busy_run < self.busy_retries {
            self.busy_run += 1;
            self.silent_run = 0;
            self.stack.push(span);
            return;
        }
        self.busy_run = 0;
        match relayed_silence_as_silent(outcome) {
            ReadOutcome::Silent => {
                self.silent_run += 1;
                let limit = self.limits.max_consecutive_silent;
                if limit > 0 && self.silent_run >= limit {
                    self.end(SweepEnd::Silent {
                        consecutive: self.silent_run,
                    });
                    return;
                }
            }
            ReadOutcome::Refused { .. } => {
                self.silent_run = 0;
                if span.count > 1 {
                    let half = span.count / 2;
                    self.stack.push(ReadSpan {
                        start: span.start + half,
                        count: span.count - half,
                    });
                    self.stack.push(ReadSpan {
                        start: span.start,
                        count: half,
                    });
                    return;
                }
            }
            ReadOutcome::Answered { values } => {
                self.silent_run = 0;
                self.found += u32::from(values);
                if self.pass == 1 {
                    self.found_in_pass_1
                        .extend((0..values).map(|i| span.start.wrapping_add(i)));
                }
            }
        }
        self.swept += u32::from(span.count);
    }

    pub fn progress(&self) -> SweepProgress {
        SweepProgress {
            swept: self.swept,
            total: self.total(),
            found: self.found,
            requests: self.requests,
            pass: self.pass,
            passes: self.limits.passes,
        }
    }

    /// The first pass's answers as runs, ascending.
    pub fn blocks(&self) -> Vec<AddressBlock> {
        AddressBlock::runs(self.found_in_pass_1.iter().copied())
    }

    /// The addresses in `start..=end` not in [`blocks`](Self::blocks).
    pub fn gaps(&self) -> Vec<AddressBlock> {
        AddressBlock::gaps(&self.blocks(), self.start, self.end)
    }

    fn total(&self) -> u32 {
        u32::from(self.end - self.start) + 1
    }

    fn start_pass(&mut self) {
        self.pass += 1;
        self.swept = 0;
        self.silent_run = 0;
        self.stack = chunk_walk(self.start, self.end, self.chunk)
            .map(|(start, count)| ReadSpan { start, count })
            .collect();
        self.stack.reverse();
    }

    fn end(&mut self, end: SweepEnd) -> SweepStep {
        self.ended = Some(end);
        SweepStep::Done(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sweep(start: u16, end: u16, chunk: u16, limits: SweepLimits) -> RegisterSweep {
        RegisterSweep::new(RegisterType::Holding, start, end, chunk, limits).unwrap()
    }

    fn refused(code: u8) -> ReadOutcome {
        ReadOutcome::Refused {
            code: ExceptionCode::from_code(code),
        }
    }

    fn answered(span: ReadSpan) -> ReadOutcome {
        ReadOutcome::Answered { values: span.count }
    }

    /// Drives `sweep` to its end, answering each read with `device`; returns
    /// the reads issued and how it ended.
    fn run(
        sweep: &mut RegisterSweep,
        mut device: impl FnMut(ReadSpan) -> ReadOutcome,
    ) -> (Vec<(u16, u16)>, SweepEnd) {
        let mut reads = Vec::new();
        loop {
            match sweep.next_step() {
                SweepStep::Read(span) => {
                    reads.push((span.start, span.count));
                    sweep.report(device(span));
                }
                SweepStep::Pass(_) => {}
                SweepStep::Done(end) => return (reads, end),
            }
        }
    }

    fn spans(blocks: &[AddressBlock]) -> Vec<(u16, u16)> {
        blocks.iter().map(|b| (b.start, b.end)).collect()
    }

    fn refusing(address: u16, code: u8) -> impl FnMut(ReadSpan) -> ReadOutcome {
        move |span| {
            if address
                .checked_sub(span.start)
                .is_some_and(|i| i < span.count)
            {
                refused(code)
            } else {
                answered(span)
            }
        }
    }

    #[test]
    fn contiguous_addresses_collapse_into_one_block() {
        let blocks = AddressBlock::runs([0, 1, 2, 3]);
        assert_eq!(spans(&blocks), [(0, 3)]);
        assert_eq!(blocks[0].len(), 4);
    }

    #[test]
    fn a_hole_splits_the_run() {
        assert_eq!(
            spans(&AddressBlock::runs([0, 1, 5, 6, 7])),
            [(0, 1), (5, 7)]
        );
    }

    #[test]
    fn a_wide_sparse_sweep_still_summarises_small() {
        // 0..24 and 40..62 present, as the Megatec's telemetry block looked.
        assert_eq!(AddressBlock::runs((0..=24).chain(40..=62)).len(), 2);
    }

    #[test]
    fn duplicate_addresses_from_repeat_passes_do_not_inflate_blocks() {
        let blocks = AddressBlock::runs([5, 5, 6, 6, 7]);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].len(), 3);
    }

    #[test]
    fn gaps_are_the_inverse_of_the_found_set() {
        let blocks = AddressBlock::runs([0, 1, 2, 6, 7]);
        assert_eq!(spans(&AddressBlock::gaps(&blocks, 0, 7)), [(3, 5)]);
    }

    #[test]
    fn nothing_found_is_one_gap_spanning_the_range() {
        let gaps = AddressBlock::gaps(&[], 10, 19);
        assert_eq!(spans(&gaps), [(10, 19)]);
        assert_eq!(gaps[0].len(), 10);
    }

    #[test]
    fn gaps_at_both_ends_are_reported() {
        let blocks = AddressBlock::runs([4, 5]);
        assert_eq!(spans(&AddressBlock::gaps(&blocks, 0, 9)), [(0, 3), (6, 9)]);
    }

    #[test]
    fn a_fully_covered_range_has_no_gaps() {
        assert!(AddressBlock::gaps(&AddressBlock::runs([0, 1, 2]), 0, 2).is_empty());
    }

    #[test]
    fn a_block_ending_at_the_top_of_the_address_space_terminates() {
        let blocks = AddressBlock::runs([65534, 65535]);
        assert_eq!(
            spans(&AddressBlock::gaps(&blocks, 65530, 65535)),
            [(65530, 65533)]
        );
    }

    #[test]
    fn the_whole_address_space_is_one_block_of_65536() {
        assert_eq!(
            AddressBlock {
                start: 0,
                end: 65535
            }
            .len(),
            65536
        );
    }

    #[test]
    fn a_bad_sweep_is_refused_with_a_range_error() {
        let new = |start, end, chunk| {
            RegisterSweep::new(
                RegisterType::Holding,
                start,
                end,
                chunk,
                SweepLimits::default(),
            )
        };
        assert_eq!(
            new(9, 0, 8).unwrap_err(),
            RangeError::Inverted { start: 9, end: 0 }
        );
        assert_eq!(new(0, 9, 0).unwrap_err(), RangeError::ZeroBlockSize);
        assert_eq!(
            new(0, 9999, 8).unwrap_err(),
            RangeError::TooManyRegisters {
                total: 10000,
                limit: 4096
            }
        );
    }

    // The desktop's `a_device_that_never_replies_ends_the_sweep_at_the_timeout_budget`,
    // replayed against the planner with the same config and fake device.
    #[test]
    fn a_device_that_never_replies_ends_the_sweep_at_the_timeout_budget() {
        let limits = SweepLimits {
            max_consecutive_silent: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 99, 8, limits);
        let (reads, end) = run(&mut s, |_| ReadOutcome::Silent);
        assert_eq!(reads, [(0, 8), (8, 8)]);
        assert_eq!(end, SweepEnd::Silent { consecutive: 2 });
        assert_eq!(s.progress().requests, 2);
        assert_eq!(s.progress().found, 0);
    }

    // The desktop's `an_exception_is_bisected_down_to_the_missing_register`, likewise.
    #[test]
    fn an_exception_is_bisected_down_to_the_missing_register() {
        let limits = SweepLimits {
            max_consecutive_silent: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 7, 8, limits);
        let (reads, end) = run(&mut s, refusing(3, 0x02));
        assert_eq!(end, SweepEnd::Complete);
        assert_eq!(spans(&s.blocks()), [(0, 2), (4, 7)]);
        assert_eq!(spans(&s.gaps()), [(3, 3)]);
        assert_eq!(
            reads,
            [(0, 8), (0, 4), (0, 2), (2, 2), (2, 1), (3, 1), (4, 4)]
        );
    }

    #[test]
    fn an_odd_chunk_splits_smaller_half_below() {
        let mut s = sweep(0, 4, 5, SweepLimits::default());
        let (reads, _) = run(&mut s, refusing(4, 0x02));
        assert_eq!(&reads[..3], [(0, 5), (0, 2), (2, 3)]);
    }

    #[test]
    fn a_chunk_clamps_to_the_banks_per_read_limit() {
        let mut s = sweep(0, 499, 500, SweepLimits::default());
        assert_eq!(
            run(&mut s, answered).0,
            [(0, 125), (125, 125), (250, 125), (375, 125)]
        );

        let mut s =
            RegisterSweep::new(RegisterType::Coil, 0, 2999, 3000, SweepLimits::default()).unwrap();
        assert_eq!(run(&mut s, answered).0, [(0, 2000), (2000, 1000)]);
    }

    #[test]
    fn silence_marks_the_whole_chunk_absent_without_splitting_it() {
        let mut s = sweep(0, 15, 8, SweepLimits::default());
        let (reads, end) = run(&mut s, |span| {
            if span.start == 0 {
                ReadOutcome::Silent
            } else {
                answered(span)
            }
        });
        assert_eq!(reads, [(0, 8), (8, 8)]);
        assert_eq!(end, SweepEnd::Complete);
        assert_eq!(spans(&s.gaps()), [(0, 7)]);
        assert_eq!(s.progress().swept, 16);
    }

    #[test]
    fn a_refusal_resets_the_silence_count() {
        let limits = SweepLimits {
            max_consecutive_silent: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 3, 1, limits);
        let mut replies = [
            ReadOutcome::Silent,
            refused(0x02),
            ReadOutcome::Silent,
            ReadOutcome::Silent,
        ]
        .into_iter();
        let (reads, end) = run(&mut s, |_| replies.next().unwrap());
        assert_eq!(reads.len(), 4);
        assert_eq!(end, SweepEnd::Silent { consecutive: 2 });
    }

    #[test]
    fn no_silence_limit_never_stops() {
        let limits = SweepLimits {
            max_consecutive_silent: 0,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 99, 1, limits);
        let (reads, end) = run(&mut s, |_| ReadOutcome::Silent);
        assert_eq!(reads.len(), 100);
        assert_eq!(end, SweepEnd::Complete);
    }

    #[test]
    fn a_gateway_that_cannot_reach_its_target_counts_as_silence() {
        for code in [0x0A, 0x0B] {
            let limits = SweepLimits {
                max_consecutive_silent: 2,
                ..SweepLimits::default()
            };
            let mut s = sweep(0, 15, 8, limits);
            let (reads, end) = run(&mut s, |_| refused(code));
            assert_eq!(reads, [(0, 8), (8, 8)], "code {code:#04x}");
            assert_eq!(end, SweepEnd::Silent { consecutive: 2 });
        }
    }

    #[test]
    fn a_gateway_silence_marks_one_chunk_absent_in_one_read() {
        for code in [0x0A, 0x0B] {
            let mut s = sweep(0, 15, 8, SweepLimits::default());
            let (reads, end) = run(&mut s, refusing(3, code));
            assert_eq!(reads, [(0, 8), (8, 8)], "code {code:#04x}");
            assert_eq!(end, SweepEnd::Complete);
            assert_eq!(spans(&s.blocks()), [(8, 15)]);
            assert_eq!(spans(&s.gaps()), [(0, 7)]);
        }
    }

    #[test]
    fn every_other_exception_code_bisects() {
        for code in (0..=u8::MAX).filter(|c| !matches!(c, 0x05 | 0x06 | 0x0A | 0x0B)) {
            let mut s = sweep(0, 7, 8, SweepLimits::default());
            let (reads, _) = run(&mut s, refusing(3, code));
            assert_eq!(reads.len(), 7, "code {code:#04x}");
            assert_eq!(spans(&s.gaps()), [(3, 3)], "code {code:#04x}");
        }
    }

    #[test]
    fn a_busy_device_is_bisected_not_treated_as_silent() {
        let limits = SweepLimits {
            max_consecutive_silent: 1,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 7, 8, limits);
        let (_, end) = run(&mut s, refusing(3, 0x06));
        assert_eq!(end, SweepEnd::Complete);
        assert_eq!(spans(&s.gaps()), [(3, 3)]);
    }

    #[test]
    fn a_busy_or_acknowledging_span_is_offered_again_before_it_is_bisected() {
        for code in [0x05, 0x06] {
            let mut s = sweep(0, 7, 8, SweepLimits::default());
            let mut replies = [refused(code), refused(code)].into_iter();
            let (reads, end) = run(&mut s, |span| replies.next().unwrap_or(answered(span)));
            assert_eq!(reads, [(0, 8), (0, 8), (0, 8)], "code {code:#04x}");
            assert_eq!(end, SweepEnd::Complete);
            assert_eq!(spans(&s.blocks()), [(0, 7)]);
        }
    }

    #[test]
    fn a_span_that_stays_busy_is_bisected_once_its_retries_run_out() {
        let mut s = sweep(0, 1, 2, SweepLimits::default()).with_busy_retries(1);
        let (reads, _) = run(&mut s, refusing(1, 0x06));
        assert_eq!(reads, [(0, 2), (0, 2), (0, 1), (1, 1), (1, 1)]);
        assert_eq!(spans(&s.gaps()), [(1, 1)]);
    }

    #[test]
    fn a_busy_span_is_read_at_most_once_plus_the_default_retries() {
        let mut s = sweep(0, 0, 1, SweepLimits::default());
        let (reads, _) = run(&mut s, |_| refused(0x06));
        assert_eq!(reads.len() as u32, 1 + DEFAULT_BUSY_RETRIES);
    }

    #[test]
    fn no_busy_retries_bisects_at_once() {
        let mut s = sweep(0, 7, 8, SweepLimits::default()).with_busy_retries(0);
        let (reads, _) = run(&mut s, refusing(3, 0x06));
        assert_eq!(reads.len(), 7);
    }

    #[test]
    fn busy_retries_spend_the_request_budget() {
        let limits = SweepLimits {
            max_requests: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 7, 8, limits);
        let (reads, end) = run(&mut s, |_| refused(0x06));
        assert_eq!(reads, [(0, 8), (0, 8)]);
        assert_eq!(end, SweepEnd::OutOfRequests { swept: 0, total: 8 });
    }

    #[test]
    fn a_gateway_code_built_as_other_still_counts_as_silence() {
        let mut s = sweep(0, 7, 8, SweepLimits::default());
        let (reads, _) = run(&mut s, |_| ReadOutcome::Refused {
            code: ExceptionCode::Other(0x0B),
        });
        assert_eq!(reads, [(0, 8)]);
    }

    #[test]
    fn the_budget_counts_across_passes() {
        let limits = SweepLimits {
            max_requests: 3,
            passes: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 15, 8, limits);
        let (reads, end) = run(&mut s, answered);
        assert_eq!(reads, [(0, 8), (8, 8), (0, 8)]);
        assert_eq!(
            end,
            SweepEnd::OutOfRequests {
                swept: 8,
                total: 16
            }
        );
    }

    #[test]
    fn no_budget_issues_nothing() {
        let limits = SweepLimits {
            max_requests: 0,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 15, 8, limits);
        let (reads, end) = run(&mut s, answered);
        assert!(reads.is_empty());
        assert_eq!(
            end,
            SweepEnd::OutOfRequests {
                swept: 0,
                total: 16
            }
        );
    }

    #[test]
    fn a_second_pass_rereads_the_same_spans_and_blocks_stay_pass_ones() {
        let limits = SweepLimits {
            passes: 2,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 15, 8, limits);
        let mut steps = Vec::new();
        let mut pass = 0;
        loop {
            match s.next_step() {
                SweepStep::Read(span) => {
                    steps.push(SweepStep::Read(span));
                    // Pass 2 finds an extra address that pass 1 did not.
                    let values = if pass == 0 { 4 } else { span.count };
                    s.report(ReadOutcome::Answered { values });
                }
                SweepStep::Pass(n) => {
                    assert_eq!(s.progress().swept, 16);
                    steps.push(SweepStep::Pass(n));
                    pass += 1;
                }
                SweepStep::Done(end) => {
                    assert_eq!(end, SweepEnd::Complete);
                    break;
                }
            }
        }
        let read = |start, count| SweepStep::Read(ReadSpan { start, count });
        assert_eq!(
            steps,
            [
                read(0, 8),
                read(8, 8),
                SweepStep::Pass(2),
                read(0, 8),
                read(8, 8)
            ]
        );
        let progress = s.progress();
        assert_eq!((progress.pass, progress.passes), (2, 2));
        assert_eq!(progress.found, 8 + 16);
        assert_eq!(progress.requests, 4);
        assert_eq!(spans(&s.blocks()), [(0, 3), (8, 11)]);
    }

    #[test]
    fn a_pass_with_bisections_still_ends_on_the_total() {
        let mut s = sweep(0, 15, 8, SweepLimits::default());
        let (reads, _) = run(&mut s, refusing(3, 0x02));
        assert_eq!(reads.len(), 8);
        assert_eq!(s.progress().swept, 16);
        assert_eq!(s.progress().total, 16);
    }

    #[test]
    fn a_short_answer_leaves_the_rest_a_gap() {
        let mut s = sweep(0, 7, 8, SweepLimits::default());
        run(&mut s, |_| ReadOutcome::Answered { values: 5 });
        assert_eq!(spans(&s.blocks()), [(0, 4)]);
        assert_eq!(spans(&s.gaps()), [(5, 7)]);
    }

    #[test]
    fn next_repeats_an_unreported_read() {
        let mut s = sweep(0, 15, 8, SweepLimits::default());
        assert_eq!(s.next_step(), s.next_step());
        assert_eq!(s.progress().requests, 0);
    }

    #[test]
    #[should_panic(expected = "outstanding")]
    fn a_report_without_a_read_panics() {
        sweep(0, 15, 8, SweepLimits::default()).report(ReadOutcome::Silent);
    }

    #[test]
    fn the_whole_address_space_sweeps_without_overflowing() {
        let limits = SweepLimits {
            max_registers: 65536,
            max_requests: u32::MAX,
            ..SweepLimits::default()
        };
        let mut s = sweep(0, 65535, 125, limits);
        let (reads, end) = run(&mut s, answered);
        assert_eq!(end, SweepEnd::Complete);
        assert_eq!(reads.len(), 525);
        assert_eq!(reads.last(), Some(&(65500, 36)));
        assert_eq!(spans(&s.blocks()), [(0, 65535)]);
        assert!(s.gaps().is_empty());
        assert_eq!(s.progress().swept, 65536);
    }

    #[test]
    fn a_refusal_at_the_top_of_the_address_space_bisects_to_it() {
        let limits = SweepLimits {
            max_registers: 65536,
            ..SweepLimits::default()
        };
        let mut s = sweep(65528, 65535, 8, limits);
        run(&mut s, refusing(65535, 0x02));
        assert_eq!(spans(&s.blocks()), [(65528, 65534)]);
        assert_eq!(spans(&s.gaps()), [(65535, 65535)]);
    }
}
