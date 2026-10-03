//! CAN bit timing: the kernel's `can_calc_bittiming`
//! (`drivers/net/can/dev/calc_bittiming.c`) and `can_sjw_set_default`
//! (`bittiming.c`), ported down to their unsigned arithmetic so they answer
//! what the kernel would for the same controller.
//!
//! `gs_usb::calculate_bittiming` is its own, older port, proved on hardware,
//! and is left as it is.

/// A controller's limits for one phase, as the kernel's `can_bittiming_const`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraints {
    pub tseg1_min: u32,
    pub tseg1_max: u32,
    pub tseg2_min: u32,
    pub tseg2_max: u32,
    pub sjw_max: u32,
    pub brp_min: u32,
    pub brp_max: u32,
    pub brp_inc: u32,
}

/// One phase's timing, in time quanta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub brp: u32,
    pub prop_seg: u32,
    pub phase_seg1: u32,
    pub phase_seg2: u32,
    pub sjw: u32,
}

impl Timing {
    /// `prop_seg + phase_seg1`.
    pub fn tseg1(self) -> u32 {
        self.prop_seg + self.phase_seg1
    }

    fn quanta(self) -> u32 {
        1 + self.tseg1() + self.phase_seg2
    }

    pub fn bitrate(self, clock_hz: u32) -> u32 {
        clock_hz / (self.brp * self.quanta())
    }

    /// Percent.
    pub fn sample_point(self) -> f32 {
        100.0 * (1 + self.tseg1()) as f32 / self.quanta() as f32
    }
}

/// CiA's recommended sample point for `bitrate`, in percent: what the kernel
/// uses when none is given.
pub fn cia_sample_point(bitrate: u32) -> f32 {
    cia_sample_point_permille(bitrate) as f32 / 10.0
}

fn cia_sample_point_permille(bitrate: u32) -> u32 {
    match bitrate {
        800_001.. => 750,
        500_001.. => 800,
        _ => 875,
    }
}

/// `None` where no timing lands within 5% of `bitrate`. `sample_point` is in
/// percent, CiA's when `None`.
pub fn calculate(
    clock_hz: u32,
    bitrate: u32,
    sample_point: Option<f32>,
    limits: &Constraints,
) -> Option<Timing> {
    if bitrate == 0 {
        return None;
    }
    let reference = match sample_point {
        None => cia_sample_point_permille(bitrate),
        Some(percent) if percent > 0.0 && percent < 100.0 => (percent * 10.0).round() as u32,
        Some(_) => return None,
    };
    let (clock, bitrate64) = (u64::from(clock_hz), u64::from(bitrate));
    let brp_inc = u64::from(limits.brp_inc.max(1));

    let mut best_bitrate_error = u64::MAX;
    let mut best_sample_point_error = u32::MAX;
    let (mut best_tseg, mut best_brp) = (0, 0);
    for tseg in ((limits.tseg1_min + limits.tseg2_min) * 2
        ..=(limits.tseg1_max + limits.tseg2_max) * 2 + 1)
        .rev()
    {
        let quanta = u64::from(1 + tseg / 2);
        let brp = (clock / (quanta * bitrate64) + u64::from(tseg % 2)) / brp_inc * brp_inc;
        if brp < u64::from(limits.brp_min) || brp > u64::from(limits.brp_max) {
            continue;
        }
        let bitrate_error = (clock / (brp * quanta)).abs_diff(bitrate64);
        if bitrate_error > best_bitrate_error {
            continue;
        }
        if bitrate_error < best_bitrate_error {
            best_sample_point_error = u32::MAX;
        }
        let sample_point_error = split_tseg(limits, reference, tseg / 2).map_or(u32::MAX, |s| s.2);
        if sample_point_error >= best_sample_point_error {
            continue;
        }
        best_sample_point_error = sample_point_error;
        best_bitrate_error = bitrate_error;
        best_tseg = tseg / 2;
        best_brp = brp as u32;
        if bitrate_error == 0 && sample_point_error == 0 {
            break;
        }
    }

    if best_bitrate_error != 0
        && (best_bitrate_error.saturating_mul(10_000) / bitrate64).max(1) > 500
    {
        return None;
    }
    let (tseg1, phase_seg2, _) = split_tseg(limits, reference, best_tseg)?;
    let prop_seg = tseg1 / 2;
    let phase_seg1 = tseg1 - prop_seg;
    let sjw = (phase_seg2 / 2).min(phase_seg1).max(1);
    if sjw > limits.sjw_max || sjw > phase_seg1 || sjw > phase_seg2 {
        return None;
    }
    Some(Timing {
        brp: best_brp,
        prop_seg,
        phase_seg1,
        phase_seg2,
        sjw,
    })
}

/// The kernel's `can_update_sample_point`: `(tseg1, tseg2, error)` for the
/// split nearest `reference` without passing it.
fn split_tseg(limits: &Constraints, reference: u32, tseg: u32) -> Option<(u32, u32, u32)> {
    let quanta = tseg + 1;
    let mut best: Option<(u32, u32, u32)> = None;
    for i in 0..=1 {
        let mut tseg2 = quanta
            .wrapping_sub(reference * quanta / 1000)
            .wrapping_sub(i)
            .clamp(limits.tseg2_min, limits.tseg2_max);
        let mut tseg1 = tseg.wrapping_sub(tseg2);
        if tseg1 > limits.tseg1_max {
            tseg1 = limits.tseg1_max;
            tseg2 = tseg.wrapping_sub(tseg1);
        }
        let sample_point = 1000u32.wrapping_mul(quanta.wrapping_sub(tseg2)) / quanta;
        let error = reference.abs_diff(sample_point);
        if sample_point <= reference && best.is_none_or(|(_, _, e)| error < e) {
            best = Some((tseg1, tseg2, error));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDE: Constraints = Constraints {
        tseg1_min: 1,
        tseg1_max: 256,
        tseg2_min: 1,
        tseg2_max: 128,
        sjw_max: 128,
        brp_min: 1,
        brp_max: 1024,
        brp_inc: 1,
    };

    #[test]
    fn cias_sample_point_steps_down_above_500k_and_800k() {
        assert_eq!(cia_sample_point(500_000), 87.5);
        assert_eq!(cia_sample_point(500_001), 80.0);
        assert_eq!(cia_sample_point(800_000), 80.0);
        assert_eq!(cia_sample_point(800_001), 75.0);
    }

    #[test]
    fn an_exact_rate_takes_the_most_quanta_at_the_smallest_prescaler() {
        let timing = calculate(80_000_000, 500_000, None, &WIDE).unwrap();
        assert_eq!(
            timing,
            Timing {
                brp: 1,
                prop_seg: 69,
                phase_seg1: 70,
                phase_seg2: 20,
                sjw: 10,
            }
        );
        assert_eq!(
            (timing.bitrate(80_000_000), timing.sample_point()),
            (500_000, 87.5)
        );
    }

    #[test]
    fn the_prescaler_moves_in_its_step() {
        let stepped = Constraints { brp_inc: 4, ..WIDE };
        let timing = calculate(80_000_000, 50_000, None, &stepped).unwrap();
        assert_eq!(timing.brp % 4, 0);
        assert_eq!(timing.bitrate(80_000_000), 50_000);
    }

    #[test]
    fn a_jump_width_past_the_controllers_is_none() {
        let narrow = Constraints { sjw_max: 4, ..WIDE };
        assert_eq!(calculate(80_000_000, 500_000, None, &narrow), None);
    }

    #[test]
    fn an_impossible_request_is_none() {
        assert_eq!(calculate(80_000_000, 0, None, &WIDE), None);
        assert_eq!(calculate(80_000_000, 500_000, Some(0.0), &WIDE), None);
        assert_eq!(calculate(80_000_000, 500_000, Some(100.0), &WIDE), None);
        assert_eq!(calculate(8_000_000, 3_000_000, None, &WIDE), None);
    }
}
