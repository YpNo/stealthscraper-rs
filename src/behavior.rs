#![cfg(feature = "browser")]
//! Human-interaction emulation: Bézier-curve mouse paths and human-like
//! keystroke timing, used to make CDP-driven input look organic.

use rand::RngExt;
use std::time::Duration;

/// Mean inter-keystroke delay (ms) for an unhurried human typist.
const KEYSTROKE_MEAN_MS: f64 = 50.0;
/// Standard deviation (ms) around [`KEYSTROKE_MEAN_MS`].
const KEYSTROKE_STDDEV_MS: f64 = 15.0;
/// Floor for a sampled delay: nobody sustains sub-20ms keystrokes.
const KEYSTROKE_MIN_MS: u64 = 20;
/// Probability that a keystroke is preceded by a "thinking" pause.
const LONG_PAUSE_PROBABILITY: f64 = 0.05;
/// Additional delay (ms) contributed by a thinking pause.
const LONG_PAUSE_MIN_MS: u64 = 150;
/// Exclusive upper bound for the thinking pause (ms).
const LONG_PAUSE_MAX_MS: u64 = 400;

/// Draws one sample from a normal distribution via the Box–Muller transform.
///
/// We need exactly one Gaussian sample per keystroke, which is a few lines of
/// arithmetic — not worth a dependency, so this replaces `rand_distr`.
fn sample_normal<R: RngExt + ?Sized>(rng: &mut R, mean: f64, std_dev: f64) -> f64 {
    // `ln(0)` is -inf, so map the uniform draw onto (0, 1] rather than [0, 1).
    let u1: f64 = 1.0 - rng.random::<f64>();
    let u2: f64 = rng.random::<f64>();
    let z0 = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
    mean + std_dev * z0
}

/// Represents a 2D coordinate for mouse movements and positions.
#[derive(Debug, Clone)]
pub struct Point {
    /// The X coordinate.
    pub x: f64,
    /// The Y coordinate.
    pub y: f64,
}

/// Generates a human-like mouse path using Bezier curves and varying speed.
pub fn generate_mouse_path(start: Point, end: Point, num_points: usize) -> Vec<Point> {
    let mut rng = rand::rng();

    // Generate two control points for the cubic Bezier curve that drift away from the straight line.
    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let dist = (dx * dx + dy * dy).sqrt();

    // Add noise to control points relative to distance
    let noise_x = dist * 0.2;
    let noise_y = dist * 0.2;

    let cp1 = Point {
        x: start.x + dx * 0.33 + (rng.random::<f64>() - 0.5) * noise_x,
        y: start.y + dy * 0.33 + (rng.random::<f64>() - 0.5) * noise_y,
    };

    let cp2 = Point {
        x: start.x + dx * 0.66 + (rng.random::<f64>() - 0.5) * noise_x,
        y: start.y + dy * 0.66 + (rng.random::<f64>() - 0.5) * noise_y,
    };

    let mut path = Vec::with_capacity(num_points);
    for i in 0..num_points {
        let t = i as f64 / (num_points - 1) as f64;
        // Ease-out function to simulate slowing down as reaching the target
        let t_eased = 1.0 - (1.0 - t).powi(3);

        let u = 1.0 - t_eased;
        let tt = t_eased * t_eased;
        let uu = u * u;
        let uuu = uu * u;
        let ttt = tt * t_eased;

        let x = uuu * start.x + 3.0 * uu * t_eased * cp1.x + 3.0 * u * tt * cp2.x + ttt * end.x;
        let y = uuu * start.y + 3.0 * uu * t_eased * cp1.y + 3.0 * u * tt * cp2.y + ttt * end.y;

        path.push(Point { x, y });
    }

    path
}

/// Simulates human typing delays. Most keys are typed reasonably fast, but sometimes there are micro-pauses.
pub fn calculate_typing_delay() -> Duration {
    let mut rng = rand::rng();
    let val = sample_normal(&mut rng, KEYSTROKE_MEAN_MS, KEYSTROKE_STDDEV_MS);

    // Clamp before the cast: a negative sample would wrap when cast to u64.
    let base_delay = if val < KEYSTROKE_MIN_MS as f64 {
        KEYSTROKE_MIN_MS
    } else {
        val as u64
    };

    // Occasional longer pause (e.g. thinking or reaching for a hard key).
    if rng.random_bool(LONG_PAUSE_PROBABILITY) {
        let pause = rng.random_range(LONG_PAUSE_MIN_MS..LONG_PAUSE_MAX_MS);
        Duration::from_millis(base_delay + pause)
    } else {
        Duration::from_millis(base_delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mouse_path() {
        let start = Point { x: 0.0, y: 0.0 };
        let end = Point { x: 100.0, y: 100.0 };
        let path = generate_mouse_path(start, end, 50);

        assert_eq!(path.len(), 50);

        let first = path.first().unwrap();
        assert!((first.x.abs() < 1.0) && (first.y.abs() < 1.0));

        let last = path.last().unwrap();
        assert!((last.x - 100.0).abs() < 1.0 && (last.y - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_calculate_typing_delay() {
        let delay = calculate_typing_delay();
        assert!(delay.as_millis() >= KEYSTROKE_MIN_MS as u128); // Minimum delay
    }

    #[test]
    fn sample_normal_is_finite_and_centred_on_the_mean() {
        let mut rng = rand::rng();
        const N: usize = 20_000;

        let samples: Vec<f64> = (0..N)
            .map(|_| sample_normal(&mut rng, KEYSTROKE_MEAN_MS, KEYSTROKE_STDDEV_MS))
            .collect();

        // Box–Muller must never produce NaN/inf (the u1 == 0 -> ln(0) trap).
        assert!(
            samples.iter().all(|s| s.is_finite()),
            "sample_normal produced a non-finite value"
        );

        // Sample mean/stddev should track the requested parameters. The
        // tolerances are loose enough that a correct sampler effectively never
        // trips them, but a broken one (wrong scale, wrong centre) does.
        let mean = samples.iter().sum::<f64>() / N as f64;
        assert!(
            (mean - KEYSTROKE_MEAN_MS).abs() < 1.5,
            "sample mean {mean} strayed from {KEYSTROKE_MEAN_MS}"
        );

        let variance = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (N - 1) as f64;
        let stddev = variance.sqrt();
        assert!(
            (stddev - KEYSTROKE_STDDEV_MS).abs() < 1.5,
            "sample stddev {stddev} strayed from {KEYSTROKE_STDDEV_MS}"
        );
    }

    #[test]
    fn typing_delay_never_underflows_on_negative_samples() {
        // The Gaussian tail can go negative; the cast to u64 must be clamped
        // first or it wraps to an astronomically large delay.
        for _ in 0..10_000 {
            let delay = calculate_typing_delay();
            assert!(
                delay.as_millis() >= KEYSTROKE_MIN_MS as u128,
                "delay {delay:?} fell below the floor"
            );
            assert!(
                delay.as_millis() < (KEYSTROKE_MIN_MS + LONG_PAUSE_MAX_MS + 1000) as u128,
                "delay {delay:?} is implausibly large (likely a u64 wrap)"
            );
        }
    }

    #[test]
    fn test_calculate_typing_delay_long_pause_branch() {
        let mut hit_long_pause = false;
        // 5% chance means after 200 tries we should almost certainly hit it
        for _ in 0..200 {
            if calculate_typing_delay().as_millis() >= 170 {
                hit_long_pause = true;
                break;
            }
        }
        assert!(hit_long_pause);
    }
}
