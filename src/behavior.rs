#![cfg(feature = "browser")]
//! Human-interaction emulation: Bézier-curve mouse paths and human-like
//! keystroke timing, used to make CDP-driven input look organic.

use rand::RngExt;
use rand_distr::{Distribution, Normal};
use std::time::Duration;

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
    let normal = Normal::new(50.0, 15.0).unwrap();
    let val = normal.sample(&mut rng);

    let base_delay = if val < 20.0 { 20 } else { val as u64 };

    // 5% chance of a longer pause (e.g. thinking or reaching for a hard key)
    if rng.random_bool(0.05) {
        let pause = rng.random_range(150..400);
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
        assert!(delay.as_millis() >= 20); // Minimum delay
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
