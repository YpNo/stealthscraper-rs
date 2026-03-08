use crate::scraper::CloudScraper;
use headless_chrome::Tab;
use std::sync::Arc;
use std::time::Duration;

/// A utility for bypassing automated bot detections and CAPTCHAs.
///
/// `GenericSolver` contains various methods to solve or evade generic security puzzles,
/// such as Cloudflare Turnstile or similar challenges.
pub struct GenericSolver;

impl GenericSolver {
    /// Attempts to solve a standard JS challenge (e.g. Cloudflare Turnstile or generic checkbox)
    /// by locating the challenge element, simulating realistic mouse movement to it, and clicking.
    pub fn solve_cloudflare_turnstile(tab: &Arc<Tab>) -> anyhow::Result<()> {
        // Wait for turnstile checkbox to appear (usually in an iframe, but sometimes standard DOM)
        // We look for a generic challenge wrapper
        let challenge_selectors = vec![
            ".cf-turnstile",
            "#challenge-stage",
            "input[type='checkbox']",
        ];

        for selector in challenge_selectors {
            if let Ok(element) = tab.wait_for_element(selector) {
                // If found, get the box coordinates
                let box_model = element.get_box_model()?;
                let center_x = box_model.content.most_left();
                let center_y = box_model.content.most_top();

                // Move mouse there slowly
                CloudScraper::human_move_mouse(tab, center_x, center_y)?;

                // Add a small hesitation before clicking
                std::thread::sleep(Duration::from_millis(150));

                // Click
                tab.click_point(headless_chrome::browser::tab::point::Point {
                    x: center_x,
                    y: center_y,
                })?;

                // Wait for the challenge to resolve
                std::thread::sleep(Duration::from_secs(3));
                return Ok(());
            }
        }

        Err(anyhow::anyhow!(
            "Could not find a challenge element to solve"
        ))
    }
}
