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

#[cfg(test)]
mod tests {
    use super::*;
    use headless_chrome::Browser;

    #[test]
    fn test_solve_cloudflare_turnstile_not_found() {
        // Just launch a normal browser to get a tab
        let browser = Browser::default().expect("Expected to get a browser");
        let tab = browser.new_tab().expect("Expected to get a tab");

        let result = GenericSolver::solve_cloudflare_turnstile(&tab);
        assert!(result.is_err());
    }

    #[test]
    fn test_solve_cloudflare_turnstile_success() {
        let browser = Browser::default().expect("Failed to launch");
        let tab = browser.new_tab().expect("Failed to create tab");

        // Load a mock page with a challenge turnstile element
        let html_content = "<html><body><div class='cf-turnstile' style='width: 300px; height: 65px;'></div></body></html>";
        let file_path = std::env::temp_dir().join("test_solver.html");
        std::fs::write(&file_path, html_content).expect("Failed to write mock HTML");
        let file_url = format!("file://{}", file_path.display());

        tab.navigate_to(&file_url).expect("Failed to navigate");
        tab.wait_until_navigated().expect("Failed to wait");

        let result = GenericSolver::solve_cloudflare_turnstile(&tab);
        assert!(result.is_ok());
    }
}
