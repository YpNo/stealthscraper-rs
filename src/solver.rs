#![cfg(feature = "browser")]
//! Interactive challenge solving — e.g. locating and clicking a Cloudflare
//! Turnstile widget with human-like mouse movement.

use std::time::Duration;

use crate::Error;
use crate::cdp::Page;
use crate::scraper::CloudScraper;

/// Selectors that may carry an interactive challenge, in order of specificity.
const CHALLENGE_SELECTORS: &[&str] = &[".cf-turnstile", "#challenge-stage", "input[type=checkbox]"];

/// How long to wait for each candidate selector.
///
/// Short on purpose: the list is tried in order, so a long wait on an absent
/// selector would delay finding the one that is actually present.
const SELECTOR_TIMEOUT: Duration = Duration::from_millis(1500);

/// How long to let the challenge resolve after the click.
const RESOLVE_WAIT: Duration = Duration::from_secs(3);

/// A utility for bypassing automated bot detections and CAPTCHAs.
///
/// `GenericSolver` contains methods to solve or evade generic security puzzles,
/// such as Cloudflare Turnstile or similar challenges.
pub struct GenericSolver;

impl GenericSolver {
    /// Attempts to solve a standard JS challenge (e.g. Cloudflare Turnstile or a
    /// generic checkbox) by locating the challenge element, moving the pointer to
    /// it realistically, and clicking its centre.
    pub async fn solve_cloudflare_turnstile(page: &Page) -> Result<(), Error> {
        for selector in CHALLENGE_SELECTORS {
            if page
                .wait_for_selector(selector, SELECTOR_TIMEOUT)
                .await
                .is_err()
            {
                continue;
            }

            // Scroll it into view, travel to it, settle, then press. A widget
            // clicked without the page ever scrolling to it — or without the
            // pointer travelling — is distinguishable from a person doing it.
            //
            // A widget that is present but unpositioned (display:none, or
            // detached) is not clickable, so keep looking rather than clicking a
            // meaningless coordinate.
            match CloudScraper::human_click(page, selector).await {
                Ok(()) => {}
                Err(Error::InteractionError(_)) => continue,
                Err(other) => return Err(other),
            }

            tokio::time::sleep(RESOLVE_WAIT).await;
            return Ok(());
        }

        Err(Error::InteractionError(
            "Could not find a challenge element to solve".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::{BrowserHandle, CdpTransport, LaunchConfig, launch};
    use crate::profile::BrowserProfile;

    const LOAD_TIMEOUT: Duration = Duration::from_secs(10);

    /// Connects to a browser, or `None` when none is installed.
    fn browser() -> Option<BrowserHandle> {
        let profile = BrowserProfile::random();
        match launch(&LaunchConfig::for_profile(&profile)) {
            Ok(browser) => Some(BrowserHandle::new(
                CdpTransport::connect(browser).expect("connect the transport"),
            )),
            Err(err) => {
                eprintln!("skipping: no browser available ({err})");
                None
            }
        }
    }

    fn data_url(body: &str) -> String {
        format!("data:text/html,{}", body.replace('#', "%23"))
    }

    #[tokio::test]
    async fn a_page_with_no_challenge_reports_that_it_found_none() {
        let Some(browser) = browser() else { return };
        let page = browser
            .open(
                &data_url("<html><body>nothing here</body></html>"),
                LOAD_TIMEOUT,
            )
            .await
            .expect("open a page");

        let result = GenericSolver::solve_cloudflare_turnstile(&page).await;
        assert!(matches!(result, Err(Error::InteractionError(_))));

        page.close().await.expect("close the page");
    }

    #[tokio::test]
    async fn a_turnstile_widget_is_clicked_at_its_centre() {
        let Some(browser) = browser() else { return };
        // The widget records where it was clicked, so the coordinates can be
        // checked rather than merely the fact that a click happened.
        let page = browser
            .open(
                &data_url(
                    "<html><body style='margin:0'>\
                     <div class='cf-turnstile' \
                     style='position:absolute;left:40px;top:60px;width:300px;height:65px'></div>\
                     <script>window.__at=null;\
                     document.querySelector('.cf-turnstile').addEventListener('click',\
                     e=>window.__at=[e.clientX,e.clientY]);</script>\
                     </body></html>",
                ),
                LOAD_TIMEOUT,
            )
            .await
            .expect("open a page");

        GenericSolver::solve_cloudflare_turnstile(&page)
            .await
            .expect("solve");

        let at = page
            .evaluate("JSON.stringify(window.__at)")
            .await
            .expect("evaluate");
        let at: Option<(f64, f64)> = at
            .as_str()
            .and_then(|raw| serde_json::from_str(raw).ok())
            .expect("the widget recorded a click");
        let (x, y) = at.expect("the click carried coordinates");

        // The widget spans x 40..340 and y 60..125, so its centre is (190, 92.5).
        // The previous implementation clicked `most_left()`/`most_top()` — the
        // top-left corner — which is both less realistic and, for a widget with
        // padding, outside the interactive area.
        assert!(
            (x - 190.0).abs() <= 1.0 && (y - 92.5).abs() <= 1.0,
            "clicked ({x}, {y}), expected the widget's centre (190, 92.5)"
        );

        page.close().await.expect("close the page");
    }

    #[tokio::test]
    async fn a_hidden_widget_is_skipped_rather_than_clicked_at_nowhere() {
        let Some(browser) = browser() else { return };
        let page = browser
            .open(
                &data_url(
                    "<html><body>\
                     <div class='cf-turnstile' style='display:none'></div>\
                     </body></html>",
                ),
                LOAD_TIMEOUT,
            )
            .await
            .expect("open a page");

        // It matches the selector but has no box, so there is no coordinate
        // worth clicking; the solver must report that it found nothing.
        let result = GenericSolver::solve_cloudflare_turnstile(&page).await;
        assert!(matches!(result, Err(Error::InteractionError(_))));

        page.close().await.expect("close the page");
    }
}
