//! Validates the stealth hooks inside a real document served over the network,
//! so the assertions run in a genuine execution context rather than a local one.

use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper};

/// How long to wait for the external page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Values `BrowserProfile::random` can report for `hardwareConcurrency`.
const PLAUSIBLE_CONCURRENCY: &[u64] = &[4, 8, 12, 16];

#[tokio::test]
async fn stealth_globals_hold_in_a_real_document() {
    let scraper = CloudScraper::builder()
        .profile(BrowserProfile::random())
        .headless(true)
        // No proxy: this exercises the DOM overrides, not the egress path.
        .disable_proxy()
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let page = scraper
        .new_stealth_page()
        .await
        .expect("Failed to open a page");

    page.navigate_and_wait("https://nowsecure.nl", LOAD_TIMEOUT)
        .await
        .expect("Failed to navigate");

    // 1. navigator.webdriver must be false in V8 itself. It is false because
    // the browser was never launched with --enable-automation, not because a
    // script patched it afterwards.
    assert_eq!(
        page.evaluate("navigator.webdriver")
            .await
            .expect("evaluate webdriver"),
        serde_json::Value::Bool(false),
        "Stealth failed: navigator.webdriver is not false"
    );

    // 2. window.chrome must be present.
    assert_eq!(
        page.evaluate("!!window.chrome")
            .await
            .expect("evaluate window.chrome"),
        serde_json::Value::Bool(true),
        "Stealth failed: window.chrome is missing"
    );

    // 3. hardwareConcurrency must report the profile's value.
    let concurrency = page
        .evaluate("navigator.hardwareConcurrency")
        .await
        .expect("evaluate hardwareConcurrency")
        .as_u64()
        .unwrap_or(0);
    assert!(
        PLAUSIBLE_CONCURRENCY.contains(&concurrency),
        "Stealth failed: hardwareConcurrency reported {concurrency}"
    );
}
