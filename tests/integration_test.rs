//! End-to-end navigation against a real, highly-available site.

use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper};

/// How long to wait for the external page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn a_stealth_page_navigates_and_returns_the_document() {
    let scraper = CloudScraper::builder()
        .profile(BrowserProfile::random())
        // No proxy: CI environments often block proxy traffic.
        .disable_proxy()
        .build()
        .await
        .expect("Failed to build CloudScraper");

    let page = scraper
        .new_stealth_page()
        .await
        .expect("Failed to create a stealth page");

    page.navigate_and_wait("https://nowsecure.nl", LOAD_TIMEOUT)
        .await
        .expect("Failed to navigate");

    // Reading the title proves the document arrived intact, not merely that
    // the navigation returned.
    assert_eq!(
        page.evaluate("document.title")
            .await
            .expect("Failed to read the title"),
        serde_json::Value::String("nowsecure.nl".to_string()),
    );
}
