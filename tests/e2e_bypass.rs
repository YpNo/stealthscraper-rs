//! Exercises the full egress path against a live Cloudflare-protected site:
//! browser → local MITM proxy → JA4-shaped upstream request → rendered document.
//!
//! # What this does and does not assert
//!
//! It asserts the **path works**: a real document comes back through the proxy,
//! rendered by the browser. If TLS termination, the impersonation client or the
//! CDP plumbing were broken, nothing would arrive.
//!
//! It does **not** assert that the challenge is defeated. At the time of
//! writing, `nowsecure.nl` serves Cloudflare's interstitial to this stack, both
//! before and after the CDP port (measured: the same ~179 KB challenge page
//! either way). Asserting a bypass here would make the suite fail for a reason
//! that has nothing to do with the code under test, and passing it off as a
//! success would be worse. The challenge state is printed instead, so a run
//! shows plainly where the stack stands.

use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper};

/// How long to wait for the protected page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
async fn a_document_comes_back_through_the_mitm_proxy() {
    let scraper = CloudScraper::builder()
        .profile(BrowserProfile::random())
        .headless(true)
        .with_debug(true)
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let page = scraper
        .new_stealth_page()
        .await
        .expect("Failed to open a page");

    page.navigate_and_wait("https://nowsecure.nl", LOAD_TIMEOUT)
        .await
        .expect("Failed to navigate to nowsecure.nl");

    let content = page.content().await.expect("Failed to read the page");

    // The egress path delivered a rendered document rather than dying in TLS.
    assert!(
        content.contains("<html"),
        "no document came back through the proxy ({} bytes)",
        content.len()
    );

    // Report where we stand without asserting it, for the reason above.
    let signal = scraper
        .detect_challenge(&page)
        .await
        .expect("Failed to classify the page");
    if content.contains("you passed") {
        println!("Cloudflare cleared: reached the protected content.");
    } else {
        println!(
            "Still challenged ({:?}); {} bytes returned. The egress path works; \
             clearing this challenge is a stealth-hardening item, not a transport one.",
            signal.kind,
            content.len()
        );
    }
}
