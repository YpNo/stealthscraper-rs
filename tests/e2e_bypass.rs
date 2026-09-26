//! Exercises the full egress path against a live Cloudflare-protected site:
//! browser → local MITM proxy → JA4-shaped upstream request → rendered document.
//!
//! # What this asserts
//!
//! Both halves of the claim: that a real document comes back through the proxy,
//! and that the page we land on is **not** a challenge.
//!
//! An earlier version of this test asserted neither. It checked
//! `content.contains("you passed")`, a string the site no longer serves, and
//! reported a challenge whenever that string was missing — which was always. The
//! conclusion drawn from it ("we do not clear Cloudflare") was wrong twice over:
//! the string check was stale, and the challenge detector was reporting a false
//! positive on any page carrying a Turnstile widget or Cloudflare's passive
//! detection script. Both are fixed; this now asserts the outcome directly from
//! the detector rather than from a magic string.

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

    // And the document is the site, not an interstitial.
    let signal = scraper
        .detect_challenge(&page)
        .await
        .expect("Failed to classify the page");
    assert!(
        !signal.is_challenge(),
        "landed on a challenge rather than the site: {:?} ({:?}), {} bytes",
        signal.kind,
        signal.evidence,
        content.len()
    );

    println!(
        "Reached nowsecure.nl unchallenged: {} bytes, classified {:?}.",
        content.len(),
        signal.kind
    );
}
