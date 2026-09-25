use std::time::Duration;

use stealthscraper_rs::CloudScraper;

/// How long to wait for a page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to let Cloudflare's challenge run before reading the page.
const CHALLENGE_WAIT: Duration = Duration::from_secs(10);

/// Where the fetched page is written, under `target/`.
const PAGE_DUMP: &str = "cloudflare_test.html";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing stealthscraper-rs...");

    // Build the CloudScraper with the local JA4 proxy enabled
    let scraper = CloudScraper::builder().build().await?;

    println!(
        "Scraper initialized. Proxy running on port: {:?}",
        scraper.proxy.as_ref().map(|p| p.port())
    );

    let page = scraper.new_stealth_page().await?;

    println!("\n[1] Testing TLS & HTTP/2 Fingerprint (tls.peet.ws)...");
    page.navigate_and_wait("https://tls.peet.ws/api/all", LOAD_TIMEOUT)
        .await?;

    let body = page
        .evaluate("document.body.innerText")
        .await?
        .as_str()
        .unwrap_or_default()
        .to_string();

    // Print a truncated response so the JA3/JA4/HTTP2 fingerprints are visible
    let print_len = std::cmp::min(1500, body.len());
    println!(
        "Peet.ws response (first 1500 chars):\n{}",
        &body[..print_len]
    );

    println!("\n======================================================\n");

    println!("[2] Testing Cloudflare Bot Protection (nowsecure.nl)...");
    page.navigate_and_wait("https://nowsecure.nl", LOAD_TIMEOUT)
        .await?;

    // The challenge runs after load and then redirects.
    println!("Waiting {CHALLENGE_WAIT:?} for Cloudflare challenges...");
    tokio::time::sleep(CHALLENGE_WAIT).await;

    let html = page.content().await?;

    // Classified rather than string-matched. The previous version looked for
    // "you passed", which the site no longer serves, so a successful visit was
    // reported as an unknown result.
    let signal = stealthscraper_rs::challenge::detect(
        &stealthscraper_rs::challenge::DetectionInput::from_body(&html),
    );
    if signal.is_challenge() {
        println!(
            "Still challenged: {:?} ({:?}), {} bytes.",
            signal.kind,
            signal.evidence,
            html.len()
        );
    } else {
        println!(
            "Reached the site unchallenged: {} bytes, classified {:?}.",
            html.len(),
            signal.kind
        );
    }

    // Into `target/`, which is already ignored. Writing the fetched page into
    // the repository root committed 175 KB of somebody else's site once
    // already, and static analysis then graded this crate on their JavaScript.
    let dump = std::path::Path::new("target").join(PAGE_DUMP);
    match tokio::fs::write(&dump, html).await {
        Ok(()) => println!("Page written to {}", dump.display()),
        Err(e) => println!("Could not write {}: {e}", dump.display()),
    }

    Ok(())
}
