//! Compile-check for the examples in README.md.
//!
//! The README's code is the first thing a reader tries, so it is built here
//! rather than trusted: an API change that invalidates it fails the build
//! instead of being discovered by a user.
//!
//! The bodies are behind a flag that is never set, so nothing here opens a
//! browser or touches the network when the example is run.

use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper, StealthSession, impersonation_client};

/// The "No browser at all" example.
async fn no_browser() -> Result<(), Box<dyn std::error::Error>> {
    let client = impersonation_client(&BrowserProfile::random()).build()?;

    let body = client
        .get("https://target-website.com")
        .send()
        .await?
        .text()
        .await?;
    println!("{} bytes", body.len());
    Ok(())
}

/// The "Dual-mode session" example.
async fn dual_mode() -> Result<(), stealthscraper_rs::Error> {
    let mut session = StealthSession::builder()
        .profile(BrowserProfile::random())
        .build();

    let response = session
        .fetch("https://target-protected-website.com")
        .await?;
    println!("{} ({} bytes)", response.status, response.body.len());

    let next = session
        .fetch("https://target-protected-website.com/page/2")
        .await?;
    println!("mode: {:?}", session.mode());
    println!("{}", next.status);

    Ok(())
}

/// The "Driving the browser directly" example.
async fn direct() -> Result<(), stealthscraper_rs::Error> {
    let profile = BrowserProfile::random();
    let scraper = CloudScraper::builder().profile(profile).build().await?;
    let page = scraper.new_stealth_page().await?;

    page.navigate_and_wait(
        "https://target-protected-website.com",
        Duration::from_secs(30),
    )
    .await?;

    let signal = scraper.solve_challenge(&page).await?;
    println!("Page cleared (challenge: {:?})", signal.kind);

    Ok(())
}

/// The "Proxy rotation, geo-consistency & resilience" example.
async fn resilient() -> Result<(), stealthscraper_rs::Error> {
    use std::sync::Arc;
    use stealthscraper_rs::{CountryCode, InMemoryStateStore, LogEventSink, RotationStrategy};

    let scraper = CloudScraper::builder()
        .with_geo_proxies([
            (
                "http://user:pass@de.proxy:8080".to_string(),
                CountryCode::new("DE").unwrap(),
            ),
            (
                "http://user:pass@fr.proxy:8080".to_string(),
                CountryCode::new("FR").unwrap(),
            ),
        ])
        .proxy_strategy(RotationStrategy::RoundRobin)
        .with_max_challenge_attempts(3)
        .with_state_store(Arc::new(InMemoryStateStore::new()))
        .with_event_sink(Arc::new(LogEventSink))
        .build()
        .await?;

    // The rotation snippet.
    let _scraper = scraper.rotate_profile().await?;
    Ok(())
}

/// The "Advanced Configuration" and "Opting out of the Proxy" snippets.
async fn configured() -> Result<(), stealthscraper_rs::Error> {
    let _scraper = CloudScraper::builder()
        .headless(false)
        .with_debug(true)
        .upstream_proxy("http://username:password@my-proxy:8080".to_string())
        .build()
        .await?;

    let _bare = CloudScraper::builder().disable_proxy().build().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Never true: this example exists to be compiled, not run.
    if std::env::var("STEALTHSCRAPER_RUN_README_EXAMPLES").is_ok() {
        no_browser().await?;
        dual_mode().await?;
        direct().await?;
        resilient().await?;
        configured().await?;
    } else {
        println!("compile-only check for the README examples; nothing was run");
    }
    Ok(())
}
