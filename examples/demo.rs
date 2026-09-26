use std::time::Duration;

use stealthscraper_rs::{BrowserProfile, CloudScraper, GenericSolver};

/// How long to wait for a page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::init();

    println!("Initializing stealthscraper-rs...");

    // 1. Generate a realistic random browser profile
    let profile = BrowserProfile::random();
    println!(
        "Selected Profile: {} on {}",
        profile.user_agent, profile.platform
    );

    // 2. Start the browser using the Builder pattern.
    // This transparently starts the local JA4 TLS proxy in the background.
    let scraper = CloudScraper::builder().profile(profile).build().await?;

    // 3. Open a stealth page. It starts blank so the stealth script is
    // installed before any document can capture the originals.
    println!("Opening a stealth page with spoofed navigator and WebGL parameters...");
    let page = scraper.new_stealth_page().await?;

    // 4. Navigate to a test page
    println!("Navigating to a fingerprinting/bot detection test site (tls.peet.ws)...");
    page.navigate_and_wait("https://tls.peet.ws/api/all", LOAD_TIMEOUT)
        .await?;

    println!("Page loaded successfully.");

    // Attempt to solve a challenge if one is present
    println!("Looking for JS challenges...");
    match GenericSolver::solve_cloudflare_turnstile(&page).await {
        Ok(_) => println!("Solved a challenge using human mouse movements."),
        Err(_) => println!("No challenge detected, or the checkbox could not be located."),
    }

    println!("Scraping completed. Exiting.");
    Ok(())
}
