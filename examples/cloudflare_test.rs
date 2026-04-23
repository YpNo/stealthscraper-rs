use rs_cloudscraper::CloudScraper;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing rs-cloudscraper...");

    // Build the CloudScraper with the local JA4 proxy enabled
    let scraper = CloudScraper::builder().build().await?;

    println!(
        "Scraper initialized. Proxy running on port: {:?}",
        scraper.proxy.as_ref().map(|p| p.port())
    );

    let tab = scraper.new_stealth_tab()?;

    println!("\n[1] Testing TLS & HTTP/2 Fingerprint (tls.peet.ws)...");
    tab.navigate_to("https://tls.peet.ws/api/all")?;
    tab.wait_until_navigated()?;

    // Wait slightly for JSON to render
    std::thread::sleep(Duration::from_secs(2));

    let body = tab.wait_for_element("body")?.get_inner_text()?;

    // Print a truncated version of the JSON response to verify JA3/JA4/HTTP2 fingerprints
    let print_len = std::cmp::min(1500, body.len());
    println!(
        "Peet.ws response (first 1500 chars):\n{}",
        &body[..print_len]
    );

    println!("\n======================================================\n");

    println!("[2] Testing Cloudflare Bot Protection (nowsecure.nl)...");
    tab.navigate_to("https://nowsecure.nl")?;

    // Cloudflare turnstile and JS challenges take a few seconds to run and redirect
    println!("Waiting 10 seconds for Cloudflare challenges...");
    std::thread::sleep(Duration::from_secs(10));

    let html = tab.wait_for_element("html")?.get_content()?;

    if html.contains("oh yeah, you passed") || html.contains("you passed") {
        println!("✅ Cloudflare completely bypassed! Detected human behavior.");
    } else if html.contains("Just a moment") || html.contains("Checking your browser") {
        println!("❌ Stuck on Cloudflare challenge page.");
    } else {
        println!("❓ Unknown result. Returned page length: {}", html.len());
    }

    std::fs::write("nowsecure.html", html).expect("Failed to write html to file");

    Ok(())
}
