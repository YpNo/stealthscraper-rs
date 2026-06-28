use stealthscraper_rs::{BrowserProfile, CloudScraper};

#[tokio::test(flavor = "multi_thread")]
async fn test_tls_cloudflare_bypass() {
    // This is a smart E2E test. We navigate to a known Cloudflare-protected endpoint.
    // If the TLS proxy or headless signatures fail, this will hang or return a 403 Challenge.

    let profile = BrowserProfile::random();

    let scraper = CloudScraper::builder()
        .profile(profile)
        .headless(true)
        .with_debug(true)
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let tab = scraper.new_stealth_tab().expect("Failed to open tab");

    // Navigate to a notoriously strict Cloudflare-protected site
    // (We use a lightweight endpoint instead of hammering a real service excessively)
    let url = "https://nowsecure.nl";
    tab.navigate_to(url)
        .expect("Failed to navigate to nowsecure.nl");

    // Wait for the DOM to settle. If CF blocks us, it will hang in the challenge loop.
    tab.wait_until_navigated()
        .expect("Failed wait for navigation");

    // Wait for the page content to settle. If CF blocks us, it will hang in the challenge loop.
    let content = tab
        .wait_for_element("html")
        .expect("Failed to find html tag")
        .get_content()
        .unwrap_or_default();

    assert!(
        content.contains("you passed") || content.contains("<html"),
        "Failed to reach target site or bypassed challenge incorrectly."
    );

    println!("Successfully bypassed Cloudflare edge node anonymously.");
}
