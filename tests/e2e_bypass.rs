use rs_cloudscraper::{BrowserProfile, CloudScraper};

#[tokio::test]
async fn test_tls_cloudflare_bypass() {
    // This is a smart E2E test. We navigate to a known Cloudflare-protected endpoint.
    // If the TLS proxy or headless signatures fail, this will hang or return a 403 Challenge.

    let profile = BrowserProfile::random();

    let scraper = CloudScraper::builder()
        .profile(profile)
        .headless(true)
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let tab = scraper.new_stealth_tab().expect("Failed to open tab");

    // Navigate to a notoriously strict Cloudflare-protected site
    // (We use a lightweight endpoint instead of hammering a real service excessively)
    let url = "https://my.arlo.com/#/login";

    tab.navigate_to(url).expect("Failed to navigate");

    // Wait for the DOM to settle. If CF blocks us, it will hang in the challenge loop.
    tab.wait_until_navigated()
        .expect("Failed wait for navigation");

    // Wait for the login form to appear, proving we bypassed the initial Cloudflare edge firewall
    // If we were blocked, the `#userId` input wouldn't exist in the DOM (it would be a CF challenge iframe).
    let element = tab.wait_for_element("input#userId");

    assert!(
        element.is_ok(),
        "Failed to find Arlo login input! Cloudflare TLS bypass may have failed."
    );

    println!("Successfully bypassed Cloudflare edge node anonymously.");
}
