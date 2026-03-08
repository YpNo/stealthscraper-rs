use rs_cloudscraper::{BrowserProfile, CloudScraper};

#[tokio::test]
async fn test_scraper_end_to_end_navigation() {
    // 1. Generate a random browser profile for the test
    let profile = BrowserProfile::random();

    // 2. Build the scraper. This initializes the headless browser AND the local JA4 TLS proxy.
    let scraper = CloudScraper::builder()
        .profile(profile)
        // Disable the proxy to ensure reliable execution in CI environments which often block proxy traffic
        .disable_proxy()
        .build()
        .await
        .expect("Failed to build CloudScraper");

    // 3. Open a tab injected with our stealth scripts
    let tab = scraper
        .new_stealth_tab()
        .expect("Failed to create stealth tab");

    // 4. Navigate to a simple, highly-available website
    tab.navigate_to("https://nowsecure.nl")
        .expect("Failed to navigate");

    // 5. Wait for the page to finish loading
    tab.wait_until_navigated()
        .expect("Failed to wait for navigation");

    // 6. Extract the <h1> element to verify the page loaded and the proxy forwarded the HTML body successfully
    let header_element = tab
        .wait_for_element("title")
        .expect("Failed to find <title> element on nowsecure.nl");
    let text = header_element
        .get_inner_text()
        .expect("Failed to get inner text");

    assert_eq!(text, "nowsecure.nl");
}
