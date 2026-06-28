use stealthscraper_rs::{BrowserProfile, CloudScraper};

#[tokio::test]
async fn test_stealth_globals_against_nowsecure() {
    // We navigate to our chosen high-availability testing endpoint
    let profile = BrowserProfile::random();

    let scraper = CloudScraper::builder()
        .profile(profile)
        .headless(true)
        .disable_proxy() // We don't need proxying latency, just testing headless VM DOM overrides
        .build()
        .await
        .expect("Failed to build stealth scraper");

    let tab = scraper.new_stealth_tab().expect("Failed to open tab");

    // Navigate to external endpoint to get a native Document Execution Context bounded by real CORS
    let url = "https://nowsecure.nl";

    tab.navigate_to(url).expect("Failed to navigate");
    tab.wait_until_navigated()
        .expect("Failed wait for navigation");

    // 1. Verify navigator.webdriver is FALSE natively in the V8 engine
    let is_webdriver = tab
        .evaluate("navigator.webdriver", false)
        .expect("Failed to evaluate webdriver");
    assert_eq!(
        is_webdriver.value.unwrap_or_default().as_bool(),
        Some(false),
        "Stealth failed: navigator.webdriver is true"
    );

    // 2. Verify window.chrome injection took hold
    let has_chrome = tab
        .evaluate("!!window.chrome", false)
        .expect("Failed to evaluate chrome object");
    assert_eq!(
        has_chrome.value.unwrap_or_default().as_bool(),
        Some(true),
        "Stealth failed: window.chrome is missing"
    );

    // 3. Verify hardware concurrency spoof
    let concurrency = tab
        .evaluate("navigator.hardwareConcurrency", false)
        .expect("Failed to evaluate concurrency");
    let concurrency_val = concurrency.value.unwrap_or_default().as_u64().unwrap_or(0);
    assert!(
        concurrency_val == 4
            || concurrency_val == 8
            || concurrency_val == 12
            || concurrency_val == 16,
        "Stealth failed: hardware_concurrency does not match bounds"
    );

    println!("Successfully validated global DOM assertions against external document.");
}
