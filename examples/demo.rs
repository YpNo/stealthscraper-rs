use rs_cloudscraper::{BrowserProfile, CloudScraper, GenericSolver};

fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::init();

    println!("Initializing rs-cloudscraper...");

    // 1. Generate a realistic random browser profile
    let profile = BrowserProfile::random();
    println!("Selected Profile: {} on {}", profile.user_agent, profile.platform);

    // 2. Start the headless browser engine
    let scraper = CloudScraper::new(Some(profile))?;
    
    // 3. Open a new stealth tab
    println!("Opening stealth tab with spoofed navigator and WebGL parameters...");
    let tab = scraper.new_stealth_tab()?;

    // 4. Navigate to a test page
    println!("Navigating to a fingerprinting/bot detection test site (e.g., tls.peal.pro)...");
    tab.navigate_to("https://tls.peal.pro/")?;
    tab.wait_until_navigated()?;

    println!("Page loaded successfully.");
    
    // Attempting to solve a challenge if present
    println!("Looking for JS challenges...");
    match GenericSolver::solve_cloudflare_turnstile(&tab) {
        Ok(_) => println!("Solved Cloudflare challenge using human mouse movements!"),
        Err(_) => println!("No challenge detected or failed to locate the checkbox."),
    }

    // Attempting to type something if there's an input
    // scraper.human_type_str(&tab, "Hello World from rs-cloudscraper")?;

    println!("Scraping completed. Exiting.");
    Ok(())
}
