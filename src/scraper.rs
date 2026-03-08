use crate::profile::BrowserProfile;
use crate::stealth::generate_stealth_js;
use crate::proxy::TlsSpoofingProxy;
use headless_chrome::{Browser, LaunchOptions};
use std::sync::Arc;
use std::time::Duration;

use crate::Error;

/// The main entry point for managing a stealthy browser instance.
///
/// `CloudScraper` wraps a `headless_chrome::Browser` and injects stealth configurations
/// (via `BrowserProfile` and stealth JavaScript scripts) to make scraping tasks highly
/// undetectable by modern bot-protection systems.
pub struct CloudScraper {
    /// The browser profile (fingerprint) being used.
    pub profile: BrowserProfile,
    /// The local TLS MITM proxy instance (kept alive with the scraper)
    pub proxy: Option<Arc<TlsSpoofingProxy>>,
    /// The underlying headless_chrome browser instance.
    browser: Browser,
}

pub struct CloudScraperBuilder {
    profile: Option<BrowserProfile>,
    use_tls_proxy: bool,
}

impl Default for CloudScraperBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudScraperBuilder {
    pub fn new() -> Self {
        Self {
            profile: None,
            use_tls_proxy: true,
        }
    }

    pub fn profile(mut self, profile: BrowserProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn disable_proxy(mut self) -> Self {
        self.use_tls_proxy = false;
        self
    }

    pub async fn build(self) -> Result<CloudScraper, Error> {
        let profile = self.profile.unwrap_or_else(BrowserProfile::random);

        let proxy = if self.use_tls_proxy {
            // We build an rquest client that impersonates the intended browser
            let impersonate_client = if profile.user_agent.contains("Chrome/120") && profile.platform.contains("Win") {
                rquest::Client::builder()
                    .emulation(rquest_util::Emulation::Chrome120) // Use rquest built-in impersonation profiles
                    .build()?
            } else if profile.user_agent.contains("Safari") && !profile.user_agent.contains("Chrome") {
                rquest::Client::builder()
                    .emulation(rquest_util::Emulation::Safari17_2_1)
                    .build()?
            } else {
                // Default fallback
                rquest::Client::builder()
                    .emulation(rquest_util::Emulation::Chrome120)
                    .build()?
            };

            // Start the local TLS proxy
            Some(TlsSpoofingProxy::start(impersonate_client).await?)
        } else {
            None
        };

        let mut args = vec![
            std::ffi::OsString::from("--disable-blink-features=AutomationControlled"),
            std::ffi::OsString::from(format!("--user-agent={}", profile.user_agent)),
            std::ffi::OsString::from(format!("--accept-lang={}", profile.accept_language)),
        ];

        if let Some(ref p) = proxy {
            args.push(std::ffi::OsString::from(format!("--proxy-server=127.0.0.1:{}", p.port())));
            args.push(std::ffi::OsString::from("--ignore-certificate-errors")); // Crucial to accept our MITM cert
        }

        let launch_options = LaunchOptions::default_builder()
            .headless(true)
            .window_size(Some((profile.viewport_width, profile.viewport_height)))
            .args(args.iter().map(|s| s.as_os_str()).collect())
            .build()
            .map_err(|e| Error::BrowserError(format!("Failed to build launch options: {}", e)))?;

        // Launch Browser
        let browser = Browser::new(launch_options)
            .map_err(|e| Error::BrowserError(format!("Failed to launch browser: {}", e)))?;

        Ok(CloudScraper { 
            profile, 
            proxy: proxy.map(Arc::new),
            browser 
        })
    }
}

impl CloudScraper {
    /// Start building a `CloudScraper` instance.
    pub fn builder() -> CloudScraperBuilder {
        CloudScraperBuilder::new()
    }


    /// Creates a new stealthy tab ready for navigation
    pub fn new_stealth_tab(&self) -> anyhow::Result<Arc<headless_chrome::Tab>> {
        let tab = self.browser.new_tab()?;
        
        // Inject our stealth script to override navigator, WebGL, etc.
        let stealth_script = generate_stealth_js(&self.profile);
        
        tab.call_method(headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
            source: stealth_script,
            world_name: None,
            include_command_line_api: None,
            run_immediately: None,
        }).map_err(|e| anyhow::anyhow!("Failed to inject stealth script: {:?}", e))?;

        Ok(tab)
    }

    /// Types a string into the current focused element with human-like delays
    pub fn human_type_str(tab: &Arc<headless_chrome::Tab>, text: &str) -> anyhow::Result<()> {
        for ch in text.chars() {
            let delay = crate::behavior::calculate_typing_delay();
            std::thread::sleep(delay);
            tab.type_str(&ch.to_string())
                .map_err(|e| anyhow::anyhow!("Failed to type char: {:?}", e))?;
        }
        Ok(())
    }

    /// Moves the mouse to a target x,y using Bezier curves to evade bot detection
    pub fn human_move_mouse(tab: &Arc<headless_chrome::Tab>, end_x: f64, end_y: f64) -> anyhow::Result<()> {
        // Assume current mouse pos is 0,0 if unknown, or we could track it.
        // For simplicity we just use a random nearby start point or default.
        let start = crate::behavior::Point { x: 100.0, y: 100.0 };
        let end = crate::behavior::Point { x: end_x, y: end_y };
        
        // Calculate curve path (e.g., 50 intermediate points)
        let path = crate::behavior::generate_mouse_path(start, end, 50);

        for point in path {
            tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point { x: point.x, y: point.y })
                .map_err(|e| anyhow::anyhow!("Failed to move mouse: {:?}", e))?;
            // small sleep to simulate rendering/polling rate 
            std::thread::sleep(Duration::from_millis(5));
        }
        
        Ok(())
    }
}
