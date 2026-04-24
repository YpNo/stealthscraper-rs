#![cfg(feature = "browser")]

use crate::profile::BrowserProfile;
use crate::proxy::TlsSpoofingProxy;
use crate::stealth::generate_stealth_js;
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

/// Builder pattern for orchestrating a new `CloudScraper` instance.
pub struct CloudScraperBuilder {
    profile: Option<BrowserProfile>,
    use_tls_proxy: bool,
    debug_mode: bool,
    headless: bool,
    proxy_server: Option<String>,
}

impl Default for CloudScraperBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudScraperBuilder {
    /// Creates a fresh CloudScraper configuration payload.
    pub fn new() -> Self {
        Self {
            profile: None,
            use_tls_proxy: true,
            debug_mode: false,
            headless: true,
            proxy_server: None,
        }
    }

    /// Attaches a specific hardware/browser fingerprint to be emulated.
    pub fn profile(mut self, profile: BrowserProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Disables the bundled TLS JA4 spoofing proxy. Be warned, you will get blocked by edge firewalls.
    pub fn disable_proxy(mut self) -> Self {
        self.use_tls_proxy = false;
        self
    }

    /// Hooks debug stdout tracing prints onto the bundled internal proxy.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }

    /// Determines whether the Chrome window should be visually hidden (default: true).
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Funnels traffic through an upstream HTTP/SOCKS proxy (e.g., `http://username:password@proxy:port`).
    pub fn upstream_proxy(mut self, proxy: String) -> Self {
        self.proxy_server = Some(proxy);
        self
    }

    /// Assembles the configuration, spawns the proxy (if enabled), and launches the headless Chrome thread natively.
    pub async fn build(self) -> Result<CloudScraper, Error> {
        // Rustls 0.23+ requires an explicitly installed crypto provider process-wide before any TLS builder is accessed.
        // We use .ok() to ignore the error if it was already installed safely.
        tokio_rustls::rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let profile = self.profile.unwrap_or_else(BrowserProfile::random);

        let proxy = if self.use_tls_proxy {
            // We build an rquest client that impersonates the intended browser
            let mut builder = rquest::Client::builder();

            if profile.user_agent.contains("Chrome/120") && profile.platform.contains("Win") {
                builder = builder.emulation(rquest_util::Emulation::Chrome120);
            } else if profile.user_agent.contains("Safari")
                && !profile.user_agent.contains("Chrome")
            {
                builder = builder.emulation(rquest_util::Emulation::Safari17_2_1);
            } else {
                builder = builder.emulation(rquest_util::Emulation::Chrome120);
            }

            // Bind an upstream proxy if the user requested one
            if let Some(ref upstream) = self.proxy_server {
                builder = builder.proxy(rquest::Proxy::all(upstream)?);
            }

            let impersonate_client = builder.timeout(Duration::from_secs(30)).build()?;

            // Start the local TLS proxy
            Some(TlsSpoofingProxy::start(impersonate_client, self.debug_mode).await?)
        } else {
            None
        };

        let mut args = vec![
            std::ffi::OsString::from("--disable-blink-features=AutomationControlled"),
            std::ffi::OsString::from(format!("--user-agent={}", profile.user_agent)),
            std::ffi::OsString::from(format!("--accept-lang={}", profile.accept_language)),
            std::ffi::OsString::from("--disable-gpu"),
            std::ffi::OsString::from("--no-sandbox"),
            std::ffi::OsString::from("--disable-dev-shm-usage"),
        ];

        if let Some(ref p) = proxy {
            args.push(std::ffi::OsString::from(format!(
                "--proxy-server=http://127.0.0.1:{}",
                p.port()
            )));
            args.push(std::ffi::OsString::from("--proxy-bypass-list=<-loopback>"));
            if self.debug_mode {
                eprintln!("[SCRAPER INFO] Browser Args: {:?}", args);
            }
            args.push(std::ffi::OsString::from("--ignore-certificate-errors")); // Crucial to accept our MITM cert
        } else if let Some(ref upstream) = self.proxy_server {
            // If proxy is entirely disabled natively but we have an upstream, bind locally
            args.push(std::ffi::OsString::from(format!(
                "--proxy-server={}",
                upstream
            )));
        }

        let launch_options = LaunchOptions::default_builder()
            .headless(self.headless)
            .window_size(Some((profile.viewport_width, profile.viewport_height)))
            .idle_browser_timeout(std::time::Duration::from_secs(120))
            .args(args.iter().map(|s| s.as_os_str()).collect())
            .build()
            .map_err(|e| Error::BrowserError(format!("Failed to build launch options: {}", e)))?;

        // Launch Browser
        let browser = Browser::new(launch_options)
            .map_err(|e| Error::BrowserError(format!("Failed to launch browser: {}", e)))?;

        Ok(CloudScraper {
            profile,
            proxy: proxy.map(Arc::new),
            browser,
        })
    }
}

impl CloudScraper {
    /// Start building a `CloudScraper` instance.
    pub fn builder() -> CloudScraperBuilder {
        CloudScraperBuilder::new()
    }

    /// Creates a new stealthy tab ready for navigation
    pub fn new_stealth_tab(&self) -> Result<Arc<headless_chrome::Tab>, Error> {
        let tab = self
            .browser
            .new_tab()
            .map_err(|e| Error::BrowserError(format!("Failed to create new tab: {:?}", e)))?;

        // Inject our stealth script to override navigator, WebGL, etc.
        let stealth_script = generate_stealth_js(&self.profile);

        tab.call_method(
            headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
                source: stealth_script,
                world_name: None,
                include_command_line_api: None,
                run_immediately: None,
            },
        )
        .map_err(|e| Error::BrowserError(format!("Failed to inject stealth script: {:?}", e)))?;

        Ok(tab)
    }

    /// Types a string into the current focused element with human-like delays
    pub fn human_type_str(tab: &Arc<headless_chrome::Tab>, text: &str) -> Result<(), Error> {
        for ch in text.chars() {
            let delay = crate::behavior::calculate_typing_delay();
            std::thread::sleep(delay);
            tab.type_str(&ch.to_string())
                .map_err(|e| Error::InteractionError(format!("Failed to type char: {:?}", e)))?;
        }
        Ok(())
    }

    /// Moves the mouse to a target x,y using Bezier curves to evade bot detection
    pub fn human_move_mouse(
        tab: &Arc<headless_chrome::Tab>,
        end_x: f64,
        end_y: f64,
    ) -> Result<(), Error> {
        // Assume current mouse pos is 0,0 if unknown, or we could track it.
        // For simplicity we just use a random nearby start point or default.
        let start = crate::behavior::Point { x: 100.0, y: 100.0 };
        let end = crate::behavior::Point { x: end_x, y: end_y };

        // Calculate curve path (e.g., 50 intermediate points)
        let path = crate::behavior::generate_mouse_path(start, end, 50);

        for point in path {
            tab.move_mouse_to_point(headless_chrome::browser::tab::point::Point {
                x: point.x,
                y: point.y,
            })
            .map_err(|e| Error::InteractionError(format!("Failed to move mouse: {:?}", e)))?;
            // small sleep to simulate rendering/polling rate
            std::thread::sleep(Duration::from_millis(5));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scraper_builder_default() {
        let builder = CloudScraper::builder();
        assert!(builder.use_tls_proxy);
        assert!(builder.profile.is_none());
    }

    #[test]
    fn test_scraper_builder_disable_proxy() {
        let builder = CloudScraper::builder().disable_proxy();
        assert!(!builder.use_tls_proxy);
    }

    #[test]
    fn test_scraper_builder_with_profile() {
        let profile = BrowserProfile::random();
        let builder = CloudScraper::builder().profile(profile.clone());

        let built_profile = builder.profile.unwrap();
        assert_eq!(built_profile.user_agent, profile.user_agent);
    }

    #[test]
    fn test_scraper_builder_default_trait() {
        let builder = CloudScraperBuilder::default();
        assert!(builder.use_tls_proxy);
    }

    #[cfg(feature = "browser")]
    #[test]
    fn test_human_interactions() {
        let browser = headless_chrome::Browser::default().expect("Failed to launch");
        let tab = browser.new_tab().expect("Failed to create tab");

        let html_content = "<html><body><input id='test_input' type='text' /></body></html>";
        let file_path = std::env::temp_dir().join("test_interactions.html");
        std::fs::write(&file_path, html_content).expect("Failed to write mock HTML");
        let file_url = format!("file://{}", file_path.display());

        tab.navigate_to(&file_url).expect("Failed to navigate");
        tab.wait_until_navigated().expect("Failed to wait");

        let input = tab
            .wait_for_element("#test_input")
            .expect("Failed to find input");
        input.click().expect("Failed to click input");

        // Test typing
        let type_res = CloudScraper::human_type_str(&tab, "test1234");
        assert!(type_res.is_ok());

        // Test mouse move
        let move_res = CloudScraper::human_move_mouse(&tab, 50.0, 50.0);
        assert!(move_res.is_ok());
    }
}
