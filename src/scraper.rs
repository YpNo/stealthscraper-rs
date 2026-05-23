#![cfg(feature = "browser")]

use crate::challenge::{Action, ChallengeKind, ChallengeSignal, DetectionInput, MitigationPolicy};
use crate::profile::BrowserProfile;
use crate::proxy::TlsSpoofingProxy;
use crate::proxy_pool::{ProxyPool, RotationStrategy};
use crate::solver::GenericSolver;
use crate::state::{DomainState, Outcome, StateStore};
use crate::stealth::generate_stealth_js;
use headless_chrome::{Browser, LaunchOptions};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Error;

/// Outbound request timeout for the impersonation client.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Cooldown applied to a host after it rate-limits us.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(300);

/// Current Unix time in seconds (saturating to 0 before the epoch).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds a `wreq` impersonation client for `profile`, optionally routed through
/// an upstream proxy. Centralised so the initial build and proxy rotation stay
/// in sync (identical JA4 emulation, only the egress proxy changes).
fn build_impersonation_client(
    profile: &BrowserProfile,
    upstream: Option<&str>,
) -> Result<wreq::Client, Error> {
    let mut builder = wreq::Client::builder();

    if profile.user_agent.contains("Chrome/120") && profile.platform.contains("Win") {
        builder = builder.emulation(wreq_util::Emulation::Chrome120);
    } else if profile.user_agent.contains("Safari") && !profile.user_agent.contains("Chrome") {
        builder = builder.emulation(wreq_util::Emulation::Safari17_2_1);
    } else {
        builder = builder.emulation(wreq_util::Emulation::Chrome120);
    }

    if let Some(upstream) = upstream {
        builder = builder.proxy(wreq::Proxy::all(upstream)?);
    }

    Ok(builder.timeout(UPSTREAM_TIMEOUT).build()?)
}

/// `headless_chrome` idle timeout: how long the browser event loop will
/// wait with no CDP traffic before it tears the browser down.
///
/// `CloudScraper` is held for the lifetime of a long-running daemon
/// (e.g. an Arlo streaming bridge). After the initial authentication the
/// browser is needed only sporadically — a token refresh, re-auth, or a
/// Cloudflare challenge that may not occur for hours. The crate default
/// (and the previous 120 s value here) kills Chrome during the first
/// idle gap; the daemon then loses its TLS-spoofing proxy and cannot
/// recover. We therefore keep the browser alive for the process
/// lifetime. The value is large but well within `Instant` range on all
/// supported platforms (10 years ≈ 3.2e17 ns ≪ i64::MAX ns), so the
/// underlying `recv_timeout` cannot overflow.
const BROWSER_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

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
    /// Policy governing how detected challenges are retried.
    policy: MitigationPolicy,
    /// Rotatable pool of upstream egress proxies.
    pool: Mutex<ProxyPool>,
    /// Optional persistent per-domain state store.
    store: Option<Arc<dyn StateStore>>,
}

/// Builder pattern for orchestrating a new `CloudScraper` instance.
pub struct CloudScraperBuilder {
    profile: Option<BrowserProfile>,
    use_tls_proxy: bool,
    debug_mode: bool,
    headless: bool,
    proxies: Vec<String>,
    rotation_strategy: RotationStrategy,
    max_challenge_attempts: u32,
    state_store: Option<Arc<dyn StateStore>>,
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
            proxies: Vec::new(),
            rotation_strategy: RotationStrategy::default(),
            max_challenge_attempts: MitigationPolicy::default().max_attempts,
            state_store: None,
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
    ///
    /// Adds a single proxy to the rotation pool; call repeatedly or use
    /// [`Self::with_proxies`] to register several.
    pub fn upstream_proxy(mut self, proxy: String) -> Self {
        self.proxies.push(proxy);
        self
    }

    /// Registers a pool of upstream proxies that rotation can switch between when
    /// the current egress IP gets hard-blocked.
    pub fn with_proxies(mut self, proxies: impl IntoIterator<Item = String>) -> Self {
        self.proxies.extend(proxies);
        self
    }

    /// Selects how the pool picks the next proxy on rotation (default: round-robin).
    pub fn proxy_strategy(mut self, strategy: RotationStrategy) -> Self {
        self.rotation_strategy = strategy;
        self
    }

    /// Sets how many times a detected challenge is waited-out/re-checked before failing.
    pub fn with_max_challenge_attempts(mut self, attempts: u32) -> Self {
        self.max_challenge_attempts = attempts;
        self
    }

    /// Attaches a persistent per-domain state store (e.g. `InMemoryStateStore` or,
    /// with the `persistence` feature, `RedbStateStore`). When set, outcomes are
    /// recorded automatically by [`CloudScraper::solve_challenge`].
    pub fn with_state_store(mut self, store: Arc<dyn StateStore>) -> Self {
        self.state_store = Some(store);
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

        // Assemble the rotatable upstream-proxy pool and pick the initial egress.
        let pool = ProxyPool::new(self.proxies.clone(), self.rotation_strategy);
        let initial_upstream = pool.selected().map(str::to_owned);

        let proxy = if self.use_tls_proxy {
            let impersonate_client =
                build_impersonation_client(&profile, initial_upstream.as_deref())?;
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
        } else if let Some(ref upstream) = initial_upstream {
            // If the MITM proxy is disabled but an upstream exists, bind Chrome to it
            // directly. Note: rotation is unavailable in this mode (no client to swap).
            args.push(std::ffi::OsString::from(format!(
                "--proxy-server={upstream}"
            )));
        }

        let launch_options = LaunchOptions::default_builder()
            .headless(self.headless)
            .window_size(Some((profile.viewport_width, profile.viewport_height)))
            .idle_browser_timeout(BROWSER_IDLE_TIMEOUT)
            .args(args.iter().map(|s| s.as_os_str()).collect())
            .build()
            .map_err(|e| Error::BrowserError(format!("Failed to build launch options: {}", e)))?;

        // Launch Browser
        let browser = Browser::new(launch_options)
            .map_err(|e| Error::BrowserError(format!("Failed to launch browser: {}", e)))?;

        // Rotation needs the MITM proxy (to swap the egress client) and at least
        // one fallback proxy to switch to.
        let can_rotate_proxy = proxy.is_some() && pool.healthy_count() >= 2;

        Ok(CloudScraper {
            profile,
            proxy: proxy.map(Arc::new),
            browser,
            policy: MitigationPolicy::new(self.max_challenge_attempts)
                .with_proxy_rotation(can_rotate_proxy),
            pool: Mutex::new(pool),
            store: self.state_store,
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

    /// Classifies the challenge (if any) currently rendered in `tab`.
    ///
    /// Detection runs over the tab's rendered DOM. HTTP status/headers are not
    /// available from the DOM, so they are left unset — body markers are
    /// sufficient to recognise Cloudflare's interstitial and Turnstile pages.
    pub fn detect_challenge(
        &self,
        tab: &Arc<headless_chrome::Tab>,
    ) -> Result<ChallengeSignal, Error> {
        let body = tab
            .get_content()
            .map_err(|e| Error::BrowserError(format!("Failed to read page content: {e:?}")))?;
        Ok(crate::challenge::detect(&DetectionInput::from_body(&body)))
    }

    /// Detects and attempts to clear any bot-protection challenge on `tab`.
    ///
    /// Loops according to the configured [`MitigationPolicy`]: it waits for
    /// non-interactive challenges to auto-resolve in the real browser, and for
    /// an interactive Turnstile it makes a best-effort click via [`GenericSolver`]
    /// before waiting. Returns the final [`ChallengeSignal`] once the page is
    /// clear, or [`Error::Challenge`] if the budget is exhausted or the page is
    /// hard-blocked.
    pub fn solve_challenge(
        &self,
        tab: &Arc<headless_chrome::Tab>,
    ) -> Result<ChallengeSignal, Error> {
        let host = Self::tab_host(tab);
        let mut attempt = 0u32;
        let mut saw_challenge = false;
        loop {
            let signal = self.detect_challenge(tab)?;
            match self.policy.decide(&signal, attempt) {
                Action::Proceed => {
                    let outcome = if saw_challenge {
                        Outcome::Challenged
                    } else {
                        Outcome::Success
                    };
                    self.record_for_host(host.as_deref(), outcome)?;
                    return Ok(signal);
                }
                Action::Fail { reason } => {
                    let outcome = match signal.kind {
                        ChallengeKind::RateLimited => Outcome::RateLimited,
                        _ => Outcome::Blocked,
                    };
                    // Best-effort: keep the original challenge error if recording fails.
                    let _ = self.record_for_host(host.as_deref(), outcome);
                    return Err(Error::Challenge(reason));
                }
                Action::Wait {
                    delay,
                    attempt: next,
                } => {
                    saw_challenge = true;
                    if signal.kind == ChallengeKind::Turnstile {
                        // Best-effort: click the interactive widget. A failure here
                        // is non-fatal; the browser may still resolve on its own.
                        let _ = GenericSolver::solve_cloudflare_turnstile(tab);
                    }
                    std::thread::sleep(delay);
                    attempt = next;
                }
                Action::RotateProxy { attempt: next } => {
                    saw_challenge = true;
                    self.rotate_proxy()?;
                    tab.reload(true, None)
                        .map_err(|e| Error::BrowserError(format!("Reload failed: {e:?}")))?;
                    tab.wait_until_navigated().map_err(|e| {
                        Error::BrowserError(format!("Navigation after rotation failed: {e:?}"))
                    })?;
                    attempt = next;
                }
            }
        }
    }

    /// Reads the persisted [`DomainState`] for `host`, if a store is configured
    /// and a record exists.
    pub fn domain_state(&self, host: &str) -> Result<Option<DomainState>, Error> {
        match &self.store {
            Some(store) => store.get(host),
            None => Ok(None),
        }
    }

    /// Records `outcome` for `host` in the configured state store (no-op if none).
    ///
    /// The current egress proxy is captured, and a [`Outcome::RateLimited`] sets a
    /// cooldown so callers can back off via [`Self::cooldown_remaining`].
    pub fn record_outcome(&self, host: &str, outcome: Outcome) -> Result<(), Error> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let now = now_unix();
        let proxy = self
            .pool
            .lock()
            .expect("proxy pool lock poisoned")
            .selected()
            .map(str::to_owned);
        let current = store.get(host)?.unwrap_or_else(|| DomainState::new(host));
        let updated = current.record(outcome, proxy, now, RATE_LIMIT_COOLDOWN);
        store.put(&updated)
    }

    /// Remaining rate-limit cooldown for `host`, if any.
    pub fn cooldown_remaining(&self, host: &str) -> Result<Option<Duration>, Error> {
        Ok(self
            .domain_state(host)?
            .and_then(|state| state.cooldown_remaining(now_unix())))
    }

    fn record_for_host(&self, host: Option<&str>, outcome: Outcome) -> Result<(), Error> {
        match host {
            Some(host) => self.record_outcome(host, outcome),
            None => Ok(()),
        }
    }

    fn tab_host(tab: &Arc<headless_chrome::Tab>) -> Option<String> {
        wreq::Url::parse(&tab.get_url())
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
    }

    /// Retires the current egress proxy and hot-swaps the MITM client to the next
    /// healthy one in the pool. Returns [`Error::Challenge`] if no proxy remains.
    fn rotate_proxy(&self) -> Result<(), Error> {
        let proxy = self.proxy.as_ref().ok_or_else(|| {
            Error::Challenge("proxy rotation requires the MITM proxy".to_string())
        })?;

        let next = {
            let mut pool = self.pool.lock().expect("proxy pool lock poisoned");
            pool.rotate()
        }
        .ok_or_else(|| Error::Challenge("no healthy proxy left to rotate to".to_string()))?;

        let client = build_impersonation_client(&self.profile, Some(&next))?;
        proxy.set_upstream_client(client);
        Ok(())
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

    #[test]
    fn test_scraper_builder_default_challenge_attempts() {
        let builder = CloudScraper::builder();
        assert_eq!(
            builder.max_challenge_attempts,
            MitigationPolicy::default().max_attempts
        );
    }

    #[test]
    fn test_scraper_builder_with_max_challenge_attempts() {
        let builder = CloudScraper::builder().with_max_challenge_attempts(7);
        assert_eq!(builder.max_challenge_attempts, 7);
    }

    #[test]
    fn test_scraper_builder_upstream_proxy_adds_to_pool() {
        let builder = CloudScraper::builder()
            .upstream_proxy("http://a:1".to_string())
            .upstream_proxy("http://b:2".to_string());
        assert_eq!(builder.proxies, vec!["http://a:1", "http://b:2"]);
    }

    #[test]
    fn test_scraper_builder_with_proxies_and_strategy() {
        let builder = CloudScraper::builder()
            .with_proxies(["http://a:1".to_string(), "http://b:2".to_string()])
            .proxy_strategy(RotationStrategy::Random);
        assert_eq!(builder.proxies.len(), 2);
        assert_eq!(builder.rotation_strategy, RotationStrategy::Random);
    }

    #[test]
    fn test_scraper_builder_default_strategy_is_round_robin() {
        let builder = CloudScraper::builder();
        assert_eq!(builder.rotation_strategy, RotationStrategy::RoundRobin);
        assert!(builder.proxies.is_empty());
    }

    #[test]
    fn test_scraper_builder_state_store_defaults_none_and_sets() {
        assert!(CloudScraper::builder().state_store.is_none());

        let store: Arc<dyn StateStore> = Arc::new(crate::state::InMemoryStateStore::new());
        let builder = CloudScraper::builder().with_state_store(store);
        assert!(builder.state_store.is_some());
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
