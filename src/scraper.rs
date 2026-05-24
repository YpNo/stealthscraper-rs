#![cfg(feature = "browser")]

use crate::challenge::{Action, ChallengeKind, ChallengeSignal, DetectionInput, MitigationPolicy};
use crate::events::{EventSink, NoopEventSink, ScraperEvent};
use crate::geo::{CountryCode, GeoResolver, Locale};
use crate::profile::BrowserProfile;
use crate::proxy::TlsSpoofingProxy;
use crate::proxy_pool::{ProxyPool, RotationStrategy};
use crate::solver::GenericSolver;
use crate::state::{DomainState, Outcome, StateStore};
use crate::stealth::generate_stealth_js;
use headless_chrome::{Browser, LaunchOptions};
use std::ffi::OsString;
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

/// Strip any `user:password@` userinfo from a proxy URL so credentials are never
/// written to logs, events, or the persisted state store.
///
/// The real (credentialed) URL is only ever handed to the `wreq` client for the
/// actual connection; everything observable is redacted.
fn redact_proxy_url(url: &str) -> String {
    if let Ok(mut parsed) = wreq::Url::parse(url) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
        return parsed.to_string();
    }
    // Unparseable: best-effort drop of anything before an '@' (possible userinfo).
    match url.split_once('@') {
        Some((_userinfo, rest)) => format!("***@{rest}"),
        None => url.to_string(),
    }
}

/// Resolve the locale for a proxy: prefer its explicit country tag, else ask the
/// optional [`GeoResolver`], then map the country to a curated [`Locale`].
fn resolve_locale(
    country: Option<CountryCode>,
    url: Option<&str>,
    resolver: Option<&Arc<dyn GeoResolver>>,
) -> Option<Locale> {
    let country = country.or_else(|| resolver?.country_of(url?))?;
    Locale::for_country(country)
}

/// Launch a headless Chrome instance for `profile`.
///
/// `proxy_port` points Chrome at the local MITM proxy (loopback); when absent,
/// `direct_upstream` (if any) is used as Chrome's proxy directly. Shared by the
/// initial build and profile rotation so both produce an identical launch.
fn launch_browser(
    profile: &BrowserProfile,
    proxy_port: Option<u16>,
    direct_upstream: Option<&str>,
    headless: bool,
    debug: bool,
) -> Result<Browser, Error> {
    let mut args = vec![
        OsString::from("--disable-blink-features=AutomationControlled"),
        OsString::from(format!("--user-agent={}", profile.user_agent)),
        OsString::from(format!("--accept-lang={}", profile.accept_language)),
        OsString::from("--disable-gpu"),
        OsString::from("--no-sandbox"),
        OsString::from("--disable-dev-shm-usage"),
    ];

    if let Some(port) = proxy_port {
        args.push(OsString::from(format!(
            "--proxy-server=http://127.0.0.1:{port}"
        )));
        args.push(OsString::from("--proxy-bypass-list=<-loopback>"));
        if debug {
            log::debug!("browser args: {args:?}");
        }
        args.push(OsString::from("--ignore-certificate-errors")); // accept our MITM cert
    } else if let Some(upstream) = direct_upstream {
        // MITM disabled but an upstream exists: bind Chrome to it directly.
        args.push(OsString::from(format!("--proxy-server={upstream}")));
    }

    let launch_options = LaunchOptions::default_builder()
        .headless(headless)
        .window_size(Some((profile.viewport_width, profile.viewport_height)))
        .idle_browser_timeout(BROWSER_IDLE_TIMEOUT)
        .args(args.iter().map(|s| s.as_os_str()).collect())
        .build()
        .map_err(|e| Error::BrowserError(format!("Failed to build launch options: {e}")))?;

    Browser::new(launch_options)
        .map_err(|e| Error::BrowserError(format!("Failed to launch browser: {e}")))
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
    /// Observability sink for scrape events.
    events: Arc<dyn EventSink>,
    /// Optional resolver for a proxy's exit country (used when untagged).
    geo_resolver: Option<Arc<dyn GeoResolver>>,
    /// Locale currently applied to new tabs, derived from the selected proxy.
    locale: Mutex<Option<Locale>>,
    /// Whether the browser runs headless (retained for profile-rotation relaunch).
    headless: bool,
    /// Whether proxy debug logging is on (retained for profile-rotation relaunch).
    debug_mode: bool,
}

/// Builder pattern for orchestrating a new `CloudScraper` instance.
pub struct CloudScraperBuilder {
    profile: Option<BrowserProfile>,
    use_tls_proxy: bool,
    debug_mode: bool,
    headless: bool,
    proxies: Vec<(String, Option<CountryCode>)>,
    rotation_strategy: RotationStrategy,
    max_challenge_attempts: u32,
    state_store: Option<Arc<dyn StateStore>>,
    event_sink: Option<Arc<dyn EventSink>>,
    geo_resolver: Option<Arc<dyn GeoResolver>>,
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
            event_sink: None,
            geo_resolver: None,
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
        self.proxies.push((proxy, None));
        self
    }

    /// Registers a pool of upstream proxies that rotation can switch between when
    /// the current egress IP gets hard-blocked.
    pub fn with_proxies(mut self, proxies: impl IntoIterator<Item = String>) -> Self {
        self.proxies
            .extend(proxies.into_iter().map(|url| (url, None)));
        self
    }

    /// Registers upstream proxies tagged with their exit country, enabling
    /// proxy-led locale derivation (Accept-Language, `navigator.languages`, and
    /// timezone are matched to the selected proxy's country).
    pub fn with_geo_proxies(
        mut self,
        proxies: impl IntoIterator<Item = (String, CountryCode)>,
    ) -> Self {
        self.proxies
            .extend(proxies.into_iter().map(|(url, cc)| (url, Some(cc))));
        self
    }

    /// Sets a resolver used to discover a proxy's exit country when it was not
    /// tagged explicitly (e.g. a GeoIP-backed implementation).
    pub fn with_geo_resolver(mut self, resolver: Arc<dyn GeoResolver>) -> Self {
        self.geo_resolver = Some(resolver);
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

    /// Attaches an observability sink (e.g. `LogEventSink`, or your own) that
    /// receives [`ScraperEvent`]s during [`CloudScraper::solve_challenge`].
    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
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
        let pool = ProxyPool::with_endpoints(self.proxies.clone(), self.rotation_strategy);
        let initial_upstream = pool.selected().map(str::to_owned);

        // Proxy-led locale: derive the browser locale from the selected proxy's
        // country so the IP and the browser's language/timezone tell one story.
        let locale = resolve_locale(
            pool.selected_country(),
            initial_upstream.as_deref(),
            self.geo_resolver.as_ref(),
        );

        let proxy = if self.use_tls_proxy {
            let impersonate_client =
                build_impersonation_client(&profile, initial_upstream.as_deref())?;
            // Start the local TLS proxy
            Some(TlsSpoofingProxy::start(impersonate_client, self.debug_mode).await?)
        } else {
            None
        };

        let browser = launch_browser(
            &profile,
            proxy.as_ref().map(TlsSpoofingProxy::port),
            if proxy.is_none() {
                initial_upstream.as_deref()
            } else {
                None
            },
            self.headless,
            self.debug_mode,
        )?;

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
            events: self.event_sink.unwrap_or_else(|| Arc::new(NoopEventSink)),
            geo_resolver: self.geo_resolver,
            locale: Mutex::new(locale),
            headless: self.headless,
            debug_mode: self.debug_mode,
        })
    }
}

impl CloudScraper {
    /// Start building a `CloudScraper` instance.
    pub fn builder() -> CloudScraperBuilder {
        CloudScraperBuilder::new()
    }

    /// Creates a new stealthy tab ready for navigation.
    ///
    /// Injects the stealth script (with `navigator.languages` matching the active
    /// locale) and applies the locale's Accept-Language/timezone/locale via CDP so
    /// the browser's geo signals stay coherent with the egress proxy's country.
    pub fn new_stealth_tab(&self) -> Result<Arc<headless_chrome::Tab>, Error> {
        let tab = self
            .browser
            .new_tab()
            .map_err(|e| Error::BrowserError(format!("Failed to create new tab: {:?}", e)))?;

        let locale = self.locale.lock().expect("locale lock poisoned").clone();
        let languages = match &locale {
            Some(loc) => loc.languages.clone(),
            None => crate::geo::languages_from_accept_language(&self.profile.accept_language),
        };

        // Inject our stealth script to override navigator, WebGL, languages, etc.
        let stealth_script = generate_stealth_js(&self.profile, &languages);

        tab.call_method(
            headless_chrome::protocol::cdp::Page::AddScriptToEvaluateOnNewDocument {
                source: stealth_script,
                world_name: None,
                include_command_line_api: None,
                run_immediately: None,
            },
        )
        .map_err(|e| Error::BrowserError(format!("Failed to inject stealth script: {:?}", e)))?;

        self.apply_locale_overrides(&tab, locale.as_ref())?;

        Ok(tab)
    }

    /// Applies the locale's Accept-Language, timezone, and locale to `tab` via CDP.
    ///
    /// These `Emulation`/`Network` overrides persist for the tab's session (they
    /// survive reloads), so this is called once at tab creation and again after a
    /// proxy rotation that changes the egress country. A `None` locale leaves the
    /// browser defaults untouched.
    fn apply_locale_overrides(
        &self,
        tab: &Arc<headless_chrome::Tab>,
        locale: Option<&Locale>,
    ) -> Result<(), Error> {
        let Some(locale) = locale else {
            return Ok(());
        };

        tab.set_user_agent(
            &self.profile.user_agent,
            Some(&locale.accept_language),
            Some(&self.profile.platform),
        )
        .map_err(|e| Error::BrowserError(format!("Failed to set Accept-Language: {e:?}")))?;

        tab.call_method(
            headless_chrome::protocol::cdp::Emulation::SetTimezoneOverride {
                timezone_id: locale.timezone.clone(),
            },
        )
        .map_err(|e| Error::BrowserError(format!("Failed to set timezone: {e:?}")))?;

        tab.call_method(
            headless_chrome::protocol::cdp::Emulation::SetLocaleOverride {
                locale: Some(locale.primary_language().to_string()),
            },
        )
        .map_err(|e| Error::BrowserError(format!("Failed to set locale: {e:?}")))?;

        Ok(())
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
    ///
    /// # Blocking
    ///
    /// Like the rest of this CDP-driven API, this is a **synchronous, blocking**
    /// call: it uses `std::thread::sleep` for back-off and blocks on CDP I/O. On
    /// an async runtime, call it from a blocking context
    /// (`tokio::task::spawn_blocking`), and run the [`TlsSpoofingProxy`] on a
    /// multi-threaded runtime — otherwise a back-off can starve the executor that
    /// serves the proxy the page is loading through.
    pub fn solve_challenge(
        &self,
        tab: &Arc<headless_chrome::Tab>,
    ) -> Result<ChallengeSignal, Error> {
        let host = Self::tab_host(tab);
        let host_ref = host.as_deref();
        let mut attempt = 0u32;
        let mut saw_challenge = false;
        loop {
            let signal = self.detect_challenge(tab)?;
            if signal.is_challenge() {
                self.events.emit(&ScraperEvent::ChallengeDetected {
                    host: host_ref,
                    kind: signal.kind,
                });
            }
            match self.policy.decide(&signal, attempt) {
                Action::Proceed => {
                    let outcome = if saw_challenge {
                        Outcome::Challenged
                    } else {
                        Outcome::Success
                    };
                    self.events.emit(&ScraperEvent::SolveSucceeded {
                        host: host_ref,
                        attempts: attempt,
                        challenged: saw_challenge,
                    });
                    self.record_for_host(host_ref, outcome)?;
                    return Ok(signal);
                }
                Action::Fail { reason } => {
                    let outcome = match signal.kind {
                        ChallengeKind::RateLimited => Outcome::RateLimited,
                        _ => Outcome::Blocked,
                    };
                    self.events.emit(&ScraperEvent::SolveFailed {
                        host: host_ref,
                        kind: signal.kind,
                        reason: &reason,
                    });
                    // Best-effort: keep the original challenge error if recording fails.
                    let _ = self.record_for_host(host_ref, outcome);
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
                    self.events.emit(&ScraperEvent::Waiting {
                        host: host_ref,
                        kind: signal.kind,
                        delay,
                    });
                    std::thread::sleep(delay);
                    attempt = next;
                }
                Action::RotateProxy { attempt: next } => {
                    saw_challenge = true;
                    // If the pool is exhausted, rotation fails: treat it as a
                    // terminal block and record it like the `Fail` arm (so the
                    // SolveFailed event and Outcome are still emitted), rather
                    // than short-circuiting with an unrecorded error.
                    if let Err(err) = self.rotate_proxy() {
                        let reason = match &err {
                            Error::Challenge(r) => r.clone(),
                            other => other.to_string(),
                        };
                        self.events.emit(&ScraperEvent::SolveFailed {
                            host: host_ref,
                            kind: signal.kind,
                            reason: &reason,
                        });
                        let _ = self.record_for_host(host_ref, Outcome::Blocked);
                        return Err(err);
                    }
                    // Re-apply the (possibly new-country) locale before reloading so
                    // the refreshed request's geo signals match the new egress.
                    let locale = self.locale.lock().expect("locale lock poisoned").clone();
                    self.apply_locale_overrides(tab, locale.as_ref())?;
                    // Redact credentials before the URL reaches the event sink/logs.
                    let upstream = self
                        .pool
                        .lock()
                        .expect("proxy pool lock poisoned")
                        .selected()
                        .map(redact_proxy_url);
                    self.events.emit(&ScraperEvent::ProxyRotated {
                        host: host_ref,
                        upstream: upstream.as_deref(),
                    });
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
        // Redact credentials: the persisted `last_proxy` must never hold `user:pass@`.
        let proxy = self
            .pool
            .lock()
            .expect("proxy pool lock poisoned")
            .selected()
            .map(redact_proxy_url);
        // Atomic read-modify-write so concurrent records on a shared scraper don't
        // lose updates.
        store.update(host, &mut |current| {
            current.record(outcome, proxy.clone(), now, RATE_LIMIT_COOLDOWN)
        })?;
        Ok(())
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
            None => {
                if self.store.is_some() {
                    log::debug!(
                        "skipping per-host state record ({outcome:?}): current tab URL has no host"
                    );
                }
                Ok(())
            }
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

        let (next, country) = {
            let mut pool = self.pool.lock().expect("proxy pool lock poisoned");
            let next = pool.rotate().ok_or_else(|| {
                Error::Challenge("no healthy proxy left to rotate to".to_string())
            })?;
            (next, pool.selected_country())
        };

        let client = build_impersonation_client(&self.profile, Some(&next))?;
        proxy.set_upstream_client(client);

        // Proxy-led: the new egress may be in a different country, so re-derive
        // the locale to keep the browser's geo signals coherent.
        let new_locale = resolve_locale(country, Some(&next), self.geo_resolver.as_ref());
        *self.locale.lock().expect("locale lock poisoned") = new_locale;
        Ok(())
    }

    /// Rotates the browser fingerprint by relaunching Chrome under a fresh random
    /// [`BrowserProfile`]. See [`Self::rotate_profile_with`].
    pub fn rotate_profile(self) -> Result<CloudScraper, Error> {
        self.rotate_profile_with(BrowserProfile::random())
    }

    /// Rotates the browser fingerprint to `profile`, **keeping the same egress IP**.
    ///
    /// Profile rotation cannot be done in place — the User-Agent and other launch
    /// flags are fixed at process start — so this **relaunches Chrome** and returns
    /// a fresh scraper, discarding the old browser and all its tabs/session state.
    /// The MITM proxy (and its port) and the current upstream proxy are preserved;
    /// only the impersonation client and browser are rebuilt for the new identity.
    ///
    /// Because it consumes `self`, it is necessarily caller-driven (it cannot run
    /// inside the tab-scoped [`Self::solve_challenge`]). Use it when a site has
    /// blocked the browser *identity* rather than the IP; for a burned IP the
    /// automatic proxy rotation inside [`Self::solve_challenge`] handles it
    /// without a relaunch.
    pub fn rotate_profile_with(self, profile: BrowserProfile) -> Result<CloudScraper, Error> {
        // Snapshot the current egress so the relaunched browser keeps the exit IP.
        let (upstream, country) = {
            let pool = self.pool.lock().expect("proxy pool lock poisoned");
            (pool.selected().map(str::to_owned), pool.selected_country())
        };

        // Rebuild the impersonation client for the new fingerprint (same egress).
        if let Some(proxy) = &self.proxy {
            let client = build_impersonation_client(&profile, upstream.as_deref())?;
            proxy.set_upstream_client(client);
        }

        // Relaunch Chrome on the same MITM port (or same direct upstream).
        let proxy_port = self.proxy.as_ref().map(|p| p.port());
        let direct_upstream = if self.proxy.is_none() {
            upstream.as_deref()
        } else {
            None
        };
        let browser = launch_browser(
            &profile,
            proxy_port,
            direct_upstream,
            self.headless,
            self.debug_mode,
        )?;

        // Egress is unchanged, but re-derive the locale defensively.
        let locale = resolve_locale(country, upstream.as_deref(), self.geo_resolver.as_ref());

        self.events.emit(&ScraperEvent::ProfileRotated {
            user_agent: &profile.user_agent,
        });

        Ok(CloudScraper {
            profile,
            proxy: self.proxy,
            browser,
            policy: self.policy,
            pool: self.pool,
            store: self.store,
            events: self.events,
            geo_resolver: self.geo_resolver,
            locale: Mutex::new(locale),
            headless: self.headless,
            debug_mode: self.debug_mode,
        })
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
        let urls: Vec<&str> = builder.proxies.iter().map(|(u, _)| u.as_str()).collect();
        assert_eq!(urls, vec!["http://a:1", "http://b:2"]);
        assert!(builder.proxies.iter().all(|(_, c)| c.is_none()));
    }

    #[test]
    fn test_scraper_builder_geo_proxies_carry_country() {
        let de = CountryCode::new("DE").unwrap();
        let builder = CloudScraper::builder().with_geo_proxies([("http://de:1".to_string(), de)]);
        assert_eq!(builder.proxies, vec![("http://de:1".to_string(), Some(de))]);
    }

    #[test]
    fn test_scraper_builder_geo_resolver_defaults_none_and_sets() {
        assert!(CloudScraper::builder().geo_resolver.is_none());

        struct FixedResolver;
        impl crate::geo::GeoResolver for FixedResolver {
            fn country_of(&self, _: &str) -> Option<CountryCode> {
                CountryCode::new("FR")
            }
        }
        let builder = CloudScraper::builder().with_geo_resolver(Arc::new(FixedResolver));
        assert!(builder.geo_resolver.is_some());
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

    #[test]
    fn redact_proxy_url_strips_credentials() {
        assert_eq!(
            redact_proxy_url("http://user:pass@proxy.example:8080"),
            "http://proxy.example:8080/"
        );
        // No credentials → unchanged host/port (modulo URL normalisation).
        assert_eq!(
            redact_proxy_url("http://proxy.example:8080"),
            "http://proxy.example:8080/"
        );
        // SOCKS scheme credentials are also stripped.
        assert!(!redact_proxy_url("socks5://u:secret@1.2.3.4:1080").contains("secret"));
        // Unparseable-as-URL but with userinfo → still redacted via the fallback.
        assert_eq!(redact_proxy_url("//u:pw@host:3128"), "***@host:3128");
    }

    #[test]
    fn resolve_locale_prefers_tag_then_resolver_then_none() {
        struct FrResolver;
        impl crate::geo::GeoResolver for FrResolver {
            fn country_of(&self, _: &str) -> Option<CountryCode> {
                CountryCode::new("FR")
            }
        }
        let resolver: Arc<dyn GeoResolver> = Arc::new(FrResolver);

        // Explicit tag wins.
        let de = CountryCode::new("DE");
        let loc = resolve_locale(de, Some("http://p"), Some(&resolver)).unwrap();
        assert_eq!(loc.timezone, "Europe/Berlin");

        // No tag -> fall back to the resolver.
        let loc = resolve_locale(None, Some("http://p"), Some(&resolver)).unwrap();
        assert_eq!(loc.country, CountryCode::new("FR").unwrap());

        // No tag and no resolver -> None.
        assert!(resolve_locale(None, Some("http://p"), None).is_none());
    }

    #[test]
    fn test_scraper_builder_event_sink_defaults_none_and_sets() {
        assert!(CloudScraper::builder().event_sink.is_none());

        let sink: Arc<dyn EventSink> = Arc::new(crate::events::LogEventSink);
        let builder = CloudScraper::builder().with_event_sink(sink);
        assert!(builder.event_sink.is_some());
    }

    fn profile_with_ua(user_agent: &str) -> BrowserProfile {
        BrowserProfile {
            user_agent: user_agent.to_string(),
            platform: "Win32".to_string(),
            hardware_concurrency: 8,
            device_memory: 16,
            webgl_vendor: "Google Inc. (NVIDIA)".to_string(),
            webgl_renderer: "ANGLE (NVIDIA)".to_string(),
            viewport_width: 1280,
            viewport_height: 800,
            accept_language: "en-US,en;q=0.9".to_string(),
        }
    }

    fn write_temp_html(name: &str, html: &str) -> String {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, html).expect("write temp html");
        format!("file://{}", path.display())
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn test_state_methods_record_and_read() {
        let store: Arc<dyn StateStore> = Arc::new(crate::state::InMemoryStateStore::new());
        let scraper = CloudScraper::builder()
            .disable_proxy()
            .headless(true)
            .profile(profile_with_ua("UA-STATE"))
            .with_state_store(Arc::clone(&store))
            .build()
            .await
            .expect("Failed to build scraper");

        assert!(scraper.domain_state("example.com").unwrap().is_none());

        scraper
            .record_outcome("example.com", Outcome::RateLimited)
            .unwrap();
        let state = scraper.domain_state("example.com").unwrap().unwrap();
        assert_eq!(state.failures, 1);
        assert_eq!(state.last_outcome, Some(Outcome::RateLimited));
        assert!(scraper.cooldown_remaining("example.com").unwrap().is_some());

        // A success clears the cooldown.
        scraper
            .record_outcome("example.com", Outcome::Success)
            .unwrap();
        assert!(scraper.cooldown_remaining("example.com").unwrap().is_none());
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn test_solve_challenge_clean_page_succeeds() {
        let scraper = CloudScraper::builder()
            .disable_proxy()
            .headless(true)
            .profile(profile_with_ua("UA-CLEAN"))
            .build()
            .await
            .expect("Failed to build scraper");

        let tab = scraper.new_stealth_tab().expect("new tab");
        let url = write_temp_html(
            "rscs_clean.html",
            "<html><body>perfectly ordinary content</body></html>",
        );
        tab.navigate_to(&url).expect("navigate");
        tab.wait_until_navigated().expect("navigated");

        let signal = scraper.solve_challenge(&tab).expect("solve");
        assert_eq!(signal.kind, ChallengeKind::None);
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn test_solve_challenge_turnstile_exhausts_and_fails() {
        let scraper = CloudScraper::builder()
            .disable_proxy()
            .headless(true)
            .with_max_challenge_attempts(1)
            .profile(profile_with_ua("UA-CHAL"))
            .build()
            .await
            .expect("Failed to build scraper");

        let tab = scraper.new_stealth_tab().expect("new tab");
        // A static Turnstile page never clears: exercises the Turnstile wait branch
        // (best-effort solver click) and the terminal failure.
        let url = write_temp_html(
            "rscs_turnstile.html",
            "<html><body><div class=\"cf-turnstile\" style=\"width:300px;height:65px;\"></div></body></html>",
        );
        tab.navigate_to(&url).expect("navigate");
        tab.wait_until_navigated().expect("navigated");

        let result = scraper.solve_challenge(&tab);
        assert!(matches!(result, Err(Error::Challenge(_))));
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn test_rotate_profile_swaps_identity_and_relaunches() {
        let scraper = CloudScraper::builder()
            .disable_proxy()
            .headless(true)
            .profile(profile_with_ua("UA-BEFORE"))
            .build()
            .await
            .expect("Failed to build scraper");
        assert_eq!(scraper.profile.user_agent, "UA-BEFORE");

        let scraper = scraper
            .rotate_profile_with(profile_with_ua("UA-AFTER"))
            .expect("Failed to rotate profile");
        assert_eq!(scraper.profile.user_agent, "UA-AFTER");

        // The relaunched browser must be usable.
        let _tab = scraper
            .new_stealth_tab()
            .expect("new tab after rotation failed");
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
