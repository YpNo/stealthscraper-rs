#![cfg(feature = "browser")]

use crate::cdp::{BrowserHandle, CdpTransport, LaunchConfig, Page, launch};
use crate::challenge::{Action, ChallengeKind, ChallengeSignal, DetectionInput, MitigationPolicy};
use crate::events::{EventSink, NoopEventSink, ScraperEvent};
use crate::geo::{CountryCode, GeoResolver, Locale};
use crate::profile::BrowserProfile;
use crate::proxy::TlsSpoofingProxy;
use crate::proxy_pool::{ProxyPool, RotationStrategy};
use crate::solver::GenericSolver;
use crate::state::{DomainState, Outcome, StateStore};
use crate::stealth::generate_stealth_js;
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
pub(crate) fn build_impersonation_client(
    profile: &BrowserProfile,
    upstream: Option<&str>,
) -> Result<wreq::Client, Error> {
    let mut builder = wreq::Client::builder();

    // Derive the fingerprint from the profile's own User-Agent so the JA4
    // signature and the advertised browser can never contradict each other.
    builder = builder.emulation(crate::emulation::for_kind(profile.browser_kind()));

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

/// Launch a browser for `profile` and connect CDP to it over its pipe.
///
/// `proxy_port` points the browser at the local MITM proxy (loopback); when
/// absent, `direct_upstream` (if any) is used as its proxy directly. Shared by
/// the initial build and profile rotation so both produce an identical launch.
fn launch_browser(
    profile: &BrowserProfile,
    proxy: Option<&TlsSpoofingProxy>,
    direct_upstream: Option<&str>,
    headless: bool,
) -> Result<BrowserHandle, Error> {
    // The identity comes from the profile, so the launched browser's
    // User-Agent cannot disagree with the JA4 signature on the wire.
    let mut config = LaunchConfig::for_profile(profile);
    config.headless = headless;

    if let Some(proxy) = proxy {
        config.proxy_server = Some(format!("http://127.0.0.1:{}", proxy.port()));
        // Trust exactly this proxy's CA key rather than disabling certificate
        // checking: an upstream that tampered with a real site would still be
        // rejected, which `--ignore-certificate-errors` would not do.
        config.trusted_spki = Some(proxy.ca_spki_pin()?);
    } else if let Some(upstream) = direct_upstream {
        // MITM disabled but an upstream exists: bind the browser to it directly.
        config.proxy_server = Some(upstream.to_string());
    }

    let browser = launch(&config)?;
    Ok(BrowserHandle::new(CdpTransport::connect(browser)?))
}

/// How long to wait for a page load the scraper itself triggers.
const PAGE_LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// The main entry point for managing a stealthy browser instance.
///
/// `CloudScraper` owns a browser driven over this crate's own CDP client and
/// injects stealth configuration (via `BrowserProfile` and stealth JavaScript)
/// to make scraping tasks hard for modern bot-protection systems to identify.
///
/// # Blocking
///
/// Every browser-driving method is `async` and never blocks a worker thread.
/// Back-off waits use `tokio::time::sleep`, so a wait cannot starve the
/// executor that serves the proxy the page is loading through.
pub struct CloudScraper {
    /// The browser profile (fingerprint) being used.
    pub profile: BrowserProfile,
    /// The local TLS MITM proxy instance (kept alive with the scraper)
    pub proxy: Option<Arc<TlsSpoofingProxy>>,
    /// The browser, driven over CDP.
    browser: BrowserHandle,
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
            proxy.as_ref(),
            if proxy.is_none() {
                initial_upstream.as_deref()
            } else {
                None
            },
            self.headless,
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

    /// Creates a new stealthy page, ready for navigation.
    ///
    /// Injects the stealth script (with `navigator.languages` matching the
    /// active locale) and applies the locale's Accept-Language/timezone/locale
    /// via CDP so the browser's geo signals stay coherent with the egress
    /// proxy's country.
    ///
    /// The page starts blank, so the stealth script is installed *before* any
    /// document loads and a page cannot capture the originals first. Navigate
    /// it with [`Page::navigate_and_wait`].
    pub async fn new_stealth_page(&self) -> Result<Page, Error> {
        let page = self.browser.new_page("about:blank").await?;

        let locale = self.locale.lock().expect("locale lock poisoned").clone();
        let languages = match &locale {
            Some(loc) => loc.languages.clone(),
            None => crate::geo::languages_from_accept_language(&self.profile.accept_language),
        };

        // Override navigator, WebGL, languages and the rest ahead of the page.
        page.add_init_script(&generate_stealth_js(&self.profile, &languages))
            .await?;

        self.apply_locale_overrides(&page, locale.as_ref()).await?;

        Ok(page)
    }

    /// Applies the locale's Accept-Language, timezone, and locale to `page`.
    ///
    /// These `Emulation` overrides persist for the page's session (they survive
    /// reloads), so this is called once at page creation and again after a proxy
    /// rotation that changes the egress country. A `None` locale leaves the
    /// browser defaults untouched.
    async fn apply_locale_overrides(
        &self,
        page: &Page,
        locale: Option<&Locale>,
    ) -> Result<(), Error> {
        let Some(locale) = locale else {
            // No locale to apply, but the Client Hints still have to agree with
            // the User-Agent — that coherence does not depend on a proxy.
            return self.apply_client_hints(page).await;
        };

        page.set_user_agent(
            &self.profile.user_agent,
            Some(&locale.accept_language),
            Some(&self.profile.platform),
            // Without these the browser derives its Client Hints from its own
            // build, so `navigator.userAgentData` contradicts the User-Agent we
            // just set. `None` for Safari, which implements no Client Hints.
            crate::client_hints::ClientHints::for_profile(&self.profile)
                .map(|hints| hints.to_cdp_metadata()),
        )
        .await?;
        page.set_timezone(&locale.timezone).await?;
        page.set_locale(locale.primary_language()).await?;
        page.set_viewport(self.profile.viewport_width, self.profile.viewport_height)
            .await?;

        Ok(())
    }

    /// Every cookie the browser holds.
    ///
    /// This is how a cleared session leaves the browser: without it, escalating
    /// would solve a challenge and then throw away the proof.
    pub async fn browser_cookies(&self) -> Result<Vec<crate::identity::Cookie>, Error> {
        self.browser.cookies().await
    }

    /// Installs `cookies` into the browser.
    ///
    /// Used when a session escalates, so the browser starts from whatever the
    /// HTTP leg already held rather than as a stranger.
    pub async fn set_browser_cookies(
        &self,
        cookies: &[crate::identity::Cookie],
    ) -> Result<(), Error> {
        self.browser.set_cookies(cookies).await
    }

    /// Makes the page's Client Hints agree with the profile's User-Agent.
    ///
    /// Applied even when no locale is known: a browser whose
    /// `navigator.userAgentData` contradicts its own `navigator.userAgent` is
    /// reporting something no real browser can.
    async fn apply_client_hints(&self, page: &Page) -> Result<(), Error> {
        let Some(hints) = crate::client_hints::ClientHints::for_profile(&self.profile) else {
            // Safari sends no Client Hints; emitting any would be the anomaly.
            return Ok(());
        };

        page.set_user_agent(
            &self.profile.user_agent,
            Some(&self.profile.accept_language),
            Some(&self.profile.platform),
            Some(hints.to_cdp_metadata()),
        )
        .await?;

        // The screen has to agree with the window whether or not a locale is
        // known; a window larger than its own display is a one-line check.
        page.set_viewport(self.profile.viewport_width, self.profile.viewport_height)
            .await
    }

    /// Classifies the challenge (if any) currently rendered in `page`.
    ///
    /// Detection runs over the page's rendered DOM. HTTP status/headers are not
    /// available from the DOM, so they are left unset — body markers are
    /// sufficient to recognise Cloudflare's interstitial and Turnstile pages.
    pub async fn detect_challenge(&self, page: &Page) -> Result<ChallengeSignal, Error> {
        let body = page.content().await?;
        Ok(crate::challenge::detect(&DetectionInput::from_body(&body)))
    }

    /// Detects and attempts to clear any bot-protection challenge on `page`.
    ///
    /// Loops according to the configured [`MitigationPolicy`]: it waits for
    /// non-interactive challenges to auto-resolve in the real browser, and for
    /// an interactive Turnstile it makes a best-effort click via
    /// [`GenericSolver`] before waiting. Returns the final [`ChallengeSignal`]
    /// once the page is clear, or [`Error::Challenge`] if the budget is
    /// exhausted or the page is hard-blocked.
    pub async fn solve_challenge(&self, page: &Page) -> Result<ChallengeSignal, Error> {
        let host = Self::page_host(page).await;
        let host_ref = host.as_deref();
        let mut attempt = 0u32;
        let mut saw_challenge = false;
        loop {
            let signal = self.detect_challenge(page).await?;
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
                        let _ = GenericSolver::solve_cloudflare_turnstile(page).await;
                    }
                    self.events.emit(&ScraperEvent::Waiting {
                        host: host_ref,
                        kind: signal.kind,
                        delay,
                    });
                    tokio::time::sleep(delay).await;
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
                    self.apply_locale_overrides(page, locale.as_ref()).await?;
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
                    // Reload through the new egress and wait for the fresh
                    // document before the next detection pass.
                    page.reload_and_wait(true, PAGE_LOAD_TIMEOUT).await?;
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
                        "skipping per-host state record ({outcome:?}): current page URL has no host"
                    );
                }
                Ok(())
            }
        }
    }

    /// The host of the page's current URL, if it has one.
    async fn page_host(page: &Page) -> Option<String> {
        let url = page.url().await.ok()?;
        wreq::Url::parse(&url)
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
    pub async fn rotate_profile(self) -> Result<CloudScraper, Error> {
        self.rotate_profile_with(BrowserProfile::random()).await
    }

    /// Rotates the browser fingerprint to `profile`, **keeping the same egress IP**.
    ///
    /// Profile rotation cannot be done in place — the User-Agent and other launch
    /// flags are fixed at process start — so this **relaunches the browser** and
    /// returns a fresh scraper, discarding the old browser and all its
    /// pages/session state.
    /// The MITM proxy (and its port) and the current upstream proxy are preserved;
    /// only the impersonation client and browser are rebuilt for the new identity.
    ///
    /// Because it consumes `self`, it is necessarily caller-driven (it cannot run
    /// inside the page-scoped [`Self::solve_challenge`]). Use it when a site has
    /// blocked the browser *identity* rather than the IP; for a burned IP the
    /// automatic proxy rotation inside [`Self::solve_challenge`] handles it
    /// without a relaunch.
    pub async fn rotate_profile_with(self, profile: BrowserProfile) -> Result<CloudScraper, Error> {
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

        // Relaunch on the same MITM port (or the same direct upstream).
        let direct_upstream = if self.proxy.is_none() {
            upstream.as_deref()
        } else {
            None
        };
        let browser = launch_browser(
            &profile,
            self.proxy.as_deref(),
            direct_upstream,
            self.headless,
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

    /// Types `text` into the focused element with human-like delays.
    ///
    /// Each character is sent as a real key press, so the page's own
    /// `keydown`/`keyup` handlers see what they would for a human typist.
    pub async fn human_type_str(page: &Page, text: &str) -> Result<(), Error> {
        for character in text.chars() {
            tokio::time::sleep(crate::behavior::calculate_typing_delay()).await;
            page.press_key(character).await?;
        }
        Ok(())
    }

    /// Scrolls `selector` into view the way a wheel does.
    ///
    /// A page that jumps straight to an element's offset did not have a wheel
    /// behind it, so the distance is sent as a series of notches. Does nothing
    /// when the element is already visible, and reports `false` when it cannot
    /// be found at all.
    pub async fn human_scroll_into_view(page: &Page, selector: &str) -> Result<bool, Error> {
        let Some(distance) = page.scroll_distance_to(selector).await? else {
            return Ok(false);
        };
        if distance == 0.0 {
            return Ok(true);
        }

        // Scrolling happens under the pointer, so it needs somewhere plausible
        // to be: the middle of the viewport.
        let (x, y) = (SCROLL_ORIGIN_X, SCROLL_ORIGIN_Y);
        for notch in crate::behavior::scroll_increments(distance) {
            page.scroll_by(x, y, notch).await?;
            tokio::time::sleep(SCROLL_STEP_INTERVAL).await;
        }

        // A wheel event starts a scroll, it does not finish one: the page keeps
        // moving for several frames after the last notch is dispatched. A
        // caller that measures an element straight away gets the position it
        // held mid-animation, moves the pointer there, and clicks where the
        // target *was* — a miss, and one that only shows up when the machine is
        // loaded enough to widen the window.
        Self::wait_for_scroll_to_settle(page).await?;

        Ok(true)
    }

    /// Waits until `window.scrollY` stops changing, or the timeout expires.
    ///
    /// Two equal samples a frame apart is the signal: the scroll offset is the
    /// thing the click coordinate depends on, so it is the thing to synchronise
    /// on rather than a fixed sleep that is either too short or wasted.
    async fn wait_for_scroll_to_settle(page: &Page) -> Result<(), Error> {
        let deadline = tokio::time::Instant::now() + SCROLL_SETTLE_TIMEOUT;
        let mut previous: Option<f64> = None;

        while tokio::time::Instant::now() < deadline {
            let current = page
                .evaluate("window.scrollY")
                .await?
                .as_f64()
                .unwrap_or_default();
            if previous == Some(current) {
                return Ok(());
            }
            previous = Some(current);
            tokio::time::sleep(SCROLL_SETTLE_POLL).await;
        }

        // Timed out: measuring a moving target is still better than refusing to
        // click, so this is not an error.
        Ok(())
    }

    /// Scrolls to `selector`, travels to it, hesitates, and clicks it.
    ///
    /// The sequence is what distinguishes this from a synthesised click: a real
    /// pointer arrives over a path, settles for a moment while drifting, and only
    /// then presses. Each of those is individually cheap to check for.
    pub async fn human_click(page: &Page, selector: &str) -> Result<(), Error> {
        if !Self::human_scroll_into_view(page, selector).await? {
            return Err(Error::InteractionError(format!(
                "cannot click {selector}: no element with a box"
            )));
        }

        let Some((x, y)) = page.element_center(selector).await? else {
            return Err(Error::InteractionError(format!(
                "cannot click {selector}: it has no position"
            )));
        };

        Self::human_move_mouse(page, x, y).await?;
        Self::human_settle(page, x, y).await?;
        page.click_point(x, y).await
    }

    /// Holds near a point, drifting, as a hand does before pressing.
    pub async fn human_settle(page: &Page, x: f64, y: f64) -> Result<(), Error> {
        let around = crate::behavior::Point { x, y };
        for point in crate::behavior::idle_drift(around, IDLE_DRIFT_MOVES) {
            page.move_mouse(point.x, point.y).await?;
            tokio::time::sleep(crate::behavior::idle_step_delay()).await;
        }
        Ok(())
    }

    /// Moves the mouse to a target along a Bézier path rather than in a jump.
    ///
    /// A pointer that teleports to its target is trivially distinguishable from
    /// a hand; the intermediate moves are the point of this method.
    pub async fn human_move_mouse(page: &Page, end_x: f64, end_y: f64) -> Result<(), Error> {
        // The real cursor position is not readable over CDP, so the path starts
        // from a fixed plausible point rather than from an unknown one.
        let start = crate::behavior::Point { x: 100.0, y: 100.0 };
        let end = crate::behavior::Point { x: end_x, y: end_y };

        for point in crate::behavior::generate_mouse_path(start, end, MOUSE_PATH_POINTS) {
            page.move_mouse(point.x, point.y).await?;
            // Approximates the rate at which a real pointer reports movement.
            tokio::time::sleep(MOUSE_STEP_INTERVAL).await;
        }

        Ok(())
    }
}

/// Intermediate points along a simulated mouse path.
const MOUSE_PATH_POINTS: usize = 50;

/// Movements made while settling on a target before clicking it.
const IDLE_DRIFT_MOVES: usize = 3;

/// Where the pointer sits while scrolling, since a wheel event needs a position.
const SCROLL_ORIGIN_X: f64 = 640.0;
/// Vertical companion to [`SCROLL_ORIGIN_X`].
const SCROLL_ORIGIN_Y: f64 = 400.0;

/// Delay between wheel notches.
const SCROLL_STEP_INTERVAL: Duration = Duration::from_millis(30);

/// Gap between samples while waiting for scrolling to come to rest.
///
/// Roughly one frame at 60Hz, so two equal samples mean the page did not move
/// across a frame boundary.
const SCROLL_SETTLE_POLL: Duration = Duration::from_millis(16);

/// How long to wait for the scroll position to stop changing before giving up
/// and measuring anyway.
///
/// A bound rather than a promise: a page animating forever must not hang a
/// click, and measuring a still-moving target is no worse than not clicking.
const SCROLL_SETTLE_TIMEOUT: Duration = Duration::from_millis(750);

/// Delay between successive mouse-move events.
const MOUSE_STEP_INTERVAL: Duration = Duration::from_millis(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::BrowserKind;

    #[test]
    fn every_generated_profile_is_chrome_and_gets_the_chrome_emulation() {
        // The original defect was a Chrome/124-126 UA always shipping the
        // Chrome120 fingerprint. There is now one measured entry per family, so
        // the invariant to hold is that a generated profile's family maps to a
        // real entry rather than to a bare client.
        for _ in 0..200 {
            let profile = BrowserProfile::random();
            let BrowserKind::Chrome(major) = profile.browser_kind() else {
                panic!("expected a Chrome profile");
            };
            assert_eq!(
                major,
                crate::emulation::CHROME_MAJOR,
                "a generated UA claims a Chrome major with no measured emulation"
            );
            let _ = crate::emulation::for_kind(profile.browser_kind());
        }
    }

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

    /// A page with known content, needing neither a network nor a temp file.
    fn data_url(html: &str) -> String {
        format!("data:text/html,{}", html.replace('#', "%23"))
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

        let page = scraper.new_stealth_page().await.expect("new page");
        page.navigate_and_wait(
            &data_url("<html><body>perfectly ordinary content</body></html>"),
            PAGE_LOAD_TIMEOUT,
        )
        .await
        .expect("navigate");

        let signal = scraper.solve_challenge(&page).await.expect("solve");
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

        let page = scraper.new_stealth_page().await.expect("new page");
        // A static interstitial never clears: exercises the Turnstile wait
        // branch (best-effort solver click) and the terminal failure.
        //
        // The fixture needs the interstitial markers, not just a widget. It
        // previously used a bare `cf-turnstile` div, which the detector treated
        // as a challenge — that was the false positive since fixed, so the
        // fixture has to be a real challenge page for the test to mean anything.
        page.navigate_and_wait(
            &data_url(
                "<html><head><title>Just a moment...</title></head><body>\
                 <div id='challenge-stage'>\
                 <div class='cf-turnstile' style='width:300px;height:65px'></div>\
                 </div><script>window._cf_chl_opt={};</script></body></html>",
            ),
            PAGE_LOAD_TIMEOUT,
        )
        .await
        .expect("navigate");

        let result = scraper.solve_challenge(&page).await;
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
            .await
            .expect("Failed to rotate profile");
        assert_eq!(scraper.profile.user_agent, "UA-AFTER");

        // The relaunched browser must be usable.
        let _page = scraper
            .new_stealth_page()
            .await
            .expect("new page after rotation failed");
    }

    #[cfg(feature = "browser")]
    #[tokio::test]
    async fn human_input_reaches_the_page_as_real_events() {
        let scraper = CloudScraper::builder()
            .disable_proxy()
            .headless(true)
            .profile(profile_with_ua("UA-INPUT"))
            .build()
            .await
            .expect("Failed to build scraper");

        let page = scraper.new_stealth_page().await.expect("new page");
        page.navigate_and_wait(
            &data_url(
                "<html><body style='margin:0'>\
                 <input id='field' style='position:absolute;left:10px;top:10px'>\
                 <script>window.__moves=0;\
                 document.addEventListener('mousemove',()=>window.__moves++);</script>\
                 </body></html>",
            ),
            PAGE_LOAD_TIMEOUT,
        )
        .await
        .expect("navigate");

        CloudScraper::human_move_mouse(&page, 50.0, 50.0)
            .await
            .expect("move the mouse");
        let moves = page.evaluate("window.__moves").await.expect("evaluate");
        assert!(
            moves.as_u64().unwrap_or(0) > 10,
            "a Bézier path should emit many moves, saw {moves}"
        );

        page.evaluate("document.getElementById('field').focus()")
            .await
            .expect("focus");
        CloudScraper::human_type_str(&page, "test1234")
            .await
            .expect("type");
        assert_eq!(
            page.evaluate("document.getElementById('field').value")
                .await
                .expect("evaluate"),
            serde_json::Value::String("test1234".to_string()),
            "typed characters did not reach the field"
        );
    }
}
