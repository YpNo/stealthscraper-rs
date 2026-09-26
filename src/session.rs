#![cfg(feature = "browser")]
//! The dual-mode session: start in the browser, run on HTTP, escalate when
//! something needs the browser again.
//!
//! This is the façade over the two transports. It owns no stealth logic of its
//! own — the identity is [`StealthIdentity`], the decisions are
//! [`SessionPolicy`], the transports are [`CloudScraper`] and [`HttpScraper`].
//! What it owns is the *transition*: making sure nothing a server can see
//! changes as the session moves between them.
//!
//! # Why this shape
//!
//! A bot-protection challenge almost always arrives on the first request to a
//! host. Solving it needs a real browser. Everything afterwards does not — but a
//! browser left running costs hundreds of megabytes of resident memory for the
//! rest of the session, which for a long-lived scraper is the dominant cost.
//!
//! So a session starts in the browser, clears whatever is in the way, hands its
//! cookies to the HTTP transport, and **shuts the browser down**. If the cheap
//! leg is later challenged, or its clearance is close to expiring, the browser
//! comes back with the same identity, re-clears, and steps out again.
//!
//! # What must not change across a transition
//!
//! The User-Agent, the TLS and HTTP/2 fingerprint, the locale, the cookies and
//! the exit IP. The first four come from one [`StealthIdentity`] that both legs
//! render from. The last is the subtle one: cookies earned behind one exit IP
//! presented from another is exactly the mismatch a protection service looks
//! for, so the session refuses to carry an identity onto a different egress.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Error;
use crate::cdp::Page;
use crate::challenge::ChallengeSignal;
use crate::events::{EventSink, NoopEventSink, ScraperEvent};
use crate::http_scraper::{HttpResponse, HttpScraper};
use crate::identity::{
    DemoteReason, EgressRef, EscalateReason, SessionMode, SessionPolicy, StealthIdentity,
    Transition,
};
use crate::profile::BrowserProfile;
use crate::scraper::{CloudScraper, CloudScraperBuilder};

/// How long to wait for a page load while clearing a challenge.
const PAGE_LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Current Unix time in seconds, saturating at 0 before the epoch.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds a [`StealthSession`].
pub struct StealthSessionBuilder {
    profile: Option<BrowserProfile>,
    policy: SessionPolicy,
    upstream: Option<String>,
    headless: bool,
    debug_mode: bool,
    event_sink: Option<Arc<dyn EventSink>>,
}

impl Default for StealthSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StealthSessionBuilder {
    /// A configuration with the default policy.
    pub fn new() -> Self {
        Self {
            profile: None,
            policy: SessionPolicy::default(),
            upstream: None,
            headless: true,
            debug_mode: false,
            event_sink: None,
        }
    }

    /// Uses a specific fingerprint rather than a random one.
    pub fn profile(mut self, profile: BrowserProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Sets the escalate/demote thresholds.
    pub fn policy(mut self, policy: SessionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Binds the session to one upstream proxy.
    ///
    /// Sticky by design: both transports use this same egress, so the exit IP
    /// that earns a clearance is the one that reuses it.
    pub fn upstream_proxy(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = Some(upstream.into());
        self
    }

    /// Whether the browser runs without a window.
    pub fn headless(mut self, headless: bool) -> Self {
        self.headless = headless;
        self
    }

    /// Turns on proxy debug logging.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }

    /// Receives a [`ScraperEvent`] for every transition.
    pub fn with_event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Creates the session.
    ///
    /// Nothing is launched here. The browser starts on the first fetch that
    /// needs it, so a session that turns out never to be challenged never pays
    /// for one.
    pub fn build(self) -> StealthSession {
        let profile = self.profile.unwrap_or_else(BrowserProfile::random);
        let mut identity = StealthIdentity::new(profile);
        identity.egress = self.upstream.as_deref().map(EgressRef::new);

        StealthSession {
            identity: Arc::new(Mutex::new(identity)),
            policy: self.policy,
            upstream: self.upstream,
            headless: self.headless,
            debug_mode: self.debug_mode,
            events: self.event_sink.unwrap_or_else(|| Arc::new(NoopEventSink)),
            browser: None,
            http: None,
        }
    }
}

/// A session that moves between a browser and plain HTTP as needed.
pub struct StealthSession {
    identity: Arc<Mutex<StealthIdentity>>,
    policy: SessionPolicy,
    /// The credentialed upstream URL, held here and never in the identity.
    upstream: Option<String>,
    headless: bool,
    debug_mode: bool,
    events: Arc<dyn EventSink>,
    /// Live only while in browser mode; dropping it reclaims the memory.
    browser: Option<CloudScraper>,
    /// Built lazily, then kept: it is cheap and holds no OS resources.
    http: Option<HttpScraper>,
}

impl StealthSession {
    /// Start building a session.
    pub fn builder() -> StealthSessionBuilder {
        StealthSessionBuilder::new()
    }

    /// The transport currently in use.
    ///
    /// Reports [`SessionMode::Http`] before anything has been launched, since
    /// that is what the next request would use.
    pub fn mode(&self) -> SessionMode {
        if self.browser.is_some() {
            SessionMode::Browser
        } else {
            SessionMode::Http
        }
    }

    /// Whether a browser process is currently running.
    ///
    /// The thing this design exists to keep false most of the time.
    pub fn browser_is_running(&self) -> bool {
        self.browser.is_some()
    }

    /// The shared identity, for inspection or persistence.
    pub fn identity(&self) -> &Arc<Mutex<StealthIdentity>> {
        &self.identity
    }

    /// Adopts a previously saved identity.
    ///
    /// Refused when the identity was earned on a different egress: its cookies
    /// belong to that exit IP, and replaying them from another is the
    /// inconsistency this design exists to avoid. Starting fresh is the correct
    /// outcome, so the caller is told rather than silently given a broken
    /// session.
    pub fn restore(&mut self, identity: StealthIdentity) -> Result<(), Error> {
        if !identity.is_bound_to(self.upstream.as_deref()) {
            let was = identity
                .egress
                .as_ref()
                .map(|e| e.as_str().to_string())
                .unwrap_or_else(|| "no proxy".to_string());
            return Err(Error::ConfigError(format!(
                "refusing to restore a session earned on {was}: its cookies belong to that \
                 exit IP, so reusing them from this one would be inconsistent"
            )));
        }

        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = identity;

        // Both transports render from the identity, so both have to go. The
        // HTTP client is cheap to rebuild; the browser is not, but leaving it
        // is worse than relaunching it — it was launched from the *previous*
        // profile, and its User-Agent, TLS fingerprint, stealth injection and
        // locale all came from there. Keeping it would mean the browser leg
        // presenting one identity while the HTTP leg presents another, which is
        // precisely the mid-session change this type exists to prevent, and it
        // would happen silently.
        self.http = None;
        self.demote_for(DemoteReason::IdentityReplaced)
    }

    /// Fetches `url`, changing transport if the policy says to.
    ///
    /// The decision is made twice: once before the request, on what is already
    /// known (is there a clearance? is it expiring?), and once on what comes
    /// back. That second pass is what turns a challenge into an escalation and a
    /// retry.
    pub async fn fetch(&mut self, url: &str) -> Result<HttpResponse, Error> {
        // Before the request: escalate if we already know HTTP will not do.
        let transition = self.decide(false);
        self.apply(transition).await?;

        // In the browser: clear the page, then reconsider — a cleared page is
        // exactly when the browser stops being worth its memory.
        if self.browser.is_some() {
            self.clear_with_browser(url).await?;
            let transition = self.decide(false);
            self.apply(transition).await?;
        }

        let response = self.http_transport()?.fetch(url).await?;
        if !response.is_challenge() {
            return Ok(response);
        }

        // The cheap leg cannot solve this, so escalate and try once more.
        let transition = self.decide(true);
        self.apply(transition).await?;
        if self.browser.is_none() {
            // The policy declined to escalate; report what we actually got
            // rather than pretending it succeeded.
            return Ok(response);
        }

        self.clear_with_browser(url).await?;
        let transition = self.decide(false);
        self.apply(transition).await?;

        // Exactly one retry. Looping would hide a browser that is not actually
        // clearing the challenge behind an unbounded number of launches.
        self.http_transport()?.fetch(url).await
    }

    /// Moves to the browser, launching one if needed.
    pub async fn escalate(&mut self) -> Result<(), Error> {
        self.escalate_for(EscalateReason::NoClearance).await
    }

    /// Leaves the browser, shutting it down.
    pub fn demote(&mut self) -> Result<(), Error> {
        self.demote_for(DemoteReason::Cleared)
    }

    /// What the policy makes of the current state.
    fn decide(&self, challenged: bool) -> Transition {
        let identity = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        self.policy
            .decide(self.mode(), &identity, challenged, now_unix())
    }

    /// Carries out a transition.
    async fn apply(&mut self, transition: Transition) -> Result<(), Error> {
        match transition {
            Transition::Stay => Ok(()),
            Transition::Escalate(reason) => self.escalate_for(reason).await,
            Transition::Demote(reason) => self.demote_for(reason),
        }
    }

    /// Launches the browser and hands it the session's cookies.
    async fn escalate_for(&mut self, reason: EscalateReason) -> Result<(), Error> {
        if self.browser.is_some() {
            return Ok(());
        }

        let profile = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.profile.clone()
        };

        let mut builder = CloudScraperBuilder::new()
            .profile(profile)
            .headless(self.headless)
            .with_debug(self.debug_mode);
        if let Some(upstream) = &self.upstream {
            builder = builder.upstream_proxy(upstream.clone());
        }
        let scraper = builder.build().await?;

        // Hand over whatever the HTTP leg has gathered, so the browser continues
        // the session rather than starting a new one the server has not seen.
        let cookies = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            guard.cookies.clone()
        };
        scraper.set_browser_cookies(&cookies).await?;

        self.events.emit(&ScraperEvent::SessionEscalated {
            reason: escalate_reason_label(reason),
        });
        self.browser = Some(scraper);
        Ok(())
    }

    /// Shuts the browser down, taking its cookies with it.
    fn demote_for(&mut self, reason: DemoteReason) -> Result<(), Error> {
        if self.browser.take().is_some() {
            self.events.emit(&ScraperEvent::SessionDemoted {
                reason: demote_reason_label(reason),
            });
        }
        Ok(())
    }

    /// Uses the browser to clear `url`, then exports its cookies.
    ///
    /// The page is closed on every path. A navigation that times out or a
    /// solver that fails would otherwise leave the tab open for the life of the
    /// browser, and `fetch` can come through here twice per request — so a run
    /// of failures accumulates renderer memory inside the one process this
    /// design exists to keep small.
    async fn clear_with_browser(&mut self, url: &str) -> Result<ChallengeSignal, Error> {
        let scraper = self
            .browser
            .as_ref()
            .ok_or_else(|| Error::Internal("clear_with_browser without a browser".into()))?;

        let page = scraper.new_stealth_page().await?;
        let outcome = Self::clear_on_page(scraper, &page, url, &self.identity).await;

        // Closing is best-effort: the clearing result is what the caller asked
        // for, and losing it because the tab would not close would be worse
        // than the leak this guards against.
        if let Err(err) = page.close().await {
            log::debug!("could not close the page used to clear {url}: {err}");
        }
        outcome
    }

    /// Clears `url` on an already-open page, leaving the page alone.
    ///
    /// Split out so the caller owns the page's lifetime and can close it
    /// whichever way this returns.
    async fn clear_on_page(
        scraper: &CloudScraper,
        page: &Page,
        url: &str,
        identity: &Arc<Mutex<StealthIdentity>>,
    ) -> Result<ChallengeSignal, Error> {
        page.navigate_and_wait(url, PAGE_LOAD_TIMEOUT).await?;
        let signal = scraper.solve_challenge(page).await?;

        // Export before the page closes: this is the whole point of the
        // escalation, and a browser shut down without it would have cleared a
        // challenge for nobody.
        let cookies = scraper.browser_cookies().await?;
        identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_cookies(cookies, now_unix());

        Ok(signal)
    }

    /// The HTTP transport, built on first use.
    fn http_transport(&mut self) -> Result<&HttpScraper, Error> {
        if self.http.is_none() {
            self.http = Some(HttpScraper::new(
                Arc::clone(&self.identity),
                self.upstream.as_deref(),
            )?);
        }
        self.http
            .as_ref()
            .ok_or_else(|| Error::Internal("HTTP transport missing after construction".into()))
    }
}

/// A stable label for an escalation reason, for events and logs.
fn escalate_reason_label(reason: EscalateReason) -> &'static str {
    match reason {
        EscalateReason::ChallengeSeen => "challenge seen over HTTP",
        EscalateReason::ClearanceExpiring => "clearance expiring",
        EscalateReason::NoClearance => "no clearance held",
    }
}

/// A stable label for a demotion reason.
fn demote_reason_label(reason: DemoteReason) -> &'static str {
    match reason {
        DemoteReason::Cleared => "page cleared",
        DemoteReason::IdentityReplaced => "identity replaced",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CLEARANCE_COOKIE, Cookie, SameSite};

    fn clearance(expires_in: u64) -> Cookie {
        Cookie {
            name: CLEARANCE_COOKIE.to_string(),
            value: "granted".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires: Some(now_unix() + expires_in),
            secure: true,
            http_only: true,
            same_site: Some(SameSite::None),
        }
    }

    #[test]
    fn a_new_session_launches_nothing() {
        // A session that is never challenged should never cost a browser.
        let session = StealthSession::builder().build();
        assert!(!session.browser_is_running());
        assert_eq!(session.mode(), SessionMode::Http);
    }

    #[test]
    fn the_builder_binds_the_identity_to_its_egress_without_credentials() {
        let session = StealthSession::builder()
            .upstream_proxy("http://user:secret@proxy.example:8080")
            .build();

        let guard = session.identity().lock().expect("lock");
        let egress = guard.egress.as_ref().expect("an egress");
        assert!(!egress.as_str().contains("secret"));
        // The credentialed URL is still available to the session itself.
        assert_eq!(
            session.upstream.as_deref(),
            Some("http://user:secret@proxy.example:8080")
        );
    }

    #[test]
    fn restoring_onto_the_same_egress_is_allowed() {
        let mut session = StealthSession::builder()
            .upstream_proxy("http://user:pass@proxy.example:8080")
            .build();

        let mut saved = StealthIdentity::new(BrowserProfile::random());
        saved.egress = Some(EgressRef::new("http://user:pass@proxy.example:8080"));
        saved.cookies = vec![clearance(3600)];

        session.restore(saved).expect("same egress should restore");
        assert!(
            session
                .identity()
                .lock()
                .expect("lock")
                .clearance(now_unix())
                .is_some()
        );
    }

    #[test]
    fn restoring_onto_a_different_egress_is_refused() {
        // The cookies belong to the old exit IP. Replaying them from a new one
        // is the exact mismatch a protection service looks for, so this must
        // fail loudly rather than hand back a session that looks wrong.
        let mut session = StealthSession::builder()
            .upstream_proxy("http://new.example:8080")
            .build();

        let mut saved = StealthIdentity::new(BrowserProfile::random());
        saved.egress = Some(EgressRef::new("http://old.example:8080"));
        saved.cookies = vec![clearance(3600)];

        let err = session.restore(saved).expect_err("should be refused");
        assert!(err.to_string().contains("old.example"), "{err}");
        // The live session is untouched by a refused restore.
        assert!(session.identity().lock().expect("lock").cookies.is_empty());
    }

    #[test]
    fn losing_the_proxy_entirely_also_refuses_a_restore() {
        let mut session = StealthSession::builder().build();

        let mut saved = StealthIdentity::new(BrowserProfile::random());
        saved.egress = Some(EgressRef::new("http://proxy.example:8080"));

        assert!(session.restore(saved).is_err());
    }

    #[test]
    fn a_session_with_a_live_clearance_stays_on_http() {
        // The steady state this design exists to reach: no browser running.
        let session = StealthSession::builder().build();
        session
            .identity()
            .lock()
            .expect("lock")
            .cookies
            .push(clearance(3600));

        assert_eq!(session.decide(false), Transition::Stay);
        assert!(!session.browser_is_running());
    }

    #[test]
    fn a_session_without_a_clearance_stays_on_http_by_default() {
        // Requiring a clearance kept the browser alive for every host that
        // never issues one, which is most of them.
        let session = StealthSession::builder().build();
        assert_eq!(session.decide(false), Transition::Stay);
    }

    #[test]
    fn a_strict_policy_asks_for_the_browser_up_front() {
        let session = StealthSession::builder()
            .policy(SessionPolicy {
                require_clearance_for_http: true,
                ..SessionPolicy::default()
            })
            .build();
        assert_eq!(
            session.decide(false),
            Transition::Escalate(EscalateReason::NoClearance)
        );
    }

    #[test]
    fn an_expiring_clearance_wants_the_browser_before_it_lapses() {
        let session = StealthSession::builder().build();
        session
            .identity()
            .lock()
            .expect("lock")
            .cookies
            .push(clearance(30));

        assert_eq!(
            session.decide(false),
            Transition::Escalate(EscalateReason::ClearanceExpiring)
        );
    }

    #[test]
    fn a_challenge_wants_the_browser_whatever_the_clearance_says() {
        let session = StealthSession::builder().build();
        session
            .identity()
            .lock()
            .expect("lock")
            .cookies
            .push(clearance(3600));

        assert_eq!(
            session.decide(true),
            Transition::Escalate(EscalateReason::ChallengeSeen)
        );
    }

    #[tokio::test]
    async fn demoting_an_idle_session_is_a_no_op() {
        // Nothing to shut down, and no event for something that did not happen.
        let mut session = StealthSession::builder().build();
        session.demote().expect("demote");
        assert!(!session.browser_is_running());
    }
}
