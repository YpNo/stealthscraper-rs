//! The portable identity a session carries between transports, and the policy
//! that decides when to switch.
//!
//! A session starts in the browser because that is where a challenge can
//! actually be solved, then drops to plain HTTP to stop paying for a browser it
//! no longer needs — Chrome is hundreds of megabytes resident, the HTTP path is
//! a few. Switching is only safe if nothing that identifies the session changes
//! across the move, so everything that does is gathered here, in one value both
//! transports can render from.
//!
//! This module is pure: no I/O, no browser, no `wreq`. The decisions live here
//! so they can be tested without either transport.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::geo::Locale;
use crate::profile::{BrowserKind, BrowserProfile};

/// Name of the cookie Cloudflare issues once a challenge is cleared.
///
/// Its expiry is what makes a session worth keeping, and what eventually forces
/// a return to the browser.
pub const CLEARANCE_COOKIE: &str = "cf_clearance";

/// A cookie, in the transport-neutral form both legs can render.
///
/// Field for field what CDP's `Network.Cookie` and a `Set-Cookie` header carry,
/// so a cookie survives the move without losing scope or expiry — a cookie that
/// arrives with the wrong `domain` or a dropped `secure` flag is a different
/// cookie, and sending it where the browser would not is itself a tell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Domain the cookie is scoped to, with any leading dot preserved.
    pub domain: String,
    /// Path the cookie is scoped to.
    pub path: String,
    /// Expiry as a Unix timestamp; `None` for a session cookie.
    pub expires: Option<u64>,
    /// Whether the cookie is restricted to secure transports.
    pub secure: bool,
    /// Whether the cookie is hidden from scripts.
    pub http_only: bool,
    /// `SameSite` attribute, when the origin set one.
    pub same_site: Option<SameSite>,
}

/// The `SameSite` attribute of a [`Cookie`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameSite {
    /// Sent only for same-site requests.
    Strict,
    /// Sent for same-site requests and top-level navigations.
    Lax,
    /// Sent for cross-site requests; requires `Secure`.
    None,
}

impl Cookie {
    /// Whether the cookie has passed `now` (Unix seconds).
    ///
    /// A session cookie never expires by time; it dies with the session.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }

    /// Seconds until this cookie expires, or `None` if it has no expiry.
    ///
    /// Saturates at zero rather than wrapping once the expiry has passed.
    pub fn remaining(&self, now: u64) -> Option<Duration> {
        self.expires
            .map(|expires| Duration::from_secs(expires.saturating_sub(now)))
    }
}

/// Whether `cookie` should be sent to `url`'s scheme, host and path.
///
/// Implements the RFC 6265 matching rules the browser applies, because the HTTP
/// leg has to make the same decisions the browser would: sending a cookie the
/// browser would have withheld — to the wrong host, over the wrong scheme, or
/// outside its path — is a difference a server can see.
pub fn cookie_applies(cookie: &Cookie, secure: bool, host: &str, path: &str) -> bool {
    if cookie.secure && !secure {
        return false;
    }
    domain_matches(&cookie.domain, host) && path_matches(&cookie.path, path)
}

/// RFC 6265 domain matching.
///
/// A leading dot means the cookie covers subdomains. Without one it is
/// host-only, and only an exact match sends it.
fn domain_matches(cookie_domain: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    match cookie_domain.strip_prefix('.') {
        Some(suffix) => {
            let suffix = suffix.to_ascii_lowercase();
            // The suffix itself matches, as do its subdomains — but not a host
            // that merely ends with the same characters (`evilexample.com`).
            host == suffix || host.ends_with(&format!(".{suffix}"))
        }
        None => host == cookie_domain.to_ascii_lowercase(),
    }
}

/// What a `Set-Cookie` `Domain` attribute is worth to a cookie from `host`.
enum DomainScope {
    /// Widen the cookie to this domain and its subdomains.
    Widen(String),
    /// Keep the cookie host-only, which is the RFC default.
    HostOnly,
    /// The sender is not entitled to this domain; drop the cookie entirely.
    Refuse,
}

/// Applies RFC 6265 §5.3 steps 4-6 to a `Domain` attribute.
///
/// Split out from `parse_set_cookie` because it is the part with the security
/// consequences, and it is easier to reason about — and to test — on its own
/// than as one more arm in a long attribute loop.
fn domain_scope(value: &str, host: &str) -> DomainScope {
    let domain = value.trim_start_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return DomainScope::HostOnly;
    }
    let request_host = host.trim_end_matches('.').to_ascii_lowercase();

    // Step 4. For an IP-literal host a `Domain` can only ever mean the host
    // itself; anything else is suffix arithmetic over octets, where `1.2.3.4`
    // would scope a cookie to `.2.3.4` and reach `9.2.3.4` later.
    if is_ip_literal(&request_host) {
        return if domain == request_host {
            DomainScope::HostOnly
        } else {
            DomainScope::Refuse
        };
    }

    // Step 5. A public suffix is not a domain anyone may scope a cookie to —
    // without this, a response from `attacker.com` sets `Domain=com` and the
    // cookie rides along on every later request to any `.com` host in the
    // session. The RFC's one exception is a host that *is* the suffix.
    if is_public_suffix(&domain) {
        return if domain == request_host {
            DomainScope::HostOnly
        } else {
            DomainScope::Refuse
        };
    }

    // Step 6. A server may widen a cookie to its own parent domain, but not
    // set one for an unrelated domain.
    if domain_matches(&format!(".{domain}"), host) {
        DomainScope::Widen(format!(".{domain}"))
    } else {
        DomainScope::Refuse
    }
}

/// Whether `host` is an IP literal rather than a registrable name.
///
/// RFC 6265 gives IP hosts no subdomain structure, so a `Domain` attribute may
/// only ever repeat the host itself. Treating octets as labels is what lets
/// `1.2.3.4` claim `.2.3.4`.
fn is_ip_literal(host: &str) -> bool {
    // An IPv6 authority arrives bracketed.
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    bare.unwrap_or(host).parse::<std::net::IpAddr>().is_ok()
}

/// Whether `domain` is itself a public suffix (`com`, `co.uk`, `github.io`).
///
/// Which names these are is data — the Public Suffix List — not something that
/// can be derived from the shape of a name: `co.uk` is one and `example.com`
/// is not, and both have two labels. Unlisted top-level names fall under the
/// list's implicit `*` rule and so count as suffixes too, which is the
/// conservative direction.
fn is_public_suffix(domain: &str) -> bool {
    psl::suffix_str(domain).is_some_and(|suffix| suffix == domain)
}

/// RFC 6265 path matching.
fn path_matches(cookie_path: &str, request_path: &str) -> bool {
    if cookie_path.is_empty() || cookie_path == "/" {
        return true;
    }
    let cookie_path = cookie_path.trim_end_matches('/');
    request_path == cookie_path
        || request_path
            .strip_prefix(cookie_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Renders the `Cookie` header value for the cookies that apply.
///
/// Returns `None` when nothing applies, so a caller sends no header at all
/// rather than an empty one — an empty `Cookie:` header is not something a
/// browser emits.
pub fn cookie_header(
    cookies: &[Cookie],
    secure: bool,
    host: &str,
    path: &str,
    now: u64,
) -> Option<String> {
    let mut applicable: Vec<&Cookie> = cookies
        .iter()
        .filter(|cookie| !cookie.is_expired(now) && cookie_applies(cookie, secure, host, path))
        .collect();

    // RFC 6265 §5.4: longer paths first. This is not cosmetic. Two cookies can
    // share a name while differing in path, and a server that reads the first
    // occurrence — which is what most frameworks do — then gets whichever one
    // the header happened to list first. Emitting them in jar order would give
    // that server a different value from the one the browser leg of the same
    // session sends, and would also be an ordering no browser produces.
    //
    // `sort_by` is stable, so cookies with equal path lengths keep the order
    // they were stored in, which is the RFC's earlier-first tiebreak.
    applicable.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));

    if applicable.is_empty() {
        return None;
    }
    Some(
        applicable
            .iter()
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

impl Cookie {
    /// Parses a `Set-Cookie` header value.
    ///
    /// `host` and `path` supply the defaults the RFC requires when the header
    /// omits `Domain` or `Path`: without them a cookie would be stored with the
    /// wrong scope and then sent to the wrong places.
    ///
    /// Returns `None` for a header with no name, or one whose `Domain` the
    /// sender is not entitled to — a server cannot set a cookie for someone
    /// else's domain, and accepting one would send it there later. Three rules
    /// decide that, all from RFC 6265 §5.3:
    ///
    /// - the `Domain` must domain-match the host that sent the header, so a
    ///   server can widen a cookie to its own parent but not to a sibling;
    /// - it must not be a **public suffix** — `Domain=com` from `attacker.com`
    ///   would otherwise ride along on every later request to any `.com` host;
    /// - for an **IP-literal** host it may only repeat that host, since octets
    ///   are not labels and `1.2.3.4` must not be able to claim `.2.3.4`.
    ///
    /// The last two both have the same RFC exception: a `Domain` equal to the
    /// host is accepted and stays host-only, rather than being rejected.
    pub fn parse_set_cookie(header: &str, host: &str, path: &str) -> Option<Self> {
        let mut parts = header.split(';');

        let (name, value) = parts.next()?.split_once('=')?;
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        let mut cookie = Self {
            name: name.to_string(),
            value: value.trim().to_string(),
            // Host-only unless the header says otherwise, which is the RFC
            // default and the stricter of the two.
            domain: host.to_ascii_lowercase(),
            path: default_path(path),
            expires: None,
            secure: false,
            http_only: false,
            same_site: None,
        };

        // `Max-Age` takes precedence over `Expires`, so it is tracked
        // separately and applied last.
        let mut max_age: Option<i64> = None;

        for attribute in parts {
            let (key, val) = match attribute.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
                None => (attribute.trim().to_ascii_lowercase(), ""),
            };

            match key.as_str() {
                "domain" => match domain_scope(val, host) {
                    DomainScope::Widen(domain) => cookie.domain = domain,
                    // The host-only default set above is already what this
                    // means, so there is nothing to change.
                    DomainScope::HostOnly => continue,
                    DomainScope::Refuse => return None,
                },
                "path" if val.starts_with('/') => cookie.path = val.to_string(),
                "max-age" => max_age = val.parse().ok(),
                "secure" => cookie.secure = true,
                "httponly" => cookie.http_only = true,
                "samesite" => {
                    cookie.same_site = match val.to_ascii_lowercase().as_str() {
                        "strict" => Some(SameSite::Strict),
                        "lax" => Some(SameSite::Lax),
                        "none" => Some(SameSite::None),
                        _ => None,
                    }
                }
                // `Expires` is left alone: its date formats are a parsing
                // liability, and every server that sets a lifetime we care
                // about also sends Max-Age. A cookie whose expiry we cannot
                // read is treated as a session cookie, which errs towards
                // dropping it rather than keeping it too long.
                _ => {}
            }
        }

        cookie.expires = max_age.map(|seconds| {
            // A zero or negative Max-Age means delete now; represent that as an
            // already-expired cookie so the normal filtering removes it.
            if seconds <= 0 { 0 } else { seconds as u64 }
        });

        Some(cookie)
    }

    /// Resolves a relative `expires` (seconds from now) against `now`.
    ///
    /// `parse_set_cookie` cannot know the current time — it is pure — so a
    /// `Max-Age` is stored as a duration and anchored here.
    pub fn anchor_max_age(&mut self, now: u64) {
        if let Some(seconds) = self.expires {
            self.expires = Some(if seconds == 0 { 0 } else { now + seconds });
        }
    }
}

/// The default cookie path for a request path, per RFC 6265 section 5.1.4.
///
/// Everything up to the last `/`, so a cookie set at `/a/b` defaults to `/a`.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => request_path[..index].to_string(),
    }
}

/// Which upstream proxy a session is bound to.
///
/// Deliberately **not** the connection URL. An egress URL routinely carries
/// `user:password@`, and this type is serialisable and persisted — so holding
/// the credentialed form would put credentials in a state store the moment
/// anyone saved an identity. Storing only the redacted form makes that
/// impossible by construction rather than by remembering to redact.
///
/// The live session keeps the credentialed URL in memory, where it is needed to
/// actually connect. A restored identity therefore identifies *which* egress it
/// was bound to, and the caller supplies the credentials again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRef(String);

impl EgressRef {
    /// Records an egress by its redacted URL.
    ///
    /// Any userinfo is stripped here, so a credentialed URL cannot be stored
    /// even by mistake.
    pub fn new(url: &str) -> Self {
        Self(redact(url))
    }

    /// The redacted URL, safe to log, persist, or show.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `url` refers to this same egress, ignoring credentials.
    ///
    /// Used to check that a restored identity is being re-bound to the proxy it
    /// earned its clearance on: the same cookies from a different exit IP is
    /// exactly the inconsistency the whole design exists to avoid.
    pub fn matches(&self, url: &str) -> bool {
        self.0 == redact(url)
    }
}

/// Strips any `user:password@` from a proxy URL.
///
/// Mirrors the redaction the scraper applies before logging, kept here so the
/// pure layer does not depend on the infrastructure one.
fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        // No scheme to anchor on: drop anything before an '@', which is where
        // userinfo would be.
        return match url.split_once('@') {
            Some((_userinfo, host)) => format!("***@{host}"),
            None => url.to_string(),
        };
    };

    match rest.split_once('@') {
        Some((_userinfo, host)) => format!("{scheme}://{host}"),
        None => url.to_string(),
    }
}

/// Everything that identifies a session, independent of how it is driven.
///
/// Both transports render from this, so moving between them changes nothing a
/// server can see: the same User-Agent and hardware story, the same TLS
/// fingerprint source, the same locale, the same cookies, the same exit IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthIdentity {
    /// The browser fingerprint: User-Agent, platform, hardware, viewport.
    pub profile: BrowserProfile,
    /// Locale derived from the egress country, when one is known.
    pub locale: Option<Locale>,
    /// Cookies collected so far, including any clearance.
    pub cookies: Vec<Cookie>,
    /// The egress this identity earned its cookies on, redacted.
    pub egress: Option<EgressRef>,
}

impl StealthIdentity {
    /// A fresh identity for `profile`, with no cookies yet.
    pub fn new(profile: BrowserProfile) -> Self {
        Self {
            profile,
            locale: None,
            cookies: Vec::new(),
            egress: None,
        }
    }

    /// The browser this identity impersonates.
    ///
    /// Derived from the profile's own User-Agent rather than stored, so the
    /// advertised browser and the TLS fingerprint cannot drift apart.
    pub fn browser_kind(&self) -> BrowserKind {
        self.profile.browser_kind()
    }

    /// The `Accept-Language` this identity should send.
    ///
    /// Prefers the proxy-led locale, falling back to the profile's own value, so
    /// the header agrees with the exit IP wherever a locale is known.
    pub fn accept_language(&self) -> &str {
        self.locale
            .as_ref()
            .map(|locale| locale.accept_language.as_str())
            .unwrap_or(&self.profile.accept_language)
    }

    /// Replaces the cookie set, dropping anything already expired.
    ///
    /// Carrying an expired cookie across a transition would send something the
    /// browser itself would have discarded.
    pub fn set_cookies(&mut self, cookies: Vec<Cookie>, now: u64) {
        self.cookies = cookies
            .into_iter()
            .filter(|cookie| !cookie.is_expired(now))
            .collect();
    }

    /// The Cloudflare clearance cookie, if the session holds a live one.
    pub fn clearance(&self, now: u64) -> Option<&Cookie> {
        self.cookies
            .iter()
            .find(|cookie| cookie.name == CLEARANCE_COOKIE && !cookie.is_expired(now))
    }

    /// How long the clearance remains valid.
    ///
    /// `None` means either no clearance or one without an expiry; a session
    /// cookie cannot be reasoned about by time, so it is not treated as
    /// expiring.
    pub fn clearance_remaining(&self, now: u64) -> Option<Duration> {
        self.clearance(now)?.remaining(now)
    }

    /// Whether this identity may be used over `egress`.
    ///
    /// Cookies earned behind one exit IP presented from another is precisely the
    /// mismatch a bot-protection service looks for, so a session that cannot
    /// keep its egress should start over rather than reuse them.
    pub fn is_bound_to(&self, egress: Option<&str>) -> bool {
        match (&self.egress, egress) {
            (Some(bound), Some(url)) => bound.matches(url),
            (None, None) => true,
            // Gaining or losing an egress changes the exit IP.
            _ => false,
        }
    }
}

/// Which transport a session is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMode {
    /// A real browser: expensive, but the only thing that can solve a challenge.
    Browser,
    /// Plain HTTP through the impersonation client: cheap, and enough once the
    /// session is cleared.
    Http,
}

/// Why a session should move to the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EscalateReason {
    /// The HTTP transport was served a challenge it cannot solve.
    ChallengeSeen,
    /// The clearance is about to expire, so renew it before it does.
    ClearanceExpiring,
    /// There is no clearance to work with.
    NoClearance,
}

/// Why a session should leave the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DemoteReason {
    /// The page is clear and a clearance cookie is held.
    Cleared,
    /// The identity the browser was launched for has been replaced, so the
    /// browser no longer represents the session.
    IdentityReplaced,
}

/// What a session should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transition {
    /// Carry on in the current mode.
    Stay,
    /// Move to the browser, for the given reason.
    Escalate(EscalateReason),
    /// Leave the browser, for the given reason.
    Demote(DemoteReason),
}

/// Thresholds governing when a session changes transport.
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    /// Renew a clearance once it is this close to expiring.
    ///
    /// Waiting for actual expiry means the next request is challenged, which
    /// costs a round trip and a browser launch under load. Renewing early trades
    /// a predictable cost for an unpredictable one.
    pub clearance_margin: Duration,
    /// Whether HTTP mode requires a clearance cookie to be held.
    ///
    /// **Off by default**, and the default matters. A host that never challenges
    /// never issues a clearance cookie, so requiring one means the session
    /// escalates to the browser and then has nothing to demote on — it stays in
    /// the browser permanently, for exactly the hosts that never needed it. That
    /// is the common case, and it defeats the point of having two transports.
    ///
    /// The reasoning for demoting without one: if the browser itself saw a clean
    /// page, HTTP will very likely see one too. Being wrong costs a single
    /// escalation, which the policy handles; never demoting costs the whole
    /// memory saving.
    ///
    /// Turn it on for a host known to challenge, where running on HTTP without a
    /// clearance is close to certain to be challenged straight away.
    pub require_clearance_for_http: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            // Long enough to absorb a browser launch and a challenge solve.
            clearance_margin: Duration::from_secs(120),
            require_clearance_for_http: false,
        }
    }
}

impl SessionPolicy {
    /// Decides what a session in `mode` should do next.
    ///
    /// `challenged` is whether the last response carried a challenge. `now` is
    /// Unix seconds, passed in rather than read so the decision stays pure and
    /// testable at any point in time.
    pub fn decide(
        &self,
        mode: SessionMode,
        identity: &StealthIdentity,
        challenged: bool,
        now: u64,
    ) -> Transition {
        match mode {
            SessionMode::Http => self.decide_http(identity, challenged, now),
            SessionMode::Browser => self.decide_browser(identity, challenged, now),
        }
    }

    fn decide_http(&self, identity: &StealthIdentity, challenged: bool, now: u64) -> Transition {
        // A challenge over HTTP cannot be solved over HTTP: no JavaScript, no
        // widget to click. It is the one unambiguous escalation.
        if challenged {
            return Transition::Escalate(EscalateReason::ChallengeSeen);
        }

        match identity.clearance(now) {
            Some(clearance) => {
                // A clearance with no expiry cannot be reasoned about by time,
                // so it is left alone until something actually challenges us.
                match clearance.remaining(now) {
                    Some(remaining) if remaining <= self.clearance_margin => {
                        Transition::Escalate(EscalateReason::ClearanceExpiring)
                    }
                    _ => Transition::Stay,
                }
            }
            // No clearance. Escalate only if the caller demands one; otherwise
            // carry on, because plenty of hosts never issue one.
            None if self.require_clearance_for_http => {
                Transition::Escalate(EscalateReason::NoClearance)
            }
            None => Transition::Stay,
        }
    }

    fn decide_browser(&self, identity: &StealthIdentity, challenged: bool, now: u64) -> Transition {
        // Still being challenged: the browser is exactly where we want to be.
        if challenged {
            return Transition::Stay;
        }

        match identity.clearance(now) {
            // Cleared and holding a usable clearance: the browser has done its
            // job and is now just occupying memory.
            Some(clearance) => match clearance.remaining(now) {
                // Do not demote onto a clearance that is about to expire; the
                // HTTP leg would immediately have to escalate again.
                Some(remaining) if remaining <= self.clearance_margin => Transition::Stay,
                _ => Transition::Demote(DemoteReason::Cleared),
            },
            // A clean page and no clearance: demote anyway. The browser found
            // nothing to solve, so there is nothing for it to keep doing.
            None if self.require_clearance_for_http => Transition::Stay,
            None => Transition::Demote(DemoteReason::Cleared),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn profile() -> BrowserProfile {
        BrowserProfile::random()
    }

    fn cookie(name: &str, expires: Option<u64>) -> Cookie {
        Cookie {
            name: name.to_string(),
            value: "v".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            expires,
            secure: true,
            http_only: true,
            same_site: Some(SameSite::None),
        }
    }

    fn identity_with(cookies: Vec<Cookie>) -> StealthIdentity {
        let mut identity = StealthIdentity::new(profile());
        identity.cookies = cookies;
        identity
    }

    // -- redaction ---------------------------------------------------------

    #[test]
    fn an_egress_reference_cannot_hold_credentials() {
        // The type is serialised into state stores, so this is the property
        // that keeps credentials out of them.
        let egress = EgressRef::new("http://user:hunter2@proxy.example:8080");
        assert!(!egress.as_str().contains("hunter2"));
        assert!(!egress.as_str().contains("user"));
        assert_eq!(egress.as_str(), "http://proxy.example:8080");

        let serialised = serde_json::to_string(&egress).expect("serialise");
        assert!(
            !serialised.contains("hunter2"),
            "credentials reached the serialised form: {serialised}"
        );
    }

    #[test]
    fn redaction_covers_schemes_and_malformed_urls() {
        assert_eq!(
            EgressRef::new("socks5://u:p@1.2.3.4:1080").as_str(),
            "socks5://1.2.3.4:1080"
        );
        assert_eq!(
            EgressRef::new("http://proxy.example:8080").as_str(),
            "http://proxy.example:8080"
        );
        // No scheme to anchor on; userinfo is still stripped.
        assert_eq!(EgressRef::new("//u:p@host:3128").as_str(), "***@host:3128");
    }

    #[test]
    fn an_egress_matches_its_own_credentialed_url() {
        let egress = EgressRef::new("http://user:pass@proxy.example:8080");
        assert!(egress.matches("http://user:pass@proxy.example:8080"));
        // Same proxy, different credentials: still the same exit IP.
        assert!(egress.matches("http://other:creds@proxy.example:8080"));
        // A different proxy is a different exit IP.
        assert!(!egress.matches("http://elsewhere.example:8080"));
    }

    // -- identity ----------------------------------------------------------

    #[test]
    fn expired_cookies_are_dropped_on_transfer() {
        let mut identity = StealthIdentity::new(profile());
        identity.set_cookies(
            vec![
                cookie("live", Some(NOW + 60)),
                cookie("dead", Some(NOW - 1)),
                cookie("session", None),
            ],
            NOW,
        );

        let names: Vec<&str> = identity.cookies.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["live", "session"]);
    }

    #[test]
    fn a_cookie_expiring_exactly_now_is_expired() {
        assert!(cookie("c", Some(NOW)).is_expired(NOW));
        assert!(!cookie("c", Some(NOW + 1)).is_expired(NOW));
        // A session cookie has no expiry time to pass.
        assert!(!cookie("c", None).is_expired(NOW));
    }

    #[test]
    fn remaining_saturates_rather_than_wrapping() {
        // Subtracting a past expiry from now must not wrap into a huge duration.
        let past = cookie("c", Some(NOW - 500));
        assert_eq!(past.remaining(NOW), Some(Duration::ZERO));
    }

    #[test]
    fn clearance_is_found_by_name_and_must_be_live() {
        let identity = identity_with(vec![
            cookie("other", Some(NOW + 999)),
            cookie(CLEARANCE_COOKIE, Some(NOW + 300)),
        ]);
        assert!(identity.clearance(NOW).is_some());
        assert_eq!(
            identity.clearance_remaining(NOW),
            Some(Duration::from_secs(300))
        );

        // Past its expiry it no longer counts.
        assert!(identity.clearance(NOW + 301).is_none());
    }

    #[test]
    fn accept_language_prefers_the_proxy_led_locale() {
        let mut identity = StealthIdentity::new(profile());
        let profile_language = identity.profile.accept_language.clone();
        assert_eq!(identity.accept_language(), profile_language);

        identity.locale =
            crate::geo::Locale::for_country(crate::geo::CountryCode::new("DE").expect("a country"));
        assert_eq!(identity.accept_language(), "de-DE,de;q=0.9,en;q=0.8");
    }

    #[test]
    fn an_identity_is_bound_to_the_egress_it_earned_cookies_on() {
        let mut identity = StealthIdentity::new(profile());
        identity.egress = Some(EgressRef::new("http://user:pass@proxy.example:8080"));

        assert!(identity.is_bound_to(Some("http://user:pass@proxy.example:8080")));
        // Reusing cookies from a different exit IP is the mismatch to avoid.
        assert!(!identity.is_bound_to(Some("http://other.example:8080")));
        // Dropping the proxy entirely also changes the exit IP.
        assert!(!identity.is_bound_to(None));

        let direct = StealthIdentity::new(profile());
        assert!(direct.is_bound_to(None));
        assert!(!direct.is_bound_to(Some("http://proxy.example:8080")));
    }

    #[test]
    fn the_browser_kind_comes_from_the_profile_not_a_stored_copy() {
        // Two fields could disagree; one derived value cannot.
        let identity = StealthIdentity::new(profile());
        assert_eq!(identity.browser_kind(), identity.profile.browser_kind());
    }

    #[test]
    fn an_identity_round_trips_through_serialisation() {
        let mut identity = StealthIdentity::new(profile());
        identity.set_cookies(vec![cookie(CLEARANCE_COOKIE, Some(NOW + 600))], NOW);
        identity.egress = Some(EgressRef::new("http://user:pass@proxy.example:8080"));

        let encoded = serde_json::to_string(&identity).expect("serialise");
        assert!(!encoded.contains("pass"), "credentials leaked: {encoded}");

        let restored: StealthIdentity = serde_json::from_str(&encoded).expect("deserialise");
        assert_eq!(restored.cookies, identity.cookies);
        assert_eq!(restored.egress, identity.egress);
        assert_eq!(restored.profile.user_agent, identity.profile.user_agent);
    }

    // -- cookie matching ---------------------------------------------------

    #[test]
    fn a_host_only_cookie_is_not_sent_to_subdomains() {
        let mut c = cookie("c", None);
        c.domain = "example.com".to_string();

        assert!(cookie_applies(&c, true, "example.com", "/"));
        // No leading dot means host-only; the browser would withhold these.
        assert!(!cookie_applies(&c, true, "www.example.com", "/"));
        assert!(!cookie_applies(&c, true, "other.test", "/"));
    }

    #[test]
    fn a_dotted_cookie_covers_the_domain_and_its_subdomains() {
        let c = cookie("c", None); // domain ".example.com"

        assert!(cookie_applies(&c, true, "example.com", "/"));
        assert!(cookie_applies(&c, true, "www.example.com", "/"));
        assert!(cookie_applies(&c, true, "deep.www.example.com", "/"));
    }

    #[test]
    fn a_suffix_lookalike_host_does_not_match() {
        // The classic domain-matching bug: `evilexample.com` ends with
        // `example.com` textually but is a different registrable domain.
        let c = cookie("c", None);
        assert!(!cookie_applies(&c, true, "evilexample.com", "/"));
        assert!(!cookie_applies(&c, true, "example.com.attacker.test", "/"));
    }

    #[test]
    fn domain_matching_ignores_case_and_a_trailing_dot() {
        let c = cookie("c", None);
        assert!(cookie_applies(&c, true, "WWW.EXAMPLE.COM", "/"));
        assert!(cookie_applies(&c, true, "www.example.com.", "/"));
    }

    #[test]
    fn a_secure_cookie_is_withheld_from_plain_http() {
        let c = cookie("c", None); // secure: true
        assert!(cookie_applies(&c, true, "example.com", "/"));
        assert!(!cookie_applies(&c, false, "example.com", "/"));

        let mut insecure = cookie("c", None);
        insecure.secure = false;
        assert!(cookie_applies(&insecure, false, "example.com", "/"));
    }

    #[test]
    fn path_matching_requires_a_boundary_not_a_prefix() {
        let mut c = cookie("c", None);
        c.path = "/app".to_string();

        assert!(cookie_applies(&c, true, "example.com", "/app"));
        assert!(cookie_applies(&c, true, "example.com", "/app/inner"));
        // `/application` merely starts with `/app`; it is a different path.
        assert!(!cookie_applies(&c, true, "example.com", "/application"));
        assert!(!cookie_applies(&c, true, "example.com", "/other"));
    }

    #[test]
    fn the_cookie_header_skips_what_does_not_apply() {
        let mut scoped = cookie("scoped", None);
        scoped.path = "/app".to_string();
        let mut insecure_only = cookie("plain", None);
        insecure_only.secure = false;

        let cookies = vec![
            cookie("always", None),
            scoped,
            insecure_only,
            cookie("stale", Some(NOW - 1)),
        ];

        let header =
            cookie_header(&cookies, true, "www.example.com", "/", NOW).expect("some cookies apply");
        assert_eq!(header, "always=v; plain=v");

        // `scoped` leads despite being stored second: RFC 6265 §5.4 orders by
        // descending path length, and the ones sharing `/` keep jar order.
        let header = cookie_header(&cookies, true, "www.example.com", "/app", NOW)
            .expect("some cookies apply");
        assert_eq!(header, "scoped=v; always=v; plain=v");
    }

    #[test]
    fn the_cookie_header_puts_longer_paths_first() {
        // RFC 6265 §5.4, and the reason it matters here: a server reading the
        // first occurrence of a repeated name must see what a browser would
        // have put there, not whatever order the jar happened to be in.
        let general = Cookie {
            name: "session".to_string(),
            value: "general".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            expires: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        let scoped = Cookie {
            value: "scoped".to_string(),
            path: "/app/inner".to_string(),
            ..general.clone()
        };
        let middle = Cookie {
            value: "middle".to_string(),
            path: "/app".to_string(),
            ..general.clone()
        };

        // Stored shortest-path-first, which is the order they would arrive in.
        let jar = vec![general, middle, scoped];
        let header = cookie_header(&jar, false, "example.com", "/app/inner/x", NOW)
            .expect("all three apply");
        assert_eq!(
            header, "session=scoped; session=middle; session=general",
            "cookies must be ordered by descending path length"
        );
    }

    #[test]
    fn no_applicable_cookies_means_no_header_at_all() {
        // An empty `Cookie:` header is not something a browser sends.
        let cookies = vec![cookie("stale", Some(NOW - 1))];
        assert_eq!(cookie_header(&cookies, true, "example.com", "/", NOW), None);
        assert_eq!(cookie_header(&[], true, "example.com", "/", NOW), None);
    }

    // -- Set-Cookie parsing ------------------------------------------------

    fn parsed(header: &str) -> Option<Cookie> {
        Cookie::parse_set_cookie(header, "www.example.com", "/app/page")
    }

    #[test]
    fn a_minimal_set_cookie_defaults_to_host_only_and_the_directory_path() {
        let c = parsed("id=abc").expect("parse");
        assert_eq!(c.name, "id");
        assert_eq!(c.value, "abc");
        // Host-only is the RFC default and the stricter reading.
        assert_eq!(c.domain, "www.example.com");
        // Default path is the request path up to the last slash.
        assert_eq!(c.path, "/app");
        assert!(!c.secure);
        assert!(!c.http_only);
        assert_eq!(c.expires, None);
    }

    #[test]
    fn attributes_are_parsed_case_insensitively() {
        let c = parsed("id=abc; Secure; HTTPONLY; SameSite=Lax; Path=/; Domain=example.com")
            .expect("parse");
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site, Some(SameSite::Lax));
        assert_eq!(c.path, "/");
        // A Domain attribute widens the cookie to subdomains.
        assert_eq!(c.domain, ".example.com");
    }

    #[test]
    fn a_server_cannot_set_a_cookie_for_an_unrelated_domain() {
        // Accepting this would mean sending the cookie to that domain later.
        assert!(parsed("id=abc; Domain=attacker.test").is_none());
        assert!(parsed("id=abc; Domain=evilexample.com").is_none());
        // Its own parent domain is allowed.
        assert!(parsed("id=abc; Domain=example.com").is_some());
    }

    #[test]
    fn a_server_cannot_scope_a_cookie_to_a_public_suffix() {
        // Without this, one compromised host in a crawl sets a cookie that
        // every later request in the session carries to unrelated hosts.
        assert!(
            parsed("id=abc; Domain=com").is_none(),
            "a bare TLD was accepted"
        );

        // Multi-label suffixes are the reason this needs the list rather than a
        // label count: `co.uk` and `example.com` are both two labels, and only
        // one of them is a domain a server may scope to.
        let from_co_uk =
            |header: &str| Cookie::parse_set_cookie(header, "shop.example.co.uk", "/app/page");
        assert!(
            from_co_uk("id=abc; Domain=co.uk").is_none(),
            "a registry suffix was accepted"
        );
        assert_eq!(
            from_co_uk("id=abc; Domain=example.co.uk")
                .expect("the registrable domain is legitimate")
                .domain,
            ".example.co.uk"
        );
    }

    #[test]
    fn a_host_that_is_itself_a_public_suffix_keeps_the_cookie_host_only() {
        // The RFC's exception: the cookie is not refused, it just does not
        // widen. Anything else would lose cookies on hosts that are suffixes.
        let c =
            Cookie::parse_set_cookie("id=abc; Domain=github.io", "github.io", "/").expect("parse");
        assert_eq!(c.domain, "github.io", "host-only, with no leading dot");
    }

    #[test]
    fn an_ip_host_cannot_scope_a_cookie_to_a_trailing_octet_run() {
        // `1.2.3.4` claiming `.2.3.4` would reach `9.2.3.4`: octets are not
        // labels, and suffix matching over them is meaningless.
        assert!(
            Cookie::parse_set_cookie("id=abc; Domain=2.3.4", "1.2.3.4", "/").is_none(),
            "an IP host widened its own cookie"
        );

        // Repeating the host exactly is allowed, and stays host-only.
        let c = Cookie::parse_set_cookie("id=abc; Domain=1.2.3.4", "1.2.3.4", "/").expect("parse");
        assert_eq!(c.domain, "1.2.3.4");

        // The same holds for a bracketed IPv6 authority.
        assert!(Cookie::parse_set_cookie("id=abc; Domain=db8::1", "[2001:db8::1]", "/").is_none());
    }

    #[test]
    fn max_age_is_stored_relative_then_anchored() {
        let mut c = parsed("id=abc; Max-Age=600").expect("parse");
        assert_eq!(c.expires, Some(600));

        c.anchor_max_age(NOW);
        assert_eq!(c.expires, Some(NOW + 600));
        assert!(!c.is_expired(NOW));
        assert!(c.is_expired(NOW + 600));
    }

    #[test]
    fn a_non_positive_max_age_means_delete_now() {
        for header in ["id=abc; Max-Age=0", "id=abc; Max-Age=-1"] {
            let mut c = parsed(header).expect("parse");
            c.anchor_max_age(NOW);
            assert!(c.is_expired(NOW), "{header} should be expired immediately");
        }
    }

    #[test]
    fn a_malformed_set_cookie_is_rejected_not_guessed() {
        assert!(parsed("").is_none());
        assert!(parsed("novalue").is_none());
        assert!(parsed("=orphanvalue").is_none());
    }

    #[test]
    fn an_empty_value_is_legal() {
        // Servers clear cookies this way; it is a value, not a parse failure.
        let c = parsed("id=").expect("parse");
        assert_eq!(c.value, "");
    }

    #[test]
    fn the_default_path_follows_the_rfc() {
        assert_eq!(default_path("/app/page"), "/app");
        assert_eq!(default_path("/page"), "/");
        assert_eq!(default_path("/"), "/");
        // A path that is not absolute cannot be trusted as a scope.
        assert_eq!(default_path("relative"), "/");
    }

    #[test]
    fn a_parsed_cookie_is_immediately_usable_for_the_header() {
        // The two halves have to agree: whatever the parser stores must scope
        // correctly when the header is rendered.
        let mut c = Cookie::parse_set_cookie(
            "session=xyz; Domain=example.com; Path=/; Secure; Max-Age=3600",
            "www.example.com",
            "/",
        )
        .expect("parse");
        c.anchor_max_age(NOW);

        let header = cookie_header(&[c], true, "api.example.com", "/v1", NOW);
        assert_eq!(header.as_deref(), Some("session=xyz"));
    }

    // -- policy ------------------------------------------------------------

    #[test]
    fn a_challenge_over_http_always_escalates() {
        // HTTP cannot run the JavaScript or click the widget, so this is the
        // one case with no judgement in it.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + 9999))]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, true, NOW),
            Transition::Escalate(EscalateReason::ChallengeSeen)
        );
    }

    #[test]
    fn http_stays_while_the_clearance_is_comfortable() {
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + 3600))]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn http_escalates_before_the_clearance_expires_not_after() {
        // Renewing on expiry means the next request is challenged; renewing
        // early turns an unpredictable cost into a scheduled one.
        let policy = SessionPolicy::default();
        let margin = policy.clearance_margin.as_secs();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + margin))]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Escalate(EscalateReason::ClearanceExpiring)
        );

        // A second outside the margin is still comfortable.
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + margin + 1))]);
        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn http_without_a_clearance_stays_by_default() {
        // The default this corrects: requiring a clearance meant a host that
        // never issues one kept the browser alive for the whole session.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie("unrelated", Some(NOW + 9999))]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn a_strict_policy_can_still_demand_a_clearance() {
        // Opt-in, for a host known to challenge every uncleared visitor.
        let policy = SessionPolicy {
            require_clearance_for_http: true,
            ..SessionPolicy::default()
        };
        let identity = identity_with(vec![]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Escalate(EscalateReason::NoClearance)
        );
    }

    #[test]
    fn a_host_that_never_challenges_never_needs_the_browser() {
        // The whole point: no challenge, no clearance, no browser.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn a_clearance_without_an_expiry_does_not_force_escalation() {
        // A session cookie cannot be reasoned about by time; escalating on it
        // would mean relaunching the browser on every single request.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, None)]);

        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn the_browser_stays_while_still_challenged() {
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + 3600))]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, true, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn the_browser_demotes_once_cleared_with_a_usable_clearance() {
        // The whole point: stop paying for a browser that has done its job.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + 3600))]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, false, NOW),
            Transition::Demote(DemoteReason::Cleared)
        );
    }

    #[test]
    fn the_browser_does_not_demote_onto_an_expiring_clearance() {
        // Demoting here would escalate again on the next request: two browser
        // launches instead of none.
        let policy = SessionPolicy::default();
        let margin = policy.clearance_margin.as_secs();
        let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + margin))]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn a_clean_page_demotes_even_without_a_clearance() {
        // If the browser found nothing to solve, there is nothing for it to
        // keep doing. Holding on here is what pinned the browser open for every
        // host that never challenges.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, false, NOW),
            Transition::Demote(DemoteReason::Cleared)
        );
    }

    #[test]
    fn a_strict_policy_keeps_the_browser_until_a_clearance_exists() {
        let policy = SessionPolicy {
            require_clearance_for_http: true,
            ..SessionPolicy::default()
        };
        let identity = identity_with(vec![]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, false, NOW),
            Transition::Stay
        );
    }

    #[test]
    fn a_session_never_both_demotes_and_escalates_without_a_clearance() {
        // The oscillation guard, for the no-clearance case specifically: the
        // default demotes a clean page, so HTTP must not immediately escalate
        // it back.
        let policy = SessionPolicy::default();
        let identity = identity_with(vec![]);

        assert_eq!(
            policy.decide(SessionMode::Browser, &identity, false, NOW),
            Transition::Demote(DemoteReason::Cleared)
        );
        assert_eq!(
            policy.decide(SessionMode::Http, &identity, false, NOW),
            Transition::Stay,
            "demoting then escalating on the same state would launch a browser \
             per request"
        );
    }

    #[test]
    fn the_modes_do_not_oscillate_on_a_steady_clearance() {
        // Demote then immediately re-escalate would launch a browser per
        // request. Whatever the clearance, at most one of the two transitions
        // may fire for a clean page.
        let policy = SessionPolicy::default();
        for seconds in [1u64, 60, 119, 120, 121, 600, 3600] {
            let identity = identity_with(vec![cookie(CLEARANCE_COOKIE, Some(NOW + seconds))]);

            let from_browser = policy.decide(SessionMode::Browser, &identity, false, NOW);
            let from_http = policy.decide(SessionMode::Http, &identity, false, NOW);

            let demoted = matches!(from_browser, Transition::Demote(_));
            let escalated = matches!(from_http, Transition::Escalate(_));
            assert!(
                !(demoted && escalated),
                "clearance of {seconds}s both demotes and escalates: \
                 browser={from_browser:?} http={from_http:?}"
            );
        }
    }
}
