#![cfg(feature = "browser")]
//! The lightweight transport: the same forged fingerprint, without a browser.
//!
//! Once a challenge is cleared, the browser is only holding memory. This leg
//! issues the same requests through `wreq` — the identical TLS and HTTP/2
//! fingerprint the browser's traffic was given, since both come from the same
//! [`StealthIdentity`] — carrying the cookies the browser earned.
//!
//! It cannot solve a challenge: there is no JavaScript and no widget to click.
//! So every response is classified, and a challenge is reported rather than
//! worked around; deciding what to do about it belongs to
//! [`SessionPolicy`](crate::identity::SessionPolicy).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Error;
use crate::challenge::{ChallengeSignal, DetectionInput};
use crate::identity::{Cookie, StealthIdentity, cookie_header};
use crate::scraper::build_impersonation_client;

/// Outbound request timeout, matching the browser leg's upstream client.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Current Unix time in seconds, saturating at 0 before the epoch.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What a fetch returned, and what it looked like.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: String,
    /// What the challenge detector made of it.
    ///
    /// Present on every response, not just failures: a challenge arrives with a
    /// perfectly ordinary status code, so the body has to be classified either
    /// way.
    pub signal: ChallengeSignal,
}

impl HttpResponse {
    /// Whether this response is a challenge rather than content.
    pub fn is_challenge(&self) -> bool {
        self.signal.is_challenge()
    }
}

/// An HTTP-only session, rendered from a [`StealthIdentity`].
///
/// Holds the identity so cookies gathered here are available when the session
/// escalates back to the browser: the two legs share one cookie set, or the
/// transfer loses whatever the cheap leg learned.
pub struct HttpScraper {
    client: wreq::Client,
    identity: Arc<Mutex<StealthIdentity>>,
}

impl HttpScraper {
    /// Builds a client for `identity`, routed through `upstream` if given.
    ///
    /// `upstream` is the credentialed proxy URL. It is passed separately rather
    /// than read from the identity because the identity deliberately cannot hold
    /// credentials; see [`EgressRef`](crate::identity::EgressRef).
    pub fn new(
        identity: Arc<Mutex<StealthIdentity>>,
        upstream: Option<&str>,
    ) -> Result<Self, Error> {
        let client = {
            let guard = identity.lock().unwrap_or_else(|e| e.into_inner());
            // The same builder the browser's egress uses, so the fingerprint on
            // the wire is the same before and after a demotion.
            build_impersonation_client(&guard.profile, upstream)?
        };

        Ok(Self { client, identity })
    }

    /// The identity this transport shares with the rest of the session.
    pub fn identity(&self) -> &Arc<Mutex<StealthIdentity>> {
        &self.identity
    }

    /// Fetches `url`, updating the identity's cookies from the response.
    ///
    /// Sends the cookies the browser would send for this URL and no others, and
    /// classifies whatever comes back.
    pub async fn fetch(&self, url: &str) -> Result<HttpResponse, Error> {
        let parsed = wreq::Url::parse(url)
            .map_err(|e| Error::ConfigError(format!("invalid URL {url}: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| Error::ConfigError(format!("URL has no host: {url}")))?
            .to_string();
        let secure = parsed.scheme() == "https";
        let path = parsed.path().to_string();

        let mut request = self.client.get(url).timeout(REQUEST_TIMEOUT);

        {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            // Accept-Language follows the proxy-led locale, so the header agrees
            // with the exit IP exactly as it does in the browser.
            request = request.header("Accept-Language", guard.accept_language());
            if let Some(header) = cookie_header(&guard.cookies, secure, &host, &path, now_unix()) {
                request = request.header("Cookie", header);
            }
        }

        let response = request.send().await?;
        let status = response.status().as_u16();

        // Header values are read out before the body is consumed, since the
        // detector wants both and the body moves the response.
        let server = header_value(&response, "server");
        let cf_mitigated = header_value(&response, "cf-mitigated");
        let cf_ray = header_value(&response, "cf-ray");
        let set_cookies: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_string))
            .collect();

        let body = response.text().await?;

        self.absorb_cookies(&set_cookies, &host, &path);

        let signal = crate::challenge::detect(&DetectionInput {
            status: Some(status),
            server: server.as_deref(),
            cf_mitigated: cf_mitigated.as_deref(),
            cf_ray: cf_ray.as_deref(),
            body: &body,
        });

        Ok(HttpResponse {
            status,
            body,
            signal,
        })
    }

    /// Merges `Set-Cookie` headers into the shared identity.
    ///
    /// A cookie replaces an existing one with the same name, domain and path —
    /// the triple that identifies a cookie — rather than accumulating duplicates
    /// that would all be sent together.
    fn absorb_cookies(&self, headers: &[String], host: &str, path: &str) {
        if headers.is_empty() {
            return;
        }
        let now = now_unix();

        let mut guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        for header in headers {
            let Some(mut cookie) = Cookie::parse_set_cookie(header, host, path) else {
                log::debug!("ignoring an unparseable Set-Cookie from {host}");
                continue;
            };
            cookie.anchor_max_age(now);

            guard.cookies.retain(|existing| {
                !(existing.name == cookie.name
                    && existing.domain == cookie.domain
                    && existing.path == cookie.path)
            });

            // A cookie the server just expired is dropped rather than stored,
            // which is how a server clears one.
            if !cookie.is_expired(now) {
                guard.cookies.push(cookie);
            }
        }
    }
}

/// Reads one response header as a string, if it is present and valid UTF-8.
fn header_value(response: &wreq::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)?
        .to_str()
        .ok()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SameSite;
    use crate::profile::BrowserProfile;

    fn scraper() -> HttpScraper {
        let identity = Arc::new(Mutex::new(StealthIdentity::new(BrowserProfile::random())));
        HttpScraper::new(identity, None).expect("build an HTTP scraper")
    }

    fn cookies_of(scraper: &HttpScraper) -> Vec<Cookie> {
        scraper
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cookies
            .clone()
    }

    #[test]
    fn a_set_cookie_is_absorbed_into_the_shared_identity() {
        let scraper = scraper();
        scraper.absorb_cookies(
            &["session=abc; Path=/; Secure; HttpOnly".to_string()],
            "www.example.com",
            "/",
        );

        let cookies = cookies_of(&scraper);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
        assert_eq!(cookies[0].value, "abc");
        assert!(cookies[0].secure);
        assert!(cookies[0].http_only);
    }

    #[test]
    fn a_repeated_cookie_replaces_rather_than_accumulates() {
        // Accumulating would send both values in one header, which no browser
        // does and which the server would read as the wrong one.
        let scraper = scraper();
        scraper.absorb_cookies(&["id=first; Path=/".to_string()], "example.com", "/");
        scraper.absorb_cookies(&["id=second; Path=/".to_string()], "example.com", "/");

        let cookies = cookies_of(&scraper);
        assert_eq!(cookies.len(), 1, "expected one cookie, got {cookies:?}");
        assert_eq!(cookies[0].value, "second");
    }

    #[test]
    fn the_same_name_at_a_different_scope_is_a_different_cookie() {
        let scraper = scraper();
        scraper.absorb_cookies(&["id=root; Path=/".to_string()], "example.com", "/");
        scraper.absorb_cookies(&["id=app; Path=/app".to_string()], "example.com", "/");

        let cookies = cookies_of(&scraper);
        assert_eq!(cookies.len(), 2, "path is part of a cookie's identity");
    }

    #[test]
    fn a_server_clearing_a_cookie_removes_it() {
        let scraper = scraper();
        scraper.absorb_cookies(&["id=value; Path=/".to_string()], "example.com", "/");
        assert_eq!(cookies_of(&scraper).len(), 1);

        // Max-Age=0 is how a server deletes a cookie.
        scraper.absorb_cookies(&["id=; Path=/; Max-Age=0".to_string()], "example.com", "/");
        assert!(
            cookies_of(&scraper).is_empty(),
            "an expired cookie should be dropped, not stored"
        );
    }

    #[test]
    fn several_set_cookie_headers_are_all_absorbed() {
        // Servers send one header per cookie; taking only the first would lose
        // the rest of the session.
        let scraper = scraper();
        scraper.absorb_cookies(
            &[
                "a=1; Path=/".to_string(),
                "b=2; Path=/".to_string(),
                "cf_clearance=xyz; Path=/; Max-Age=3600".to_string(),
            ],
            "example.com",
            "/",
        );

        let cookies = cookies_of(&scraper);
        assert_eq!(cookies.len(), 3);
        let guard = scraper.identity.lock().expect("lock");
        assert!(
            guard.clearance(now_unix()).is_some(),
            "the clearance cookie should be recognised"
        );
    }

    #[test]
    fn an_unparseable_set_cookie_is_skipped_not_fatal() {
        let scraper = scraper();
        scraper.absorb_cookies(
            &["garbage".to_string(), "good=1; Path=/".to_string()],
            "example.com",
            "/",
        );

        let cookies = cookies_of(&scraper);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "good");
    }

    #[test]
    fn a_cookie_for_another_domain_is_refused() {
        let scraper = scraper();
        scraper.absorb_cookies(
            &["evil=1; Domain=attacker.test; Path=/".to_string()],
            "example.com",
            "/",
        );
        assert!(
            cookies_of(&scraper).is_empty(),
            "a server must not set a cookie for an unrelated domain"
        );
    }

    #[test]
    fn the_client_is_built_from_the_identitys_own_profile() {
        // Both legs must render the same fingerprint; the shared builder is
        // what guarantees it, so assert the identity is the source.
        let profile = BrowserProfile::random();
        let user_agent = profile.user_agent.clone();
        let identity = Arc::new(Mutex::new(StealthIdentity::new(profile)));
        let scraper = HttpScraper::new(Arc::clone(&identity), None).expect("build");

        assert_eq!(
            scraper.identity().lock().expect("lock").profile.user_agent,
            user_agent
        );
    }

    #[test]
    fn same_site_survives_a_round_trip_through_absorption() {
        let scraper = scraper();
        scraper.absorb_cookies(
            &["id=1; Path=/; SameSite=Strict".to_string()],
            "example.com",
            "/",
        );
        assert_eq!(cookies_of(&scraper)[0].same_site, Some(SameSite::Strict));
    }
}
