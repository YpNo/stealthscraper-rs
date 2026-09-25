//! Building an impersonating HTTP client without a browser.
//!
//! The gate on many "protected" endpoints is a TLS/HTTP-2 fingerprint check and
//! nothing more: no JavaScript challenge, no interstitial. Against one of those,
//! a browser is pure overhead — the [`emulation`](crate::emulation) table and a
//! `wreq` client are enough, and this module is the two-line way to get there.
//!
//! It is available in the **default build**, with no `browser` feature and no
//! headless Chrome anywhere in the dependency graph.
//!
//! ```no_run
//! use stealthscraper_rs::{BrowserProfile, impersonation_client};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let profile = BrowserProfile::random();
//! let client = impersonation_client(&profile).build()?;
//! let body = client.get("https://example.com").send().await?.text().await?;
//! # Ok(())
//! # }
//! ```
//!
//! A [`wreq::ClientBuilder`] is returned rather than a finished client, so the
//! caller can still add a proxy, a cookie jar, timeouts or redirect policy. The
//! `wreq` types needed for that are re-exported as [`crate::wreq`], so a consumer
//! does not have to depend on `wreq` directly and risk drifting onto a different
//! version from the one this crate builds its emulation against.
//!
//! # What the returned builder already carries
//!
//! - the measured TLS and HTTP/2 emulation for the profile's browser, chosen
//!   from the profile's own parsed User-Agent so the two cannot disagree,
//! - `User-Agent`, from the profile,
//! - `Sec-CH-UA`, `Sec-CH-UA-Mobile` and `Sec-CH-UA-Platform`, derived from the
//!   same profile — omitted entirely for a Safari profile, which implements no
//!   Client Hints and for which sending them would be a contradiction,
//! - `Accept-Language`, from the profile.
//!
//! The emulation deliberately does **not** set the first three itself; they
//! belong to the profile, and an emulation that supplied its own would silently
//! override it. That is a defect this crate has already shipped once.
//!
//! # When you still want a browser
//!
//! If the target serves an actual JavaScript challenge, this is not enough — use
//! [`StealthSession`](crate::session::StealthSession) under the `browser`
//! feature, which clears the challenge in a real browser and then hands the
//! whole identity, cookies included, to exactly this kind of client.

use crate::client_hints::ClientHints;
use crate::emulation;
use crate::profile::BrowserProfile;

/// A `wreq` client builder that impersonates `profile`.
///
/// See the [module docs](self) for what the builder already carries and what it
/// deliberately leaves to the caller.
///
/// # Examples
///
/// Through an upstream proxy, with a cookie jar:
///
/// ```no_run
/// use stealthscraper_rs::{BrowserProfile, impersonation_client, wreq};
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = impersonation_client(&BrowserProfile::random())
///     .proxy(wreq::Proxy::all("http://user:pass@proxy:8080")?)
///     .cookie_store(true)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub fn impersonation_client(profile: &BrowserProfile) -> wreq::ClientBuilder {
    let mut headers = wreq::header::HeaderMap::new();

    if let Ok(value) = wreq::header::HeaderValue::from_str(&profile.user_agent) {
        headers.insert(wreq::header::USER_AGENT, value);
    }
    if let Ok(value) = wreq::header::HeaderValue::from_str(&profile.accept_language) {
        headers.insert(wreq::header::ACCEPT_LANGUAGE, value);
    }

    // `None` for Safari, which exposes no Client Hints at all. Emitting them
    // under a Safari User-Agent would be a contradiction of its own.
    if let Some(hints) = ClientHints::for_profile(profile) {
        for (name, value) in [
            ("sec-ch-ua", hints.sec_ch_ua()),
            ("sec-ch-ua-mobile", hints.sec_ch_ua_mobile().to_string()),
            ("sec-ch-ua-platform", hints.sec_ch_ua_platform()),
        ] {
            if let (Ok(name), Ok(value)) = (
                wreq::header::HeaderName::from_bytes(name.as_bytes()),
                wreq::header::HeaderValue::from_str(&value),
            ) {
                headers.insert(name, value);
            }
        }
    }

    wreq::Client::builder()
        .emulation(emulation::for_kind(profile.browser_kind()))
        .default_headers(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::BrowserKind;

    /// A profile carrying `user_agent`.
    fn profile_with(user_agent: &str) -> BrowserProfile {
        let mut profile = BrowserProfile::random();
        profile.user_agent = user_agent.to_string();
        profile
    }

    #[test]
    fn a_client_builds_for_every_generated_profile() {
        // The builder must not be constructible into a broken state: a consumer
        // calling `.build()` on it is the whole point of returning a builder.
        for _ in 0..50 {
            let profile = BrowserProfile::random();
            assert!(
                impersonation_client(&profile).build().is_ok(),
                "a generated profile produced a client that will not build"
            );
        }
    }

    #[test]
    fn a_safari_profile_builds_too() {
        // Safari takes the `None` client-hints path, which must not panic or
        // leave the builder unusable.
        let profile = profile_with(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/27.0 Safari/605.1.15",
        );
        assert_eq!(profile.browser_kind(), BrowserKind::Safari(27));
        assert!(impersonation_client(&profile).build().is_ok());
    }

    #[test]
    fn a_user_agent_that_cannot_be_a_header_is_skipped_not_fatal() {
        // A caller can set any string on a profile. A newline cannot be a header
        // value, and dropping it is better than panicking or emitting a
        // malformed request.
        let profile = profile_with("Mozilla/5.0 (bad\nheader)");
        assert!(impersonation_client(&profile).build().is_ok());
    }
}
