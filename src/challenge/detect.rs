//! Pure, side-effect-free detection of bot-protection challenges.

use super::types::{ChallengeKind, ChallengeSignal, Confidence, DetectionInput};

/// HTTP status returned by Cloudflare when rate limiting (error 1015).
const STATUS_RATE_LIMITED: u16 = 429;

/// Markers that identify a Cloudflare **interstitial** — a page whose entire
/// purpose is the challenge.
///
/// This distinction is the whole difficulty. Cloudflare injects
/// `/cdn-cgi/challenge-platform/scripts/jsd/main.js` into *ordinary* pages as
/// passive bot detection, and sites embed Turnstile widgets in their own forms.
/// Neither is a challenge. Keying on those markers reported almost every
/// Cloudflare-protected page as challenged, which made the detector worse than
/// useless: it sent the solver into a retry loop on pages that had already
/// loaded, and kept a dual-mode session permanently escalated to the browser.
///
/// Verified against a real capture of nowsecure.nl, which serves its own content
/// *and* carries both a Turnstile widget and the passive script.
const INTERSTITIAL_MARKERS: &[&str] = &[
    // The interstitial's title, and the most reliable single marker.
    "just a moment",
    // The challenge options object, present only on a challenge page.
    "cf_chl_opt",
    // Orchestration endpoints, as opposed to the passive `scripts/jsd/` path.
    "challenge-platform/h/b/orchestrate",
    "challenge-platform/h/g/orchestrate",
    // The interstitial's own copy.
    "enable javascript and cookies to continue",
    "challenge-error-title",
    // Structural elements of the challenge page.
    "id=\"challenge-form\"",
    "id=\"challenge-stage\"",
    "cf-challenge-running",
];

/// Markers for an interactive Turnstile widget.
///
/// On their own these mean only that a Turnstile exists somewhere on the page,
/// which is true of any site using it for its own forms. A Turnstile is a
/// *challenge* only in interstitial context, or when `cf-mitigated` says so.
const TURNSTILE_MARKERS: &[&str] = &[
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
    "turnstile/v0/api.js",
];

const IUAM_MARKERS: &[&str] = &[
    "checking your browser before accessing",
    "cf-im-under-attack",
    "jschl-answer",
    "jschl_vc",
];
const ACCESS_DENIED_MARKERS: &[&str] = &[
    "error 1020",
    "access denied",
    "you have been blocked",
    "attention required",
];
const RATE_LIMIT_MARKERS: &[&str] = &["error 1015", "rate limited", "too many requests"];

/// Classify a response/page into a [`ChallengeSignal`].
///
/// This is a pure function: it performs no I/O and never mutates its input, so
/// it is trivially unit-testable and safe to call from any layer. Detection
/// proceeds from the most specific, highest-confidence signals (status codes,
/// the `cf-mitigated` header, interactive widgets) to weaker heuristics.
pub fn detect(input: &DetectionInput<'_>) -> ChallengeSignal {
    let body = input.body.to_ascii_lowercase();
    let looks_like_cloudflare = is_cloudflare(input, &body);

    // 1. Status-code driven signals are the strongest. An HTTP 429 is
    //    unambiguous regardless of vendor; the generic text markers
    //    ("rate limited", "too many requests") are too broad to trust without a
    //    Cloudflare context, or they would flag innocent pages that merely
    //    mention the phrase.
    if input.status == Some(STATUS_RATE_LIMITED)
        || (looks_like_cloudflare && contains_any(&body, RATE_LIMIT_MARKERS))
    {
        return ChallengeSignal {
            kind: ChallengeKind::RateLimited,
            confidence: Confidence::High,
            evidence: vec!["rate-limit (429 / error 1015)"],
        };
    }

    if contains_any(&body, ACCESS_DENIED_MARKERS) && looks_like_cloudflare {
        return ChallengeSignal {
            kind: ChallengeKind::AccessDenied,
            confidence: Confidence::High,
            evidence: vec!["access-denied marker (e.g. error 1020)"],
        };
    }

    // 2. The `cf-mitigated: challenge` header is an explicit challenge flag.
    if input
        .cf_mitigated
        .is_some_and(|v| v.eq_ignore_ascii_case("challenge"))
    {
        // Fall through to body markers to refine, but default to a JS challenge.
        if contains_any(&body, TURNSTILE_MARKERS) {
            return turnstile_signal("cf-mitigated header + turnstile widget");
        }
        return ChallengeSignal {
            kind: ChallengeKind::JsChallenge,
            confidence: Confidence::High,
            evidence: vec!["cf-mitigated: challenge"],
        };
    }

    // 3. Body markers, but only in interstitial context. A Turnstile widget or
    //    the passive detection script on an otherwise normal page is not a
    //    challenge, and treating it as one is what made this detector fire on
    //    almost every Cloudflare site.
    if contains_any(&body, INTERSTITIAL_MARKERS) {
        if contains_any(&body, TURNSTILE_MARKERS) {
            return turnstile_signal("turnstile widget on a challenge interstitial");
        }
        return ChallengeSignal {
            kind: ChallengeKind::JsChallenge,
            confidence: Confidence::High,
            evidence: vec!["cloudflare challenge interstitial"],
        };
    }
    if contains_any(&body, IUAM_MARKERS) {
        return ChallengeSignal {
            kind: ChallengeKind::IuamV1,
            confidence: Confidence::High,
            evidence: vec!["legacy IUAM marker"],
        };
    }

    // 4. Behind Cloudflare, but with no challenge marker anywhere. This is the
    //    normal state of a large part of the web and is **not** a challenge:
    //    reporting it as one (previously `Unknown`, which `is_challenge`
    //    counts) made every protected page look blocked. The vendor is recorded
    //    as evidence so a caller can still see it.
    if looks_like_cloudflare {
        return ChallengeSignal {
            kind: ChallengeKind::None,
            confidence: Confidence::High,
            evidence: vec!["served by cloudflare, no challenge marker"],
        };
    }

    ChallengeSignal::none()
}

fn turnstile_signal(evidence: &'static str) -> ChallengeSignal {
    ChallengeSignal {
        kind: ChallengeKind::Turnstile,
        confidence: Confidence::High,
        evidence: vec![evidence],
    }
}

/// Heuristic: does this response originate from Cloudflare's edge?
fn is_cloudflare(input: &DetectionInput<'_>, lower_body: &str) -> bool {
    let server_is_cf = input
        .server
        .is_some_and(|s| s.to_ascii_lowercase().contains("cloudflare"));
    server_is_cf
        || input.cf_ray.is_some()
        || input.cf_mitigated.is_some()
        || lower_body.contains("cloudflare")
        || lower_body.contains("/cdn-cgi/")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input_with(status: Option<u16>, body: &str) -> DetectionInput<'_> {
        DetectionInput {
            status,
            server: None,
            cf_mitigated: None,
            cf_ray: None,
            body,
        }
    }

    #[test]
    fn detect_clean_page_returns_none() {
        let input = input_with(Some(200), "<html><body>Hello world</body></html>");
        let signal = detect(&input);
        assert_eq!(signal.kind, ChallengeKind::None);
        assert!(!signal.is_challenge());
    }

    /// The shape of a real Cloudflare-protected page that is **not**
    /// challenged, taken from a capture of nowsecure.nl: its own content, the
    /// passive detection script, and a Turnstile widget it embeds itself.
    const PROTECTED_BUT_NOT_CHALLENGED: &str = "<html><head><title>nowsecure.nl</title>\
         <script src=\"/cdn-cgi/challenge-platform/scripts/jsd/main.js\"></script></head>\
         <body><h1>nowsecure.nl</h1><p>site content</p>\
         <div class=\"cf-turnstile\" data-sitekey=\"0x4\"></div></body></html>";

    /// The shape of an actual interstitial.
    const REAL_INTERSTITIAL: &str = "<html><head><title>Just a moment...</title></head>\
         <body><div id=\"challenge-stage\"></div>\
         <script>window._cf_chl_opt={cvId:'3'};</script>\
         <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1\"></script>\
         </body></html>";

    #[test]
    fn a_protected_page_with_its_own_turnstile_is_not_a_challenge() {
        // The defect this guards: `cf-turnstile` anywhere in the body was read
        // as an unsolved challenge, so a site embedding Turnstile in its own
        // form looked permanently blocked. Measured on nowsecure.nl, which
        // serves its content *and* a widget.
        let input = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8f2a1b"),
            body: PROTECTED_BUT_NOT_CHALLENGED,
        };
        let signal = detect(&input);
        assert!(
            !signal.is_challenge(),
            "a page that merely embeds Turnstile is not challenged: {signal:?}"
        );
    }

    #[test]
    fn the_passive_detection_script_is_not_a_challenge() {
        // Cloudflare injects scripts/jsd/main.js into ordinary pages. Keying on
        // "challenge-platform" therefore fired on almost every protected site.
        let input = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8f2a1b"),
            body: "<html><body>real content\
                   <script src=\"/cdn-cgi/challenge-platform/scripts/jsd/main.js\"></script>\
                   </body></html>",
        };
        assert!(!detect(&input).is_challenge());
    }

    #[test]
    fn being_served_by_cloudflare_is_not_a_challenge() {
        // Previously `Unknown`, which `is_challenge` counts — so every page
        // behind Cloudflare looked blocked and the solver looped on it.
        let input = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8f2a1b"),
            body: "<html><body>an ordinary page</body></html>",
        };
        let signal = detect(&input);
        assert!(!signal.is_challenge());
        assert_eq!(signal.kind, ChallengeKind::None);
        // The vendor is still reported, so the information is not lost.
        assert!(!signal.evidence.is_empty());
    }

    #[test]
    fn a_real_interstitial_is_still_detected() {
        // The other half: narrowing the markers must not stop us seeing an
        // actual challenge.
        let input = input_with(Some(403), REAL_INTERSTITIAL);
        let signal = detect(&input);
        assert!(signal.is_challenge(), "{signal:?}");
        assert_eq!(signal.kind, ChallengeKind::JsChallenge);
    }

    #[test]
    fn a_turnstile_on_an_interstitial_is_a_turnstile_challenge() {
        let body = "<html><head><title>Just a moment...</title></head><body>\
             <div class=\"cf-turnstile\"></div>\
             <script>window._cf_chl_opt={};</script></body></html>";
        let signal = detect(&input_with(Some(403), body));
        assert_eq!(signal.kind, ChallengeKind::Turnstile, "{signal:?}");
    }

    #[test]
    fn the_cf_mitigated_header_still_overrides_the_page_shape() {
        // An explicit header beats body heuristics: a Turnstile widget plus
        // `cf-mitigated: challenge` is a challenge even without interstitial
        // markers, because the edge said so.
        let input = DetectionInput {
            status: Some(403),
            server: Some("cloudflare"),
            cf_mitigated: Some("challenge"),
            cf_ray: None,
            body: "<div class=\"cf-turnstile\"></div>",
        };
        assert_eq!(detect(&input).kind, ChallengeKind::Turnstile);
    }

    #[test]
    fn a_bare_turnstile_widget_alone_is_not_a_challenge() {
        // This test previously asserted the opposite, and that expectation was
        // the bug: a Turnstile widget with no challenge context around it is
        // just a widget, which any site may embed in its own form. Updated
        // deliberately rather than worked around.
        let input = input_with(
            Some(403),
            "<div class=\"cf-turnstile\" data-sitekey=\"x\"></div>",
        );
        let signal = detect(&input);
        assert!(
            !signal.is_challenge(),
            "a widget without interstitial context or cf-mitigated is not a \
             challenge: {signal:?}"
        );
    }

    #[test]
    fn detect_managed_challenge_returns_js_challenge() {
        let input = input_with(
            Some(503),
            "<title>Just a moment...</title><script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate\"></script>",
        );
        assert_eq!(detect(&input).kind, ChallengeKind::JsChallenge);
    }

    #[test]
    fn detect_legacy_iuam_returns_iuam_v1() {
        let input = input_with(
            Some(503),
            "<body>Checking your browser before accessing example.com <input name=\"jschl_vc\"></body>",
        );
        assert_eq!(detect(&input).kind, ChallengeKind::IuamV1);
    }

    #[test]
    fn detect_rate_limited_by_status() {
        // HTTP 429 is unambiguous regardless of vendor.
        let input = input_with(Some(429), "slow down");
        let signal = detect(&input);
        assert_eq!(signal.kind, ChallengeKind::RateLimited);
        assert_eq!(signal.confidence, Confidence::High);
    }

    #[test]
    fn detect_rate_limit_text_requires_cloudflare_context() {
        // Generic "too many requests" text on a non-Cloudflare 200 page is NOT a
        // rate-limit challenge (would otherwise spuriously cool down innocent hosts).
        let benign = input_with(
            Some(200),
            "Our API returns 'too many requests' when you exceed the quota.",
        );
        assert_eq!(detect(&benign).kind, ChallengeKind::None);

        // The same marker with a Cloudflare fingerprint does classify as RateLimited.
        let cf = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8abc"),
            body: "error 1015: rate limited",
        };
        assert_eq!(detect(&cf).kind, ChallengeKind::RateLimited);
    }

    #[test]
    fn detect_access_denied_requires_cloudflare_context() {
        // "access denied" alone (no CF fingerprint) should not be a hard CF block.
        let plain = input_with(Some(403), "Access denied by application firewall");
        assert_eq!(detect(&plain).kind, ChallengeKind::None);

        // With a Cloudflare fingerprint it classifies as AccessDenied.
        let cf = DetectionInput {
            status: Some(403),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8abc"),
            body: "Access denied | error 1020",
        };
        assert_eq!(detect(&cf).kind, ChallengeKind::AccessDenied);
    }

    #[test]
    fn detect_cf_mitigated_header_without_body_marker_is_js_challenge() {
        let input = DetectionInput {
            status: Some(403),
            server: Some("cloudflare"),
            cf_mitigated: Some("challenge"),
            cf_ray: None,
            body: "",
        };
        assert_eq!(detect(&input).kind, ChallengeKind::JsChallenge);
    }

    #[test]
    fn detect_cf_mitigated_header_with_turnstile_prefers_turnstile() {
        let input = DetectionInput {
            status: Some(403),
            server: Some("cloudflare"),
            cf_mitigated: Some("CHALLENGE"),
            cf_ray: None,
            body: "<div class=\"cf-turnstile\"></div>",
        };
        assert_eq!(detect(&input).kind, ChallengeKind::Turnstile);
    }

    #[test]
    fn cloudflare_without_a_marker_is_clean_not_unknown() {
        // Previously this asserted `Unknown`, which `is_challenge()` counts as
        // a challenge — so every page behind Cloudflare was treated as blocked
        // and the solver looped on it. Being served by Cloudflare is the normal
        // state of much of the web.
        let input = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8abc123"),
            body: "<html>some page served via /cdn-cgi/</html>",
        };
        let signal = detect(&input);
        assert_eq!(signal.kind, ChallengeKind::None);
        assert!(!signal.is_challenge());
        // The vendor is still recorded, so nothing is lost by not calling it a
        // challenge.
        assert!(
            signal.evidence.iter().any(|e| e.contains("cloudflare")),
            "the Cloudflare origin should still be reported: {signal:?}"
        );
    }

    #[test]
    fn detect_is_case_insensitive() {
        let input = input_with(Some(503), "<TITLE>JUST A MOMENT...</TITLE>");
        assert_eq!(detect(&input).kind, ChallengeKind::JsChallenge);
    }
}
