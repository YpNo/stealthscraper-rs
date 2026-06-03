//! Pure, side-effect-free detection of bot-protection challenges.

use super::types::{ChallengeKind, ChallengeSignal, Confidence, DetectionInput};

/// HTTP status returned by Cloudflare when rate limiting (error 1015).
const STATUS_RATE_LIMITED: u16 = 429;

/// Body markers (lower-cased) that, when present, indicate a specific challenge.
const TURNSTILE_MARKERS: &[&str] = &[
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
    "turnstile/v0/api.js",
];
const JS_CHALLENGE_MARKERS: &[&str] = &[
    "/cdn-cgi/challenge-platform/",
    "cf_chl_opt",
    "challenge-platform",
    "just a moment",
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

    // 3. Body-marker driven signals. Order matters: interactive Turnstile before
    //    the generic managed-challenge platform, and legacy IUAM last.
    if contains_any(&body, TURNSTILE_MARKERS) {
        return turnstile_signal("turnstile widget marker");
    }
    if contains_any(&body, JS_CHALLENGE_MARKERS) {
        return ChallengeSignal {
            kind: ChallengeKind::JsChallenge,
            confidence: Confidence::High,
            evidence: vec!["managed challenge-platform marker"],
        };
    }
    if contains_any(&body, IUAM_MARKERS) {
        return ChallengeSignal {
            kind: ChallengeKind::IuamV1,
            confidence: Confidence::High,
            evidence: vec!["legacy IUAM marker"],
        };
    }

    // 4. Looks like Cloudflare but nothing specific matched.
    if looks_like_cloudflare {
        return ChallengeSignal {
            kind: ChallengeKind::Unknown,
            confidence: Confidence::Low,
            evidence: vec!["cloudflare fingerprint without a known challenge marker"],
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

    #[test]
    fn detect_turnstile_widget_returns_turnstile() {
        let input = input_with(
            Some(403),
            "<div class=\"cf-turnstile\" data-sitekey=\"x\"></div>",
        );
        assert_eq!(detect(&input).kind, ChallengeKind::Turnstile);
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
    fn detect_cloudflare_without_marker_is_unknown_low_confidence() {
        let input = DetectionInput {
            status: Some(200),
            server: Some("cloudflare"),
            cf_mitigated: None,
            cf_ray: Some("8abc123"),
            body: "<html>some page served via /cdn-cgi/</html>",
        };
        let signal = detect(&input);
        assert_eq!(signal.kind, ChallengeKind::Unknown);
        assert_eq!(signal.confidence, Confidence::Low);
    }

    #[test]
    fn detect_is_case_insensitive() {
        let input = input_with(Some(503), "<TITLE>JUST A MOMENT...</TITLE>");
        assert_eq!(detect(&input).kind, ChallengeKind::JsChallenge);
    }
}
