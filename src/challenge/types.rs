//! Core value types describing a detected bot-protection challenge.

/// The category of bot-protection challenge identified on a response or page.
///
/// Variants intentionally stay coarse: distinguishing Cloudflare "managed v2"
/// from "managed v3" reliably from client-visible markers is not possible, so
/// non-interactive JavaScript challenges are grouped under [`ChallengeKind::JsChallenge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// No challenge detected; the response looks like normal content.
    None,
    /// Legacy Cloudflare "I'm Under Attack Mode" interstitial (JS proof-of-work).
    IuamV1,
    /// Cloudflare managed JavaScript challenge (non-interactive).
    JsChallenge,
    /// Cloudflare Turnstile interactive widget.
    Turnstile,
    /// Hard block / access denied (e.g. Cloudflare error 1020).
    AccessDenied,
    /// Rate limited (HTTP 429 / Cloudflare error 1015).
    RateLimited,
    /// Response resembles a protection page but could not be classified.
    Unknown,
}

/// Confidence attached to a [`ChallengeSignal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Weak heuristic match (e.g. looks like a protection vendor but no specific marker).
    Low,
    /// One corroborating marker.
    Medium,
    /// Strong, unambiguous marker (status code or vendor-specific token).
    High,
}

/// The result of running [`detect`](crate::challenge::detect) over a response/page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeSignal {
    /// The classified challenge category.
    pub kind: ChallengeKind,
    /// How sure the detector is about [`Self::kind`].
    pub confidence: Confidence,
    /// Human-readable labels for the markers that matched, for tracing/debugging.
    pub evidence: Vec<&'static str>,
}

impl ChallengeSignal {
    /// A clean "no challenge" signal.
    pub fn none() -> Self {
        Self {
            kind: ChallengeKind::None,
            confidence: Confidence::High,
            evidence: Vec::new(),
        }
    }

    /// Returns `true` when an actual challenge (anything but [`ChallengeKind::None`]) was detected.
    pub fn is_challenge(&self) -> bool {
        !matches!(self.kind, ChallengeKind::None)
    }
}

/// Transport-neutral inputs for challenge detection.
///
/// Deliberately built from primitives (no `http`/`wreq`/`hyper` types) so the
/// detector stays in the pure domain layer and can be fed from either the MITM
/// proxy's upstream response or the rendered DOM of the headless browser.
#[derive(Debug, Clone, Copy)]
pub struct DetectionInput<'a> {
    /// HTTP status code, when known.
    pub status: Option<u16>,
    /// Value of the `Server` response header, when present.
    pub server: Option<&'a str>,
    /// Value of the `cf-mitigated` response header, when present.
    pub cf_mitigated: Option<&'a str>,
    /// Value of the `cf-ray` response header, when present.
    pub cf_ray: Option<&'a str>,
    /// Response body or rendered DOM HTML.
    pub body: &'a str,
}

impl<'a> DetectionInput<'a> {
    /// Build an input from just a body/DOM string (no HTTP metadata available).
    pub fn from_body(body: &'a str) -> Self {
        Self {
            status: None,
            server: None,
            cf_mitigated: None,
            cf_ray: None,
            body,
        }
    }
}
