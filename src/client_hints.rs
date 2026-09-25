//! User-Agent Client Hints, derived from the profile so they cannot contradict it.
//!
//! Chrome reports its identity twice: once in the `User-Agent` string, and again
//! in structured Client Hints (`Sec-CH-UA*` headers and
//! `navigator.userAgentData`). Overriding only the first leaves the two
//! disagreeing, which is a stronger signal than an unusual User-Agent on its
//! own — the contradiction cannot happen on a real browser.
//!
//! Measured on Chromium 153 with a spoofed Chrome-on-Windows User-Agent, the
//! page saw `userAgent` claiming Chrome 124 on Windows while
//! `userAgentData.platform` said `Linux` and `brands` said `Chromium 153`. This
//! module removes that contradiction by deriving every hint from the same
//! profile the User-Agent comes from.
//!
//! # Secure contexts only
//!
//! `navigator.userAgentData` is exposed only in a secure context. On a `data:`
//! URL it is `undefined`, which is correct behaviour and not something to
//! imitate — so any check of these values has to run over https or loopback.
//!
//! # What is measured and what is not
//!
//! - **Certain**, from the profile's own User-Agent: the platform, the major
//!   version, `mobile` (false for every desktop profile), `model` (empty for
//!   desktop).
//! - **Measured** on branded Google Chrome 153 (macOS 27), cross-checked against
//!   the unbranded Chromium 153 on the build host: the brand list and its order,
//!   the GREASE entry, the full version, and the macOS `platformVersion`.
//! - **Not measured**: `platformVersion` for Windows — the last value in this
//!   file taken from documentation rather than from a browser. See
//!   [`PLATFORM_VERSIONS`].

use serde_json::{Value, json};

use crate::profile::{BrowserKind, BrowserProfile};

/// The GREASE brand Chrome 153 emits.
///
/// **Measured**, and corroborated across two independent builds: branded Google
/// Chrome 153 on macOS 27 and the unbranded Chromium 153 on the build host both
/// report `"Not_A Brand";v="8"`. Agreement between a branded and an unbranded
/// build on different operating systems is what shows this entry is determined
/// by the *major version* — which is how Chrome's GREASE algorithm works.
///
/// It therefore has to be recaptured whenever
/// [`CHROME_MAJOR`](crate::emulation::CHROME_MAJOR) moves: both the punctuation
/// and the version cycle.
///
/// The previous value, `"Not-A.Brand";v="99"`, came from `wreq-util`'s table —
/// built for Chrome 124 — and was simply wrong for 153.
const GREASE_BRAND: (&str, &str) = ("Not_A Brand", "8");

/// The full version a real Chrome reports in `fullVersionList` and
/// `uaFullVersion`.
///
/// **Measured** from branded Google Chrome 153 on macOS 27. It replaces a
/// generated `{major}.0.0.0`, whose stated rationale — that a zeroed build
/// "merely looks unremarkable" — the capture refutes: no real Chrome reports a
/// zeroed build here, so the zeros were themselves the signal.
///
/// The User-Agent is a different matter and genuinely does carry `153.0.0.0`,
/// because Chrome's reduced User-Agent freezes everything below the major.
///
/// Recapture alongside [`GREASE_BRAND`] when the major moves.
const CHROME_FULL_VERSION: &str = "153.0.8010.53";

/// `platformVersion` per platform.
///
/// **Not measured.** Linux really does report an empty string (confirmed on
/// Chromium 153); the Windows and macOS values are the documented mapping and
/// should be replaced with captures from a real branded Chrome on those
/// platforms, the same way the Safari TLS entry was.
const PLATFORM_VERSIONS: &[(&str, &str)] = &[
    // NOT measured: the documented mapping. Windows 10 and 11 both report 10.0.0
    // or higher; 15.0.0 is Windows 11.
    ("Windows", "15.0.0"),
    // Measured on branded Google Chrome 153, macOS 27. The previous value,
    // 14.6.1, was the documented mapping and was several releases stale.
    ("macOS", "27.0.0"),
    // Measured: Linux really does report an empty string.
    ("Linux", ""),
];

/// Architecture reported for every profile this crate generates.
///
/// All generated profiles are desktop x86-64; an ARM profile would need its own
/// value, and would also need a User-Agent to match.
const ARCHITECTURE: &str = "x86";

/// Bitness matching [`ARCHITECTURE`].
const BITNESS: &str = "64";

/// Client Hints coherent with one profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHints {
    /// `Sec-CH-UA-Platform`, e.g. `Windows`.
    pub platform: String,
    /// `Sec-CH-UA-Platform-Version`.
    pub platform_version: String,
    /// The browser's major version, as the brand list reports it.
    pub major_version: String,
    /// The full version, as `uaFullVersion` and `fullVersionList` report it.
    pub full_version: String,
    /// `Sec-CH-UA-Arch`.
    pub architecture: String,
    /// `Sec-CH-UA-Bitness`.
    pub bitness: String,
    /// `Sec-CH-UA-Mobile`.
    pub mobile: bool,
    /// `Sec-CH-UA-Model`, empty on desktop.
    pub model: String,
}

/// The Client Hints platform name for a `navigator.platform` value and UA.
///
/// Derived from the User-Agent's own OS token rather than from
/// `navigator.platform`, because the User-Agent is what a server compares
/// against.
fn platform_for(user_agent: &str) -> &'static str {
    if user_agent.contains("Windows") {
        "Windows"
    } else if user_agent.contains("Macintosh") || user_agent.contains("Mac OS X") {
        "macOS"
    } else if user_agent.contains("CrOS") {
        "Chrome OS"
    } else if user_agent.contains("Android") {
        "Android"
    } else {
        "Linux"
    }
}

/// The full version to report for `major`.
///
/// The measured build belongs to one specific major, so a profile claiming any
/// other major gets a zeroed build rather than a real build number paired with
/// the wrong version — an inconsistency checkable against public release data.
/// Generated profiles always claim the measured major.
fn full_version_for(major: u32) -> String {
    if major == crate::emulation::CHROME_MAJOR {
        CHROME_FULL_VERSION.to_string()
    } else {
        format!("{major}.0.0.0")
    }
}

/// The documented `platformVersion` for a platform, or empty when unknown.
fn platform_version_for(platform: &str) -> &'static str {
    PLATFORM_VERSIONS
        .iter()
        .find(|(name, _)| *name == platform)
        .map(|(_, version)| *version)
        .unwrap_or("")
}

impl ClientHints {
    /// Derives the hints that agree with `profile`.
    ///
    /// Everything comes from the profile's own User-Agent, so the two cannot
    /// drift apart. Returns `None` for a Safari profile: Safari implements no
    /// Client Hints at all, and emitting them would be a contradiction of its
    /// own.
    pub fn for_profile(profile: &BrowserProfile) -> Option<Self> {
        let major = match profile.browser_kind() {
            BrowserKind::Chrome(major) => major,
            // Safari sends no Sec-CH-UA and exposes no navigator.userAgentData.
            // Inventing them would be worse than the absence.
            BrowserKind::Safari(_) => return None,
        };

        let platform = platform_for(&profile.user_agent);

        Some(Self {
            platform: platform.to_string(),
            platform_version: platform_version_for(platform).to_string(),
            major_version: major.to_string(),
            // A measured build, not a zeroed one: no real Chrome reports
            // `{major}.0.0.0` here. See `CHROME_FULL_VERSION`.
            full_version: full_version_for(major),
            architecture: ARCHITECTURE.to_string(),
            bitness: BITNESS.to_string(),
            // Every profile this crate generates is desktop.
            mobile: false,
            model: String::new(),
        })
    }

    /// The brand list, in the shape `navigator.userAgentData.brands` reports.
    ///
    /// Three entries for branded Chrome, in the order **measured** from Google
    /// Chrome 153: `Google Chrome`, the greased entry, then `Chromium`.
    ///
    /// The order is part of the fingerprint, and it is neither alphabetical nor
    /// stable across versions: Chrome permutes the list from a seed derived from
    /// the major version, so it must be recaptured whenever
    /// [`CHROME_MAJOR`](crate::emulation::CHROME_MAJOR) moves. Two earlier
    /// versions of this got it wrong — one led with the greased entry (invented
    /// outright), the next led with `Chromium` (taken from a Chrome 124 table).
    ///
    /// A profile claiming Chrome must report the `Google Chrome` brand: a plain
    /// Chromium build does not, and the User-Agent says Chrome.
    pub fn brands(&self) -> Vec<(String, String)> {
        vec![
            ("Google Chrome".to_string(), self.major_version.clone()),
            (GREASE_BRAND.0.to_string(), GREASE_BRAND.1.to_string()),
            ("Chromium".to_string(), self.major_version.clone()),
        ]
    }

    /// The same list with full versions, for `fullVersionList`.
    pub fn full_version_list(&self) -> Vec<(String, String)> {
        // Derived from `brands` rather than restated, because the two lists must
        // carry the same brands in the same order — a page can compare them, and
        // when this repeated the list literally the two orders drifted apart.
        self.brands()
            .into_iter()
            .map(|(brand, version)| {
                let full = if brand == GREASE_BRAND.0 {
                    // The greased entry keeps its own version, padded to the
                    // four-part shape the real list uses.
                    format!("{version}.0.0.0")
                } else {
                    self.full_version.clone()
                };
                (brand, full)
            })
            .collect()
    }

    /// `Emulation.setUserAgentOverride`'s `userAgentMetadata` parameter.
    ///
    /// Setting this is what makes `navigator.userAgentData` and the `Sec-CH-UA*`
    /// headers agree with the spoofed User-Agent; without it the browser derives
    /// them from its own build and contradicts itself.
    pub fn to_cdp_metadata(&self) -> Value {
        let brands: Vec<Value> = self
            .brands()
            .into_iter()
            .map(|(brand, version)| json!({ "brand": brand, "version": version }))
            .collect();
        let full_versions: Vec<Value> = self
            .full_version_list()
            .into_iter()
            .map(|(brand, version)| json!({ "brand": brand, "version": version }))
            .collect();

        json!({
            "brands": brands,
            "fullVersionList": full_versions,
            "platform": self.platform,
            "platformVersion": self.platform_version,
            "architecture": self.architecture,
            "bitness": self.bitness,
            "model": self.model,
            "mobile": self.mobile,
            "wow64": false,
            "fullVersion": self.full_version,
        })
    }

    /// The `Sec-CH-UA-Platform` header value, quoted as a structured header.
    pub fn sec_ch_ua_platform(&self) -> String {
        format!("\"{}\"", self.platform)
    }

    /// The `Sec-CH-UA-Mobile` header value, as a structured boolean.
    pub fn sec_ch_ua_mobile(&self) -> &'static str {
        if self.mobile { "?1" } else { "?0" }
    }

    /// The `Sec-CH-UA` header value.
    ///
    /// Provided for the HTTP transport, where the header is set directly rather
    /// than derived by a browser.
    pub fn sec_ch_ua(&self) -> String {
        self.brands()
            .into_iter()
            .map(|(brand, version)| format!("\"{brand}\";v=\"{version}\""))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values captured from branded Google Chrome 153 on macOS 27, verbatim.
    ///
    /// Pinned here so a future edit to the constants has to be a deliberate
    /// recapture rather than a silent drift away from the browser.
    mod captured_chrome_153_macos {
        pub const BRANDS: &[(&str, &str)] = &[
            ("Google Chrome", "153"),
            ("Not_A Brand", "8"),
            ("Chromium", "153"),
        ];
        pub const PLATFORM_VERSION: &str = "27.0.0";
        pub const FULL_VERSION: &str = "153.0.8010.53";
    }

    #[test]
    fn the_brand_list_matches_the_capture_exactly() {
        // Order included: Chrome permutes the list from a major-version seed, so
        // the sequence is as much a fingerprint as the names are.
        let profile = mac_profile();
        let hints = ClientHints::for_profile(&profile).expect("Chrome hints");
        let brands = hints.brands();

        let expected: Vec<(String, String)> = captured_chrome_153_macos::BRANDS
            .iter()
            .map(|(b, v)| ((*b).to_string(), (*v).to_string()))
            .collect();
        assert_eq!(brands, expected, "the brand list drifted from the capture");
    }

    #[test]
    fn the_greased_brand_is_tied_to_the_measured_major() {
        // Both the punctuation and the version cycle with the major, so moving
        // CHROME_MAJOR without recapturing GREASE_BRAND is a silent regression.
        // This test is the tripwire: if it fails after a version bump, capture
        // the new value with `examples/capture_hints` rather than editing it to
        // match.
        assert_eq!(
            crate::emulation::CHROME_MAJOR,
            153,
            "CHROME_MAJOR moved: recapture GREASE_BRAND, the brand order and \
             CHROME_FULL_VERSION from a branded Chrome at the new major"
        );
        assert_eq!(GREASE_BRAND, ("Not_A Brand", "8"));
    }

    #[test]
    fn the_macos_platform_version_is_the_captured_one() {
        let hints = ClientHints::for_profile(&mac_profile()).expect("Chrome hints");
        assert_eq!(
            hints.platform_version,
            captured_chrome_153_macos::PLATFORM_VERSION
        );
    }

    #[test]
    fn the_full_version_is_a_real_build_not_a_zeroed_one() {
        // No real Chrome reports `{major}.0.0.0` in fullVersionList, so a zeroed
        // build is a signal rather than a neutral placeholder.
        let hints = ClientHints::for_profile(&mac_profile()).expect("Chrome hints");
        assert_eq!(hints.full_version, captured_chrome_153_macos::FULL_VERSION);
        assert!(
            !hints.full_version.ends_with(".0.0.0"),
            "the full version fell back to a zeroed build: {}",
            hints.full_version
        );
    }

    #[test]
    fn an_unmeasured_major_gets_a_zeroed_build_not_the_wrong_one() {
        // Pairing the measured build number with a different major would be
        // checkable against public release data, which is worse than zeros.
        assert_eq!(full_version_for(124), "124.0.0.0");
        assert_eq!(
            full_version_for(crate::emulation::CHROME_MAJOR),
            captured_chrome_153_macos::FULL_VERSION
        );
    }

    /// A profile claiming the measured Chrome on macOS.
    fn mac_profile() -> BrowserProfile {
        let mut profile = BrowserProfile::random();
        profile.user_agent = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
            crate::emulation::CHROME_MAJOR
        );
        profile
    }

    fn chrome_profile(user_agent: &str) -> BrowserProfile {
        BrowserProfile {
            user_agent: user_agent.to_string(),
            platform: "Win32".to_string(),
            hardware_concurrency: 8,
            device_memory: 16,
            webgl_vendor: "Vendor".to_string(),
            webgl_renderer: "Renderer".to_string(),
            viewport_width: 1920,
            viewport_height: 1080,
            accept_language: "en-US".to_string(),
        }
    }

    const WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    const MAC_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    const LINUX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
         AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";

    #[test]
    fn the_platform_follows_the_user_agents_own_os() {
        // The User-Agent is what a server compares the hints against, so it is
        // the source rather than navigator.platform.
        for (ua, expected) in [
            (WINDOWS_UA, "Windows"),
            (MAC_UA, "macOS"),
            (LINUX_UA, "Linux"),
        ] {
            let hints = ClientHints::for_profile(&chrome_profile(ua)).expect("Chrome hints");
            assert_eq!(hints.platform, expected, "for {ua}");
        }
    }

    #[test]
    fn the_versions_follow_the_user_agents_major() {
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        assert_eq!(hints.major_version, "124");
        assert_eq!(hints.full_version, "124.0.0.0");

        let hints = ClientHints::for_profile(&chrome_profile(MAC_UA)).expect("hints");
        assert_eq!(hints.major_version, "126");
    }

    #[test]
    fn safari_gets_no_client_hints_at_all() {
        // Safari implements none. Emitting them would be its own contradiction,
        // so the absence is the correct answer rather than a gap.
        assert!(ClientHints::for_profile(&chrome_profile(SAFARI_UA)).is_none());
    }

    #[test]
    fn a_chrome_profile_reports_the_google_chrome_brand() {
        // A plain Chromium build reports only Chromium; a User-Agent claiming
        // Chrome has to report Google Chrome too, or the two disagree.
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        let brands = hints.brands();

        assert_eq!(
            brands.len(),
            3,
            "expected greased + Chromium + Google Chrome"
        );
        assert!(brands.iter().any(|(b, v)| b == "Chromium" && v == "124"));
        assert!(
            brands
                .iter()
                .any(|(b, v)| b == "Google Chrome" && v == "124")
        );
        // Every real brand list carries a greased entry.
        assert!(brands.iter().any(|(b, _)| b == GREASE_BRAND.0));
    }

    #[test]
    fn the_header_form_is_quoted_per_structured_headers() {
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        let header = hints.sec_ch_ua();

        assert!(header.contains(r#""Chromium";v="124""#), "{header}");
        assert!(header.contains(r#""Google Chrome";v="124""#), "{header}");
        assert_eq!(header.matches(", ").count(), 2, "three entries, two joins");

        // The brand text and order measured from branded Google Chrome 153; the
        // major here comes from this fixture's User-Agent, which is what makes
        // the two transports agree with the browser being claimed.
        assert_eq!(
            header,
            r#""Google Chrome";v="124", "Not_A Brand";v="8", "Chromium";v="124""#
        );
    }

    #[test]
    fn the_platform_and_mobile_headers_are_structured_values() {
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        // Quoted string and boolean per RFC 8941, as Chrome sends them.
        assert_eq!(hints.sec_ch_ua_platform(), r#""Windows""#);
        assert_eq!(hints.sec_ch_ua_mobile(), "?0");
    }

    #[test]
    fn the_cdp_metadata_carries_every_field_chrome_reports() {
        // Measured from Chromium 153's getHighEntropyValues; a missing field
        // reads as empty to a page, which is itself a difference.
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        let metadata = hints.to_cdp_metadata();

        for field in [
            "brands",
            "fullVersionList",
            "platform",
            "platformVersion",
            "architecture",
            "bitness",
            "model",
            "mobile",
            "wow64",
        ] {
            assert!(metadata.get(field).is_some(), "missing {field}");
        }
        assert_eq!(metadata["platform"], "Windows");
        assert_eq!(metadata["architecture"], "x86");
        assert_eq!(metadata["bitness"], "64");
        assert_eq!(metadata["mobile"], false);
        assert_eq!(metadata["model"], "");
    }

    #[test]
    fn linux_reports_an_empty_platform_version_as_chromium_does() {
        // Confirmed on Chromium 153: an empty string, not a fabricated number.
        let hints = ClientHints::for_profile(&chrome_profile(LINUX_UA)).expect("hints");
        assert_eq!(hints.platform_version, "");
    }

    #[test]
    fn the_full_version_list_mirrors_the_brand_list() {
        // A page can compare the two; different brands between them would be a
        // contradiction no browser produces.
        let hints = ClientHints::for_profile(&chrome_profile(WINDOWS_UA)).expect("hints");
        let brands: Vec<String> = hints.brands().into_iter().map(|(b, _)| b).collect();
        let full: Vec<String> = hints
            .full_version_list()
            .into_iter()
            .map(|(b, _)| b)
            .collect();
        assert_eq!(brands, full);
    }

    #[test]
    fn an_unparseable_user_agent_still_yields_coherent_hints() {
        // browser_kind falls back to a Chrome major, so the hints must too
        // rather than producing an empty version.
        let hints = ClientHints::for_profile(&chrome_profile("something unrecognisable"))
            .expect("a fallback still yields Chrome hints");
        assert!(!hints.major_version.is_empty());
        assert_eq!(hints.platform, "Linux");
    }
}
