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
//! - **Observed** on Chromium 153: the GREASE brand entry. A greased brand is
//!   meant to be arbitrary and ignored, so using the value the local browser
//!   actually emits is preferable to inventing one.
//! - **Not measured**: `platformVersion` for Windows and macOS. The values below
//!   are the documented mapping, but this crate has not captured them from a
//!   real branded Chrome on those platforms the way the Safari TLS entry was
//!   captured. See [`PLATFORM_VERSIONS`].

use serde_json::{Value, json};

use crate::profile::{BrowserKind, BrowserProfile};

/// The GREASE brand Chromium 153 emits, measured rather than invented.
///
/// A greased entry exists to be varied and ignored, so its exact text carries no
/// coherence requirement — but emitting one is required, since every real
/// Chromium brand list contains one.
const GREASE_BRAND: (&str, &str) = ("Not_A Brand", "8");

/// `platformVersion` per platform.
///
/// **Not measured.** Linux really does report an empty string (confirmed on
/// Chromium 153); the Windows and macOS values are the documented mapping and
/// should be replaced with captures from a real branded Chrome on those
/// platforms, the same way the Safari TLS entry was.
const PLATFORM_VERSIONS: &[(&str, &str)] = &[
    // Windows 10 and 11 both report 10.0.0 or higher; 15.0.0 is Windows 11.
    ("Windows", "15.0.0"),
    ("macOS", "14.6.1"),
    // Confirmed empty on Chromium 153.
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
            // A real full version has four parts. Only the major is known from
            // the User-Agent, so the rest is zeroed rather than guessed at: a
            // wrong build number is checkable against public release data,
            // while a zeroed one merely looks unremarkable.
            full_version: format!("{major}.0.0.0"),
            architecture: ARCHITECTURE.to_string(),
            bitness: BITNESS.to_string(),
            // Every profile this crate generates is desktop.
            mobile: false,
            model: String::new(),
        })
    }

    /// The brand list, in the shape `navigator.userAgentData.brands` reports.
    ///
    /// Three entries for branded Chrome: the greased entry, `Chromium`, and
    /// `Google Chrome`. A profile claiming Chrome must report the Google Chrome
    /// brand — a plain Chromium build does not, and the User-Agent says Chrome.
    pub fn brands(&self) -> Vec<(String, String)> {
        vec![
            (GREASE_BRAND.0.to_string(), GREASE_BRAND.1.to_string()),
            ("Chromium".to_string(), self.major_version.clone()),
            ("Google Chrome".to_string(), self.major_version.clone()),
        ]
    }

    /// The same list with full versions, for `fullVersionList`.
    pub fn full_version_list(&self) -> Vec<(String, String)> {
        vec![
            (
                GREASE_BRAND.0.to_string(),
                format!("{}.0.0.0", GREASE_BRAND.1),
            ),
            ("Chromium".to_string(), self.full_version.clone()),
            ("Google Chrome".to_string(), self.full_version.clone()),
        ]
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
