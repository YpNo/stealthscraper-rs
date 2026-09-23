//! Browser fingerprint profiles: the user agent, platform, hardware
//! characteristics, WebGL strings, viewport, and locale that define a
//! synthetic-yet-realistic browser identity.

use rand::RngExt;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};

/// The browser engine and major version a profile impersonates.
///
/// This is the single source of truth linking a profile's User-Agent to the
/// TLS/HTTP2 fingerprint applied on the wire, so the two cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    /// Chrome/Chromium at the given major version.
    Chrome(u32),
    /// Safari at the given major version.
    Safari(u32),
}

/// Major version assumed when a User-Agent cannot be parsed.
///
/// Chosen to match the most common profile this crate generates rather than a
/// sentinel, so an unparseable UA still yields a plausible fingerprint.
const FALLBACK_CHROME_MAJOR: u32 = 124;

/// Extracts the major version immediately following `token` in `ua`.
///
/// e.g. `major_after("… Chrome/124.0.0.0 …", "Chrome/") == Some(124)`.
fn major_after(ua: &str, token: &str) -> Option<u32> {
    let rest = ua.split_once(token)?.1;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

impl BrowserProfile {
    /// The browser identity implied by this profile's User-Agent.
    ///
    /// Safari is only reported when the UA carries `Safari` *without* `Chrome`,
    /// since every Chromium UA also ends in a `Safari/537.36` token.
    pub fn browser_kind(&self) -> BrowserKind {
        let ua = &self.user_agent;

        if let Some(major) = major_after(ua, "Chrome/") {
            return BrowserKind::Chrome(major);
        }

        if ua.contains("Safari") {
            // Safari reports its real version in `Version/17.2`, not the
            // frozen `Safari/605.1.15` build token.
            if let Some(major) = major_after(ua, "Version/") {
                return BrowserKind::Safari(major);
            }
        }

        BrowserKind::Chrome(FALLBACK_CHROME_MAJOR)
    }
}

/// Represents the fingerprint of a particular browser configuration.
///
/// This struct holds all the necessary details to spoof a realistic browser identity,
/// including user agent, platform, hardware concurrency, and WebGL specifics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProfile {
    /// The User-Agent string of the browser.
    pub user_agent: String,
    /// The navigator.platform value (e.g., "Win32", "MacIntel", "Linux x86_64").
    pub platform: String,
    /// The number of logical processors available (navigator.hardwareConcurrency).
    pub hardware_concurrency: u32,
    /// The approximate amount of device memory in gigabytes (navigator.deviceMemory).
    pub device_memory: u32,
    /// The unmasked WebGL vendor string.
    pub webgl_vendor: String,
    /// The unmasked WebGL renderer string.
    pub webgl_renderer: String,
    /// The width of the viewport in pixels.
    pub viewport_width: u32,
    /// The height of the viewport in pixels.
    pub viewport_height: u32,
    /// The Accept-Language header to send with requests, also injected into navigator.languages.
    pub accept_language: String,
}

impl BrowserProfile {
    /// Generates a random realistic browser profile.
    ///
    /// The generated profile randomly selects from modern Chrome usage variants (v124 - v126)
    /// over Windows, Linux, and Mac platforms. It accurately spoofs corresponding hardware
    /// capabilities, including realistic CPU cores (`hardware_concurrency`) and RAM (`device_memory`),
    /// as well as binding platform-specific WebGL renderers (e.g. `Apple M2`, `RTX 3080`).
    pub fn random() -> Self {
        let mut rng = rand::rng();

        // Every major here must have an exact fingerprint available, so the UA
        // and the JA4 signature agree without falling back to a near match.
        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ];

        let webgl_vendors = [
            "Google Inc. (NVIDIA)",
            "Google Inc. (Apple)",
            "Google Inc. (Intel)",
        ];

        let webgl_renderers = [
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (Apple, Apple M2, OpenGL 4.1)",
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ];

        let concurrency = [4, 8, 12, 16];
        let memory = [8, 16, 32];
        let dimensions = [(1920, 1080), (2560, 1440), (1366, 768), (1440, 900)];

        let chosen_ua = user_agents.choose(&mut rng).unwrap();
        // Crude matching of platform to UA for realism
        let chosen_platform = if chosen_ua.contains("Windows") {
            "Win32"
        } else if chosen_ua.contains("Macintosh") {
            "MacIntel"
        } else {
            "Linux x86_64"
        };

        let chosen_vendor = if chosen_ua.contains("Macintosh") {
            webgl_vendors[1]
        } else {
            webgl_vendors[0]
        };
        let chosen_renderer = if chosen_ua.contains("Macintosh") {
            webgl_renderers[2]
        } else if chosen_ua.contains("Windows") {
            // Pick a random windows renderer
            if rng.random_bool(0.5) {
                webgl_renderers[0]
            } else {
                webgl_renderers[3]
            }
        } else {
            webgl_renderers[0]
        };

        let (width, height) = dimensions.choose(&mut rng).unwrap();

        Self {
            user_agent: chosen_ua.to_string(),
            platform: chosen_platform.to_string(),
            hardware_concurrency: *concurrency.choose(&mut rng).unwrap(),
            device_memory: *memory.choose(&mut rng).unwrap(),
            webgl_vendor: chosen_vendor.to_string(),
            webgl_renderer: chosen_renderer.to_string(),
            viewport_width: *width,
            viewport_height: *height,
            accept_language: "en-US,en;q=0.9".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_browser_profile() {
        let profile = BrowserProfile::random();

        assert!(!profile.user_agent.is_empty());
        assert!(!profile.platform.is_empty());
        assert!(profile.hardware_concurrency > 0);
        assert!(profile.device_memory > 0);
        assert!(!profile.webgl_vendor.is_empty());
        assert!(!profile.webgl_renderer.is_empty());
        assert!(profile.viewport_width >= 1024);
        assert!(profile.viewport_height >= 768);
        assert_eq!(profile.accept_language, "en-US,en;q=0.9");
    }

    fn profile_with_ua(user_agent: &str) -> BrowserProfile {
        let mut profile = BrowserProfile::random();
        profile.user_agent = user_agent.to_string();
        profile
    }

    #[test]
    fn browser_kind_parses_chrome_major() {
        let profile = profile_with_ua(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        );
        assert_eq!(profile.browser_kind(), BrowserKind::Chrome(126));
    }

    #[test]
    fn browser_kind_prefers_chrome_over_the_trailing_safari_token() {
        // Every Chromium UA ends in `Safari/537.36`; that must not read as Safari.
        let profile = profile_with_ua(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        );
        assert_eq!(profile.browser_kind(), BrowserKind::Chrome(124));
    }

    #[test]
    fn browser_kind_reads_safari_version_not_build_token() {
        // Real Safari: version lives in `Version/17.4`, not `Safari/605.1.15`.
        let profile = profile_with_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        );
        assert_eq!(profile.browser_kind(), BrowserKind::Safari(17));
    }

    #[test]
    fn browser_kind_falls_back_on_unparseable_user_agent() {
        assert_eq!(
            profile_with_ua("definitely-not-a-user-agent").browser_kind(),
            BrowserKind::Chrome(FALLBACK_CHROME_MAJOR)
        );
        // A `Chrome/` token with no digits must not panic or mis-parse.
        assert_eq!(
            profile_with_ua("Mozilla/5.0 Chrome/").browser_kind(),
            BrowserKind::Chrome(FALLBACK_CHROME_MAJOR)
        );
    }

    #[test]
    fn random_profiles_report_a_chrome_major_matching_their_user_agent() {
        // Regression guard for the JA4/UA mismatch: the parsed major must be
        // the one actually written in the UA string, for every generated profile.
        for _ in 0..200 {
            let profile = BrowserProfile::random();
            let BrowserKind::Chrome(major) = profile.browser_kind() else {
                panic!("generated profile was not Chrome: {}", profile.user_agent);
            };
            assert!(
                profile.user_agent.contains(&format!("Chrome/{major}.")),
                "parsed major {major} absent from UA {}",
                profile.user_agent
            );
        }
    }

    #[test]
    fn test_profile_serialization() {
        let profile = BrowserProfile::random();
        let json = serde_json::to_string(&profile).expect("Failed to serialize");
        let deserialized: BrowserProfile =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(profile.user_agent, deserialized.user_agent);
        assert_eq!(profile.platform, deserialized.platform);
    }

    #[test]
    fn test_realistic_profile_bindings() {
        for _ in 0..100 {
            let profile = BrowserProfile::random();
            if profile.user_agent.contains("Macintosh") {
                assert_eq!(profile.platform, "MacIntel");
                assert_eq!(profile.webgl_vendor, "Google Inc. (Apple)");
                assert!(profile.webgl_renderer.contains("Apple"));
            } else if profile.user_agent.contains("Windows") {
                assert_eq!(profile.platform, "Win32");
                assert_eq!(profile.webgl_vendor, "Google Inc. (NVIDIA)");
                assert!(
                    profile.webgl_renderer.contains("NVIDIA")
                        || profile.webgl_renderer.contains("Intel")
                );
            } else {
                assert_eq!(profile.platform, "Linux x86_64");
                assert_eq!(profile.webgl_vendor, "Google Inc. (NVIDIA)");
            }

            // Checking constraints matching dimensions and hardware limits
            assert!(
                profile.hardware_concurrency == 4
                    || profile.hardware_concurrency == 8
                    || profile.hardware_concurrency == 12
                    || profile.hardware_concurrency == 16
            );
            assert!(
                profile.device_memory == 8
                    || profile.device_memory == 16
                    || profile.device_memory == 32
            );
        }
    }
}
