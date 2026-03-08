use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};

/// Represents the fingerprint of a particular browser configuration.
///
/// This struct holds all the necessary details to spoof a realistic browser identity,
/// including user agent, platform, hardware concurrency, and WebGL specifics.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Generates a random realistic Windows Chrome profile.
    pub fn random() -> Self {
        let mut rng = rand::rng();

        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ];

        let webgl_vendors = [
            "Google Inc. (NVIDIA)",
            "Google Inc. (Apple)",
            "Google Inc. (Intel)",
        ];

        let webgl_renderers = [
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (Apple, Apple M1, OpenGL 4.1)",
            "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ];

        let concurrency = [4, 8, 12, 16];
        let memory = [4, 8, 16, 32];
        let dimensions = [(1920, 1080), (2560, 1440), (1366, 768)];

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
            webgl_renderers[1]
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

    #[test]
    fn test_profile_serialization() {
        let profile = BrowserProfile::random();
        let json = serde_json::to_string(&profile).expect("Failed to serialize");
        let deserialized: BrowserProfile =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(profile.user_agent, deserialized.user_agent);
        assert_eq!(profile.platform, deserialized.platform);
    }
}
