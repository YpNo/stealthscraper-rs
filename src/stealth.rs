//! Stealth JavaScript injected before any page script, masking the differences
//! between this browser and the [`BrowserProfile`](crate::profile::BrowserProfile)
//! it claims to be.
//!
//! # What this does *not* do
//!
//! It deliberately leaves alone everything the browser already reports
//! correctly. Measured against Chromium 153, a headless browser launched by this
//! crate already has the right five PDF plugins, the right
//! `[object NetworkInformation]` connection, `pdfViewerEnabled` true, and
//! `navigator.webdriver` false (the launcher never passes
//! `--enable-automation`). Overriding those replaced correct native values with
//! worse imitations — a plain `[1, 2, 3]` array where a `PluginArray` belongs is
//! a stronger signal than the thing it was hiding.
//!
//! # Native shape
//!
//! Two structural properties are as important as the values:
//!
//! - **`navigator` has no own properties.** Every property lives on
//!   `Navigator.prototype`, so anything defined on the instance shows up in
//!   `Object.getOwnPropertyNames(navigator)` — a one-line check. Overrides are
//!   therefore installed on the prototype.
//! - **Accessors report native code.** A real getter stringifies as
//!   `function get hardwareConcurrency() { [native code] }`. An arrow function
//!   shows its source, so `Function.prototype.toString` is patched to report the
//!   native form for the accessors installed here.
//!
//! # Noise
//!
//! Canvas and audio noise is derived from the profile and applied **once per
//! buffer**, not per read. Real hardware gives the same answer twice; a
//! fingerprint that changes between two reads of the same canvas is itself the
//! signal. See [`noise_seed`](crate::stealth::noise_seed).

use sha2::{Digest, Sha256};

use crate::profile::BrowserProfile;

/// Fallback `navigator.languages`, since a real browser never reports an empty list.
const DEFAULT_LANGUAGES: &[&str] = &["en-US", "en"];

/// A stable per-identity seed for fingerprint noise.
///
/// Hashed from the profile so it is identical for every read within a session —
/// as real hardware is — and different for a different identity. Re-perturbing
/// on each read, which this replaces, makes a canvas fingerprint unstable in a
/// way no real device is.
pub fn noise_seed(profile: &BrowserProfile) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(profile.user_agent.as_bytes());
    hasher.update(profile.platform.as_bytes());
    hasher.update(profile.webgl_vendor.as_bytes());
    hasher.update(profile.webgl_renderer.as_bytes());
    hasher.update(profile.hardware_concurrency.to_le_bytes());
    hasher.update(profile.device_memory.to_le_bytes());
    let digest = hasher.finalize();

    // Any four bytes would do; the low word keeps the value small in the script.
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Encodes a value as a JavaScript literal.
///
/// Every injected value goes through this. Interpolating a profile string into
/// `"{value}"` directly is a script-injection hazard and, more immediately, a
/// correctness one: a single `"` in a User-Agent produced syntactically invalid
/// JavaScript, which silently disabled *every* hook in this script rather than
/// failing visibly.
fn js_literal<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// Generates the stealth script for `profile`, with `languages` as
/// `navigator.languages`.
///
/// Intended for `Page.addScriptToEvaluateOnNewDocument`, so it runs before any
/// page script and a page cannot capture the originals first.
pub fn generate_stealth_js(profile: &BrowserProfile, languages: &[String]) -> String {
    let languages: Vec<String> = if languages.is_empty() {
        DEFAULT_LANGUAGES.iter().map(|l| l.to_string()).collect()
    } else {
        languages.to_vec()
    };

    format!(
        r#"
(function() {{
    'use strict';

    // ---------------------------------------------------------------------
    // Native shape: make our own accessors indistinguishable from built-ins.
    // ---------------------------------------------------------------------

    // Functions defined here, mapped to the name a real accessor would report.
    const nativeNames = new WeakMap();
    const originalToString = Function.prototype.toString;

    const patchedToString = function toString() {{
        const name = nativeNames.get(this);
        if (name !== undefined) {{
            return name;
        }}
        return originalToString.call(this);
    }};
    // The patch must not expose itself: `Function.prototype.toString.toString()`
    // has to look native too.
    nativeNames.set(patchedToString, 'function toString() {{ [native code] }}');
    Function.prototype.toString = patchedToString;

    /// Redefines `prop` on `target`'s prototype with a native-looking getter.
    const defineNative = (target, prop, value) => {{
        const getter = function() {{ return value; }};
        nativeNames.set(getter, 'function get ' + prop + '() {{ [native code] }}');

        const existing = Object.getOwnPropertyDescriptor(target, prop);
        try {{
            Object.defineProperty(target, prop, {{
                get: getter,
                set: undefined,
                // Mirror the real descriptor where there is one, so the shape
                // does not change along with the value.
                enumerable: existing ? existing.enumerable : true,
                configurable: existing ? existing.configurable : true
            }});
        }} catch (e) {{
            // A non-configurable property cannot be redefined. Leaving the real
            // value is better than throwing and aborting the whole script.
        }}
    }};

    // Installed on the prototype, never the instance: a real `navigator` has no
    // own properties, so `Object.getOwnPropertyNames(navigator)` must stay empty.
    const nav = Navigator.prototype;

    defineNative(nav, 'hardwareConcurrency', {concurrency});
    defineNative(nav, 'deviceMemory', {memory});
    defineNative(nav, 'platform', {platform});
    defineNative(nav, 'userAgent', {user_agent});
    defineNative(nav, 'languages', Object.freeze({languages}));

    // `webdriver` is already false because the launcher never passes
    // --enable-automation. This is belt and braces for a browser started
    // elsewhere, not the primary defence.
    defineNative(nav, 'webdriver', false);

    // Deliberately untouched, because the browser already reports them
    // correctly and an imitation would be worse:
    //   navigator.plugins / mimeTypes  -- real PluginArray with the PDF set
    //   navigator.pdfViewerEnabled     -- already true
    //   navigator.connection           -- real NetworkInformation

    // ---------------------------------------------------------------------
    // WebGL: report the profile's adapter rather than the real one.
    // ---------------------------------------------------------------------

    const UNMASKED_VENDOR = 37445;
    const UNMASKED_RENDERER = 37446;

    const patchWebGl = (ctor) => {{
        if (!ctor) return;
        const originalGetParameter = ctor.prototype.getParameter;
        const getParameter = function getParameter(parameter) {{
            if (parameter === UNMASKED_VENDOR) return {webgl_vendor};
            if (parameter === UNMASKED_RENDERER) return {webgl_renderer};
            return originalGetParameter.call(this, parameter);
        }};
        nativeNames.set(getParameter, 'function getParameter() {{ [native code] }}');
        ctor.prototype.getParameter = getParameter;
    }};

    patchWebGl(window.WebGLRenderingContext);
    patchWebGl(window.WebGL2RenderingContext);

    // ---------------------------------------------------------------------
    // Deterministic noise, seeded per identity.
    // ---------------------------------------------------------------------

    // A small, fast PRNG. Seeded from the identity, so the sequence is the same
    // on every page of a session and different for a different identity.
    const makeRandom = (seed) => {{
        let state = seed >>> 0;
        return () => {{
            state = (state + 0x6D2B79F5) >>> 0;
            let t = state;
            t = Math.imul(t ^ (t >>> 15), t | 1) >>> 0;
            t = (t ^ (t + Math.imul(t ^ (t >>> 7), t | 61))) >>> 0;
            return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
        }};
    }};

    const SEED = {seed};

    // Buffers already perturbed, so a second read returns the same values.
    // Without this, reading the same canvas twice gives different answers,
    // which no real hardware does.
    const perturbed = new WeakSet();

    const noiseFor = (index) => {{
        // Derived from the seed and the position, so it is stable for a given
        // identity and pixel but not a constant offset across the image.
        const random = makeRandom((SEED ^ Math.imul(index, 0x9E3779B1)) >>> 0);
        return random() < 0.5 ? 0 : 1;
    }};

    const perturbImageData = (imageData) => {{
        if (!imageData || !imageData.data || perturbed.has(imageData.data.buffer)) {{
            return imageData;
        }}
        const data = imageData.data;
        // Only the alpha-free channels, and sparsely: enough to break an exact
        // hash match without visibly altering the image.
        for (let i = 0; i < data.length; i += 4) {{
            const delta = noiseFor(i);
            if (delta === 0) continue;
            data[i] = Math.min(255, data[i] + delta);
        }}
        perturbed.add(data.buffer);
        return imageData;
    }};

    if (window.CanvasRenderingContext2D) {{
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        const getImageData = function getImageData(...args) {{
            return perturbImageData(originalGetImageData.apply(this, args));
        }};
        nativeNames.set(getImageData, 'function getImageData() {{ [native code] }}');
        CanvasRenderingContext2D.prototype.getImageData = getImageData;
    }}

    if (window.AudioBuffer) {{
        const originalGetChannelData = AudioBuffer.prototype.getChannelData;
        const getChannelData = function getChannelData(channel) {{
            const samples = originalGetChannelData.call(this, channel);
            // Once per buffer: the returned Float32Array is the same object on
            // every call, so perturbing per call would accumulate drift.
            if (samples && samples.length > 0 && !perturbed.has(samples.buffer)) {{
                const random = makeRandom(SEED ^ channel);
                for (let i = 0; i < samples.length; i += 1000) {{
                    samples[i] = samples[i] + (random() - 0.5) * 1e-7;
                }}
                perturbed.add(samples.buffer);
            }}
            return samples;
        }};
        nativeNames.set(getChannelData, 'function getChannelData() {{ [native code] }}');
        AudioBuffer.prototype.getChannelData = getChannelData;
    }}

    // ---------------------------------------------------------------------
    // Remaining surfaces.
    // ---------------------------------------------------------------------

    // Headless reports 'denied' for notifications where a real profile reports
    // 'default'; the rest of the API is left alone.
    if (window.Notification && navigator.permissions) {{
        const originalQuery = navigator.permissions.query;
        const query = function query(parameters) {{
            if (parameters && parameters.name === 'notifications') {{
                return Promise.resolve({{ state: Notification.permission, name: 'notifications', onchange: null }});
            }}
            return originalQuery.call(this, parameters);
        }};
        nativeNames.set(query, 'function query() {{ [native code] }}');
        navigator.permissions.query = query;
    }}

    // A real Chrome has window.chrome; headless builds may not.
    if (!window.chrome) {{
        window.chrome = {{
            app: {{
                isInstalled: false,
                InstallState: {{ DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }},
                RunningState: {{ CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }}
            }},
            runtime: {{
                OnInstalledReason: {{ CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' }},
                OnRestartRequiredReason: {{ APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' }},
                PlatformArch: {{ ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' }},
                PlatformOs: {{ ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' }},
                RequestUpdateCheckStatus: {{ NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' }}
            }}
        }};
    }}

    // WebRTC can reveal the host's real addresses regardless of the proxy, so
    // data channels are stubbed rather than left to enumerate candidates.
    if (window.RTCPeerConnection) {{
        const OriginalRtc = window.RTCPeerConnection;
        const Patched = function RTCPeerConnection(...args) {{
            const connection = new OriginalRtc(...args);
            connection.createDataChannel = () => ({{
                close: () => {{}},
                send: () => {{}},
                addEventListener: () => {{}},
                removeEventListener: () => {{}}
            }});
            return connection;
        }};
        nativeNames.set(Patched, 'function RTCPeerConnection() {{ [native code] }}');
        Patched.prototype = OriginalRtc.prototype;
        window.RTCPeerConnection = Patched;
    }}
}})();
"#,
        concurrency = profile.hardware_concurrency,
        memory = profile.device_memory,
        platform = js_literal(&profile.platform),
        user_agent = js_literal(&profile.user_agent),
        languages = js_literal(&languages),
        webgl_vendor = js_literal(&profile.webgl_vendor),
        webgl_renderer = js_literal(&profile.webgl_renderer),
        seed = noise_seed(profile),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> BrowserProfile {
        BrowserProfile {
            user_agent: "TestUserAgent".to_string(),
            platform: "TestPlatform".to_string(),
            hardware_concurrency: 8,
            device_memory: 16,
            webgl_vendor: "TestVendor".to_string(),
            webgl_renderer: "TestRenderer".to_string(),
            viewport_width: 1920,
            viewport_height: 1080,
            accept_language: "en-US".to_string(),
        }
    }

    #[test]
    fn the_profile_values_reach_the_script() {
        let script = generate_stealth_js(&profile(), &["fr-FR".to_string(), "fr".to_string()]);

        assert!(script.contains(r#""TestUserAgent""#));
        assert!(script.contains(r#""TestPlatform""#));
        assert!(script.contains(r#""TestVendor""#));
        assert!(script.contains(r#""TestRenderer""#));
        assert!(script.contains("'hardwareConcurrency', 8"));
        assert!(script.contains("'deviceMemory', 16"));
        assert!(script.contains(r#"["fr-FR","fr"]"#));
    }

    #[test]
    fn empty_languages_floor_to_a_plausible_default() {
        // A real browser never reports an empty navigator.languages.
        let script = generate_stealth_js(&profile(), &[]);
        assert!(script.contains(r#"["en-US","en"]"#));
        assert!(!script.contains("Object.freeze([])"));
    }

    #[test]
    fn a_quote_in_a_profile_value_cannot_break_the_script() {
        // This was a real defect: interpolating into "{value}" turned a single
        // quote into invalid JavaScript, which silently disabled every hook in
        // the script rather than failing visibly.
        let mut hostile = profile();
        hostile.user_agent = r#"Agent" ; alert(1); //"#.to_string();
        hostile.webgl_renderer = "Renderer\"\\\n".to_string();

        let script = generate_stealth_js(&hostile, &["en\"US".to_string()]);

        // The raw sequence that would have ended the string literal early must
        // not appear; the encoded form must.
        assert!(!script.contains(r#""Agent" ; alert(1); //""#));
        assert!(script.contains(r#""Agent\" ; alert(1); //""#));
        assert!(!script.contains("Renderer\"\\\n"));
    }

    #[test]
    fn values_are_defined_on_the_prototype_not_the_instance() {
        // A real navigator has no own properties, so anything defined on the
        // instance is visible to Object.getOwnPropertyNames.
        let script = generate_stealth_js(&profile(), &[]);
        assert!(script.contains("const nav = Navigator.prototype;"));
        assert!(
            !script.contains("defineProperty(navigator,"),
            "overrides must target the prototype, not the navigator instance"
        );
    }

    #[test]
    fn the_correct_native_surfaces_are_left_alone() {
        // Measured against Chromium 153: these are already right, and replacing
        // them with imitations is worse than leaving them.
        let script = generate_stealth_js(&profile(), &[]);
        assert!(
            !script.contains("'plugins'"),
            "the real PluginArray must not be replaced"
        );
        assert!(!script.contains("'mimeTypes'"));
        assert!(!script.contains("'pdfViewerEnabled'"));
        assert!(
            !script.contains("[1, 2, 3]") && !script.contains("[1,2,3]"),
            "a plain array where a PluginArray belongs is a stronger signal \
             than the value it hides"
        );
    }

    #[test]
    fn accessors_are_registered_as_native() {
        let script = generate_stealth_js(&profile(), &[]);
        // The exact form a real accessor reports, measured from Chromium.
        assert!(script.contains("'function get ' + prop + '() { [native code] }'"));
        // The patch must not reveal itself either.
        assert!(script.contains("function toString() { [native code] }"));
    }

    #[test]
    fn the_noise_seed_is_stable_for_one_profile() {
        // Real hardware answers the same way twice.
        let profile = profile();
        assert_eq!(noise_seed(&profile), noise_seed(&profile));
    }

    #[test]
    fn the_noise_seed_differs_between_identities() {
        // ...but two identities must not share a fingerprint.
        let first = profile();
        let mut second = profile();
        second.user_agent = "Different".to_string();
        assert_ne!(noise_seed(&first), noise_seed(&second));

        let mut third = profile();
        third.webgl_renderer = "Other GPU".to_string();
        assert_ne!(noise_seed(&first), noise_seed(&third));
    }

    #[test]
    fn noise_is_applied_once_per_buffer() {
        // Re-perturbing on every read makes a canvas unstable, which is the
        // signal this is supposed to remove.
        let script = generate_stealth_js(&profile(), &[]);
        assert!(script.contains("const perturbed = new WeakSet();"));
        assert!(script.contains("perturbed.has(imageData.data.buffer)"));
        assert!(script.contains("perturbed.has(samples.buffer)"));
    }

    #[test]
    fn zero_valued_hardware_still_produces_a_literal() {
        let mut zeroed = profile();
        zeroed.hardware_concurrency = 0;
        zeroed.device_memory = 0;
        let script = generate_stealth_js(&zeroed, &[]);
        assert!(script.contains("'hardwareConcurrency', 0"));
        assert!(script.contains("'deviceMemory', 0"));
    }

    #[test]
    fn the_script_is_a_closed_iife() {
        let script = generate_stealth_js(&profile(), &[]);
        assert!(script.trim_start().starts_with("(function() {"));
        assert!(script.trim_end().ends_with("})();"));
        // Balanced braces, as a cheap guard against a truncated template.
        let opens = script.matches('{').count();
        let closes = script.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces in the generated script");
    }
}
