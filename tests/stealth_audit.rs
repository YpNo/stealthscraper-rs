//! The stealth audit: asserts, in a real browser, the signals a detection
//! script actually reads.
//!
//! Every check here is one a page can perform in a line or two of JavaScript.
//! They are asserted against a live Chromium rather than against the generated
//! script, because what matters is what the browser ends up reporting — a hook
//! that looks right in source and does nothing is worse than no hook at all.

#![cfg(feature = "browser")]

use std::time::Duration;

use serde_json::Value;
use stealthscraper_rs::CloudScraper;
use stealthscraper_rs::profile::BrowserProfile;

/// How long to wait for the fixture page to load.
const LOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// A page with a canvas and an audio context to fingerprint.
const FIXTURE: &str = "data:text/html,<html><body>\
     <canvas id=c width=64 height=64></canvas>\
     <script>\
     const ctx=document.getElementById('c').getContext('2d');\
     ctx.fillStyle='#f60';ctx.fillRect(0,0,40,20);\
     ctx.fillStyle='rgba(0,80,160,0.7)';ctx.font='14px sans-serif';\
     ctx.fillText('audit',2,30);\
     </script></body></html>";

/// Builds a scraper with the stealth script installed, or `None` with no browser.
async fn scraper(profile: BrowserProfile) -> Option<CloudScraper> {
    match CloudScraper::builder()
        .profile(profile)
        .headless(true)
        .disable_proxy()
        .build()
        .await
    {
        Ok(scraper) => Some(scraper),
        Err(err) => {
            eprintln!("skipping: no browser available ({err})");
            None
        }
    }
}

#[tokio::test]
async fn the_navigator_instance_has_no_own_properties() {
    // The cheapest possible check on a patched browser, and the one the
    // previous implementation failed: overrides defined on the instance rather
    // than the prototype are listed here, while a real navigator lists nothing.
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    let own = page
        .evaluate("JSON.stringify(Object.getOwnPropertyNames(navigator))")
        .await
        .expect("evaluate");
    assert_eq!(
        own.as_str(),
        Some("[]"),
        "navigator gained own properties, which a real one never has"
    );
}

#[tokio::test]
async fn the_spoofed_values_are_what_the_page_reads() {
    let profile = BrowserProfile::random();
    let expected_cores = profile.hardware_concurrency;
    let expected_platform = profile.platform.clone();
    let expected_renderer = profile.webgl_renderer.clone();

    let Some(scraper) = scraper(profile).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    assert_eq!(
        page.evaluate("navigator.hardwareConcurrency")
            .await
            .expect("evaluate")
            .as_u64(),
        Some(expected_cores as u64)
    );
    assert_eq!(
        page.evaluate("navigator.platform")
            .await
            .expect("evaluate")
            .as_str(),
        Some(expected_platform.as_str())
    );

    // WebGL should report the profile's adapter, not the host's.
    let renderer = page
        .evaluate(
            "(() => { const gl = document.createElement('canvas').getContext('webgl'); \
             return gl ? String(gl.getParameter(37446)) : null; })()",
        )
        .await
        .expect("evaluate");
    match renderer.as_str() {
        Some(reported) => assert_eq!(reported, expected_renderer),
        // A container without a GL context cannot answer; that is not a failure
        // of the hook.
        None => eprintln!("no WebGL context available; renderer check skipped"),
    }
}

#[tokio::test]
async fn patched_accessors_report_native_code() {
    // A detection script reads the descriptor's getter and stringifies it. An
    // arrow function shows its source and gives the game away immediately.
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    for property in ["hardwareConcurrency", "platform", "userAgent", "languages"] {
        let source = page
            .evaluate(&format!(
                "String(Object.getOwnPropertyDescriptor(Navigator.prototype, '{property}').get)"
            ))
            .await
            .expect("evaluate");
        let source = source.as_str().unwrap_or_default();
        assert_eq!(
            source,
            format!("function get {property}() {{ [native code] }}"),
            "the {property} accessor does not look native"
        );
    }

    // The patch must not reveal itself either.
    assert_eq!(
        page.evaluate("Function.prototype.toString.toString()")
            .await
            .expect("evaluate")
            .as_str(),
        Some("function toString() { [native code] }")
    );

    // A genuinely native function must still report native code, and an
    // ordinary page function must still show its source — over-reporting
    // everything as native is its own anomaly.
    assert!(
        page.evaluate("Object.keys.toString()")
            .await
            .expect("evaluate")
            .as_str()
            .unwrap_or_default()
            .contains("[native code]")
    );
    assert!(
        page.evaluate("(function pageFn(a){return a+1}).toString()")
            .await
            .expect("evaluate")
            .as_str()
            .unwrap_or_default()
            .contains("return a+1"),
        "a page's own function should still show its source"
    );
}

#[tokio::test]
async fn the_real_plugin_array_survives_untouched() {
    // The previous implementation replaced this with [1, 2, 3]. The shape is
    // what a detection script checks, not just the length.
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    assert_eq!(
        page.evaluate("Object.prototype.toString.call(navigator.plugins)")
            .await
            .expect("evaluate")
            .as_str(),
        Some("[object PluginArray]")
    );
    assert_eq!(
        page.evaluate("String(navigator.plugins instanceof PluginArray)")
            .await
            .expect("evaluate")
            .as_str(),
        Some("true")
    );
    assert_eq!(
        page.evaluate("navigator.plugins.length")
            .await
            .expect("evaluate")
            .as_u64(),
        Some(5),
        "expected Chromium's five PDF viewer plugins"
    );
    // Each entry must be a real Plugin with its mime types, which a plain array
    // of numbers has no way to imitate.
    assert_eq!(
        page.evaluate("navigator.plugins[0].name")
            .await
            .expect("evaluate")
            .as_str(),
        Some("PDF Viewer")
    );
    assert_eq!(
        page.evaluate("Object.prototype.toString.call(navigator.plugins[0])")
            .await
            .expect("evaluate")
            .as_str(),
        Some("[object Plugin]")
    );
    assert_eq!(
        page.evaluate("navigator.plugins[0][0].type")
            .await
            .expect("evaluate")
            .as_str(),
        Some("application/pdf")
    );
}

#[tokio::test]
async fn a_canvas_fingerprint_is_stable_within_a_session() {
    // Real hardware answers the same way twice. Noise re-applied on every read
    // makes the fingerprint unstable, which is itself the signal — and the
    // previous implementation did exactly that.
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    let read = "(() => { const ctx = document.getElementById('c').getContext('2d'); \
                const d = ctx.getImageData(0, 0, 64, 64).data; \
                let h = 0; for (let i = 0; i < d.length; i++) { h = (h * 31 + d[i]) | 0; } \
                return String(h); })()";

    let first = page.evaluate(read).await.expect("first read");
    let second = page.evaluate(read).await.expect("second read");
    let third = page.evaluate(read).await.expect("third read");

    assert_eq!(
        first, second,
        "the canvas fingerprint changed between reads"
    );
    assert_eq!(second, third, "the canvas fingerprint is not stable");
}

#[tokio::test]
async fn two_identities_produce_different_canvas_fingerprints() {
    // Stability must not come from doing nothing: two profiles have to differ,
    // or every session of this crate shares one fingerprint.
    let read = "(() => { const ctx = document.getElementById('c').getContext('2d'); \
                const d = ctx.getImageData(0, 0, 64, 64).data; \
                let h = 0; for (let i = 0; i < d.length; i++) { h = (h * 31 + d[i]) | 0; } \
                return String(h); })()";

    let mut first_profile = BrowserProfile::random();
    first_profile.webgl_renderer = "ANGLE (Audit, Adapter One)".to_string();
    let mut second_profile = BrowserProfile::random();
    second_profile.webgl_renderer = "ANGLE (Audit, Adapter Two)".to_string();

    let Some(one) = scraper(first_profile).await else {
        return;
    };
    let page = one.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");
    let first = page.evaluate(read).await.expect("read");
    drop(one);

    let Some(two) = scraper(second_profile).await else {
        return;
    };
    let page = two.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");
    let second = page.evaluate(read).await.expect("read");

    assert_ne!(
        first, second,
        "two identities produced the same canvas fingerprint"
    );
}

#[tokio::test]
async fn an_audio_fingerprint_does_not_drift_across_reads() {
    // The previous implementation added a constant to sample zero on every
    // call, so repeated reads of one buffer accumulated drift.
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    let read = "(() => { \
        const ctx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 4096, 44100); \
        const buffer = ctx.createBuffer(1, 4096, 44100); \
        const first = buffer.getChannelData(0)[0]; \
        const second = buffer.getChannelData(0)[0]; \
        return JSON.stringify([first, second]); })()";

    let result = page.evaluate(read).await.expect("evaluate");
    let pair: Vec<f64> =
        serde_json::from_str(result.as_str().unwrap_or("[]")).expect("decode the sample pair");
    assert_eq!(pair.len(), 2, "expected two reads of the same buffer");
    assert_eq!(
        pair[0], pair[1],
        "the audio sample drifted between two reads of one buffer"
    );
}

#[tokio::test]
async fn the_automation_marker_is_absent_and_chrome_is_present() {
    let Some(scraper) = scraper(BrowserProfile::random()).await else {
        return;
    };
    let page = scraper.new_stealth_page().await.expect("page");
    page.navigate_and_wait(FIXTURE, LOAD_TIMEOUT)
        .await
        .expect("navigate");

    // False because the launcher never passes --enable-automation, not because
    // a script patched it after the fact.
    assert_eq!(
        page.evaluate("navigator.webdriver")
            .await
            .expect("evaluate"),
        Value::Bool(false)
    );
    assert_eq!(
        page.evaluate("!!window.chrome").await.expect("evaluate"),
        Value::Bool(true)
    );
    // A headless build reports these correctly already; assert we did not break
    // them while patching their neighbours.
    assert_eq!(
        page.evaluate("navigator.pdfViewerEnabled")
            .await
            .expect("evaluate"),
        Value::Bool(true)
    );
    assert_eq!(
        page.evaluate("Object.prototype.toString.call(navigator.connection)")
            .await
            .expect("evaluate")
            .as_str(),
        Some("[object NetworkInformation]")
    );
}
