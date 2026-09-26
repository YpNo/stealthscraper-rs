//! What the HTTP transport actually puts on the wire.
//!
//! The headers are asserted against a loopback server rather than against the
//! code that builds them, because the emulation contributes its own defaults and
//! the interesting question is which value wins.
//!
//! This exists because that question had the wrong answer. `wreq-util`'s Chrome
//! emulation carries a User-Agent captured from whichever machine built the
//! table — measured as a macOS string — and it overrode the profile's. A Windows
//! profile therefore sent a macOS User-Agent on the HTTP leg while sending a
//! Windows one in the browser, so a session that demoted changed identity
//! mid-flight: exactly what a shared `StealthIdentity` exists to prevent.

#![cfg(feature = "browser")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use stealthscraper_rs::http_scraper::HttpScraper;
use stealthscraper_rs::{BrowserProfile, StealthIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fetches through the HTTP transport and returns the request headers it sent.
async fn headers_for(profile: BrowserProfile) -> HashMap<String, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let port = listener.local_addr().expect("local address").port();

    let captured: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&captured);

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buffer = vec![0u8; 8192];
            if let Ok(read) = socket.read(&mut buffer).await {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                    String::from_utf8_lossy(&buffer[..read]).into_owned();
            }
            let body = "<html><body>ok</body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let identity = Arc::new(Mutex::new(StealthIdentity::new(profile)));
    let scraper = HttpScraper::new(identity, None).expect("build the HTTP transport");
    let _ = scraper.fetch(&format!("http://127.0.0.1:{port}/")).await;

    let request = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
    request
        .lines()
        .skip(1) // the request line
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// As [`headers_for`], but preserving the order the headers were sent in.
async fn ordered_headers(profile: BrowserProfile) -> Vec<(String, String)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    let port = listener.local_addr().expect("local address").port();

    let captured: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&captured);

    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buffer = vec![0u8; 8192];
            if let Ok(read) = socket.read(&mut buffer).await {
                *sink.lock().unwrap_or_else(|e| e.into_inner()) =
                    String::from_utf8_lossy(&buffer[..read]).into_owned();
            }
            let body = "<html><body>ok</body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let identity = Arc::new(Mutex::new(StealthIdentity::new(profile)));
    let scraper = HttpScraper::new(identity, None).expect("build the HTTP transport");
    let _ = scraper.fetch(&format!("http://127.0.0.1:{port}/")).await;

    let request = captured.lock().unwrap_or_else(|e| e.into_inner()).clone();
    request
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

/// Fetches through the HTTP transport and returns the header names it sent, in
/// wire order.
async fn header_order_for(profile: BrowserProfile) -> Vec<String> {
    ordered_headers(profile)
        .await
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_user_agent_is_the_profiles_not_the_emulations() {
    // A Windows profile must send a Windows User-Agent. The emulation's own
    // value is a macOS string, so this fails loudly if it wins again.
    let mut profile = BrowserProfile::random();
    profile.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        .to_string();
    let expected = profile.user_agent.clone();

    let headers = headers_for(profile).await;

    assert_eq!(
        headers.get("user-agent").map(String::as_str),
        Some(expected.as_str()),
        "the emulation's User-Agent overrode the profile's"
    );
    assert!(
        !headers
            .get("user-agent")
            .is_some_and(|ua| ua.contains("Macintosh")),
        "a Windows profile sent a macOS User-Agent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_hints_agree_with_the_user_agent_sent() {
    // The same coherence the browser leg now has: the structured hints must not
    // contradict the User-Agent string beside them.
    let mut profile = BrowserProfile::random();
    profile.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        .to_string();

    let headers = headers_for(profile).await;

    assert_eq!(
        headers.get("sec-ch-ua-platform").map(String::as_str),
        Some("\"Windows\""),
        "the platform hint contradicts the User-Agent"
    );
    assert_eq!(
        headers.get("sec-ch-ua-mobile").map(String::as_str),
        Some("?0")
    );

    let brands = headers.get("sec-ch-ua").expect("a Sec-CH-UA header");
    assert!(
        brands.contains(r#""Google Chrome";v="124""#),
        "brand versions must match the User-Agent major: {brands}"
    );
    assert!(
        !brands.contains(r#"v="153""#),
        "the real browser version leaked into the brands: {brands}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mac_profile_sends_mac_hints() {
    // The other direction, so the fix is not just hard-coding Windows.
    let mut profile = BrowserProfile::random();
    profile.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        .to_string();

    let headers = headers_for(profile).await;

    assert!(
        headers
            .get("user-agent")
            .is_some_and(|ua| ua.contains("Macintosh")),
        "the profile's macOS User-Agent was not sent"
    );
    assert_eq!(
        headers.get("sec-ch-ua-platform").map(String::as_str),
        Some("\"macOS\"")
    );
    assert!(
        headers
            .get("sec-ch-ua")
            .is_some_and(|b| b.contains(r#"v="126""#)),
        "the brand version should follow this profile's major"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_accept_language_follows_the_profile() {
    let mut profile = BrowserProfile::random();
    profile.accept_language = "de-DE,de;q=0.9,en;q=0.8".to_string();
    let expected = profile.accept_language.clone();

    let headers = headers_for(profile).await;

    assert_eq!(
        headers.get("accept-language").map(String::as_str),
        Some(expected.as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_emulations_own_fingerprint_headers_still_come_through() {
    // Overriding the identity headers must not cost the emulation's other
    // browser-shaped headers, which are part of what makes the request look
    // like Chrome.
    let headers = headers_for(BrowserProfile::random()).await;

    for expected in [
        "accept",
        "accept-encoding",
        "sec-fetch-mode",
        "sec-fetch-dest",
    ] {
        assert!(
            headers.contains_key(expected),
            "the emulation's {expected} header was lost, headers: {:?}",
            headers.keys().collect::<Vec<_>>()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_advertised_encodings_are_the_ones_chromium_advertises() {
    // Measured from Chromium 153. Two ways to get this wrong, and the test
    // catches both: dropping `zstd` marks the client as not-Chrome, and
    // advertising an encoding `wreq` cannot decode returns a compressed body to
    // the caller — which is how this was found.
    let headers = headers_for(BrowserProfile::random()).await;

    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("gzip, deflate, br, zstd"),
        "the advertised encodings drifted from the browser's"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_navigation_carries_the_browsers_accept_and_fetch_metadata() {
    let headers = headers_for(BrowserProfile::random()).await;

    assert!(
        headers
            .get("accept")
            .is_some_and(|a| a.starts_with("text/html,application/xhtml+xml")),
        "Accept is not the navigation value the browser sends: {:?}",
        headers.get("accept")
    );
    for (name, value) in [
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-user", "?1"),
        ("sec-fetch-dest", "document"),
        ("upgrade-insecure-requests", "1"),
    ] {
        assert_eq!(
            headers.get(name).map(String::as_str),
            Some(value),
            "{name} does not match the captured navigation"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_headers_are_sent_in_the_order_the_browser_sends_them() {
    // Header order is a fingerprint of its own: the right headers in the wrong
    // order still identifies a non-browser client. This is the order measured
    // from Chromium 153 over HTTP/1.1, restricted to the ones this request
    // carries (no Cookie on a first fetch, and `priority` is HTTP/2 only).
    let order = header_order_for(BrowserProfile::random()).await;

    let expected = [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language",
    ];

    let positions: Vec<Option<usize>> = expected
        .iter()
        .map(|name| order.iter().position(|sent| sent == name))
        .collect();
    for (name, position) in expected.iter().zip(&positions) {
        assert!(position.is_some(), "{name} was not sent at all: {order:?}");
    }
    let found: Vec<usize> = positions.into_iter().flatten().collect();
    assert!(
        found.windows(2).all(|w| w[0] < w[1]),
        "headers are out of the measured order: {order:?}"
    );
}

/// A Safari profile, whose emulation and header set differ from Chrome's.
fn safari_profile() -> BrowserProfile {
    let mut profile = BrowserProfile::random();
    profile.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
         AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15"
        .to_string();
    profile
}

#[tokio::test(flavor = "multi_thread")]
async fn safari_sends_its_own_header_set_not_chromes() {
    // Measured from Safari 27. The absences matter as much as the values: Chrome
    // sends sec-fetch-user and upgrade-insecure-requests on a navigation and
    // Safari sends neither, so emitting them would contradict the User-Agent.
    let headers = headers_for(safari_profile()).await;

    assert_eq!(
        headers.get("accept").map(String::as_str),
        Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        "Safari's Accept carries no image types, unlike Chrome's"
    );
    assert_eq!(
        headers.get("priority").map(String::as_str),
        Some("u=0, i"),
        "Safari sends Priority even on HTTP/1.1"
    );
    for (name, value) in [
        ("sec-fetch-dest", "document"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
    ] {
        assert_eq!(headers.get(name).map(String::as_str), Some(value));
    }
    for absent in ["sec-fetch-user", "upgrade-insecure-requests"] {
        assert!(
            !headers.contains_key(absent),
            "{absent} is a Chrome header; Safari sends none: {:?}",
            headers.keys().collect::<Vec<_>>()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn safari_sends_no_client_hints_at_all() {
    // Safari implements no UA Client Hints. Emitting them would be a
    // contradiction no real Safari produces.
    let headers = headers_for(safari_profile()).await;

    for absent in ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"] {
        assert!(
            !headers.contains_key(absent),
            "{absent} was sent for a Safari profile"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn safari_headers_follow_the_measured_order() {
    // The order measured over HTTP/1.1, and the same order the h2 capture's
    // HPACK block implies once the Huffman-coded names are filled in.
    let order = header_order_for(safari_profile()).await;

    let expected = [
        "sec-fetch-dest",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "accept-language",
        "priority",
        "accept-encoding",
    ];

    let positions: Vec<Option<usize>> = expected
        .iter()
        .map(|name| order.iter().position(|sent| sent == name))
        .collect();
    for (name, position) in expected.iter().zip(&positions) {
        assert!(position.is_some(), "{name} was not sent at all: {order:?}");
    }
    let found: Vec<usize> = positions.into_iter().flatten().collect();
    assert!(
        found.windows(2).all(|w| w[0] < w[1]),
        "headers are out of the measured order: {order:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_two_browsers_send_different_headers() {
    // If these matched, the header half of the emulation would be doing nothing
    // and both profiles would look like the same client.
    let chrome = headers_for(BrowserProfile::random()).await;
    let safari = headers_for(safari_profile()).await;

    assert_ne!(chrome.get("accept"), safari.get("accept"));
    assert!(chrome.contains_key("sec-ch-ua") && !safari.contains_key("sec-ch-ua"));
    assert!(
        chrome.contains_key("upgrade-insecure-requests")
            && !safari.contains_key("upgrade-insecure-requests")
    );
}
