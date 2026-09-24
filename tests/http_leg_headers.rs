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
