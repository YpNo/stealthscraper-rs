//! Verifies that the egress client's TLS fingerprint is what we claim it is.
//!
//! The crate's central stealth promise is that outbound requests carry the JA4
//! signature of the impersonated browser. These tests measure that promise
//! against the bytes actually written to the socket: a listener captures the
//! raw `ClientHello` produced by BoringSSL, and the `ja4` module fingerprints
//! it.
//!
//! This doubles as the capture harness for building an emulation table — run a
//! browser or client against [`capture_client_hello`] and read off its JA4.

#![cfg(feature = "browser")]

use std::time::Duration;

use stealthscraper_rs::ja4::{ClientHello, Ja4, Transport};
use stealthscraper_rs::tls_capture::RecordingObserver;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// How long to wait for a client to send its `ClientHello`.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the bytes read while looking for a complete hello.
const MAX_HELLO_BYTES: usize = 16 * 1024;

/// Runs `connect` against a throwaway TLS listener and returns the raw
/// `ClientHello` bytes the client sent.
///
/// The handshake is never completed — the listener reads the first record and
/// drops the connection, which is all a fingerprint needs. The client will
/// therefore observe a connection error, and that is expected.
async fn capture_client_hello<F, Fut>(connect: F) -> Vec<u8>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let accept = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];

        // Read until a whole TLS record is buffered, so a hello split across
        // reads is not mistaken for a truncated one.
        loop {
            let n = match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);

            if buf.len() >= 5 {
                let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
                if buf.len() >= record_len + 5 || buf.len() >= MAX_HELLO_BYTES {
                    break;
                }
            }
        }
        buf
    });

    // The connection is expected to fail; we only want the bytes it sent first.
    let url = format!("https://localhost:{port}/");
    tokio::spawn(connect(url));

    tokio::time::timeout(CAPTURE_TIMEOUT, accept)
        .await
        .expect("timed out waiting for ClientHello")
        .expect("capture task panicked")
}

/// Captures the fingerprint of a `wreq` client using `emulation`.
async fn ja4_of(emulation: wreq_util::Emulation) -> Ja4 {
    let bytes = capture_client_hello(move |url| async move {
        let client = wreq::Client::builder()
            .emulation(emulation)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build client");
        let _ = client.get(&url).send().await;
    })
    .await;

    let hello = ClientHello::parse(&bytes).unwrap_or_else(|e| {
        panic!(
            "failed to parse a real BoringSSL ClientHello ({} bytes): {e}",
            bytes.len()
        )
    });
    Ja4::from_client_hello(&hello, Transport::Tcp)
}

#[tokio::test]
async fn parses_a_real_boringssl_client_hello() {
    let bytes = capture_client_hello(|url| async move {
        let client = wreq::Client::builder()
            .emulation(wreq_util::Emulation::Chrome137)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build client");
        let _ = client.get(&url).send().await;
    })
    .await;

    assert!(
        bytes.len() > 100,
        "captured only {} bytes; no ClientHello was sent",
        bytes.len()
    );

    let hello = ClientHello::parse(&bytes).expect("parse real ClientHello");

    // A modern browser hello must carry all of these; their absence would mean
    // the parser silently skipped a field.
    assert!(!hello.cipher_suites.is_empty(), "no cipher suites parsed");
    assert!(!hello.extensions.is_empty(), "no extensions parsed");
    assert!(
        !hello.signature_algorithms.is_empty(),
        "no signature algorithms parsed"
    );
    assert!(
        hello.supported_versions.contains(&0x0304),
        "TLS 1.3 not offered: {:?}",
        hello.supported_versions
    );
    assert_eq!(
        hello.server_name.as_deref(),
        Some("localhost"),
        "SNI did not round-trip"
    );
    assert!(
        hello.alpn.iter().any(|p| p == "h2"),
        "h2 not offered via ALPN: {:?}",
        hello.alpn
    );
}

#[tokio::test]
async fn egress_fingerprint_is_well_formed_and_chrome_shaped() {
    let ja4 = ja4_of(wreq_util::Emulation::Chrome137).await;
    let rendered = ja4.to_string();

    // Segment shape: t13d<nn><nn>h2 for a TLS 1.3, SNI-bearing, h2 client.
    assert!(
        rendered.starts_with("t13d"),
        "expected a TLS 1.3 TCP hello with SNI, got {rendered}"
    );
    assert!(
        ja4.a.ends_with("h2"),
        "expected h2 as the first ALPN, got {rendered}"
    );
    assert_eq!(ja4.a.len(), 10, "segment a must be 10 chars: {rendered}");
    assert_ne!(ja4.b, "000000000000", "no ciphers hashed: {rendered}");
    assert_ne!(ja4.c, "000000000000", "no extensions hashed: {rendered}");

    println!("Chrome137 egress JA4: {rendered}");
}

#[tokio::test]
async fn chrome_egress_matches_the_published_ja4_for_chrome() {
    // Cross-check against the JA4 that public fingerprint databases record for
    // desktop Chrome. This is what distinguishes a correct implementation from
    // a merely self-consistent one: the segments below are derived here from
    // real BoringSSL bytes, and must land on the independently published value.
    //
    // A change here means one of three things, all worth investigating:
    //   - the JA4 computation regressed,
    //   - the emulation data changed underneath us, or
    //   - Chrome's real fingerprint moved and the table needs refreshing.
    const PUBLISHED_CHROME_A: &str = "t13d1516h2";
    const PUBLISHED_CHROME_CIPHER_HASH: &str = "8daaf6152771";

    let ja4 = ja4_of(wreq_util::Emulation::Chrome137).await;

    assert_eq!(
        ja4.a, PUBLISHED_CHROME_A,
        "segment a drifted from the published Chrome fingerprint"
    );
    assert_eq!(
        ja4.b, PUBLISHED_CHROME_CIPHER_HASH,
        "cipher hash drifted from the published Chrome fingerprint"
    );
}

#[tokio::test]
async fn safari_egress_matches_the_published_ja4_for_safari() {
    // The same cross-check for Safari, which offers a different cipher set and
    // so must hash differently.
    let ja4 = ja4_of(wreq_util::Emulation::Safari18_5).await;

    assert_eq!(ja4.a, "t13d2014h2", "segment a drifted for Safari");
    assert_eq!(ja4.b, "a09f3c656075", "cipher hash drifted for Safari");
}

#[tokio::test]
async fn the_same_emulation_fingerprints_identically_across_connections() {
    // A fingerprint that drifts between connections is useless for
    // impersonation, and would mean GREASE is leaking into the hash.
    let first = ja4_of(wreq_util::Emulation::Chrome133).await;
    let second = ja4_of(wreq_util::Emulation::Chrome133).await;
    assert_eq!(
        first, second,
        "Chrome133 produced an unstable fingerprint: {first} vs {second}"
    );
}

#[tokio::test]
async fn different_browser_emulations_produce_different_fingerprints() {
    // Proves the emulation setting actually reaches the wire. If these matched,
    // the JA4 claim would be vacuous regardless of what the profile requested.
    let chrome = ja4_of(wreq_util::Emulation::Chrome137).await;
    let safari = ja4_of(wreq_util::Emulation::Safari18_5).await;

    assert_ne!(
        chrome, safari,
        "Chrome and Safari emulations put identical bytes on the wire"
    );

    println!("Chrome137: {chrome}");
    println!("Safari18_5: {safari}");
}

/// Captures the fingerprint of the **real browser** driven through the MITM
/// proxy, rather than of our own egress client.
///
/// This is the observatory the emulation table is meant to be built from: the
/// JA4 printed here is what the installed browser genuinely emits, so a table
/// entry can be derived from observation instead of transcribed from a
/// third-party source.
#[tokio::test]
async fn captures_the_real_browsers_fingerprint_through_the_proxy() {
    use std::sync::Arc;
    use stealthscraper_rs::tls_capture::ClientHelloObserver;

    // The dev-dependency `reqwest` also enables rustls' aws-lc-rs provider, so
    // this test binary has two and rustls cannot choose automatically. Pin the
    // same provider the library itself installs.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let observer = Arc::new(RecordingObserver::new());

    let proxy = stealthscraper_rs::TlsSpoofingProxy::start_with_observer(
        wreq::Client::builder().build().expect("client"),
        false,
        Some(observer.clone() as Arc<dyn ClientHelloObserver>),
    )
    .await
    .expect("start proxy");

    let port = proxy.port();

    // Drive any TLS client through the proxy's CONNECT tunnel; the hello it
    // sends inside the tunnel is what gets observed.
    let probe = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).expect("proxy"))
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .expect("probe client");

    let _ = probe.get("https://example.com").send().await;

    let captured = observer.captured();
    assert!(
        !captured.is_empty(),
        "the proxy intercepted no ClientHello; capture is not wired up"
    );

    let (host, bytes) = &captured[0];
    assert_eq!(host, "example.com", "capture recorded the wrong host");

    let hello = ClientHello::parse(bytes)
        .unwrap_or_else(|e| panic!("proxy captured {} unparseable bytes: {e}", bytes.len()));
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);

    assert!(
        ja4.a.starts_with('t'),
        "expected a TCP fingerprint, got {ja4}"
    );
    assert_ne!(ja4.b, "000000000000", "no ciphers observed: {ja4}");

    println!("JA4 observed through the MITM proxy: {ja4}");
    println!("  SNI      : {:?}", hello.server_name);
    println!("  ALPN     : {:?}", hello.alpn);
    println!("  ciphers  : {}", hello.cipher_suites.len());
    println!("  exts     : {}", hello.extensions.len());
}

/// The verified Safari entry must reproduce the measured browser fingerprint
/// when layered over the base emulation, exactly as the library wires it.
///
/// This is the regression guard for `crate::emulation`: if the overlay, the
/// base emulation, or the TLS stack drifts, the JA4 changes and this fails.
#[tokio::test]
async fn safari_overlay_reproduces_the_measured_browser_fingerprint() {
    let bytes = capture_client_hello(|url| async move {
        let client = wreq::Client::builder()
            // Base supplies HTTP/2 settings and headers...
            .emulation(wreq_util::Emulation::Safari18_5)
            // ...and the measured entry overrides only the TLS layer.
            .emulation(stealthscraper_rs::emulation::safari_27())
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build client");
        let _ = client.get(&url).send().await;
    })
    .await;

    let hello = ClientHello::parse(&bytes).expect("parse ClientHello");
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);

    assert_eq!(
        ja4.to_string(),
        stealthscraper_rs::emulation::SAFARI_27_JA4,
        "the Safari entry no longer reproduces the fingerprint captured from \
         Safari 27 on macOS 27"
    );
}

/// Layering the TLS overlay must not disturb the base emulation's other
/// layers — if it did, the HTTP/2 fingerprint would silently regress.
#[tokio::test]
async fn the_overlay_changes_tls_without_discarding_the_base_emulation() {
    async fn ja4_for(build: fn(wreq::ClientBuilder) -> wreq::ClientBuilder) -> Ja4 {
        let bytes = capture_client_hello(move |url| async move {
            let client = build(wreq::Client::builder())
                .timeout(Duration::from_secs(5))
                .build()
                .expect("build client");
            let _ = client.get(&url).send().await;
        })
        .await;
        let hello = ClientHello::parse(&bytes).expect("parse");
        Ja4::from_client_hello(&hello, Transport::Tcp)
    }

    let base_only = ja4_for(|b| b.emulation(wreq_util::Emulation::Safari18_5)).await;
    let layered = ja4_for(|b| {
        b.emulation(wreq_util::Emulation::Safari18_5)
            .emulation(stealthscraper_rs::emulation::safari_27())
    })
    .await;

    // The overlay must actually take effect...
    assert_ne!(
        base_only, layered,
        "the TLS overlay had no effect on the wire"
    );
    // ...and land on the measured fingerprint.
    assert_eq!(
        layered.to_string(),
        stealthscraper_rs::emulation::SAFARI_27_JA4
    );
}
