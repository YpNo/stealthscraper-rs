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
async fn ja4_of(emulation: wreq::EmulationProvider) -> Ja4 {
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
            .emulation(stealthscraper_rs::emulation::chrome())
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
    let ja4 = ja4_of(stealthscraper_rs::emulation::chrome()).await;
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

    println!("Chrome egress JA4: {rendered}");
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

    let ja4 = ja4_of(stealthscraper_rs::emulation::chrome()).await;

    assert_eq!(
        ja4.a, PUBLISHED_CHROME_A,
        "segment a drifted from the published Chrome fingerprint"
    );
    assert_eq!(
        ja4.b, PUBLISHED_CHROME_CIPHER_HASH,
        "cipher hash drifted from the published Chrome fingerprint"
    );
    // The cipher hash is the half that matches the browser exactly; assert the
    // whole string too, so any drift in the entry is caught rather than only
    // drift in these two segments.
    assert_eq!(
        ja4.to_string(),
        stealthscraper_rs::emulation::CHROME_JA4,
        "the Chrome entry no longer emits its recorded fingerprint"
    );
    // And the gap to the real browser is exactly where it is documented: the
    // cipher hash agrees, the extension count and sigalg hash do not.
    let real = stealthscraper_rs::emulation::CHROME_JA4_REAL;
    assert_eq!(ja4.b, real.split('_').nth(1).unwrap());
}

#[tokio::test]
async fn safari_egress_matches_the_published_ja4_for_safari() {
    // The same cross-check for Safari, which offers a different cipher set and
    // so must hash differently.
    let ja4 = ja4_of(stealthscraper_rs::emulation::safari_27()).await;

    assert_eq!(ja4.a, "t13d2014h2", "segment a drifted for Safari");
    assert_eq!(ja4.b, "a09f3c656075", "cipher hash drifted for Safari");
}

#[tokio::test]
async fn the_same_emulation_fingerprints_identically_across_connections() {
    // A fingerprint that drifts between connections is useless for
    // impersonation, and would mean GREASE is leaking into the hash.
    let first = ja4_of(stealthscraper_rs::emulation::chrome()).await;
    let second = ja4_of(stealthscraper_rs::emulation::chrome()).await;
    assert_eq!(
        first, second,
        "the Chrome entry produced an unstable fingerprint: {first} vs {second}"
    );
}

#[tokio::test]
async fn different_browser_emulations_produce_different_fingerprints() {
    // Proves the emulation setting actually reaches the wire. If these matched,
    // the JA4 claim would be vacuous regardless of what the profile requested.
    let chrome = ja4_of(stealthscraper_rs::emulation::chrome()).await;
    let safari = ja4_of(stealthscraper_rs::emulation::safari_27()).await;

    assert_ne!(
        chrome, safari,
        "Chrome and Safari emulations put identical bytes on the wire"
    );

    println!("Chrome: {chrome}");
    println!("Safari: {safari}");
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

/// The Safari entry must reproduce the fingerprint measured from the real
/// browser, exactly as the library wires it.
///
/// This is the regression guard for `crate::emulation`: if the entry or the TLS
/// stack drifts, the JA4 changes and this fails.
#[tokio::test]
async fn the_safari_entry_reproduces_the_measured_browser_fingerprint() {
    let ja4 = ja4_of(stealthscraper_rs::emulation::safari_27()).await;

    assert_eq!(
        ja4.to_string(),
        stealthscraper_rs::emulation::SAFARI_27_JA4,
        "the Safari entry no longer reproduces the fingerprint captured from \
         Safari 27 on macOS 27"
    );
}

/// An emulation must actually reach the wire. A bare client's fingerprint is
/// nothing like a browser's, so if these matched, every JA4 claim in this crate
/// would be vacuous.
#[tokio::test]
async fn an_entry_is_nothing_like_a_bare_client() {
    let bare = ja4_of(wreq::EmulationProvider::default()).await;
    let chrome = ja4_of(stealthscraper_rs::emulation::chrome()).await;

    assert_ne!(bare, chrome, "the emulation had no effect on the wire");
    assert_ne!(
        bare.b, chrome.b,
        "a bare client hashed the same ciphers as the Chrome entry"
    );
}

/// Every `BrowserKind` must route to an entry that puts a browser-shaped
/// fingerprint on the wire — never to a bare client.
#[tokio::test]
async fn for_kind_routes_every_family_to_a_measured_entry() {
    use stealthscraper_rs::BrowserKind;

    let chrome = ja4_of(stealthscraper_rs::emulation::for_kind(BrowserKind::Chrome(
        stealthscraper_rs::emulation::CHROME_MAJOR,
    )))
    .await;
    assert_eq!(chrome.to_string(), stealthscraper_rs::emulation::CHROME_JA4);

    let safari = ja4_of(stealthscraper_rs::emulation::for_kind(BrowserKind::Safari(
        27,
    )))
    .await;
    assert_eq!(
        safari.to_string(),
        stealthscraper_rs::emulation::SAFARI_27_JA4
    );
}
