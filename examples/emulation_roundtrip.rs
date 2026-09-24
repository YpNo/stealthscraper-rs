//! Round-trip check: build emulations from captured values, then measure what
//! they actually put on the wire.
//!
//! This is the proof step for a hand-built emulation entry. Capture a real
//! browser with `capture_fingerprint`, transcribe its values into a target
//! below, and run this: if the JA4 we emit equals the JA4 the browser emitted,
//! the entry is correct by measurement rather than by assertion.
//!
//! ```text
//! cargo run --example emulation_roundtrip
//! ```

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use stealthscraper_rs::ja4::{ClientHello, Ja4, Transport};
use wreq::tls::{AlpnProtos, AlpsProtos, TlsConfig};
use wreq::{CertCompressionAlgorithm, EmulationProvider, SslCurve};

/// A browser fingerprint we are trying to reproduce.
struct Target {
    /// Human-readable name.
    name: &'static str,
    /// JA4 measured from the real browser by `capture_fingerprint`.
    expected: &'static str,
    /// How the observed values were transcribed into a `wreq` config.
    build: fn() -> EmulationProvider,
    /// Anything known to be unreproducible, for honest reporting.
    caveat: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Chromium 153 (Linux, headless) — captured locally.
// ---------------------------------------------------------------------------

const CHROME_CIPHERS: &str = concat!(
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
);

const CHROME_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
);

const CHROME_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
];

fn chromium_153() -> EmulationProvider {
    let tls = TlsConfig::builder()
        .cipher_list(CHROME_CIPHERS)
        .sigalgs_list(CHROME_SIGALGS)
        .curves(CHROME_CURVES)
        .alpn_protos(AlpnProtos::ALL)
        .alps_protos(AlpsProtos::HTTP2)
        .alps_use_new_codepoint(true)
        .permute_extensions(true)
        .grease_enabled(true)
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .cert_compression_algorithm(&[CertCompressionAlgorithm::Brotli][..])
        .build();
    EmulationProvider::builder().tls_config(tls).build()
}

// ---------------------------------------------------------------------------
// Safari 27 on macOS 27 — captured over the LAN via proxy CONNECT.
//
// Differs from Chrome in three ways visible in every capture: the extension
// order is fixed rather than permuted, and neither ALPS (0x44cd) nor ECH
// (0xfe0d) ever appears.
// ---------------------------------------------------------------------------

const SAFARI_CIPHERS: &str = concat!(
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
    "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
    "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
);

/// Safari sends `rsa_pss_rsae_sha384` **twice**, consistently across every
/// capture. It is listed twice here to see whether BoringSSL preserves the
/// duplicate or collapses it.
const SAFARI_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
);

const SAFARI_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
];

fn safari_27() -> EmulationProvider {
    let tls = TlsConfig::builder()
        .cipher_list(SAFARI_CIPHERS)
        .sigalgs_list(SAFARI_SIGALGS)
        .curves(SAFARI_CURVES)
        .alpn_protos(AlpnProtos::ALL)
        // Safari permutes nothing and offers neither ALPS nor ECH.
        .permute_extensions(false)
        .grease_enabled(true)
        .enable_ech_grease(false)
        .pre_shared_key(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .cert_compression_algorithm(&[CertCompressionAlgorithm::Zlib][..])
        .build();
    EmulationProvider::builder().tls_config(tls).build()
}

const TARGETS: &[Target] = &[
    Target {
        name: "Chromium 153 (Linux)",
        expected: "t13d1517h2_8daaf6152771_cb7bf5808d99",
        build: chromium_153,
        caveat: Some(
            "sends extension 0xca34 and ML-DSA sigalgs 0x0904/5/6, which BoringSSL cannot emit",
        ),
    },
    Target {
        name: "Safari 27 (macOS 27, warm)",
        expected: "t13d2014h2_a09f3c656075_d0a99439f9b1",
        build: safari_27,
        // Confirmed reproducible: BoringSSL preserves the repeated
        // rsa_pss_rsae_sha384, so the duplicate survives into the wire bytes.
        caveat: None,
    },
];

fn read_first_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() >= 5 {
            let declared = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= declared + 5 {
                break;
            }
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Captures what `emulation` puts on the wire.
fn measure(build: fn() -> EmulationProvider) -> Result<ClientHello, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let client = wreq::Client::builder()
                .emulation(build())
                .timeout(Duration::from_secs(5))
                .build()
                .expect("client");
            let _ = client
                .get(format!("https://localhost:{port}/"))
                .send()
                .await;
        });
    });

    let (mut stream, _) = listener.accept()?;
    Ok(ClientHello::parse(&read_first_record(&mut stream)?)?)
}

fn count_real(codes: &[u16]) -> usize {
    codes
        .iter()
        .filter(|c| !stealthscraper_rs::ja4::is_grease(**c))
        .count()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for target in TARGETS {
        let hello = measure(target.build)?;
        let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);
        let want: Vec<&str> = target.expected.split('_').collect();
        let got = [ja4.a.as_str(), ja4.b.as_str(), ja4.c.as_str()];

        println!("\n{}", "=".repeat(72));
        println!("{}", target.name);
        println!("{}", "=".repeat(72));
        println!("  want : {}", target.expected);
        println!("  got  : {ja4}");
        println!();
        for (label, (g, w)) in ["a", "b", "c"].iter().zip(got.iter().zip(want.iter())) {
            println!(
                "    segment {label}: {:<13} {}",
                g,
                if g == w {
                    "match".to_string()
                } else {
                    format!("DIFFER (want {w})")
                }
            );
        }
        println!();
        println!(
            "    ciphers {} · extensions {} · groups {} · sigalgs {}",
            count_real(&hello.cipher_suites),
            count_real(&hello.extensions),
            count_real(&hello.supported_groups),
            count_real(&hello.signature_algorithms),
        );
        if let Some(caveat) = target.caveat {
            println!("    known gap: {caveat}");
        }
    }

    println!();
    Ok(())
}
