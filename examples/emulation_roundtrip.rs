//! Round-trip check: build an emulation from captured values, then measure what
//! it actually puts on the wire.
//!
//! This is the proof step for a hand-built emulation entry. Capture a real
//! browser with `capture_fingerprint`, transcribe its values into the config
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

/// JA4 measured from Chromium 153 by `capture_fingerprint`.
const CHROMIUM_153_JA4: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";

/// Cipher suites Chromium 153 offers, GREASE excluded, in wire order.
const CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-AES128-SHA:",
    "ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:",
    "AES256-GCM-SHA384:",
    "AES128-SHA:",
    "AES256-SHA"
);

/// Signature schemes Chromium 153 offers, minus the ML-DSA entries
/// (0x0904/0x0905/0x0906), which BoringSSL has no name for.
const SIGALGS_LIST: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha512"
);

/// Named groups Chromium 153 offers, GREASE excluded, in wire order.
const CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
];

/// Builds the candidate emulation from the captured values.
fn candidate_emulation() -> EmulationProvider {
    let tls = TlsConfig::builder()
        .cipher_list(CIPHER_LIST)
        .sigalgs_list(SIGALGS_LIST)
        .curves(CURVES)
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

fn read_first_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= 5 {
            let declared = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= declared + 5 {
                break;
            }
        }
    }
    Ok(buf)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    // Fire the request from a worker; this thread captures the hello.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let client = wreq::Client::builder()
                .emulation(candidate_emulation())
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
    let bytes = read_first_record(&mut stream)?;
    let hello = ClientHello::parse(&bytes)?;
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);

    let target: Vec<&str> = CHROMIUM_153_JA4.split('_').collect();
    let matches = ja4.to_string() == CHROMIUM_153_JA4;

    println!("target (Chromium 153) : {CHROMIUM_153_JA4}");
    println!("ours                  : {ja4}");
    println!();
    println!(
        "  segment a: {:<12} vs {:<12} {}",
        ja4.a,
        target[0],
        if ja4.a == target[0] {
            "match"
        } else {
            "DIFFER"
        }
    );
    println!(
        "  segment b: {:<12} vs {:<12} {}",
        ja4.b,
        target[1],
        if ja4.b == target[1] {
            "match"
        } else {
            "DIFFER"
        }
    );
    println!(
        "  segment c: {:<12} vs {:<12} {}",
        ja4.c,
        target[2],
        if ja4.c == target[2] {
            "match"
        } else {
            "DIFFER"
        }
    );
    println!();
    println!(
        "ciphers   : {} non-GREASE",
        count_real(&hello.cipher_suites)
    );
    println!("extensions: {} non-GREASE", count_real(&hello.extensions));
    println!(
        "groups    : {} non-GREASE",
        count_real(&hello.supported_groups)
    );
    println!(
        "sigalgs   : {} non-GREASE",
        count_real(&hello.signature_algorithms)
    );
    println!();
    println!("extensions we emit (wire order):");
    for code in &hello.extensions {
        let grease = if stealthscraper_rs::ja4::is_grease(*code) {
            " (GREASE)"
        } else {
            ""
        };
        println!("  0x{code:04x}{grease}");
    }

    println!();
    if matches {
        println!("ROUND TRIP MATCHES — the emulation reproduces the browser exactly.");
    } else {
        println!("ROUND TRIP DIFFERS — see the segment breakdown above.");
    }

    Ok(())
}

fn count_real(codes: &[u16]) -> usize {
    codes
        .iter()
        .filter(|c| !stealthscraper_rs::ja4::is_grease(**c))
        .count()
}
