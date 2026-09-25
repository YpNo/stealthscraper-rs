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
use wreq::EmulationProvider;

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
// The library's entries, measured against the browsers they claim to be.
//
// These call into `stealthscraper_rs::emulation` rather than restating its
// values, so this check cannot drift from what the crate actually ships.
// ---------------------------------------------------------------------------

fn chromium_153() -> EmulationProvider {
    stealthscraper_rs::emulation::chrome()
}

fn safari_27() -> EmulationProvider {
    stealthscraper_rs::emulation::safari_27()
}

const TARGETS: &[Target] = &[
    Target {
        name: "Chromium 153 (Linux)",
        expected: stealthscraper_rs::emulation::CHROME_JA4_REAL,
        build: chromium_153,
        caveat: Some(
            "sends extension 0xca34 and ML-DSA sigalgs 0x0904/5/6, which BoringSSL cannot emit",
        ),
    },
    Target {
        name: "Safari 27 (macOS 27, warm)",
        expected: stealthscraper_rs::emulation::SAFARI_27_JA4,
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
