//! Captures the TLS fingerprint of any client that connects, and prints the
//! values needed to build an emulation entry for it.
//!
//! The listener never answers the handshake: a client sends its `ClientHello`
//! immediately after connecting, so reading that first record is enough. The
//! client will show a connection error — that is expected and harmless.
//!
//! # Usage
//!
//! ```text
//! cargo run --example capture_fingerprint             # 0.0.0.0:8443
//! cargo run --example capture_fingerprint -- 0.0.0.0:9000
//! ```
//!
//! **Prefer proxy mode.** Configure the browser to use `<this-host>:8443` as its
//! HTTPS proxy, then visit any real `https://` site. The listener answers the
//! `CONNECT` and captures the hello sent inside the tunnel.
//!
//! Visiting `https://<this-host>:8443/` directly also works, but a browser omits
//! SNI when the URL is a bare IP address. That flips JA4's SNI flag from `d` to
//! `i` and drops the `server_name` extension from the count, so the fingerprint
//! will not match the one that browser presents to real sites.
//!
//! Code-point names below come from the IANA TLS registries. A wrong or missing
//! name cannot silently corrupt an emulation: the round-trip check — emulate the
//! captured values, re-capture our own hello, compare JA4 — fails if the
//! transcription is wrong.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use stealthscraper_rs::ja4::{ClientHello, Ja4, Transport};

/// Default listen address: all interfaces, so remote browsers can reach it.
const DEFAULT_BIND: &str = "0.0.0.0:8443";

/// Bytes in a TLS record header.
const RECORD_HEADER_LEN: usize = 5;

/// Upper bound on bytes read while waiting for a complete hello.
const MAX_HELLO_BYTES: usize = 16 * 1024;

/// Cipher suite code points, as BoringSSL's `cipher_list` spells them.
const CIPHER_NAMES: &[(u16, &str)] = &[
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"),
    (0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    (0xc030, "ECDHE-RSA-AES256-GCM-SHA384"),
    (0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305"),
    (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305"),
    (0xc013, "ECDHE-RSA-AES128-SHA"),
    (0xc014, "ECDHE-RSA-AES256-SHA"),
    (0xc009, "ECDHE-ECDSA-AES128-SHA"),
    (0xc00a, "ECDHE-ECDSA-AES256-SHA"),
    (0x009c, "AES128-GCM-SHA256"),
    (0x009d, "AES256-GCM-SHA384"),
    (0x002f, "AES128-SHA"),
    (0x0035, "AES256-SHA"),
    (0xc008, "ECDHE-ECDSA-DES-CBC3-SHA"),
    (0xc012, "ECDHE-RSA-DES-CBC3-SHA"),
    (0x000a, "DES-CBC3-SHA"),
];

/// Signature scheme code points, as BoringSSL's `sigalgs_list` spells them.
const SIGALG_NAMES: &[(u16, &str)] = &[
    (0x0403, "ecdsa_secp256r1_sha256"),
    (0x0503, "ecdsa_secp384r1_sha384"),
    (0x0603, "ecdsa_secp521r1_sha512"),
    (0x0804, "rsa_pss_rsae_sha256"),
    (0x0805, "rsa_pss_rsae_sha384"),
    (0x0806, "rsa_pss_rsae_sha512"),
    (0x0401, "rsa_pkcs1_sha256"),
    (0x0501, "rsa_pkcs1_sha384"),
    (0x0601, "rsa_pkcs1_sha512"),
    (0x0807, "ed25519"),
    (0x0808, "ed448"),
    (0x0201, "rsa_pkcs1_sha1"),
    (0x0203, "ecdsa_sha1"),
];

/// Named-group code points, as `wreq`'s `SslCurve` spells them.
const CURVE_NAMES: &[(u16, &str)] = &[
    (0x0017, "SECP256R1"),
    (0x0018, "SECP384R1"),
    (0x0019, "SECP521R1"),
    (0x001d, "X25519"),
    (0x001e, "X448"),
    (0x11ec, "X25519MLKEM768"),
    (0x6399, "X25519KYBER768DRAFT00"),
];

/// Extension code points, for human-readable output only.
const EXTENSION_NAMES: &[(u16, &str)] = &[
    (0x0000, "server_name"),
    (0x0005, "status_request"),
    (0x000a, "supported_groups"),
    (0x000b, "ec_point_formats"),
    (0x000d, "signature_algorithms"),
    (0x0010, "application_layer_protocol_negotiation"),
    (0x0012, "signed_certificate_timestamp"),
    (0x0015, "padding"),
    (0x0017, "extended_master_secret"),
    (0x001b, "compress_certificate"),
    (0x001c, "record_size_limit"),
    (0x0022, "delegated_credentials"),
    (0x0023, "session_ticket"),
    (0x002b, "supported_versions"),
    (0x002d, "psk_key_exchange_modes"),
    (0x0033, "key_share"),
    (0x0039, "quic_transport_parameters"),
    (0x44cd, "application_settings"),
    (0xfe0d, "encrypted_client_hello"),
    (0xff01, "renegotiation_info"),
];

fn lookup(table: &[(u16, &str)], code: u16) -> Option<String> {
    table
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, name)| (*name).to_string())
}

/// Renders `code` as `0xNNNN name`, or `0xNNNN <unknown>`.
fn describe(table: &[(u16, &str)], code: u16) -> String {
    match lookup(table, code) {
        Some(name) => format!("0x{code:04x} {name}"),
        None => format!("0x{code:04x} <unknown>"),
    }
}

/// Joins the names for `codes`, reporting any that have no mapping.
///
/// Unmapped code points are surfaced loudly rather than skipped, since a
/// silently dropped cipher would produce a subtly wrong emulation.
fn name_list(table: &[(u16, &str)], codes: &[u16], skip_grease: bool) -> (String, Vec<u16>) {
    let mut names = Vec::new();
    let mut unknown = Vec::new();

    for &code in codes {
        if skip_grease && stealthscraper_rs::ja4::is_grease(code) {
            continue;
        }
        match lookup(table, code) {
            Some(name) => names.push(name),
            None => unknown.push(code),
        }
    }

    (names.join(":"), unknown)
}

/// Reads bytes until a whole TLS record is buffered.
fn read_record(stream: &mut TcpStream, seed: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut buf = seed;
    let mut chunk = [0u8; 4096];

    loop {
        if buf.len() >= RECORD_HEADER_LEN {
            let declared = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= declared + RECORD_HEADER_LEN || buf.len() >= MAX_HELLO_BYTES {
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

/// Reads the opening `ClientHello`, transparently handling a proxy `CONNECT`.
///
/// The mode is detected from the first byte: a TLS record starts with `0x16`,
/// while a proxy request starts with the ASCII `CONNECT`. Supporting both means
/// one listener serves either style of use — and the proxy path is the one that
/// yields a realistic fingerprint, because a browser omits SNI entirely when
/// the URL is a bare IP address, which changes the JA4.
///
/// Returns the hello bytes and the `CONNECT` target when there was one.
fn read_client_hello(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Option<String>)> {
    let mut head = [0u8; 8];
    let n = stream.read(&mut head)?;
    if n == 0 {
        return Ok((Vec::new(), None));
    }
    let seed = head[..n].to_vec();

    if !seed.starts_with(b"CONNECT") {
        // Direct TLS: the bytes already read are the start of the record.
        return Ok((read_record(stream, seed)?, None));
    }

    // Proxy mode: consume the request head, acknowledge, then read the hello
    // the client sends inside the tunnel.
    let mut request = seed;
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..n]);
        if request.len() > MAX_HELLO_BYTES {
            break;
        }
    }

    let target = String::from_utf8_lossy(&request)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(str::to_string);

    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    stream.flush()?;

    Ok((read_record(stream, Vec::new())?, target))
}

/// `"  (GREASE)"` when `code` is a GREASE value, else empty.
fn grease_marker(code: u16) -> &'static str {
    if stealthscraper_rs::ja4::is_grease(code) {
        "  (GREASE)"
    } else {
        ""
    }
}

fn report(peer: &str, target: Option<&str>, bytes: &[u8]) {
    println!("\n{}", "=".repeat(72));
    println!("ClientHello from {peer}  ({} bytes)", bytes.len());
    if let Some(target) = target {
        println!("via proxy CONNECT to {target}");
    }
    println!("{}", "=".repeat(72));

    let hello = match ClientHello::parse(bytes) {
        Ok(hello) => hello,
        Err(err) => {
            println!("could not parse: {err}");
            return;
        }
    };

    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);
    println!("\nJA4: {ja4}");
    println!("  SNI  : {:?}", hello.server_name);
    println!("  ALPN : {:?}", hello.alpn);

    println!(
        "\n-- Cipher suites ({}, wire order) --",
        hello.cipher_suites.len()
    );
    for code in &hello.cipher_suites {
        println!(
            "  {}{}",
            describe(CIPHER_NAMES, *code),
            grease_marker(*code)
        );
    }

    println!(
        "\n-- Extensions ({}, wire order) --",
        hello.extensions.len()
    );
    for code in &hello.extensions {
        println!(
            "  {}{}",
            describe(EXTENSION_NAMES, *code),
            grease_marker(*code)
        );
    }

    println!(
        "\n-- Supported groups ({}, wire order) --",
        hello.supported_groups.len()
    );
    for code in &hello.supported_groups {
        println!("  {}{}", describe(CURVE_NAMES, *code), grease_marker(*code));
    }

    println!(
        "\n-- Signature algorithms ({}, wire order) --",
        hello.signature_algorithms.len()
    );
    for code in &hello.signature_algorithms {
        println!(
            "  {}{}",
            describe(SIGALG_NAMES, *code),
            grease_marker(*code)
        );
    }

    // The transcription block: paste these straight into a TlsConfig.
    println!("\n{}", "-".repeat(72));
    println!("TlsConfig values");
    println!("{}", "-".repeat(72));

    let (ciphers, unknown_ciphers) = name_list(CIPHER_NAMES, &hello.cipher_suites, true);
    println!("\ncipher_list:\n  \"{ciphers}\"");
    if !unknown_ciphers.is_empty() {
        println!(
            "  !! unmapped cipher code points (add them to CIPHER_NAMES): {}",
            unknown_ciphers
                .iter()
                .map(|c| format!("0x{c:04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let (sigalgs, unknown_sigalgs) = name_list(SIGALG_NAMES, &hello.signature_algorithms, true);
    println!("\nsigalgs_list:\n  \"{sigalgs}\"");
    if !unknown_sigalgs.is_empty() {
        println!(
            "  !! unmapped signature schemes: {}",
            unknown_sigalgs
                .iter()
                .map(|c| format!("0x{c:04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let versions: Vec<String> = hello
        .supported_versions
        .iter()
        .map(|v| format!("0x{v:04x}{}", grease_marker(*v)))
        .collect();
    println!("\nsupported_versions: {}", versions.join(", "));

    let (curves, unknown_curves) = name_list(CURVE_NAMES, &hello.supported_groups, true);
    let curve_expr = curves
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|n| format!("SslCurve::{n}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("\ncurves:\n  &[{curve_expr}]");
    if !unknown_curves.is_empty() {
        println!(
            "  !! unmapped named groups: {}",
            unknown_curves
                .iter()
                .map(|c| format!("0x{c:04x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let grease: BTreeSet<bool> = hello
        .cipher_suites
        .iter()
        .chain(hello.extensions.iter())
        .map(|c| stealthscraper_rs::ja4::is_grease(*c))
        .collect();
    println!("\ngrease_enabled: {}", grease.contains(&true));
}

fn main() -> std::io::Result<()> {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    let listener = TcpListener::bind(&bind)?;

    println!("Fingerprint capture listening on {bind}");
    println!();
    println!(
        "Point a browser at https://<this-host>:{}/ and dismiss the",
        { bind.rsplit(':').next().unwrap_or("8443").to_string() }
    );
    println!("certificate or connection warning — the ClientHello is sent before");
    println!("any warning appears, so it is already captured.");
    println!();
    println!("Press Ctrl-C to stop.");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };

        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        match read_client_hello(&mut stream) {
            Ok((bytes, target)) if !bytes.is_empty() => report(&peer, target.as_deref(), &bytes),
            Ok(_) => println!("\n{peer} connected but sent nothing"),
            Err(err) => eprintln!("\nread from {peer} failed: {err}"),
        }
    }

    Ok(())
}
