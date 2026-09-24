//! Computation of the JA4 TLS client fingerprint.
//!
//! JA4 (FoxIO) summarises a `ClientHello` as `a_b_c`:
//!
//! - **a** — `<proto><tls_version><sni><cipher_count><ext_count><alpn>`, 10 chars.
//! - **b** — first 12 hex chars of SHA-256 over the *sorted* cipher list.
//! - **c** — first 12 hex chars of SHA-256 over the *sorted* extension list
//!   (excluding SNI and ALPN) plus the signature algorithms in **wire order**.
//!
//! GREASE values (RFC 8701) are excluded everywhere: they are randomised per
//! connection, so including them would make the fingerprint unstable.

use sha2::{Digest, Sha256};

use super::parse::{ClientHello, ext};

/// Number of hex characters retained from each truncated SHA-256.
const HASH_TRUNCATE_LEN: usize = 12;

/// Placeholder used when the hashed list is empty, per the JA4 spec.
const EMPTY_HASH: &str = "000000000000";

/// Largest count representable in JA4's two-digit fields.
const MAX_TWO_DIGIT_COUNT: usize = 99;

/// Returns whether `value` is a GREASE code point (RFC 8701).
///
/// GREASE values are `0x?a?a` with both bytes equal: `0x0a0a`, `0x1a1a`, …,
/// `0xfafa`.
pub fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Formats a code point as JA4's lowercase, zero-padded 4-digit hex.
fn hex4(value: u16) -> String {
    format!("{value:04x}")
}

/// Truncated SHA-256 over a comma-joined list, or the all-zero placeholder.
fn truncated_hash(parts: &[String]) -> String {
    if parts.is_empty() {
        return EMPTY_HASH.to_string();
    }
    let joined = parts.join(",");
    let digest = Sha256::digest(joined.as_bytes());
    // Two hex chars per byte, so six bytes cover the 12-char prefix.
    let hex: String = digest
        .iter()
        .take(HASH_TRUNCATE_LEN / 2)
        .map(|b| format!("{b:02x}"))
        .collect();
    hex
}

/// The transport a fingerprint was observed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS over TCP, rendered as `t`.
    Tcp,
    /// TLS over QUIC, rendered as `q`.
    Quic,
}

impl Transport {
    fn code(self) -> char {
        match self {
            Transport::Tcp => 't',
            Transport::Quic => 'q',
        }
    }
}

/// Renders the two-character TLS version code.
///
/// The negotiated version is whatever the `supported_versions` extension
/// advertises highest; only when that extension is absent does the legacy
/// handshake version apply (TLS 1.3 always pins `legacy_version` to 1.2).
fn version_code(hello: &ClientHello) -> &'static str {
    let highest = hello
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(hello.legacy_version);

    match highest {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

/// Renders JA4's two-character ALPN code from the first offered protocol.
///
/// Uses the protocol's first and last characters (`h2` -> `h2`,
/// `http/1.1` -> `h1`). Non-alphanumeric bytes are hex-encoded so the code
/// stays printable, and an absent ALPN yields `00`.
fn alpn_code(hello: &ClientHello) -> String {
    let Some(first) = hello.alpn.iter().find(|p| !p.is_empty()) else {
        return "00".to_string();
    };

    let bytes = first.as_bytes();
    // Safe: the `find` above guarantees a non-empty protocol.
    let (head, tail) = (bytes[0], bytes[bytes.len() - 1]);

    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        format!("{}{}", head as char, tail as char)
    } else {
        // Hex of the outer bytes, per the spec's non-alphanumeric rule.
        format!("{:x}{:x}", head >> 4, tail & 0x0f)
    }
}

/// A JA4 TLS client fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4 {
    /// The `a` segment: protocol, version, SNI, counts, ALPN.
    pub a: String,
    /// The `b` segment: truncated hash of the sorted cipher list.
    pub b: String,
    /// The `c` segment: truncated hash of extensions and signature algorithms.
    pub c: String,
}

impl Ja4 {
    /// Computes the JA4 fingerprint of `hello` observed over `transport`.
    pub fn from_client_hello(hello: &ClientHello, transport: Transport) -> Self {
        let ciphers: Vec<u16> = hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();

        let extensions: Vec<u16> = hello
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();

        let sni_code = if hello.extensions.contains(&ext::SERVER_NAME) {
            'd'
        } else {
            'i'
        };

        let a = format!(
            "{}{}{}{:02}{:02}{}",
            transport.code(),
            version_code(hello),
            sni_code,
            ciphers.len().min(MAX_TWO_DIGIT_COUNT),
            extensions.len().min(MAX_TWO_DIGIT_COUNT),
            alpn_code(hello),
        );

        // Segment b: ciphers sorted numerically (equivalent to sorting the
        // zero-padded hex strings, and clearer about intent).
        let mut sorted_ciphers = ciphers;
        sorted_ciphers.sort_unstable();
        let b = truncated_hash(&sorted_ciphers.iter().copied().map(hex4).collect::<Vec<_>>());

        // Segment c: SNI and ALPN are counted in `a` but excluded here, since
        // both vary with the request rather than the client.
        let mut sorted_extensions: Vec<u16> = extensions
            .into_iter()
            .filter(|e| *e != ext::SERVER_NAME && *e != ext::ALPN)
            .collect();
        sorted_extensions.sort_unstable();

        let mut c_parts: Vec<String> = sorted_extensions.iter().copied().map(hex4).collect();
        let sig_algs: Vec<String> = hello
            .signature_algorithms
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .map(hex4)
            .collect();

        // Signature algorithms keep wire order and are appended after `_`.
        let c = if c_parts.is_empty() && sig_algs.is_empty() {
            EMPTY_HASH.to_string()
        } else {
            let extension_part = c_parts.join(",");
            c_parts = vec![if sig_algs.is_empty() {
                extension_part
            } else {
                format!("{}_{}", extension_part, sig_algs.join(","))
            }];
            truncated_hash(&c_parts)
        };

        Self { a, b, c }
    }
}

impl std::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.a, self.b, self.c)
    }
}
