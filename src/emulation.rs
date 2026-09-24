//! Browser TLS fingerprints verified by measurement.
//!
//! Every entry here was produced the same way, and none was transcribed from a
//! third-party table:
//!
//! 1. capture a real browser's `ClientHello` (`examples/capture_fingerprint`),
//! 2. read its cipher, curve, signature-scheme and extension lists,
//! 3. express those through [`wreq::tls::TlsConfig`],
//! 4. capture what *our* client then emits and require the two JA4s to match
//!    (`examples/emulation_roundtrip`, and the `ja4_egress` integration test).
//!
//! Step 4 is what makes an entry trustworthy: a transcription error changes the
//! hash, so a matching fingerprint cannot be a coincidence.
//!
//! # Why these are overlays
//!
//! An entry sets **only** the TLS layer. HTTP/2 settings and default headers
//! are left untouched so the entry can be layered over a base emulation that
//! supplies them — [`wreq::ClientBuilder::emulation`] applies each part only
//! when present, so a later call overrides TLS while earlier HTTP/2 and header
//! configuration survives.
//!
//! That split is deliberate. The `ja4` module can prove a TLS fingerprint is
//! right, but nothing here yet measures HTTP/2 SETTINGS, so those are left to
//! the base emulation rather than being guessed at.

use wreq::tls::{AlpnProtos, TlsConfig};
use wreq::{CertCompressionAlgorithm, EmulationProvider, EmulationProviderFactory, SslCurve};

use crate::profile::BrowserKind;

/// A TLS-only emulation, intended to be layered over a base emulation.
///
/// See the [module docs](self) for why HTTP/2 and headers are deliberately
/// left unset.
pub struct TlsOverlay(TlsConfig);

impl EmulationProviderFactory for TlsOverlay {
    fn emulation(self) -> EmulationProvider {
        EmulationProvider::builder().tls_config(self.0).build()
    }
}

/// Cipher suites Safari 27 offers, in wire order.
const SAFARI_27_CIPHERS: &str = concat!(
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:",
    "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:",
    "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA"
);

/// Signature schemes Safari 27 offers, in wire order.
///
/// `rsa_pss_rsae_sha384` genuinely appears **twice** — observed in every
/// capture, and reproduced here because BoringSSL preserves the repetition
/// rather than collapsing it. Removing the duplicate changes the fingerprint.
const SAFARI_27_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1"
);

/// Named groups Safari 27 offers, in wire order.
const SAFARI_27_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
];

/// The JA4 this entry reproduces, for a connection carrying a session ticket.
///
/// Asserted by the `ja4_egress` integration test, so a drift in either our
/// configuration or the underlying TLS stack fails the build.
pub const SAFARI_27_JA4: &str = "t13d2014h2_a09f3c656075_d0a99439f9b1";

/// Safari 27 on macOS 27, captured over the LAN and verified by round-trip.
///
/// Three traits distinguish it from Chrome, and all three were observed in
/// every capture:
///
/// - the extension order is **fixed**, not permuted,
/// - ALPS (`0x44cd`) is never offered,
/// - ECH (`0xfe0d`) is never offered.
///
/// # Session sensitivity
///
/// Safari's fingerprint depends on session state. A connection carrying a
/// session ticket presents 14 extensions ([`SAFARI_27_JA4`]); a cold one to a
/// host never visited omits `session_ticket` and presents 13
/// (`t13d2013h2_a09f3c656075_7f0f34a4126d`). This entry reproduces the former,
/// which is what a TLS stack with a warm session cache naturally produces.
pub fn safari_27() -> TlsOverlay {
    TlsOverlay(
        TlsConfig::builder()
            .cipher_list(SAFARI_27_CIPHERS)
            .sigalgs_list(SAFARI_27_SIGALGS)
            .curves(SAFARI_27_CURVES)
            .alpn_protos(AlpnProtos::ALL)
            .permute_extensions(false)
            .grease_enabled(true)
            .enable_ech_grease(false)
            .pre_shared_key(true)
            .enable_ocsp_stapling(true)
            .enable_signed_cert_timestamps(true)
            .cert_compression_algorithm(&[CertCompressionAlgorithm::Zlib][..])
            .build(),
    )
}

/// The verified TLS entry for `kind`, if one exists.
///
/// Returning `None` means we have no measured entry and the base emulation
/// should stand unmodified — never a guess.
///
/// Chrome has no entry yet: the installed BoringSSL cannot emit the `0xca34`
/// extension or the ML-DSA signature schemes current Chrome sends, so no
/// configuration reproduces it exactly. The base emulation remains the closest
/// available match.
pub fn verified_tls(kind: BrowserKind) -> Option<TlsOverlay> {
    match kind {
        // Safari's TLS stack has been stable for many releases: the cipher
        // hash measured from Safari 27 is identical to the one wreq-util
        // records for Safari 18.5, so this entry is applied to any Safari.
        BrowserKind::Safari(_) => Some(safari_27()),
        BrowserKind::Chrome(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safari_profiles_get_a_verified_entry() {
        for major in [15, 18, 26, 27] {
            assert!(
                verified_tls(BrowserKind::Safari(major)).is_some(),
                "Safari {major} should map to the verified entry"
            );
        }
    }

    #[test]
    fn chrome_has_no_entry_until_boringssl_can_reproduce_it() {
        // Asserting the absence keeps the limitation explicit: if an entry is
        // added, this test must be updated deliberately rather than by accident.
        for major in [124, 137, 153] {
            assert!(verified_tls(BrowserKind::Chrome(major)).is_none());
        }
    }

    #[test]
    fn the_sigalg_duplicate_is_preserved_in_the_list() {
        // Safari really does send rsa_pss_rsae_sha384 twice; dropping it would
        // silently change the fingerprint.
        let occurrences = SAFARI_27_SIGALGS.matches("rsa_pss_rsae_sha384").count();
        assert_eq!(
            occurrences, 2,
            "the deliberate duplicate signature scheme was lost"
        );
    }

    #[test]
    fn overlay_builds_without_panicking() {
        // `EmulationProvider`'s fields are private to `wreq`, so the overlay's
        // shape cannot be asserted here. What actually matters — that layering
        // reproduces Safari's fingerprint while leaving the base emulation's
        // HTTP/2 configuration intact — is measured on the wire by
        // `tests/ja4_egress.rs`.
        let _ = safari_27().emulation();
    }
}
