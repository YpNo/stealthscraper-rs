//! The MITM certificate authority: one CA per process, leaves minted on demand
//! and cached per host.
//!
//! # Why this exists
//!
//! The proxy previously called `generate_simple_self_signed` for **every**
//! `CONNECT`. That put a key generation on the critical path of each new HTTPS
//! tunnel — a measurable CPU cost and latency spike, paid again for every
//! connection to a host already visited.
//!
//! Here the key generation happens twice for the whole process: once for the CA,
//! once for the key that every leaf shares. After that, a repeat visit to a host
//! is a cache lookup, and a first visit is a single signature.
//!
//! # Why the CA is ephemeral
//!
//! The CA is generated in memory at startup and never written to disk. A CA key
//! persisted on disk — especially one installed into a system or browser trust
//! store so the proxy's certificates are accepted — is a standing
//! man-in-the-middle capability against the machine it sits on, for as long as
//! the file exists. Regenerating per process means a leaked memory image is
//! worth nothing after exit, and there is no file to steal.
//!
//! The cost of that choice is that the browser cannot pre-trust the CA, so it is
//! launched with certificate errors ignored for the loopback leg. That trade is
//! deliberate: the alternative reduces a transient in-memory secret to a durable
//! on-disk one.
//!
//! [`CertAuthority::ca_pem`] exposes the certificate (never the key) for a caller
//! that wants to trust this specific instance for its lifetime.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::Error;

/// Distinct hosts whose certificates are kept.
///
/// The host comes from the `CONNECT` target, which is untrusted input, so the
/// cache has to be bounded: without a limit, a page opening tunnels to many
/// generated hostnames would grow it without end.
const MAX_CACHED_HOSTS: usize = 256;

/// How long a minted leaf certificate is valid for.
///
/// Well inside the 398-day maximum browsers enforce for publicly trusted
/// certificates, so a leaf stays acceptable if the CA is ever trusted properly
/// rather than bypassed.
const LEAF_VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// How long the process's CA is valid for.
const CA_VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 365);

/// Backdating applied to both, absorbing clock skew between us and the browser.
const BACKDATE: Duration = Duration::from_secs(60 * 60);

/// The name the CA presents, so it is identifiable in a certificate viewer.
const CA_COMMON_NAME: &str = "stealthscraper-rs local MITM CA";

/// ALPN protocols offered on the intercepted leg.
///
/// HTTP/1.1 only: the proxy re-emits each request through `wreq`, which owns the
/// upstream HTTP/2 fingerprint. Offering h2 here would have the browser
/// negotiate it with *us*, putting our own HTTP/2 settings on a connection whose
/// fingerprint is supposed to be `wreq`'s.
const ALPN_PROTOCOLS: &[&[u8]] = &[b"http/1.1"];

/// Longest DNS name that can appear in a certificate, per RFC 1035.
const MAX_HOST_LEN: usize = 253;

/// Longest single DNS label.
const MAX_LABEL_LEN: usize = 63;

/// Whether `host` is a name worth minting a certificate for.
///
/// This validation is ours to do. `rcgen` checks only that a SAN is IA5
/// (ASCII), not that it is a well-formed host — so a `CONNECT` target
/// containing spaces, control characters or a NUL byte is accepted into a
/// certificate without it. The target is attacker-influenced, and it becomes
/// both a certificate field and a cache key, so it is parsed here rather than
/// trusted.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }

    // An address literal is legitimate: a CONNECT to a bare IP is normal.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    // A trailing dot is a legal absolute name; an empty label anywhere else is
    // not, which `split` would otherwise let through.
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() {
        return false;
    }

    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            // A wildcard is valid only as a whole leading label, which this
            // deliberately does not special-case: we never need to mint one.
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// A certificate authority that mints and caches per-host leaf certificates.
#[derive(Debug)]
pub struct CertAuthority {
    /// Signs every leaf.
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate in DER form, for [`Self::ca_pem`].
    ca_der: Vec<u8>,
    /// One key shared by every leaf, so a new host costs a signature and not a
    /// key generation. The browser never compares keys across hosts, and this
    /// leg is only ever spoken to by the browser we launched.
    leaf_key: KeyPair,
    /// Ready-to-use TLS configuration per host, newest-last.
    cache: Mutex<LeafCache>,
}

/// Bounded, insertion-ordered cache of per-host TLS configurations.
#[derive(Debug, Default)]
struct LeafCache {
    configs: HashMap<String, Arc<ServerConfig>>,
    /// Insertion order, used to evict the oldest entry when full.
    order: VecDeque<String>,
}

impl LeafCache {
    fn get(&self, host: &str) -> Option<Arc<ServerConfig>> {
        self.configs.get(host).cloned()
    }

    fn insert(&mut self, host: String, config: Arc<ServerConfig>) {
        if self.configs.contains_key(&host) {
            return;
        }
        // Evict the oldest rather than clearing everything, so a burst of
        // one-off hosts cannot flush the hosts actually being used.
        while self.configs.len() >= MAX_CACHED_HOSTS {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.configs.remove(&oldest);
                }
                // Nothing left to evict; stop rather than loop forever.
                None => break,
            }
        }
        self.order.push_back(host.clone());
        self.configs.insert(host, config);
    }
}

/// Seconds since the Unix epoch, saturating at 0 before it.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A validity window around now, as rcgen wants it.
fn validity(lifetime: Duration) -> Result<(time::OffsetDateTime, time::OffsetDateTime), Error> {
    let now = unix_now();
    let from = time::OffsetDateTime::from_unix_timestamp(now - BACKDATE.as_secs() as i64)
        .map_err(|e| Error::TlsError(format!("certificate start time out of range: {e}")))?;
    let until = time::OffsetDateTime::from_unix_timestamp(now + lifetime.as_secs() as i64)
        .map_err(|e| Error::TlsError(format!("certificate end time out of range: {e}")))?;
    Ok((from, until))
}

impl CertAuthority {
    /// Generates a fresh CA and the key its leaves will share.
    ///
    /// Both key generations happen here, so no later request pays for one.
    pub fn generate() -> Result<Self, Error> {
        let ca_key = KeyPair::generate()
            .map_err(|e| Error::TlsError(format!("CA key generation failed: {e}")))?;
        let leaf_key = KeyPair::generate()
            .map_err(|e| Error::TlsError(format!("leaf key generation failed: {e}")))?;

        let mut params = CertificateParams::default();
        let (not_before, not_after) = validity(CA_VALIDITY)?;
        params.not_before = not_before;
        params.not_after = not_after;
        // A path length of 0 lets this CA sign leaves but not further CAs, so a
        // leaked leaf cannot be used to issue anything.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(
            DnType::CommonName,
            DnValue::Utf8String(CA_COMMON_NAME.to_string()),
        );

        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|e| Error::TlsError(format!("CA certificate generation failed: {e}")))?;
        let ca_der = ca_cert.der().to_vec();

        Ok(Self {
            issuer: Issuer::new(params, ca_key),
            ca_der,
            leaf_key,
            cache: Mutex::new(LeafCache::default()),
        })
    }

    /// The CA certificate in PEM form.
    ///
    /// Only the certificate: the private key is never exposed, so this can be
    /// handed to anything that needs to trust this process's proxy.
    pub fn ca_pem(&self) -> String {
        pem_block("CERTIFICATE", &self.ca_der)
    }

    /// The TLS configuration to terminate a connection for `host`.
    ///
    /// The first call for a host mints and caches a certificate; later calls are
    /// a lookup. `host` comes from `CONNECT` and is untrusted, so it is
    /// validated before anything is minted or cached under it.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, Error> {
        if !is_valid_host(host) {
            return Err(Error::TlsError(format!(
                "refusing to mint a certificate for an invalid CONNECT host {host:?}"
            )));
        }

        if let Some(config) = self.locked_cache().get(host) {
            return Ok(config);
        }

        let config = Arc::new(self.mint(host)?);

        // A concurrent call may have inserted the same host meanwhile. Both
        // configurations are equally valid, so keep whichever landed first
        // rather than replacing it and invalidating nothing.
        let mut cache = self.locked_cache();
        if let Some(existing) = cache.get(host) {
            return Ok(existing);
        }
        cache.insert(host.to_string(), Arc::clone(&config));
        Ok(config)
    }

    /// Number of hosts currently cached.
    pub fn cached_hosts(&self) -> usize {
        self.locked_cache().configs.len()
    }

    /// Builds a TLS configuration for `host` without consulting the cache.
    fn mint(&self, host: &str) -> Result<ServerConfig, Error> {
        let chain = self.certificate_chain(host)?;
        self.config_from(host, chain)
    }

    /// Mints the leaf for `host` and returns it with the CA appended.
    fn certificate_chain(&self, host: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| Error::TlsError(format!("invalid CONNECT host {host:?}: {e}")))?;

        let (not_before, not_after) = validity(LEAF_VALIDITY)?;
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // The SAN carries the host; the common name mirrors it so the
        // certificate reads correctly in a viewer.
        params
            .distinguished_name
            .push(DnType::CommonName, DnValue::Utf8String(host.to_string()));

        let leaf = params
            .signed_by(&self.leaf_key, &self.issuer)
            .map_err(|e| Error::TlsError(format!("leaf certificate for {host} failed: {e}")))?;

        // The chain includes the CA so the browser can build a path to it
        // without having been given the CA separately.
        let chain = vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(self.ca_der.clone()),
        ];
        Ok(chain)
    }

    /// Builds the TLS configuration from an already-minted chain.
    ///
    /// Split out from [`Self::mint`] so a test can inspect the chain, which
    /// rustls does not expose once it is inside a `ServerConfig`.
    fn config_from(
        &self,
        host: &str,
        chain: Vec<CertificateDer<'static>>,
    ) -> Result<ServerConfig, Error> {
        let key = PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()).into();

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| Error::TlsError(format!("TLS config for {host} failed: {e}")))?;
        config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();

        Ok(config)
    }

    /// The cache lock, recovering from a poisoned mutex.
    ///
    /// The lock is never held across an await and the guarded data is a plain
    /// map, so a panic elsewhere must not make the proxy stop serving.
    fn locked_cache(&self) -> std::sync::MutexGuard<'_, LeafCache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Wraps DER bytes in a PEM block.
///
/// Hand-rolled rather than pulling in a PEM crate: this is base64 with a header,
/// used once, for an output nothing parses in a hot path.
fn pem_block(label: &str, der: &[u8]) -> String {
    let encoded = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Standard base64, no padding shortcuts.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> CertAuthority {
        // rustls needs a process-wide provider before any config is built.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        CertAuthority::generate().expect("generate a CA")
    }

    #[test]
    fn the_same_host_is_served_from_cache() {
        let ca = authority();

        let first = ca.server_config("example.com").expect("first");
        let second = ca.server_config("example.com").expect("second");

        // The point of the cache: one certificate, not one per connection.
        assert!(
            Arc::ptr_eq(&first, &second),
            "a repeat host should reuse the cached configuration"
        );
        assert_eq!(ca.cached_hosts(), 1);
    }

    #[test]
    fn different_hosts_get_different_certificates() {
        let ca = authority();

        let a = ca.server_config("a.example").expect("a");
        let b = ca.server_config("b.example").expect("b");

        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(ca.cached_hosts(), 2);
    }

    #[test]
    fn the_cache_is_bounded_against_untrusted_hosts() {
        // The CONNECT host is attacker-influenced, so the cache must not grow
        // without limit.
        let ca = authority();
        for index in 0..MAX_CACHED_HOSTS + 50 {
            ca.server_config(&format!("host{index}.example"))
                .expect("mint");
        }
        assert!(
            ca.cached_hosts() <= MAX_CACHED_HOSTS,
            "cache grew to {} entries, past the {MAX_CACHED_HOSTS} limit",
            ca.cached_hosts()
        );
    }

    #[test]
    fn eviction_drops_the_oldest_and_keeps_the_newest() {
        let ca = authority();
        for index in 0..MAX_CACHED_HOSTS {
            ca.server_config(&format!("host{index}.example"))
                .expect("mint");
        }
        // One more evicts the oldest entry, not an arbitrary one.
        ca.server_config("newcomer.example").expect("mint");

        let cache = ca.locked_cache();
        assert!(
            cache.get("newcomer.example").is_some(),
            "the newest host should be retained"
        );
        assert!(
            cache.get("host0.example").is_none(),
            "the oldest host should have been evicted"
        );
        assert!(
            cache
                .get(&format!("host{}.example", MAX_CACHED_HOSTS - 1))
                .is_some(),
            "a recent host should survive eviction"
        );
    }

    #[test]
    fn an_ip_literal_host_is_accepted() {
        // A CONNECT to a bare address is legal and must not be rejected.
        let ca = authority();
        assert!(ca.server_config("127.0.0.1").is_ok());
    }

    #[test]
    fn an_invalid_host_is_refused() {
        // rcgen accepts any ASCII string as a SAN, so without our own check
        // these would all be minted into a certificate and cached.
        let ca = authority();
        for host in [
            "",
            "not a valid host",
            "has\u{0}nul",
            "has\nnewline",
            "double..dot",
            "-leading.hyphen",
            "trailing-.hyphen",
            "tab\tseparated",
            "semi;colon",
            "slash/path",
        ] {
            let result = ca.server_config(host);
            assert!(
                matches!(result, Err(Error::TlsError(_))),
                "{host:?} should have been refused, got {result:?}"
            );
        }
        assert_eq!(ca.cached_hosts(), 0, "a refused host must not be cached");
    }

    #[test]
    fn an_over_long_host_is_refused() {
        // A 253-character limit exists in the DNS; the cache key should not be
        // allowed to grow past it either.
        let ca = authority();
        let too_long = format!("{}.example", "a".repeat(MAX_HOST_LEN));
        assert!(matches!(
            ca.server_config(&too_long),
            Err(Error::TlsError(_))
        ));

        let long_label = format!("{}.example", "a".repeat(MAX_LABEL_LEN + 1));
        assert!(matches!(
            ca.server_config(&long_label),
            Err(Error::TlsError(_))
        ));
    }

    #[test]
    fn ordinary_hosts_are_accepted() {
        let ca = authority();
        for host in [
            "example.com",
            "sub.domain.example.com",
            "with-hyphen.example",
            "under_score.example",
            "absolute.example.com.",
            "localhost",
            "127.0.0.1",
            "::1",
            &format!("{}.example", "a".repeat(MAX_LABEL_LEN)),
        ] {
            assert!(
                ca.server_config(host).is_ok(),
                "{host:?} should have been accepted"
            );
        }
    }

    #[test]
    fn the_exported_pem_carries_the_certificate_and_no_key() {
        let ca = authority();
        let pem = ca.ca_pem();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        // A private key must never be exportable through this path.
        assert!(!pem.contains("PRIVATE KEY"));

        // Every body line is within the PEM line length.
        for line in pem.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64, "PEM line too long: {}", line.len());
        }
    }

    #[test]
    fn base64_matches_known_vectors() {
        // From RFC 4648 section 10, including the padding cases.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_covers_the_whole_alphabet() {
        // A wrong alphabet entry would corrupt the PEM for some inputs only, so
        // exercise every 6-bit value rather than trusting the table by eye.
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = base64_encode(&all_bytes);
        assert!(
            encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "encoded output left the base64 alphabet"
        );
        assert_eq!(encoded.len(), all_bytes.len().div_ceil(3) * 4);
    }

    #[test]
    fn the_local_leg_offers_only_http1() {
        // Negotiating h2 with the browser would put *our* HTTP/2 settings on a
        // connection whose fingerprint is supposed to be wreq's.
        let ca = authority();
        let config = ca.server_config("example.com").expect("mint");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_leaf_is_served_with_the_ca_in_its_chain() {
        let ca = authority();
        let chain = ca
            .certificate_chain("example.com")
            .expect("mint a certificate chain");

        // Leaf plus issuer, so the browser can build a path without having been
        // handed the CA separately.
        assert_eq!(chain.len(), 2, "expected a leaf and its issuer");
        assert_eq!(
            chain[1].as_ref(),
            ca.ca_der.as_slice(),
            "the second entry should be this CA"
        );
        assert_ne!(
            chain[0].as_ref(),
            ca.ca_der.as_slice(),
            "the leaf must not be the CA itself"
        );
    }
}
