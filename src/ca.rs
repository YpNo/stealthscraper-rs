//! The MITM certificate authority: one CA per process, leaves minted on demand
//! and cached per host.
//!
//! # Why this exists
//!
//! The proxy previously called `generate_simple_self_signed` for **every**
//! `CONNECT`, then built a fresh TLS configuration around it. Here both key
//! generations happen once for the whole process — one for the CA, one shared by
//! every leaf — so a first visit to a host costs a single signature and a repeat
//! visit is a cache lookup.
//!
//! # Why BoringSSL and not rustls
//!
//! `wreq` already links BoringSSL for the egress leg, because forging a JA4
//! fingerprint is impossible without it: rustls deliberately exposes no control
//! over extension order, GREASE, curve order or ALPS. That is not going to
//! change, so BoringSSL is permanent here.
//!
//! Given that, terminating the intercepted leg with rustls meant carrying a
//! *second* TLS stack and a second cryptographic implementation (`ring`) purely
//! for a loopback connection we speak to ourselves. Using the stack that is
//! already linked removes ten crates and, more importantly, leaves this crate
//! with one cryptographic implementation to track rather than two.
//!
//! # Why the CA is ephemeral
//!
//! The CA is generated in memory at startup and never written to disk. A CA key
//! persisted on disk — especially one installed into a system or browser trust
//! store so the proxy's certificates are accepted — is a standing
//! man-in-the-middle capability against the machine it sits on, for as long as
//! the file exists. Regenerating per process means there is no file to steal and
//! a leaked memory image is worth nothing after exit.
//!
//! The cost of that choice is that the browser cannot pre-trust the CA, so it is
//! launched with certificate errors ignored for the loopback leg. That trade is
//! deliberate: the alternative turns a transient in-memory secret into a durable
//! on-disk one.
//!
//! [`CertAuthority::ca_pem`](crate::ca::CertAuthority::ca_pem) exposes the certificate
//! (never the key) for a caller
//! that wants to trust this specific instance for its lifetime.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::PoisonError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use btls::asn1::{Asn1Integer, Asn1Time};
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::{PKey, Private};
use btls::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use btls::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use btls::x509::{X509, X509Name, X509NameBuilder};

use crate::Error;

/// Distinct hosts whose certificates are kept.
///
/// The host comes from the `CONNECT` target, which is untrusted input, so the
/// cache has to be bounded: without a limit, a page opening tunnels to many
/// generated hostnames would grow it without end.
const MAX_CACHED_HOSTS: usize = 256;

/// How long a minted leaf certificate is valid for, in days.
///
/// Well inside the 398-day maximum browsers enforce for publicly trusted
/// certificates, so a leaf stays acceptable if the CA is ever trusted properly
/// rather than bypassed.
const LEAF_VALIDITY_DAYS: u32 = 30;

/// How long the process's CA is valid for, in days.
const CA_VALIDITY_DAYS: u32 = 365;

/// Backdating applied to both, absorbing clock skew between us and the browser.
const BACKDATE: Duration = Duration::from_secs(60 * 60);

/// The name the CA presents, so it is identifiable in a certificate viewer.
const CA_COMMON_NAME: &str = "stealthscraper-rs local MITM CA";

/// Bits of randomness in a certificate serial number.
///
/// A predictable serial is not a vulnerability here, but the randomness costs
/// nothing and keeps two leaves for one host distinguishable.
const SERIAL_BITS: i32 = 64;

/// ALPN offered on the intercepted leg, in TLS wire form (length-prefixed).
///
/// HTTP/1.1 only: the proxy re-emits each request through `wreq`, which owns the
/// upstream HTTP/2 fingerprint. Negotiating h2 with the browser here would put
/// *our* HTTP/2 settings on a connection whose fingerprint is supposed to be
/// `wreq`'s.
const ALPN_WIRE: &[u8] = b"\x08http/1.1";

/// Longest DNS name that can appear in a certificate, per RFC 1035.
const MAX_HOST_LEN: usize = 253;

/// Longest single DNS label.
const MAX_LABEL_LEN: usize = 63;

/// Whether `host` is a name worth minting a certificate for.
///
/// This validation is ours to do. A certificate library will happily put an
/// arbitrary ASCII string in a SAN — `rcgen` checks only that it is IA5, and
/// BoringSSL's `SubjectAlternativeName::dns` does not validate either — so a
/// `CONNECT` target containing spaces, control characters or a NUL byte would go
/// straight into a certificate. The target is attacker-influenced and becomes
/// both a certificate field and a cache key, so it is parsed here.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return false;
    }

    // An address literal is legitimate: a CONNECT to a bare IP is normal.
    if host.parse::<IpAddr>().is_ok() {
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
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Maps a BoringSSL error into the crate's error type.
fn tls_err(context: &'static str) -> impl FnOnce(btls::error::ErrorStack) -> Error {
    move |e| Error::TlsError(format!("{context}: {e}"))
}

/// Generates a P-256 key pair.
///
/// P-256 rather than RSA: generation is microseconds instead of tens of
/// milliseconds, and browsers have accepted ECDSA leaves for years.
fn generate_key() -> Result<PKey<Private>, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(tls_err("selecting the P-256 curve"))?;
    let key = EcKey::generate(&group).map_err(tls_err("generating an EC key"))?;
    PKey::from_ec_key(key).map_err(tls_err("wrapping the EC key"))
}

/// A random serial number.
fn random_serial() -> Result<Asn1Integer, Error> {
    let mut serial = BigNum::new().map_err(tls_err("allocating a serial number"))?;
    serial
        .rand(SERIAL_BITS, MsbOption::MAYBE_ZERO, false)
        .map_err(tls_err("randomising a serial number"))?;
    serial
        .to_asn1_integer()
        .map_err(tls_err("encoding a serial number"))
}

/// Longest string X.509 allows in a CommonName (RFC 5280, ub-common-name).
const MAX_COMMON_NAME_LEN: usize = 64;

/// A distinguished name carrying just a common name.
///
/// `value` is truncated to fit. The limit is real — a longer CommonName is
/// rejected outright, and hostnames longer than 64 characters are common — but
/// the field itself is legacy: browsers have matched on subjectAltName alone
/// since Chrome 58, so a shortened CommonName costs nothing while an absent
/// certificate would cost the connection.
fn common_name(value: &str) -> Result<X509Name, Error> {
    // Hosts are validated as ASCII before reaching here, so a byte-wise
    // truncation cannot split a character.
    let value = &value[..value.len().min(MAX_COMMON_NAME_LEN)];

    let mut builder = X509NameBuilder::new().map_err(tls_err("building a name"))?;
    builder
        .append_entry_by_text("CN", value)
        .map_err(tls_err("setting the common name"))?;
    Ok(builder.build())
}

/// The validity window for a certificate living `days` from now.
fn validity(days: u32) -> Result<(Asn1Time, Asn1Time), Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let not_before = Asn1Time::from_unix(now - BACKDATE.as_secs() as i64)
        .map_err(tls_err("encoding a start time"))?;
    let not_after = Asn1Time::days_from_now(days).map_err(tls_err("encoding an end time"))?;
    Ok((not_before, not_after))
}

/// A certificate authority that mints and caches per-host leaf certificates.
pub struct CertAuthority {
    ca_cert: X509,
    ca_key: PKey<Private>,
    /// One key shared by every leaf, so a new host costs a signature and not a
    /// key generation. The browser never compares keys across hosts, and this
    /// leg is only ever spoken to by the browser we launched.
    leaf_key: PKey<Private>,
    cache: Mutex<LeafCache>,
}

// The key and certificate handles are not `Debug`, and would not be safe to
// print if they were; this reports only the cache size.
impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("cached_hosts", &self.cached_hosts())
            .finish_non_exhaustive()
    }
}

/// Bounded, insertion-ordered cache of per-host acceptors.
#[derive(Default)]
struct LeafCache {
    acceptors: HashMap<String, Arc<SslAcceptor>>,
    /// Insertion order, used to evict the oldest entry when full.
    order: VecDeque<String>,
}

impl LeafCache {
    fn get(&self, host: &str) -> Option<Arc<SslAcceptor>> {
        self.acceptors.get(host).cloned()
    }

    fn insert(&mut self, host: String, acceptor: Arc<SslAcceptor>) {
        if self.acceptors.contains_key(&host) {
            return;
        }
        // Evict the oldest rather than clearing everything, so a burst of
        // one-off hosts cannot flush the hosts actually being used.
        while self.acceptors.len() >= MAX_CACHED_HOSTS {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.acceptors.remove(&oldest);
                }
                // Nothing left to evict; stop rather than loop forever.
                None => break,
            }
        }
        self.order.push_back(host.clone());
        self.acceptors.insert(host, acceptor);
    }
}

impl CertAuthority {
    /// Generates a fresh CA and the key its leaves will share.
    ///
    /// Both key generations happen here, so no later request pays for one.
    pub fn generate() -> Result<Self, Error> {
        let ca_key = generate_key()?;
        let leaf_key = generate_key()?;
        let ca_cert = Self::build_ca(&ca_key)?;

        Ok(Self {
            ca_cert,
            ca_key,
            leaf_key,
            cache: Mutex::new(LeafCache::default()),
        })
    }

    /// The CA certificate in PEM form.
    ///
    /// Only the certificate: the private key is never exposed, so this can be
    /// handed to anything that needs to trust this process's proxy.
    pub fn ca_pem(&self) -> Result<String, Error> {
        let pem = self
            .ca_cert
            .to_pem()
            .map_err(tls_err("encoding the CA certificate"))?;
        String::from_utf8(pem)
            .map_err(|e| Error::TlsError(format!("CA certificate PEM was not UTF-8: {e}")))
    }

    /// The browser flag value that trusts exactly this CA's public key.
    ///
    /// Base64 of the SHA-256 of the CA's `SubjectPublicKeyInfo`, which is what
    /// `--ignore-certificate-errors-spki-list` expects.
    ///
    /// This is what lets the browser accept our certificates without
    /// `--ignore-certificate-errors`. The difference is not cosmetic: that flag
    /// makes the browser accept *any* invalid certificate from *any* server, so
    /// a hostile upstream could impersonate a site and the browser would not
    /// object. Pinning narrows the exemption to this one process-local key and
    /// leaves every other certificate error fatal.
    pub fn spki_pin(&self) -> Result<String, Error> {
        let public_key = self
            .ca_cert
            .public_key()
            .map_err(tls_err("reading the CA public key"))?;
        let spki = public_key
            .public_key_to_der()
            .map_err(tls_err("encoding the CA public key"))?;
        let digest = btls::hash::hash(MessageDigest::sha256(), &spki)
            .map_err(tls_err("hashing the CA public key"))?;
        Ok(btls::base64::encode_block(&digest))
    }

    /// The acceptor that terminates a connection for `host`.
    ///
    /// The first call for a host mints and caches a certificate; later calls are
    /// a lookup. `host` comes from `CONNECT` and is untrusted, so it is validated
    /// before anything is minted or cached under it.
    pub fn acceptor(&self, host: &str) -> Result<Arc<SslAcceptor>, Error> {
        if !is_valid_host(host) {
            return Err(Error::TlsError(format!(
                "refusing to mint a certificate for an invalid CONNECT host {host:?}"
            )));
        }

        if let Some(acceptor) = self.locked_cache().get(host) {
            return Ok(acceptor);
        }

        let acceptor = Arc::new(self.build_acceptor(host)?);

        // A concurrent call may have inserted the same host meanwhile. Both are
        // equally valid, so keep whichever landed first.
        let mut cache = self.locked_cache();
        if let Some(existing) = cache.get(host) {
            return Ok(existing);
        }
        cache.insert(host.to_string(), Arc::clone(&acceptor));
        Ok(acceptor)
    }

    /// Number of hosts currently cached.
    pub fn cached_hosts(&self) -> usize {
        self.locked_cache().acceptors.len()
    }

    /// Builds the self-signed CA certificate.
    fn build_ca(ca_key: &PKey<Private>) -> Result<X509, Error> {
        let name = common_name(CA_COMMON_NAME)?;
        let (not_before, not_after) = validity(CA_VALIDITY_DAYS)?;

        let serial = random_serial()?;

        let mut builder = X509::builder().map_err(tls_err("building the CA certificate"))?;
        // Version 2 is the encoding of X.509 v3.
        builder.set_version(2).map_err(tls_err("setting version"))?;
        builder
            .set_serial_number(&serial)
            .map_err(tls_err("setting the serial"))?;
        builder
            .set_subject_name(&name)
            .map_err(tls_err("setting the subject"))?;
        // Self-signed: the issuer is its own subject.
        builder
            .set_issuer_name(&name)
            .map_err(tls_err("setting the issuer"))?;
        builder
            .set_pubkey(ca_key)
            .map_err(tls_err("setting the CA public key"))?;
        builder
            .set_not_before(&not_before)
            .map_err(tls_err("setting notBefore"))?;
        builder
            .set_not_after(&not_after)
            .map_err(tls_err("setting notAfter"))?;

        // pathlen:0 lets this CA sign leaves but not further CAs, so a leaked
        // leaf cannot be used to issue anything.
        let basic_constraints = BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(0)
            .build()
            .map_err(tls_err("building basicConstraints"))?;
        builder
            .append_extension(&basic_constraints)
            .map_err(tls_err("adding basicConstraints"))?;
        let key_usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(tls_err("building keyUsage"))?;
        builder
            .append_extension(&key_usage)
            .map_err(tls_err("adding keyUsage"))?;

        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .map_err(tls_err("building subjectKeyIdentifier"))?;
        builder
            .append_extension(&subject_key_id)
            .map_err(tls_err("adding subjectKeyIdentifier"))?;

        builder
            .sign(ca_key, MessageDigest::sha256())
            .map_err(tls_err("signing the CA certificate"))?;

        Ok(builder.build())
    }

    /// Mints the leaf certificate for `host`.
    fn build_leaf(&self, host: &str) -> Result<X509, Error> {
        let (not_before, not_after) = validity(LEAF_VALIDITY_DAYS)?;

        let serial = random_serial()?;
        let subject = common_name(host)?;

        let mut builder = X509::builder().map_err(tls_err("building a leaf certificate"))?;
        builder.set_version(2).map_err(tls_err("setting version"))?;
        builder
            .set_serial_number(&serial)
            .map_err(tls_err("setting the serial"))?;
        builder
            .set_subject_name(&subject)
            .map_err(tls_err("setting the subject"))?;
        builder
            .set_issuer_name(self.ca_cert.subject_name())
            .map_err(tls_err("setting the issuer"))?;
        builder
            .set_pubkey(&self.leaf_key)
            .map_err(tls_err("setting the leaf public key"))?;
        builder
            .set_not_before(&not_before)
            .map_err(tls_err("setting notBefore"))?;
        builder
            .set_not_after(&not_after)
            .map_err(tls_err("setting notAfter"))?;

        let basic_constraints = BasicConstraints::new()
            .critical()
            .build()
            .map_err(tls_err("building basicConstraints"))?;
        builder
            .append_extension(&basic_constraints)
            .map_err(tls_err("adding basicConstraints"))?;
        let key_usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(tls_err("building keyUsage"))?;
        builder
            .append_extension(&key_usage)
            .map_err(tls_err("adding keyUsage"))?;
        let extended_key_usage = ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .map_err(tls_err("building extendedKeyUsage"))?;
        builder
            .append_extension(&extended_key_usage)
            .map_err(tls_err("adding extendedKeyUsage"))?;

        // An address literal has to go in as an iPAddress SAN; a dNSName holding
        // an address does not match it.
        let mut san = SubjectAlternativeName::new();
        match host.parse::<IpAddr>() {
            Ok(_) => san.ip(host),
            Err(_) => san.dns(host),
        };
        let san = san
            .build(&builder.x509v3_context(Some(&self.ca_cert), None))
            .map_err(tls_err("building subjectAltName"))?;
        builder
            .append_extension(&san)
            .map_err(tls_err("adding subjectAltName"))?;

        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(&self.ca_cert), None))
            .map_err(tls_err("building authorityKeyIdentifier"))?;
        builder
            .append_extension(&authority_key_id)
            .map_err(tls_err("adding authorityKeyIdentifier"))?;

        builder
            .sign(&self.ca_key, MessageDigest::sha256())
            .map_err(tls_err("signing the leaf certificate"))?;

        Ok(builder.build())
    }

    /// Builds the acceptor presenting `host`'s certificate.
    fn build_acceptor(&self, host: &str) -> Result<SslAcceptor, Error> {
        let leaf = self.build_leaf(host)?;

        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
            .map_err(tls_err("building the TLS acceptor"))?;
        builder
            .set_private_key(&self.leaf_key)
            .map_err(tls_err("setting the leaf key"))?;
        builder
            .set_certificate(&leaf)
            .map_err(tls_err("setting the leaf certificate"))?;
        // The CA travels with the leaf so the browser can build a path to it
        // without having been given the CA separately.
        builder
            .add_extra_chain_cert(self.ca_cert.clone())
            .map_err(tls_err("adding the CA to the chain"))?;

        // ALPN on a server is a selection callback, not a list: `set_alpn_protos`
        // is the client-side call and would silently do nothing here.
        builder.set_alpn_select_callback(|_ssl, client_protocols| {
            select_next_proto(ALPN_WIRE, client_protocols).ok_or(AlpnError::NOACK)
        });

        Ok(builder.build())
    }

    /// The cache lock, recovering from a poisoned mutex.
    ///
    /// The lock is never held across an await and the guarded data is a plain
    /// map, so a panic elsewhere must not make the proxy stop serving.
    fn locked_cache(&self) -> std::sync::MutexGuard<'_, LeafCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btls::stack::Stack;
    use btls::x509::X509StoreContext;
    use btls::x509::store::X509StoreBuilder;

    fn authority() -> CertAuthority {
        CertAuthority::generate().expect("generate a CA")
    }

    #[test]
    fn the_same_host_is_served_from_cache() {
        let ca = authority();

        let first = ca.acceptor("example.com").expect("first");
        let second = ca.acceptor("example.com").expect("second");

        // The point of the cache: one certificate, not one per connection.
        assert!(
            Arc::ptr_eq(&first, &second),
            "a repeat host should reuse the cached acceptor"
        );
        assert_eq!(ca.cached_hosts(), 1);
    }

    #[test]
    fn different_hosts_get_different_acceptors() {
        let ca = authority();

        let a = ca.acceptor("a.example").expect("a");
        let b = ca.acceptor("b.example").expect("b");

        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(ca.cached_hosts(), 2);
    }

    #[test]
    fn the_cache_is_bounded_against_untrusted_hosts() {
        // The CONNECT host is attacker-influenced, so the cache must not grow
        // without limit.
        let ca = authority();
        for index in 0..MAX_CACHED_HOSTS + 50 {
            ca.acceptor(&format!("host{index}.example")).expect("mint");
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
            ca.acceptor(&format!("host{index}.example")).expect("mint");
        }
        ca.acceptor("newcomer.example").expect("mint");

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
    fn an_invalid_host_is_refused() {
        // A certificate library will put any ASCII string in a SAN, so without
        // our own check these would be minted and cached.
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
            let result = ca.acceptor(host);
            assert!(
                matches!(result, Err(Error::TlsError(_))),
                "{host:?} should have been refused"
            );
        }
        assert_eq!(ca.cached_hosts(), 0, "a refused host must not be cached");
    }

    #[test]
    fn an_over_long_host_is_refused() {
        let ca = authority();
        let too_long = format!("{}.example", "a".repeat(MAX_HOST_LEN));
        assert!(matches!(ca.acceptor(&too_long), Err(Error::TlsError(_))));

        let long_label = format!("{}.example", "a".repeat(MAX_LABEL_LEN + 1));
        assert!(matches!(ca.acceptor(&long_label), Err(Error::TlsError(_))));
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
                ca.acceptor(host).is_ok(),
                "{host:?} should have been accepted"
            );
        }
    }

    #[test]
    fn a_long_host_still_gets_a_certificate() {
        // X.509 caps the CommonName at 64 characters and rejects anything
        // longer, so a long host would fail to mint entirely if the full name
        // were used there. The subjectAltName still carries it in full, which is
        // what browsers actually match on.
        let ca = authority();
        let host = format!("{}.{}.example.com", "a".repeat(60), "b".repeat(60));
        assert!(host.len() > MAX_COMMON_NAME_LEN);

        let leaf = ca.build_leaf(&host).expect("a long host should still mint");
        let names = leaf.subject_alt_names().expect("a subjectAltName");
        let dns: Vec<&str> = names.iter().filter_map(|n| n.dnsname()).collect();
        assert_eq!(dns, vec![host.as_str()], "the SAN must carry the full host");
    }

    #[test]
    fn the_spki_pin_is_a_sha256_digest_of_the_public_key() {
        let ca = authority();
        let pin = ca.spki_pin().expect("compute the pin");

        // Base64 of a 32-byte digest is 44 characters including one '=' pad.
        let decoded = btls::base64::decode_block(&pin).expect("valid base64");
        assert_eq!(decoded.len(), 32, "expected a SHA-256 digest");

        // It must be the CA's own key, not some other certificate's.
        let spki = ca
            .ca_cert
            .public_key()
            .expect("public key")
            .public_key_to_der()
            .expect("SPKI");
        let expected = btls::hash::hash(MessageDigest::sha256(), &spki).expect("hash");
        assert_eq!(decoded, expected.as_ref());
    }

    #[test]
    fn two_authorities_pin_differently() {
        // The pin has to be per-CA, or trusting one process would trust another.
        let first = authority().spki_pin().expect("first pin");
        let second = authority().spki_pin().expect("second pin");
        assert_ne!(first, second);
    }

    #[test]
    fn the_exported_pem_carries_the_certificate_and_no_key() {
        let ca = authority();
        let pem = ca.ca_pem().expect("export the CA");

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        // A private key must never be exportable through this path.
        assert!(!pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn a_leaf_verifies_against_the_ca_as_a_trust_root() {
        // The strongest available statement: a full path validation, which
        // enforces the CA's basicConstraints and key usage rather than trusting
        // that the builder calls did what they looked like.
        let ca = authority();
        let leaf = ca.build_leaf("example.com").expect("mint a leaf");

        let mut store = X509StoreBuilder::new().expect("store builder");
        store
            .add_cert(ca.ca_cert.clone())
            .expect("trust our own CA");
        let store = store.build();

        let chain = Stack::new().expect("empty chain");
        let mut context = X509StoreContext::new().expect("store context");
        let verified = context
            .init(&store, &leaf, &chain, |c| c.verify_cert())
            .expect("run verification");

        assert!(verified, "the leaf did not verify against its own CA");
    }

    #[test]
    fn the_ca_issued_the_leaf() {
        let ca = authority();
        let leaf = ca.build_leaf("example.com").expect("mint a leaf");

        // `issued` is a Result in btls, not an enum with an OK variant.
        assert!(
            ca.ca_cert.issued(&leaf).is_ok(),
            "the issuer linkage between CA and leaf is broken"
        );
    }

    #[test]
    fn a_leaf_carries_its_host_as_a_dns_san() {
        let ca = authority();
        let leaf = ca.build_leaf("example.com").expect("mint a leaf");

        let names = leaf.subject_alt_names().expect("a subjectAltName");
        let dns: Vec<&str> = names.iter().filter_map(|n| n.dnsname()).collect();
        assert_eq!(dns, vec!["example.com"]);
        // A dNSName is the right type here; an iPAddress would not match a name.
        assert!(names.iter().all(|n| n.ipaddress().is_none()));
    }

    #[test]
    fn an_address_literal_becomes_an_ip_san_not_a_dns_one() {
        // A dNSName holding an address does not match the address, so the
        // distinction is load-bearing rather than cosmetic.
        let ca = authority();
        let leaf = ca.build_leaf("127.0.0.1").expect("mint a leaf");

        let names = leaf.subject_alt_names().expect("a subjectAltName");
        let addresses: Vec<&[u8]> = names.iter().filter_map(|n| n.ipaddress()).collect();
        assert_eq!(addresses, vec![&[127u8, 0, 0, 1][..]]);
        assert!(
            names.iter().all(|n| n.dnsname().is_none()),
            "an address must not be encoded as a dNSName"
        );
    }

    #[test]
    fn the_ca_names_itself_so_it_is_identifiable() {
        let ca = authority();
        let subject = ca.ca_cert.subject_name();
        let common = subject
            .entries()
            .next()
            .expect("a common name")
            .data()
            .as_utf8()
            .expect("UTF-8 common name")
            .to_string();
        assert_eq!(common, CA_COMMON_NAME);

        // Self-signed: the CA is its own issuer.
        assert!(
            ca.ca_cert.issued(&ca.ca_cert).is_ok(),
            "the CA should be self-issued"
        );
    }

    #[test]
    fn a_leaf_is_already_valid_and_expires_within_the_browser_cap() {
        let ca = authority();
        let leaf = ca.build_leaf("example.com").expect("mint a leaf");

        // Backdated, so clock skew against the browser cannot make it
        // not-yet-valid.
        let now = Asn1Time::days_from_now(0).expect("now");
        assert!(leaf.not_before() < now, "the leaf should already be valid");

        // Inside the 398-day cap browsers enforce — unlike rcgen's default
        // 1975-4096 window, which no browser would accept.
        let cap = Asn1Time::days_from_now(398).expect("cap");
        assert!(leaf.not_after() < cap, "the leaf outlives the browser cap");
        assert!(leaf.not_after() > now, "the leaf is already expired");
    }

    #[test]
    fn two_leaves_for_one_host_have_distinct_serials() {
        let ca = authority();
        let first = ca.build_leaf("example.com").expect("first");
        let second = ca.build_leaf("example.com").expect("second");

        let serial = |cert: &X509| {
            cert.serial_number()
                .to_bn()
                .expect("serial as a bignum")
                .to_vec()
        };
        assert_ne!(
            serial(&first),
            serial(&second),
            "serials should be random, not fixed"
        );
    }
}
