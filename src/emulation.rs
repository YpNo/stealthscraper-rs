//! Browser emulations, every value measured from a real browser.
//!
//! No value here was transcribed from a third-party fingerprint table. Each one
//! was produced the same way:
//!
//! 1. capture a real browser's `ClientHello` (`examples/capture_fingerprint`)
//!    and its opening HTTP/2 frames (`examples/capture_h2`),
//! 2. read the cipher, curve, signature-scheme and extension lists, the
//!    SETTINGS entries in wire order, the connection `WINDOW_UPDATE`, the
//!    `HEADERS` priority block, and the header names and order (`capture_h2
//!    --h1`, where HPACK does not hide them),
//! 3. express those through [`wreq::tls::TlsConfig`] and
//!    [`wreq::Http2Config`],
//! 4. capture what *our* client then emits and require the two JA4s to match
//!    (`examples/emulation_roundtrip`, and the `ja4_egress` integration test).
//!
//! Step 4 is what makes an entry trustworthy: a transcription error changes the
//! hash, so a matching fingerprint cannot be a coincidence.
//!
//! # What is deliberately not set here
//!
//! An entry never sets `User-Agent`, `Sec-CH-UA*` or `Accept-Language`. Those
//! belong to the active [`BrowserProfile`](crate::profile::BrowserProfile) and
//! the proxy-led locale, and an emulation that supplied its own would silently
//! override them — which is exactly the defect that made the HTTP leg advertise
//! a different browser from the one the profile described.
//!
//! The emulation's header order *does* name them, so when the
//! caller sets them they land in the measured position.

use wreq::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, HeaderMap, HeaderName, HeaderValue, OrigHeaderMap,
    USER_AGENT,
};
use wreq::http2::{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
};
use wreq::tls::{AlpnProtocol, AlpsProtocol, TlsOptions};
use wreq::{Emulation, Group};

use crate::cert_compression::{Brotli, Zlib};
use wreq::tls::compress::CertificateCompressor;

use crate::profile::BrowserKind;

// ---------------------------------------------------------------------------
// Chromium 153 — TLS
// ---------------------------------------------------------------------------

/// The certificate compression Chromium 153 offers: brotli only.
const CHROME_COMPRESSORS: &[&'static dyn CertificateCompressor] = &[&Brotli];

/// The certificate compression Safari 27 offers: zlib only.
const SAFARI_COMPRESSORS: &[&'static dyn CertificateCompressor] = &[&Zlib];

/// Cipher suites Chromium 153 offers, in wire order.
const CHROME_CIPHERS: &str = concat!(
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:",
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA"
);

/// Signature schemes Chromium 153 offers, in wire order.
///
/// The browser also offers three ML-DSA schemes (`0x0904`, `0x0905`, `0x0906`)
/// after these. This one is a real BoringSSL limitation and not a binding gap:
/// `btls`'s BoringSSL has ML-DSA as a *primitive* (`include/openssl/mldsa.h`)
/// but defines no `SSL_SIGN_*` constant for it and carries no entry in the
/// signature-algorithm name table, and `sigalgs_list` takes names rather than
/// code points. See [`CHROME_JA4`].
const CHROME_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
);

/// Named groups Chromium 153 offers, in wire order.
///
/// A colon-separated BoringSSL curve list, which is how `wreq` 6 takes them;
/// `wreq` 5 took `&[SslCurve]`. The spellings are BoringSSL's own — a wrong name
/// is not silent, because it changes the JA4 and `ja4_egress` asserts it.
const CHROME_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// The Chrome major this entry reproduces: the browser that was captured, and
/// the one this crate launches.
///
/// [`BrowserProfile::random`](crate::profile::BrowserProfile::random) claims
/// this major in every User-Agent it generates, so the advertised version, the
/// launched binary and the TLS fingerprint all describe the same browser.
pub const CHROME_MAJOR: u32 = 153;

/// The JA4 this entry emits, verified by round-trip.
///
/// This is **not** the JA4 Chromium 153 itself emits, which is
/// [`CHROME_JA4_REAL`]. The two differ in the extension count (16 vs 17) and the
/// signature-algorithm hash. The cipher hash already matches exactly.
///
/// The gap is a property of the stack, not of this data: `wreq-util`'s newest
/// Chrome entry, measured through the same harness before it was removed,
/// emitted this exact same string.
///
/// # The two halves of the gap have different causes
///
/// - **Extension `0xca34` (`trust_anchors`) is *reachable in principle*.**
///   `btls`'s BoringSSL defines `TLSEXT_TYPE_trust_anchors` and exposes
///   `SSL_CTX_set1_requested_trust_anchors`, which sends the extension even when
///   given zero ids — exactly the empty form Chrome sends. What is missing is
///   the binding: `btls` does not expose it in Rust and `wreq` does not plumb it
///   to `TlsOptions`. Reaching it from here would need `unsafe` FFI, which
///   `#![forbid(unsafe_code)]` rules out. It was a genuine BoringSSL limitation
///   under `boring2` 4.15 and is no longer, so it is tracked upstream rather
///   than worked around here:
///   - <https://github.com/0x676e67/btls/issues/209> (expose the setter)
///   - <https://github.com/0x676e67/wreq/issues/1298> (plumb it to `TlsOptions`)
///
///   When both land, add the knob and re-run `examples/emulation_roundtrip`:
///   segment `a` should move to `t13d1517h2`, and [`CHROME_JA4`] with it.
/// - **The ML-DSA signature schemes are a real limitation.** `btls`'s BoringSSL
///   has ML-DSA as a primitive but defines no `SSL_SIGN_*` constant for it and
///   carries no entry in the signature-algorithm name table, and `sigalgs_list`
///   takes names rather than code points. Nothing above can close this one.
///
/// Closing the first alone would move segment `a` from `t13d1516h2` to
/// `t13d1517h2`; segment `c` needs the second.
pub const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// The JA4 Chromium 153 actually emits, for reference and for the round-trip
/// report. See [`CHROME_JA4`] for why it is not reproducible here.
pub const CHROME_JA4_REAL: &str = "t13d1517h2_8daaf6152771_cb7bf5808d99";

// ---------------------------------------------------------------------------
// Chromium 153 — HTTP/2
// ---------------------------------------------------------------------------

/// `SETTINGS_HEADER_TABLE_SIZE` as Chromium 153 sends it.
const CHROME_HEADER_TABLE_SIZE: u32 = 65_536;

/// `SETTINGS_INITIAL_WINDOW_SIZE` as Chromium 153 sends it.
const CHROME_INITIAL_STREAM_WINDOW: u32 = 6_291_456;

/// `SETTINGS_MAX_HEADER_LIST_SIZE` as Chromium 153 sends it.
const CHROME_MAX_HEADER_LIST_SIZE: u32 = 262_144;

/// The connection window Chromium 153 ends up with.
///
/// The browser sends `WINDOW_UPDATE(+15663105)` on stream 0, which on top of
/// the protocol's initial 65535 gives this total. `wreq` takes the total and
/// emits the increment.
const CHROME_CONNECTION_WINDOW: u32 = 15_728_640;

/// Weight byte in Chromium 153's `HEADERS` priority block.
///
/// The wire carries 255, which HTTP/2 defines as weight 256.
const CHROME_HEADERS_WEIGHT: u8 = 255;

/// SETTINGS identifiers in the order Chromium 153 writes them.
///
/// Only four are actually sent — the browser omits `MaxConcurrentStreams` and
/// `MaxFrameSize` entirely — so the remaining entries are left unset and this
/// order only decides where they *would* go.
const CHROME_SETTINGS_IDS: [SettingId; 8] = [
    SettingId::HeaderTableSize,
    SettingId::EnablePush,
    SettingId::InitialWindowSize,
    SettingId::MaxHeaderListSize,
    SettingId::MaxConcurrentStreams,
    SettingId::MaxFrameSize,
    SettingId::EnableConnectProtocol,
    SettingId::NoRfc7540Priorities,
];

/// Pseudo-header order in Chromium 153's request: `:method`, `:authority`,
/// `:scheme`, `:path`. Note authority precedes scheme, which is not the order a
/// bare HTTP/2 client uses.
const CHROME_PSEUDO_IDS: [PseudoId; 4] = [
    PseudoId::Method,
    PseudoId::Authority,
    PseudoId::Scheme,
    PseudoId::Path,
];

// ---------------------------------------------------------------------------
// Chromium 153 — headers
// ---------------------------------------------------------------------------

/// Builds a `SettingsOrder` from ids in wire order.
fn settings_order(ids: [SettingId; 8]) -> SettingsOrder {
    SettingsOrder::builder().extend(ids).build()
}

/// Builds a `PseudoOrder` from ids in wire order.
fn pseudo_order(ids: [PseudoId; 4]) -> PseudoOrder {
    PseudoOrder::builder().extend(ids).build()
}

/// `Accept` on a top-level navigation, verbatim from the capture.
const CHROME_ACCEPT: &str = concat!(
    "text/html,application/xhtml+xml,application/xml;q=0.9,",
    "image/avif,image/webp,image/apng,*/*;q=0.8,",
    "application/signed-exchange;v=b3;q=0.7"
);

/// `Accept-Encoding` as Chromium 153 sends it. `zstd` is present in current
/// Chrome and its absence is a signal.
const CHROME_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// Client-hint and fetch-metadata header names, which `wreq::header` has no
/// constants for.
const SEC_CH_UA: &str = "sec-ch-ua";
const SEC_CH_UA_MOBILE: &str = "sec-ch-ua-mobile";
const SEC_CH_UA_PLATFORM: &str = "sec-ch-ua-platform";
const UPGRADE_INSECURE_REQUESTS: &str = "upgrade-insecure-requests";
const SEC_FETCH_SITE: &str = "sec-fetch-site";
const SEC_FETCH_MODE: &str = "sec-fetch-mode";
const SEC_FETCH_USER: &str = "sec-fetch-user";
const SEC_FETCH_DEST: &str = "sec-fetch-dest";
const PRIORITY: &str = "priority";

/// Fetch-metadata values for a top-level navigation, which is what a scraper
/// fetching a page performs. A subresource request would carry different values,
/// but this client only issues navigations.
const NAVIGATION_METADATA: &[(&str, &str)] = &[
    (SEC_FETCH_SITE, "none"),
    (SEC_FETCH_MODE, "navigate"),
    (SEC_FETCH_USER, "?1"),
    (SEC_FETCH_DEST, "document"),
];

/// Header order Chromium 153 uses, measured over HTTP/1.1 and cross-checked
/// against the HPACK block over h2.
///
/// `User-Agent`, the three `Sec-CH-UA*` headers and `Accept-Language` appear
/// here but are **not** set by this module; naming them fixes where the caller's
/// values land.
///
/// `priority` is the one entry not read directly: HPACK Huffman-codes it, and
/// Chrome does not send it over HTTP/1.1 where names are plaintext. It is
/// identified by elimination — the h1 head accounts for all twelve other
/// headers, the h2 block carries thirteen in the same relative order, and the
/// extra one sits last. Safari's capture, where `Priority` *is* sent over h1 and
/// lands in the same relative place, corroborates it. This module does not set
/// the header, so the entry only fixes where it would go.
fn chrome_header_names() -> [&'static str; 13] {
    [
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        UPGRADE_INSECURE_REQUESTS,
        USER_AGENT.as_str(),
        ACCEPT.as_str(),
        SEC_FETCH_SITE,
        SEC_FETCH_MODE,
        SEC_FETCH_USER,
        SEC_FETCH_DEST,
        ACCEPT_ENCODING.as_str(),
        ACCEPT_LANGUAGE.as_str(),
        PRIORITY,
    ]
}

/// The same order as the map `wreq` takes.
fn chrome_header_order() -> OrigHeaderMap {
    order_map(&chrome_header_names())
}

/// Builds the ordered header map `wreq` 6 takes, from names in wire order.
fn order_map(names: &[&str]) -> OrigHeaderMap {
    let mut map = OrigHeaderMap::with_capacity(names.len());
    for name in names {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            map.insert(name);
        }
    }
    map
}

/// The headers Chromium 153 sends that do not depend on the profile or locale.
fn chrome_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(CHROME_ACCEPT));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static(CHROME_ACCEPT_ENCODING),
    );
    if let Ok(name) = HeaderName::from_bytes(UPGRADE_INSECURE_REQUESTS.as_bytes()) {
        headers.insert(name, HeaderValue::from_static("1"));
    }
    for (name, value) in NAVIGATION_METADATA {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    headers
}

/// Chromium 153 on Linux, captured locally and verified by round-trip.
///
/// TLS reproduces [`CHROME_JA4`]; HTTP/2 reproduces the browser's SETTINGS,
/// connection window, `HEADERS` priority and pseudo-header order exactly.
pub fn chrome() -> Emulation {
    let tls = TlsOptions::builder()
        .cipher_list(CHROME_CIPHERS)
        .sigalgs_list(CHROME_SIGALGS)
        .curves_list(CHROME_CURVES)
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .alps_protocols([AlpsProtocol::HTTP2])
        .alps_use_new_codepoint(true)
        .permute_extensions(true)
        .grease_enabled(true)
        .enable_ech_grease(true)
        .pre_shared_key(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .certificate_compressors(CHROME_COMPRESSORS)
        .build();

    let http2 = Http2Options::builder()
        .header_table_size(CHROME_HEADER_TABLE_SIZE)
        .enable_push(false)
        .initial_window_size(CHROME_INITIAL_STREAM_WINDOW)
        .max_header_list_size(CHROME_MAX_HEADER_LIST_SIZE)
        .initial_connection_window_size(CHROME_CONNECTION_WINDOW)
        .settings_order(settings_order(CHROME_SETTINGS_IDS))
        .headers_pseudo_order(pseudo_order(CHROME_PSEUDO_IDS))
        .headers_stream_dependency(StreamDependency::new(
            StreamId::ZERO,
            CHROME_HEADERS_WEIGHT,
            true,
        ))
        .build();

    Emulation::builder()
        .tls_options(tls)
        .http2_options(http2)
        .headers(chrome_default_headers())
        .orig_headers(chrome_header_order())
        // A `Group` labels the emulation for connection reuse: two clients with
        // different fingerprints must not share a pooled connection.
        .build(Group::new("chrome"))
}

// ---------------------------------------------------------------------------
// Safari 27
// ---------------------------------------------------------------------------

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

/// Named groups Safari 27 offers, in wire order. See [`CHROME_CURVES`] for the
/// format.
const SAFARI_27_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

// ---------------------------------------------------------------------------
// Safari 27 — HTTP/2
// ---------------------------------------------------------------------------

/// `SETTINGS_MAX_CONCURRENT_STREAMS` as Safari 27 sends it.
///
/// Chrome does not send this setting at all; Safari does. The presence or
/// absence of an identifier is as much a fingerprint as its value.
const SAFARI_MAX_CONCURRENT_STREAMS: u32 = 100;

/// `SETTINGS_INITIAL_WINDOW_SIZE` as Safari 27 sends it.
const SAFARI_INITIAL_STREAM_WINDOW: u32 = 2_097_152;

/// The connection window Safari 27 ends up with.
///
/// `WINDOW_UPDATE(+10420225)` on stream 0, on top of the protocol's initial
/// 65535.
const SAFARI_CONNECTION_WINDOW: u32 = 10_485_760;

/// SETTINGS identifiers in the order Safari 27 writes them.
///
/// Four are sent: `EnablePush`, `MaxConcurrentStreams`, `InitialWindowSize` and
/// setting `0x9` — `SETTINGS_NO_RFC7540_PRIORITIES`, which `wreq` calls
/// `UnknownSetting9`. Safari sends no `HeaderTableSize`, `MaxFrameSize` or
/// `MaxHeaderListSize`, so those are left unset and this order only decides
/// where they would go.
const SAFARI_SETTINGS_IDS: [SettingId; 8] = [
    SettingId::EnablePush,
    SettingId::MaxConcurrentStreams,
    SettingId::InitialWindowSize,
    SettingId::NoRfc7540Priorities,
    SettingId::HeaderTableSize,
    SettingId::MaxFrameSize,
    SettingId::MaxHeaderListSize,
    SettingId::EnableConnectProtocol,
];

/// Pseudo-header order in Safari 27's request: `:method`, `:scheme`,
/// `:authority`, `:path` — scheme before authority, the opposite of Chrome.
const SAFARI_PSEUDO_IDS: [PseudoId; 4] = [
    PseudoId::Method,
    PseudoId::Scheme,
    PseudoId::Authority,
    PseudoId::Path,
];

// ---------------------------------------------------------------------------
// Safari 27 — headers
// ---------------------------------------------------------------------------

/// `Accept` on a top-level navigation, verbatim from the capture.
///
/// Much shorter than Chrome's: Safari lists no image types here.
const SAFARI_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// `Accept-Encoding` as Safari 27 sends it — the same four as Chrome.
const SAFARI_ACCEPT_ENCODING: &str = "gzip, deflate, br, zstd";

/// `Priority` on a navigation (RFC 9218): urgency 0, incremental.
///
/// Safari sends this on HTTP/1.1 as well as HTTP/2; Chrome sends it only on
/// HTTP/2. The favicon request in the same capture carries `u=3, i`, so the
/// value belongs to the navigation rather than to the browser.
const SAFARI_PRIORITY: &str = "u=0, i";

/// Fetch-metadata values Safari 27 sends on a navigation.
///
/// Note what is **absent** next to Chrome's set: no `sec-fetch-user` and no
/// `upgrade-insecure-requests`. Sending either would be a difference from the
/// browser being claimed.
const SAFARI_NAVIGATION_METADATA: &[(&str, &str)] = &[
    (SEC_FETCH_DEST, "document"),
    (SEC_FETCH_SITE, "none"),
    (SEC_FETCH_MODE, "navigate"),
];

/// Header order Safari 27 uses on a navigation.
///
/// Measured over HTTP/1.1 and cross-checked against the HPACK block over h2:
/// the four names HPACK hid fall in exactly these positions, which is what makes
/// the two captures corroborate rather than merely coexist.
///
/// `Host` and `Connection` are omitted: both are HTTP/1.1 framing that the
/// client owns, and over h2 the first becomes `:authority`.
fn safari_header_names() -> [&'static str; 8] {
    [
        SEC_FETCH_DEST,
        USER_AGENT.as_str(),
        ACCEPT.as_str(),
        SEC_FETCH_SITE,
        SEC_FETCH_MODE,
        ACCEPT_LANGUAGE.as_str(),
        PRIORITY,
        ACCEPT_ENCODING.as_str(),
    ]
}

/// The same order as the map `wreq` takes.
fn safari_header_order() -> OrigHeaderMap {
    order_map(&safari_header_names())
}

/// The headers Safari 27 sends that do not depend on the profile or locale.
fn safari_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static(SAFARI_ACCEPT));
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static(SAFARI_ACCEPT_ENCODING),
    );
    if let Ok(name) = HeaderName::from_bytes(PRIORITY.as_bytes()) {
        headers.insert(name, HeaderValue::from_static(SAFARI_PRIORITY));
    }
    for (name, value) in SAFARI_NAVIGATION_METADATA {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    headers
}

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
///
/// # HTTP/2
///
/// Measured over the LAN with `examples/capture_h2`, identical across four
/// connections. Safari differs from Chrome in every part of it: a different set
/// of SETTINGS identifiers in a different order, a smaller connection window,
/// **no** priority block on `HEADERS` (flags `0x05`, so the `PRIORITY` bit is
/// clear), and `:scheme` before `:authority` in the pseudo-header order.
///
/// # Headers
///
/// Measured over HTTP/1.1, where the names arrive as plaintext, and corroborated
/// by the h2 capture: the four names HPACK had hidden sit in exactly the
/// positions that capture predicted.
///
/// Safari's set is not Chrome's with different values — it is a different set.
/// There is no `sec-fetch-user` and no `upgrade-insecure-requests`, the `Accept`
/// carries no image types, and `Priority` (RFC 9218) is sent even on HTTP/1.1,
/// which Chrome does not do.
pub fn safari_27() -> Emulation {
    let tls = TlsOptions::builder()
        .cipher_list(SAFARI_27_CIPHERS)
        .sigalgs_list(SAFARI_27_SIGALGS)
        .curves_list(SAFARI_27_CURVES)
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .permute_extensions(false)
        .grease_enabled(true)
        .enable_ech_grease(false)
        .pre_shared_key(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .certificate_compressors(SAFARI_COMPRESSORS)
        .build();

    let http2 = Http2Options::builder()
        .enable_push(false)
        .max_concurrent_streams(SAFARI_MAX_CONCURRENT_STREAMS)
        .initial_window_size(SAFARI_INITIAL_STREAM_WINDOW)
        // Setting 0x9, which Safari sends as 1. `wreq` 6 names it properly;
        // version 5 called it `unknown_setting9`.
        .no_rfc7540_priorities(true)
        .initial_connection_window_size(SAFARI_CONNECTION_WINDOW)
        .settings_order(settings_order(SAFARI_SETTINGS_IDS))
        .headers_pseudo_order(pseudo_order(SAFARI_PSEUDO_IDS))
        // No `headers_stream_dependency`: Safari's HEADERS frame carries no
        // priority block, where Chrome's does.
        .build();

    Emulation::builder()
        .tls_options(tls)
        .http2_options(http2)
        .headers(safari_default_headers())
        .orig_headers(safari_header_order())
        .build(Group::new("safari"))
}

/// The emulation for `kind`.
///
/// There is one entry per browser family rather than per version, because every
/// entry is measured and only one version of each family has been captured.
/// Mapping a whole family onto its measured entry is honest about that; a
/// per-version table would imply measurements that do not exist.
pub fn for_kind(kind: BrowserKind) -> Emulation {
    match kind {
        BrowserKind::Chrome(_) => chrome(),
        // Safari's TLS stack has been stable across many releases: the cipher
        // hash measured from Safari 27 is identical to the one published for
        // Safari 18.5, so this entry is applied to any Safari.
        BrowserKind::Safari(_) => safari_27(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_browser_kind_maps_to_an_entry() {
        // No `None` case: an unmapped kind would silently fall back to a bare
        // client, whose fingerprint matches no browser at all.
        for kind in [
            BrowserKind::Chrome(124),
            BrowserKind::Chrome(153),
            BrowserKind::Safari(17),
            BrowserKind::Safari(27),
        ] {
            let _ = for_kind(kind);
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
    fn the_chrome_gap_is_recorded_rather_than_hidden() {
        // The two constants must differ: if they are ever made equal without a
        // BoringSSL that can emit 0xca34 and the ML-DSA schemes, the claim that
        // the entry reproduces the browser would be false.
        assert_ne!(CHROME_JA4, CHROME_JA4_REAL);
        // Same cipher hash: the gap is in the extension count and sigalg hash.
        let ours: Vec<&str> = CHROME_JA4.split('_').collect();
        let real: Vec<&str> = CHROME_JA4_REAL.split('_').collect();
        assert_eq!(ours[1], real[1], "the cipher hash must already match");
        assert_ne!(ours[0], real[0]);
        assert_ne!(ours[2], real[2]);
    }

    #[test]
    fn chrome_default_headers_never_carry_profile_owned_values() {
        // Setting any of these here would override what the profile and the
        // proxy-led locale decide — the defect that made the HTTP leg advertise
        // a different browser from the one the profile described.
        let headers = chrome_default_headers();
        for name in [
            USER_AGENT.as_str(),
            ACCEPT_LANGUAGE.as_str(),
            SEC_CH_UA,
            SEC_CH_UA_MOBILE,
            SEC_CH_UA_PLATFORM,
        ] {
            assert!(
                !headers.contains_key(name),
                "{name} must be left to the caller"
            );
        }
    }

    #[test]
    fn the_header_order_names_every_header_that_is_sent() {
        // A header that is sent but unnamed in the order lands wherever the
        // client happens to put it, which is a fingerprint of its own.
        let named: Vec<&str> = chrome_header_names().to_vec();
        for name in chrome_default_headers().keys() {
            assert!(
                named.contains(&name.as_str()),
                "{name} is sent but missing from the header order"
            );
        }
        // And the caller-owned ones are named too.
        for name in [
            USER_AGENT.as_str(),
            ACCEPT_LANGUAGE.as_str(),
            SEC_CH_UA,
            SEC_CH_UA_MOBILE,
            SEC_CH_UA_PLATFORM,
        ] {
            assert!(named.contains(&name), "{name} is missing from the order");
        }
    }

    #[test]
    fn the_settings_order_is_a_permutation_with_no_repeats() {
        let mut seen: Vec<String> = CHROME_SETTINGS_IDS
            .iter()
            .map(|s| format!("{s:?}"))
            .collect();
        seen.sort();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "a settings identifier is repeated");
    }

    #[test]
    fn the_pseudo_order_puts_authority_before_scheme() {
        // Measured from the browser, and the one place a bare HTTP/2 client
        // differs: it emits method, scheme, authority, path.
        assert_eq!(
            CHROME_PSEUDO_IDS,
            [
                PseudoId::Method,
                PseudoId::Authority,
                PseudoId::Scheme,
                PseudoId::Path
            ]
        );
        // And Safari transposes the middle two.
        assert_eq!(
            SAFARI_PSEUDO_IDS,
            [
                PseudoId::Method,
                PseudoId::Scheme,
                PseudoId::Authority,
                PseudoId::Path
            ]
        );
    }
}
