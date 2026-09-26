//! Tests for the JA4 parser and fingerprint computation.
//!
//! `ClientHello` bytes are assembled by a builder rather than pasted as an
//! opaque hex blob, so each test states exactly which field it exercises.

use super::*;

/// Wraps `body` in a length prefix `len_bytes` wide, big-endian.
fn prefixed(len_bytes: usize, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let mut out = match len_bytes {
        1 => vec![len as u8],
        2 => (len as u16).to_be_bytes().to_vec(),
        3 => vec![(len >> 16) as u8, (len >> 8) as u8, len as u8],
        _ => panic!("unsupported prefix width"),
    };
    out.extend_from_slice(body);
    out
}

fn u16s(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// Builds a syntactically valid `ClientHello` for testing.
#[derive(Default)]
struct HelloBuilder {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl HelloBuilder {
    fn new() -> Self {
        Self {
            legacy_version: 0x0303,
            ..Self::default()
        }
    }

    fn ciphers(mut self, ciphers: &[u16]) -> Self {
        self.ciphers = ciphers.to_vec();
        self
    }

    fn extension(mut self, ext_type: u16, data: Vec<u8>) -> Self {
        self.extensions.push((ext_type, data));
        self
    }

    fn sni(self, host: &str) -> Self {
        let entry = [vec![0u8], prefixed(2, host.as_bytes())].concat();
        let list = prefixed(2, &entry);
        self.extension(0x0000, list)
    }

    fn alpn(self, protocols: &[&str]) -> Self {
        let entries: Vec<u8> = protocols
            .iter()
            .flat_map(|p| prefixed(1, p.as_bytes()))
            .collect();
        let list = prefixed(2, &entries);
        self.extension(0x0010, list)
    }

    fn signature_algorithms(self, algs: &[u16]) -> Self {
        let list = prefixed(2, &u16s(algs));
        self.extension(0x000d, list)
    }

    fn supported_versions(self, versions: &[u16]) -> Self {
        let list = prefixed(1, &u16s(versions));
        self.extension(0x002b, list)
    }

    /// Serialises the handshake message (no TLS record wrapper).
    fn build_handshake(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]); // random
        body.extend_from_slice(&prefixed(1, &[])); // empty session id
        body.extend_from_slice(&prefixed(2, &u16s(&self.ciphers)));
        body.extend_from_slice(&prefixed(1, &[0])); // null compression

        if !self.extensions.is_empty() {
            let mut exts = Vec::new();
            for (ext_type, data) in &self.extensions {
                exts.extend_from_slice(&ext_type.to_be_bytes());
                exts.extend_from_slice(&prefixed(2, data));
            }
            body.extend_from_slice(&prefixed(2, &exts));
        }

        let mut out = vec![0x01]; // ClientHello
        out.extend_from_slice(&prefixed(3, &body));
        out
    }

    /// Serialises the message wrapped in a TLS handshake record.
    fn build_record(&self) -> Vec<u8> {
        let handshake = self.build_handshake();
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&prefixed(2, &handshake));
        out
    }
}

/// A hello shaped like a modern TLS 1.3 browser client.
fn browser_like() -> HelloBuilder {
    HelloBuilder::new()
        .ciphers(&[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f])
        .sni("example.com")
        .signature_algorithms(&[0x0403, 0x0804, 0x0401])
        .supported_versions(&[0x0304, 0x0303])
        .alpn(&["h2", "http/1.1"])
}

#[test]
fn parses_a_bare_handshake_and_a_record_identically() {
    let builder = browser_like();
    let from_handshake = ClientHello::parse(&builder.build_handshake()).expect("handshake");
    let from_record = ClientHello::parse(&builder.build_record()).expect("record");
    assert_eq!(from_handshake, from_record);
}

#[test]
fn extracts_every_fingerprint_relevant_field() {
    let hello = ClientHello::parse(&browser_like().build_record()).expect("parse");

    assert_eq!(
        hello.cipher_suites,
        vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]
    );
    assert_eq!(hello.server_name.as_deref(), Some("example.com"));
    assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    assert_eq!(hello.signature_algorithms, vec![0x0403, 0x0804, 0x0401]);
    assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);
    // Extension identifiers are recorded in wire order.
    assert_eq!(hello.extensions, vec![0x0000, 0x000d, 0x002b, 0x0010]);
}

#[test]
fn grease_detection_matches_rfc8701_code_points() {
    for byte in 0x0u16..=0xf {
        let grease = (byte << 12) | 0x0a00 | (byte << 4) | 0x0a;
        assert!(is_grease(grease), "0x{grease:04x} should be GREASE");
    }
    for real in [0x1301u16, 0xc02b, 0x0000, 0x002b, 0x0a0b, 0x0b0a] {
        assert!(!is_grease(real), "0x{real:04x} should not be GREASE");
    }
}

#[test]
fn grease_is_excluded_from_counts_and_hashes() {
    let plain = browser_like();
    let greased = HelloBuilder::new()
        .ciphers(&[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f])
        .sni("example.com")
        .signature_algorithms(&[0x0403, 0x0804, 0x0401])
        .supported_versions(&[0x2a2a, 0x0304, 0x0303])
        .alpn(&["h2", "http/1.1"])
        .extension(0x3a3a, vec![]);

    let a = Ja4::from_client_hello(
        &ClientHello::parse(&plain.build_record()).unwrap(),
        Transport::Tcp,
    );
    let b = Ja4::from_client_hello(
        &ClientHello::parse(&greased.build_record()).unwrap(),
        Transport::Tcp,
    );

    // GREASE is randomised per connection, so it must not perturb any segment.
    assert_eq!(a, b, "GREASE changed the fingerprint");
}

#[test]
fn segment_a_encodes_transport_version_sni_counts_and_alpn() {
    let hello = ClientHello::parse(&browser_like().build_record()).unwrap();
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);

    // t=TCP, 13=TLS1.3 (from supported_versions, not legacy 0x0303),
    // d=SNI present, 05 ciphers, 04 extensions, h2 from the first ALPN.
    assert_eq!(ja4.a, "t13d0504h2");

    let quic = Ja4::from_client_hello(&hello, Transport::Quic);
    assert!(quic.a.starts_with('q'));
}

#[test]
fn segment_a_reports_i_when_sni_is_absent() {
    let hello = ClientHello::parse(
        &HelloBuilder::new()
            .ciphers(&[0x1301])
            .supported_versions(&[0x0304])
            .build_record(),
    )
    .unwrap();
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);
    assert_eq!(&ja4.a[3..4], "i");
    // No ALPN offered -> the spec's "00" placeholder.
    assert!(ja4.a.ends_with("00"));
}

#[test]
fn version_comes_from_supported_versions_not_legacy_field() {
    // TLS 1.3 clients pin legacy_version to 0x0303 and signal 1.3 via the
    // extension; reading the legacy field would misreport every modern client.
    let hello = ClientHello::parse(
        &HelloBuilder::new()
            .ciphers(&[0x1301])
            .supported_versions(&[0x0304])
            .build_record(),
    )
    .unwrap();
    assert_eq!(hello.legacy_version, 0x0303);
    assert!(
        Ja4::from_client_hello(&hello, Transport::Tcp)
            .a
            .starts_with("t13")
    );

    // Without the extension, the legacy field is authoritative.
    let legacy =
        ClientHello::parse(&HelloBuilder::new().ciphers(&[0xc02f]).build_record()).unwrap();
    assert!(
        Ja4::from_client_hello(&legacy, Transport::Tcp)
            .a
            .starts_with("t12")
    );
}

#[test]
fn cipher_order_does_not_change_segment_b() {
    // Segment b hashes a *sorted* list, so reordering must be invisible.
    let forward = HelloBuilder::new()
        .ciphers(&[0x1301, 0x1302, 0x1303])
        .supported_versions(&[0x0304]);
    let reversed = HelloBuilder::new()
        .ciphers(&[0x1303, 0x1302, 0x1301])
        .supported_versions(&[0x0304]);

    let a = Ja4::from_client_hello(
        &ClientHello::parse(&forward.build_record()).unwrap(),
        Transport::Tcp,
    );
    let b = Ja4::from_client_hello(
        &ClientHello::parse(&reversed.build_record()).unwrap(),
        Transport::Tcp,
    );
    assert_eq!(a.b, b.b);
}

#[test]
fn signature_algorithm_order_does_change_segment_c() {
    // Signature algorithms keep wire order, unlike the extension list, so a
    // reordering is a genuinely different client.
    let forward = HelloBuilder::new()
        .ciphers(&[0x1301])
        .supported_versions(&[0x0304])
        .signature_algorithms(&[0x0403, 0x0804]);
    let reversed = HelloBuilder::new()
        .ciphers(&[0x1301])
        .supported_versions(&[0x0304])
        .signature_algorithms(&[0x0804, 0x0403]);

    let a = Ja4::from_client_hello(
        &ClientHello::parse(&forward.build_record()).unwrap(),
        Transport::Tcp,
    );
    let b = Ja4::from_client_hello(
        &ClientHello::parse(&reversed.build_record()).unwrap(),
        Transport::Tcp,
    );
    assert_ne!(a.c, b.c);
}

#[test]
fn sni_and_alpn_are_counted_but_excluded_from_segment_c() {
    // Both vary with the request rather than the client, so they must not
    // affect segment c even though they appear in the segment-a count.
    let with_sni = HelloBuilder::new()
        .ciphers(&[0x1301])
        .supported_versions(&[0x0304])
        .signature_algorithms(&[0x0403])
        .sni("example.com")
        .alpn(&["h2"]);
    let other_sni = HelloBuilder::new()
        .ciphers(&[0x1301])
        .supported_versions(&[0x0304])
        .signature_algorithms(&[0x0403])
        .sni("totally-different.test")
        .alpn(&["h2"]);

    let a = Ja4::from_client_hello(
        &ClientHello::parse(&with_sni.build_record()).unwrap(),
        Transport::Tcp,
    );
    let b = Ja4::from_client_hello(
        &ClientHello::parse(&other_sni.build_record()).unwrap(),
        Transport::Tcp,
    );
    assert_eq!(a, b, "the SNI host leaked into the fingerprint");
}

#[test]
fn display_renders_the_three_underscore_separated_segments() {
    let hello = ClientHello::parse(&browser_like().build_record()).unwrap();
    let rendered = Ja4::from_client_hello(&hello, Transport::Tcp).to_string();

    let segments: Vec<&str> = rendered.split('_').collect();
    assert_eq!(segments.len(), 3, "expected a_b_c, got {rendered}");
    assert_eq!(segments[0].len(), 10);
    assert_eq!(segments[1].len(), 12);
    assert_eq!(segments[2].len(), 12);
    assert!(
        segments[1].chars().all(|c| c.is_ascii_hexdigit()),
        "segment b is not hex: {rendered}"
    );
    assert!(
        segments[2].chars().all(|c| c.is_ascii_hexdigit()),
        "segment c is not hex: {rendered}"
    );
}

#[test]
fn fingerprint_is_deterministic() {
    let bytes = browser_like().build_record();
    let first = Ja4::from_client_hello(&ClientHello::parse(&bytes).unwrap(), Transport::Tcp);
    let second = Ja4::from_client_hello(&ClientHello::parse(&bytes).unwrap(), Transport::Tcp);
    assert_eq!(first, second);
}

#[test]
fn empty_cipher_and_extension_lists_use_the_zero_placeholder() {
    let hello = ClientHello::parse(&HelloBuilder::new().build_record()).unwrap();
    let ja4 = Ja4::from_client_hello(&hello, Transport::Tcp);
    assert_eq!(ja4.b, "000000000000");
    assert_eq!(ja4.c, "000000000000");
}

// --- Malformed input: every case must be a typed error, never a panic. ---

#[test]
fn rejects_a_non_client_hello_message() {
    // 0x02 is ServerHello.
    let mut bytes = browser_like().build_handshake();
    bytes[0] = 0x02;
    assert_eq!(
        ClientHello::parse(&bytes),
        Err(Ja4Error::NotClientHello(0x02))
    );
}

#[test]
fn rejects_empty_input() {
    assert_eq!(ClientHello::parse(&[]), Err(Ja4Error::Truncated));
}

#[test]
fn rejects_truncation_at_every_offset_without_panicking() {
    let full = browser_like().build_record();
    for cut in 0..full.len() {
        // The only contract is: never panic, and never claim success on a
        // prefix that cannot contain the whole message.
        let result = ClientHello::parse(&full[..cut]);
        assert!(
            result.is_err(),
            "prefix of {cut} bytes parsed as a complete ClientHello"
        );
    }
    assert!(ClientHello::parse(&full).is_ok());
}

#[test]
fn rejects_a_length_that_overruns_the_buffer() {
    let mut bytes = browser_like().build_handshake();
    // Inflate the 24-bit handshake length far beyond the real body.
    bytes[1] = 0xff;
    bytes[2] = 0xff;
    assert_eq!(ClientHello::parse(&bytes), Err(Ja4Error::Truncated));
}

#[test]
fn rejects_an_odd_length_cipher_list() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&prefixed(1, &[]));
    // Three bytes cannot be a whole number of u16 cipher suites.
    body.extend_from_slice(&prefixed(2, &[0x13, 0x01, 0x13]));
    body.extend_from_slice(&prefixed(1, &[0]));

    let mut bytes = vec![0x01];
    bytes.extend_from_slice(&prefixed(3, &body));

    assert!(matches!(
        ClientHello::parse(&bytes),
        Err(Ja4Error::Malformed(_))
    ));
}

#[test]
fn tolerates_a_hello_with_no_extension_block() {
    // Pre-TLS-1.2 hellos omit extensions entirely; that is legal, not an error.
    let hello = ClientHello::parse(&HelloBuilder::new().ciphers(&[0xc02f]).build_record())
        .expect("extension-less hello should parse");
    assert!(hello.extensions.is_empty());
}
