//! What the emulations put on the wire over HTTP/2.
//!
//! `ja4_egress` does this for the TLS half. This is the other half: the SETTINGS
//! frame in wire order, the connection `WINDOW_UPDATE`, whether `HEADERS` carries
//! a priority block, and the pseudo-header order.
//!
//! The expected values are the ones captured from the real browsers with
//! `examples/capture_h2` — Chromium 153 locally, Safari 27 over the LAN — so a
//! failure here means the emulation stopped matching the browser it claims to
//! be, not merely that it changed.

#![cfg(feature = "browser")]

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use boring2::asn1::{Asn1Integer, Asn1Time};
use boring2::bn::{BigNum, MsbOption};
use boring2::ec::{EcGroup, EcKey};
use boring2::hash::MessageDigest;
use boring2::nid::Nid;
use boring2::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use boring2::x509::X509NameBuilder;
use boring2::x509::extension::SubjectAlternativeName;
use wreq::EmulationProvider;

/// ALPN offering only h2, so the client must speak it.
const ALPN_H2: &[u8] = b"\x02h2";

/// The connection preface that opens every HTTP/2 connection.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Bytes in an HTTP/2 frame header.
const FRAME_HEADER_LEN: usize = 9;

const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

/// `HEADERS` flag indicating the payload opens with a priority block.
const FLAG_PRIORITY: u8 = 0x20;

/// The protocol's initial connection window, which `WINDOW_UPDATE` adds to.
const INITIAL_CONNECTION_WINDOW: u32 = 65_535;

/// What a client sends when it opens a connection.
#[derive(Debug)]
struct Opening {
    /// `(identifier, value)` in wire order.
    settings: Vec<(u16, u32)>,
    /// Total connection window after the stream-0 `WINDOW_UPDATE`.
    connection_window: u32,
    /// Whether `HEADERS` carried a priority block.
    has_priority: bool,
    /// Pseudo-header names, in order, without the leading colon.
    pseudo: Vec<String>,
}

/// HPACK static-table names for the indices a request's pseudo-headers use.
fn static_name(index: usize) -> Option<&'static str> {
    Some(match index {
        1 => ":authority",
        2 | 3 => ":method",
        4 | 5 => ":path",
        6 | 7 => ":scheme",
        _ => return None,
    })
}

/// Decodes an HPACK integer, returning the value and bytes consumed.
fn hpack_int(bytes: &[u8], prefix_bits: u32) -> Option<(usize, usize)> {
    let mask = (1u16 << prefix_bits) - 1;
    let first = (*bytes.first()? as u16) & mask;
    if first < mask {
        return Some((first as usize, 1));
    }
    let mut value = mask as usize;
    let mut shift = 0;
    for (i, byte) in bytes.iter().enumerate().skip(1) {
        value += ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    None
}

/// Skips a length-prefixed string literal, returning bytes consumed. Values may
/// be Huffman-coded; only names are needed here, and pseudo-header names always
/// come from the static table.
fn skip_string(bytes: &[u8]) -> Option<usize> {
    let (len, used) = hpack_int(bytes, 7)?;
    Some(used + len)
}

/// Recovers pseudo-header names, in order, from an HPACK block.
fn pseudo_names(mut block: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    while let Some(&byte) = block.first() {
        let consumed = if byte & 0x80 != 0 {
            let Some((index, used)) = hpack_int(block, 7) else {
                break;
            };
            if let Some(name) = static_name(index) {
                names.push(name.to_string());
            }
            used
        } else if byte & 0x40 != 0 {
            let Some((index, used)) = hpack_int(block, 6) else {
                break;
            };
            if let Some(name) = static_name(index) {
                names.push(name.to_string());
            }
            let after_name = if index == 0 {
                let Some(skipped) = block.get(used..).and_then(skip_string) else {
                    break;
                };
                used + skipped
            } else {
                used
            };
            let Some(value) = block.get(after_name..).and_then(skip_string) else {
                break;
            };
            after_name + value
        } else if byte & 0x20 != 0 {
            let Some((_, used)) = hpack_int(block, 5) else {
                break;
            };
            used
        } else {
            let Some((index, used)) = hpack_int(block, 4) else {
                break;
            };
            if let Some(name) = static_name(index) {
                names.push(name.to_string());
            }
            let after_name = if index == 0 {
                let Some(skipped) = block.get(used..).and_then(skip_string) else {
                    break;
                };
                used + skipped
            } else {
                used
            };
            let Some(value) = block.get(after_name..).and_then(skip_string) else {
                break;
            };
            after_name + value
        };
        if consumed == 0 || consumed > block.len() {
            break;
        }
        block = &block[consumed..];
    }
    names
        .into_iter()
        .map(|name| name.trim_start_matches(':').to_string())
        .collect()
}

/// Reads until `want` bytes are buffered or the peer stops sending.
fn fill(stream: &mut impl Read, buf: &mut Vec<u8>, want: usize) -> bool {
    let mut chunk = [0u8; 4096];
    while buf.len() < want {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    true
}

/// Terminates one h2 connection from a client using `emulation` and reports what
/// it sent before any response.
fn capture(build: fn() -> EmulationProvider) -> Opening {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("curve");
    let key =
        boring2::pkey::PKey::from_ec_key(EcKey::generate(&group).expect("key")).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .expect("cn");
    let name = name.build();

    let mut serial = BigNum::new().expect("bignum");
    serial
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("serial");
    let serial = Asn1Integer::from_bn(&serial).expect("serial");
    let not_before = Asn1Time::days_from_now(0).expect("not before");
    let not_after = Asn1Time::days_from_now(1).expect("not after");

    let mut builder = boring2::x509::X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("pubkey");
    builder.set_not_before(&not_before).expect("not before");
    builder.set_not_after(&not_after).expect("not after");
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(None, None))
        .expect("san");
    builder.append_extension(san).expect("san");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let cert = builder.build();

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor");
    acceptor.set_private_key(&key).expect("key");
    acceptor.set_certificate(&cert).expect("cert");
    acceptor.set_alpn_select_callback(|_ssl, offered| {
        select_next_proto(ALPN_H2, offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = acceptor.build();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let client = wreq::Client::builder()
                .emulation(build())
                .cert_verification(false)
                .timeout(Duration::from_secs(5))
                .build()
                .expect("client");
            let _ = client
                .get(format!("https://localhost:{port}/"))
                .send()
                .await;
        });
    });

    let (stream, _) = listener.accept().expect("accept");
    let stream: TcpStream = stream;
    let mut tls = acceptor.accept(stream).expect("handshake");

    let mut buf = Vec::new();
    assert!(fill(&mut tls, &mut buf, PREFACE.len()), "no preface");
    assert_eq!(&buf[..PREFACE.len()], PREFACE, "not an HTTP/2 client");

    let mut opening = Opening {
        settings: Vec::new(),
        connection_window: INITIAL_CONNECTION_WINDOW,
        has_priority: false,
        pseudo: Vec::new(),
    };

    let mut cursor = PREFACE.len();
    while opening.pseudo.is_empty() {
        if !fill(&mut tls, &mut buf, cursor + FRAME_HEADER_LEN) {
            break;
        }
        let head = &buf[cursor..cursor + FRAME_HEADER_LEN];
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let kind = head[3];
        let flags = head[4];
        if !fill(&mut tls, &mut buf, cursor + FRAME_HEADER_LEN + len) {
            break;
        }
        let body = &buf[cursor + FRAME_HEADER_LEN..cursor + FRAME_HEADER_LEN + len];

        match kind {
            FRAME_SETTINGS => {
                for entry in body.as_chunks::<6>().0 {
                    opening.settings.push((
                        u16::from_be_bytes([entry[0], entry[1]]),
                        u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
                    ));
                }
            }
            FRAME_WINDOW_UPDATE if body.len() >= 4 => {
                let increment = u32::from_be_bytes([body[0] & 0x7f, body[1], body[2], body[3]]);
                opening.connection_window = INITIAL_CONNECTION_WINDOW.saturating_add(increment);
            }
            FRAME_HEADERS => {
                opening.has_priority = flags & FLAG_PRIORITY != 0;
                let block = if opening.has_priority && body.len() >= 5 {
                    &body[5..]
                } else {
                    body
                };
                opening.pseudo = pseudo_names(block);
            }
            _ => {}
        }
        cursor += FRAME_HEADER_LEN + len;
    }

    opening
}

#[test]
fn the_chrome_entry_reproduces_the_browsers_http2() {
    // Captured from Chromium 153: four settings, MaxConcurrentStreams and
    // MaxFrameSize absent entirely, and a priority block on HEADERS.
    let opening = capture(stealthscraper_rs::emulation::chrome);

    assert_eq!(
        opening.settings,
        vec![
            (0x1, 65_536),    // HeaderTableSize
            (0x2, 0),         // EnablePush
            (0x4, 6_291_456), // InitialWindowSize
            (0x6, 262_144),   // MaxHeaderListSize
        ],
        "the SETTINGS frame drifted from the Chromium 153 capture"
    );
    assert_eq!(opening.connection_window, 15_728_640);
    assert!(
        opening.has_priority,
        "Chrome's HEADERS frame carries a priority block"
    );
    assert_eq!(opening.pseudo, ["method", "authority", "scheme", "path"]);
}

#[test]
fn the_safari_entry_reproduces_the_browsers_http2() {
    // Captured from Safari 27 over the LAN, identical across four connections.
    // Every part of it differs from Chrome.
    let opening = capture(stealthscraper_rs::emulation::safari_27);

    assert_eq!(
        opening.settings,
        vec![
            (0x2, 0),         // EnablePush
            (0x3, 100),       // MaxConcurrentStreams
            (0x4, 2_097_152), // InitialWindowSize
            (0x9, 1),         // NoRfc7540Priorities
        ],
        "the SETTINGS frame drifted from the Safari 27 capture"
    );
    assert_eq!(opening.connection_window, 10_485_760);
    assert!(
        !opening.has_priority,
        "Safari's HEADERS frame carries no priority block"
    );
    assert_eq!(opening.pseudo, ["method", "scheme", "authority", "path"]);
}

#[test]
fn the_two_browsers_are_distinguishable_on_http2_alone() {
    // If these matched, the HTTP/2 half of the emulation would be doing nothing,
    // and a server could tell the two apart while we claimed to be either.
    let chrome = capture(stealthscraper_rs::emulation::chrome);
    let safari = capture(stealthscraper_rs::emulation::safari_27);

    assert_ne!(chrome.settings, safari.settings);
    assert_ne!(chrome.pseudo, safari.pseudo);
    assert_ne!(chrome.connection_window, safari.connection_window);
    assert_ne!(chrome.has_priority, safari.has_priority);
}
