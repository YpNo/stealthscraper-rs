//! Captures the HTTP/2 fingerprint of any client that connects: the SETTINGS
//! frame in wire order, the connection `WINDOW_UPDATE`, any `PRIORITY` frames,
//! and the pseudo-header order inside the first request.
//!
//! This is the HTTP/2 counterpart of `capture_fingerprint`, which covers the
//! TLS half. Together they supply every value `wreq`'s `Http2Config` and
//! `TlsConfig` take, measured rather than transcribed.
//!
//! # Usage
//!
//! ```text
//! cargo run --example capture_h2                    # 0.0.0.0:9444
//! cargo run --example capture_h2 -- 0.0.0.0:9000
//! cargo run --example capture_h2 -- --h1             # read header names
//! ```
//!
//! `--h1` offers only HTTP/1.1 so the request head arrives as plaintext. Use it
//! to read the header *names and order* a client sends; HPACK would otherwise
//! Huffman-code every name that is not in its 61-entry static table.
//!
//! The listener generates a self-signed certificate and prints its SPKI pin plus
//! a ready-to-paste browser command line. Chrome accepts exactly that one key for
//! that one run, so nothing has to be installed into a trust store:
//!
//! ```text
//! chromium --ignore-certificate-errors-spki-list=<pin> https://127.0.0.1:9444/
//! ```
//!
//! A `wreq` client is pointed at it with `.tls_cert_verification(false)`.
//!
//! The listener never answers: it reads the client's opening frames and closes.
//! The client will report a connection error, which is expected.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use btls::asn1::{Asn1Integer, Asn1Time};
use btls::bn::{BigNum, MsbOption};
use btls::ec::{EcGroup, EcKey};
use btls::hash::MessageDigest;
use btls::nid::Nid;
use btls::pkey::{PKey, Private};
use btls::ssl::{AlpnError, SslAcceptor, SslMethod, select_next_proto};
use btls::x509::extension::{BasicConstraints, SubjectAlternativeName};
use btls::x509::{X509, X509NameBuilder};

/// Default listen address: all interfaces, so remote browsers can reach it.
const DEFAULT_BIND: &str = "0.0.0.0:9444";

/// ALPN wire format offering only h2, so a client that can speak it must.
const ALPN_H2: &[u8] = b"\x02h2";

/// ALPN offering only HTTP/1.1, used by `--h1` to read the request head as
/// plaintext. HPACK would otherwise Huffman-code every header name that is not
/// in the static table, which is most of the interesting ones.
const ALPN_H1: &[u8] = b"\x08http/1.1";

/// The client connection preface that opens every HTTP/2 connection.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Bytes in an HTTP/2 frame header.
const FRAME_HEADER_LEN: usize = 9;

/// Upper bound on bytes read from one client, so a peer cannot grow the buffer
/// without limit.
const MAX_BYTES: usize = 64 * 1024;

/// Deadline on any single read, so a client that is waiting for a response
/// cannot stall the capture indefinitely.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Frame types we decode. Others are reported by number and skipped.
const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

/// `HEADERS` flag indicating the payload opens with a priority block.
const FLAG_PRIORITY: u8 = 0x20;

/// Settings identifiers, named as `wreq`'s `SettingsOrder` spells them.
const SETTING_NAMES: &[(u16, &str)] = &[
    (0x1, "HeaderTableSize"),
    (0x2, "EnablePush"),
    (0x3, "MaxConcurrentStreams"),
    (0x4, "InitialWindowSize"),
    (0x5, "MaxFrameSize"),
    (0x6, "MaxHeaderListSize"),
    (0x8, "EnableConnectProtocol"),
    (0x9, "NoRfc7540Priorities"),
];

/// HPACK static table names, indices 1..=61 (RFC 7541 appendix A).
const STATIC_NAMES: &[&str] = &[
    ":authority",
    ":method",
    ":method",
    ":path",
    ":path",
    ":scheme",
    ":scheme",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    ":status",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-ranges",
    "accept",
    "access-control-allow-origin",
    "age",
    "allow",
    "authorization",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-range",
    "content-type",
    "cookie",
    "date",
    "etag",
    "expect",
    "expires",
    "from",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "last-modified",
    "link",
    "location",
    "max-forwards",
    "proxy-authenticate",
    "proxy-authorization",
    "range",
    "referer",
    "refresh",
    "retry-after",
    "server",
    "set-cookie",
    "strict-transport-security",
    "transfer-encoding",
    "user-agent",
    "vary",
    "via",
    "www-authenticate",
];

fn setting_name(id: u16) -> String {
    SETTING_NAMES
        .iter()
        .find(|(code, _)| *code == id)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("Unknown(0x{id:x})"))
}

fn static_name(index: usize) -> String {
    STATIC_NAMES
        .get(index.wrapping_sub(1))
        .map(|n| (*n).to_string())
        .unwrap_or_else(|| format!("<static {index}>"))
}

// ---------------------------------------------------------------------------
// A self-signed certificate for the listener
// ---------------------------------------------------------------------------

/// Generates a self-signed P-256 certificate valid for localhost, returning it
/// with its key and the base64 SHA-256 of its SPKI (Chrome's pin format).
fn self_signed() -> Result<(X509, PKey<Private>, String), Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    let serial = Asn1Integer::from_bn(&serial)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    // Bound first: these are owned values and the setters take references.
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(1)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    let basic_constraints = BasicConstraints::new().critical().build()?;
    builder.append_extension(&basic_constraints)?;
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(&san)?;
    builder.sign(&key, MessageDigest::sha256())?;
    let cert = builder.build();

    let spki = cert.public_key()?.public_key_to_der()?;
    let pin = btls::base64::encode_block(&btls::hash::hash(MessageDigest::sha256(), &spki)?);

    Ok((cert, key, pin))
}

// ---------------------------------------------------------------------------
// Frame decoding
// ---------------------------------------------------------------------------

/// Reads until `want` bytes are buffered or the peer stops sending.
fn fill(stream: &mut impl Read, buf: &mut Vec<u8>, want: usize) -> std::io::Result<bool> {
    let mut chunk = [0u8; 4096];
    while buf.len() < want {
        if buf.len() >= MAX_BYTES {
            return Ok(false);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(false);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(true)
}

/// Decodes an HPACK integer with an `prefix_bits`-wide prefix, returning the
/// value and how many bytes it consumed.
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

/// Skips a length-prefixed string literal, returning bytes consumed. The value
/// is not decoded: it may be Huffman-coded, and only header *names* are needed
/// here, which pseudo-headers always take from the static table.
fn skip_string(bytes: &[u8]) -> Option<usize> {
    let (len, used) = hpack_int(bytes, 7)?;
    Some(used + len)
}

/// Recovers header names, in order, from an HPACK block.
///
/// Only the fields needed to read pseudo-header order are decoded; a literal
/// name (index 0) is reported as `<literal>` rather than Huffman-decoded, which
/// no browser does for a pseudo-header.
fn header_names(mut block: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    while let Some(&byte) = block.first() {
        let consumed = if byte & 0x80 != 0 {
            // Indexed header field: name and value both from a table.
            match hpack_int(block, 7) {
                Some((index, used)) => {
                    names.push(static_name(index));
                    used
                }
                None => break,
            }
        } else if byte & 0x40 != 0 {
            // Literal with incremental indexing: 6-bit name index.
            match literal(block, 6) {
                Some((name, used)) => {
                    names.push(name);
                    used
                }
                None => break,
            }
        } else if byte & 0x20 != 0 {
            // Dynamic table size update: no header.
            match hpack_int(block, 5) {
                Some((_, used)) => used,
                None => break,
            }
        } else {
            // Literal without indexing / never indexed: 4-bit name index.
            match literal(block, 4) {
                Some((name, used)) => {
                    names.push(name);
                    used
                }
                None => break,
            }
        };
        if consumed == 0 || consumed > block.len() {
            break;
        }
        block = &block[consumed..];
    }
    names
}

/// Decodes one literal header field's name, returning it and bytes consumed.
fn literal(block: &[u8], prefix_bits: u32) -> Option<(String, usize)> {
    let (index, used) = hpack_int(block, prefix_bits)?;
    let (name, after_name) = if index == 0 {
        (
            "<literal>".to_string(),
            used + skip_string(block.get(used..)?)?,
        )
    } else {
        (static_name(index), used)
    };
    let value_len = skip_string(block.get(after_name..)?)?;
    Some((name, after_name + value_len))
}

/// Reads and reports an HTTP/1.1 request head.
///
/// The head ends at the first blank line, and reading must stop there: a browser
/// keeps the connection open waiting for a response, so reading to end-of-stream
/// would block until it gives up. A short response is sent afterwards so the
/// browser shows a page instead of an error.
fn report_http1(stream: &mut (impl Read + Write), mut buf: Vec<u8>) -> std::io::Result<()> {
    println!("  HTTP/1.1 request head, in wire order:");

    const HEAD_END: &[u8] = b"\r\n\r\n";
    let mut chunk = [0u8; 4096];
    while !buf.windows(HEAD_END.len()).any(|w| w == HEAD_END) {
        if buf.len() >= MAX_BYTES {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => {
                println!("    (read ended: {e})");
                break;
            }
        }
    }

    let text = String::from_utf8_lossy(&buf);
    for line in text.split("\r\n") {
        if line.is_empty() {
            break;
        }
        println!("    {line}");
    }

    let body = "<html><body>captured</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    Ok(())
}

/// Reads and reports the client's opening frames.
fn report(stream: &mut (impl Read + Write)) -> std::io::Result<()> {
    let mut buf = Vec::new();

    if !fill(stream, &mut buf, PREFACE.len())? {
        println!("  client closed before sending the HTTP/2 preface");
        return Ok(());
    }
    if &buf[..PREFACE.len()] != PREFACE {
        return report_http1(stream, buf);
    }
    println!("  preface: ok");
    let mut cursor = PREFACE.len();

    let mut saw_headers = false;
    while !saw_headers {
        if !fill(stream, &mut buf, cursor + FRAME_HEADER_LEN)? {
            break;
        }
        let head = &buf[cursor..cursor + FRAME_HEADER_LEN];
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let kind = head[3];
        let flags = head[4];
        let stream_id = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);

        if !fill(stream, &mut buf, cursor + FRAME_HEADER_LEN + len)? {
            break;
        }
        let body = &buf[cursor + FRAME_HEADER_LEN..cursor + FRAME_HEADER_LEN + len];

        match kind {
            FRAME_SETTINGS => {
                println!("  SETTINGS ({} entries, in wire order):", body.len() / 6);
                for entry in body.as_chunks::<6>().0 {
                    let id = u16::from_be_bytes([entry[0], entry[1]]);
                    let value = u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]);
                    println!("    {:<24} {value}", setting_name(id));
                }
            }
            FRAME_WINDOW_UPDATE => {
                let inc = u32::from_be_bytes([body[0] & 0x7f, body[1], body[2], body[3]]);
                println!("  WINDOW_UPDATE stream {stream_id}: +{inc}");
                if stream_id == 0 {
                    println!(
                        "    => initial_connection_window_size = 65535 + {inc} = {}",
                        65_535u64 + inc as u64
                    );
                }
            }
            FRAME_PRIORITY => {
                let dep = u32::from_be_bytes([body[0] & 0x7f, body[1], body[2], body[3]]);
                let exclusive = body[0] & 0x80 != 0;
                println!(
                    "  PRIORITY stream {stream_id}: depends on {dep}, weight {}, exclusive {exclusive}",
                    body[4] as u16 + 1
                );
            }
            FRAME_HEADERS => {
                println!("  HEADERS stream {stream_id} (flags 0x{flags:02x}):");
                let mut block = body;
                if flags & FLAG_PRIORITY != 0 && block.len() >= 5 {
                    let dep = u32::from_be_bytes([block[0] & 0x7f, block[1], block[2], block[3]]);
                    let exclusive = block[0] & 0x80 != 0;
                    println!(
                        "    priority: depends on {dep}, weight {}, exclusive {exclusive}",
                        block[4] as u16 + 1
                    );
                    block = &block[5..];
                }
                let names = header_names(block);
                let pseudo: Vec<&String> = names.iter().filter(|n| n.starts_with(':')).collect();
                println!(
                    "    pseudo order: {}",
                    pseudo
                        .iter()
                        .map(|n| n.trim_start_matches(':'))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("    all headers : {}", names.join(", "));
                saw_headers = true;
            }
            FRAME_DATA => println!("  DATA stream {stream_id}: {len} bytes"),
            other => println!("  frame type 0x{other:02x} stream {stream_id}: {len} bytes"),
        }

        cursor += FRAME_HEADER_LEN + len;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let h1_only = args.iter().any(|a| a == "--h1");
    let bind = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or(DEFAULT_BIND.to_string());
    let alpn: &[u8] = if h1_only { ALPN_H1 } else { ALPN_H2 };
    let (cert, key, pin) = self_signed()?;

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_private_key(&key)?;
    builder.set_certificate(&cert)?;
    // ALPN on a server is a selection callback, not a list.
    builder.set_alpn_select_callback(move |_ssl, offered| {
        select_next_proto(alpn, offered).ok_or(AlpnError::NOACK)
    });
    let acceptor = builder.build();

    let listener = TcpListener::bind(&bind)?;
    let port = listener.local_addr()?.port();
    println!(
        "listening on {bind}, offering only {}\n",
        if h1_only { "http/1.1" } else { "h2" }
    );
    println!("browser:");
    println!("  chromium --ignore-certificate-errors-spki-list={pin} https://127.0.0.1:{port}/\n");
    println!(
        "wreq: point a client with .tls_cert_verification(false) at https://127.0.0.1:{port}/\n"
    );

    for incoming in listener.incoming() {
        let stream: TcpStream = match incoming {
            Ok(stream) => stream,
            Err(e) => {
                println!("accept failed: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        // A browser that is waiting for a response never closes the connection,
        // so every read needs a deadline or the capture stalls on a peer that is
        // behaving perfectly normally.
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        println!("{}", "=".repeat(72));
        println!("connection from {peer}");
        println!("{}", "=".repeat(72));

        match acceptor.accept(stream) {
            Ok(mut tls) => {
                let alpn = tls
                    .ssl()
                    .selected_alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .unwrap_or_else(|| "<none>".to_string());
                println!("  ALPN: {alpn}");
                if let Err(e) = report(&mut tls) {
                    println!("  read ended: {e}");
                }
                let _ = tls.flush();
            }
            Err(e) => println!("  TLS handshake failed: {e}"),
        }
        println!();
    }
    Ok(())
}
