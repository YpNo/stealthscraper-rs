//! Bounds-checked parsing of a TLS `ClientHello`.
//!
//! The input is attacker-controlled (it arrives off a socket), so every read is
//! length-checked and the parser never panics, slices out of range, or
//! allocates based on an unvalidated length.

use super::Ja4Error;

/// TLS record content type for a handshake record.
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// Handshake message type for `ClientHello`.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Length of the `random` field in a `ClientHello`.
const CLIENT_HELLO_RANDOM_LEN: usize = 32;

/// Extension identifiers whose contents contribute to a JA4 fingerprint.
pub(super) mod ext {
    /// `server_name` (SNI).
    pub const SERVER_NAME: u16 = 0x0000;
    /// `supported_groups` (named curves).
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// `application_layer_protocol_negotiation` (ALPN).
    pub const ALPN: u16 = 0x0010;
    /// `supported_versions`.
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// A non-panicking cursor over a byte slice.
///
/// Every accessor returns [`Ja4Error::Truncated`] rather than panicking when the
/// buffer is shorter than the read requires.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Consumes exactly `n` bytes.
    fn take(&mut self, n: usize) -> Result<&'a [u8], Ja4Error> {
        let end = self.pos.checked_add(n).ok_or(Ja4Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Ja4Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, Ja4Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Ja4Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<u32, Ja4Error> {
        let bytes = self.take(3)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    /// Consumes a block prefixed by a big-endian length of `len_bytes` width.
    fn block(&mut self, len_bytes: usize) -> Result<&'a [u8], Ja4Error> {
        let len = match len_bytes {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            3 => self.u24()? as usize,
            _ => return Err(Ja4Error::Malformed("unsupported length prefix width")),
        };
        self.take(len)
    }
}

/// Reads a sequence of `u16` values covering the whole of `buf`.
///
/// A trailing odd byte means the sender lied about the block length, so the
/// input is rejected rather than silently truncated.
fn u16_list(buf: &[u8]) -> Result<Vec<u16>, Ja4Error> {
    let (pairs, remainder) = buf.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(Ja4Error::Malformed("odd-length u16 list"));
    }
    Ok(pairs.iter().copied().map(u16::from_be_bytes).collect())
}

/// The `ClientHello` fields that a JA4 fingerprint is derived from.
///
/// GREASE values are retained here — filtering is the fingerprint's concern, so
/// that callers inspecting a capture still see exactly what was on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    /// `legacy_version` from the handshake body (e.g. `0x0303` for TLS 1.2).
    pub legacy_version: u16,
    /// Offered cipher suites, in wire order.
    pub cipher_suites: Vec<u16>,
    /// Extension identifiers, in wire order.
    pub extensions: Vec<u16>,
    /// Versions from the `supported_versions` extension, in wire order.
    pub supported_versions: Vec<u16>,
    /// Entries from the `signature_algorithms` extension, in wire order.
    pub signature_algorithms: Vec<u16>,
    /// Named groups from the `supported_groups` extension, in wire order.
    ///
    /// These are the curves an emulation entry must reproduce; order is part of
    /// the fingerprint even though JA4 itself does not hash them.
    pub supported_groups: Vec<u16>,
    /// ALPN protocol identifiers, in wire order.
    pub alpn: Vec<String>,
    /// The SNI host, when a `server_name` extension carried one.
    pub server_name: Option<String>,
}

impl ClientHello {
    /// Parses a `ClientHello`, accepting either a full TLS record or a bare
    /// handshake message.
    ///
    /// Browsers send the `ClientHello` in a single record in practice; a
    /// fragmented one is reported as [`Ja4Error::Truncated`] rather than being
    /// partially parsed into a misleading fingerprint.
    pub fn parse(bytes: &[u8]) -> Result<Self, Ja4Error> {
        let body = match bytes.first() {
            Some(&CONTENT_TYPE_HANDSHAKE) => {
                let mut record = Reader::new(bytes);
                let _content_type = record.u8()?;
                let _legacy_record_version = record.u16()?;
                record.block(2)?
            }
            Some(&HANDSHAKE_TYPE_CLIENT_HELLO) => bytes,
            Some(other) => return Err(Ja4Error::NotClientHello(*other)),
            None => return Err(Ja4Error::Truncated),
        };

        let mut r = Reader::new(body);

        let handshake_type = r.u8()?;
        if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(Ja4Error::NotClientHello(handshake_type));
        }

        // The handshake length must cover the rest of the message; a shorter
        // value means the hello was split across records.
        let handshake_len = r.u24()? as usize;
        let mut r = Reader::new(r.take(handshake_len)?);

        let legacy_version = r.u16()?;
        let _random = r.take(CLIENT_HELLO_RANDOM_LEN)?;
        let _session_id = r.block(1)?;
        let cipher_suites = u16_list(r.block(2)?)?;
        let _compression_methods = r.block(1)?;

        let mut hello = Self {
            legacy_version,
            cipher_suites,
            ..Self::default()
        };

        // Extensions are optional in the wire format (SSLv3-era hellos omit the
        // block entirely), so an absent extensions block is not an error.
        if r.is_empty() {
            return Ok(hello);
        }

        let mut ext_reader = Reader::new(r.block(2)?);
        while !ext_reader.is_empty() {
            let ext_type = ext_reader.u16()?;
            let ext_data = ext_reader.block(2)?;
            hello.extensions.push(ext_type);
            hello.absorb_extension(ext_type, ext_data)?;
        }

        Ok(hello)
    }

    /// Records the contents of an extension that feeds the fingerprint.
    ///
    /// Unknown extensions still count towards the fingerprint by identifier, so
    /// they are accepted without inspecting their payload.
    fn absorb_extension(&mut self, ext_type: u16, data: &[u8]) -> Result<(), Ja4Error> {
        match ext_type {
            ext::SERVER_NAME => {
                let mut r = Reader::new(data);
                // An empty server_name payload is legal (a client may send the
                // extension with no entries); treat it as "no host".
                if r.is_empty() {
                    return Ok(());
                }
                let mut list = Reader::new(r.block(2)?);
                while !list.is_empty() {
                    let name_type = list.u8()?;
                    let name = list.block(2)?;
                    // name_type 0 is host_name; other types carry no hostname.
                    if name_type == 0 {
                        self.server_name = Some(String::from_utf8_lossy(name).into_owned());
                        break;
                    }
                }
            }
            ext::SIGNATURE_ALGORITHMS => {
                let mut r = Reader::new(data);
                self.signature_algorithms = u16_list(r.block(2)?)?;
            }
            ext::SUPPORTED_GROUPS => {
                let mut r = Reader::new(data);
                self.supported_groups = u16_list(r.block(2)?)?;
            }
            ext::ALPN => {
                let mut r = Reader::new(data);
                let mut list = Reader::new(r.block(2)?);
                while !list.is_empty() {
                    let proto = list.block(1)?;
                    self.alpn.push(String::from_utf8_lossy(proto).into_owned());
                }
            }
            ext::SUPPORTED_VERSIONS => {
                let mut r = Reader::new(data);
                self.supported_versions = u16_list(r.block(1)?)?;
            }
            _ => {}
        }
        Ok(())
    }
}
