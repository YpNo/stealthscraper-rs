//! Certificate compression codecs for the TLS handshake ([RFC 8879]).
//!
//! # Why this exists
//!
//! The `compress_certificate` extension is part of the `ClientHello`, so which
//! algorithms a browser advertises is part of its fingerprint: Chrome offers
//! brotli, Safari offers zlib, and offering neither — or the wrong one — changes
//! the JA4.
//!
//! `wreq` 5 took an enum of algorithm identifiers and supplied the codecs
//! itself. `wreq` 6 takes `&dyn CertificateCompressor`, with no implementations
//! in the crate, so the codecs have to be provided here.
//!
//! # Cost
//!
//! None, in dependency terms: `brotli` and `flate2` are already in the graph
//! because `wreq`'s own response-decompression features pull them. They are
//! named directly here rather than relied on transitively.
//!
//! [RFC 8879]: https://datatracker.ietf.org/doc/html/rfc8879

use std::io::{self, Write};

use wreq::tls::compress::{CertificateCompressionAlgorithm, CertificateCompressor, Codec};

/// Compression level for brotli.
///
/// The handshake is latency-sensitive and certificate chains are small, so this
/// is deliberately not the maximum. It does not affect the fingerprint: only the
/// advertised algorithm identifier appears in the `ClientHello`.
const BROTLI_QUALITY: u32 = 5;

/// Brotli window size, in log2 bytes. The RFC 7932 default.
const BROTLI_WINDOW: u32 = 22;

/// Upper bound on a decompressed certificate chain.
///
/// The peer controls the compressed bytes, so decompression needs a ceiling or a
/// small input could be made to expand without limit.
const MAX_DECOMPRESSED: usize = 1 << 20;

/// Brotli certificate compression, as Chrome offers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Brotli;

/// Zlib certificate compression, as Safari offers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Zlib;

impl CertificateCompressor for Brotli {
    fn compress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut writer = brotli::CompressorWriter::new(
                output,
                input.len().max(1),
                BROTLI_QUALITY,
                BROTLI_WINDOW,
            );
            writer.write_all(input)?;
            writer.flush()
        })
    }

    fn decompress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut reader = brotli::Decompressor::new(input, input.len().max(1));
            copy_bounded(&mut reader, output)
        })
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::BROTLI
    }
}

impl CertificateCompressor for Zlib {
    fn compress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut encoder =
                flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
            encoder.write_all(input)?;
            encoder.finish().map(|_| ())
        })
    }

    fn decompress(&self) -> Codec {
        Codec::Pointer(|input, output| {
            let mut reader = flate2::read::ZlibDecoder::new(input);
            copy_bounded(&mut reader, output)
        })
    }

    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        CertificateCompressionAlgorithm::ZLIB
    }
}

/// Copies `reader` into `output`, refusing to expand past [`MAX_DECOMPRESSED`].
///
/// The input is the peer's, so an unbounded copy would let a small compressed
/// payload exhaust memory.
fn copy_bounded(reader: &mut impl io::Read, output: &mut dyn Write) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut written = 0usize;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        written = written.saturating_add(read);
        if written > MAX_DECOMPRESSED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed certificate expanded past the allowed size",
            ));
        }
        output.write_all(&buffer[..read])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a codec pair over `input` and returns what came back out.
    fn round_trip(compress: Codec, decompress: Codec, input: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        match compress {
            Codec::Pointer(f) => f(input, &mut compressed).expect("compress"),
            Codec::Dynamic(f) => f(input, &mut compressed).expect("compress"),
        }
        let mut out = Vec::new();
        match decompress {
            Codec::Pointer(f) => f(&compressed, &mut out).expect("decompress"),
            Codec::Dynamic(f) => f(&compressed, &mut out).expect("decompress"),
        }
        out
    }

    /// Something certificate-shaped: repetitive enough to compress.
    fn sample() -> Vec<u8> {
        b"-----BEGIN CERTIFICATE-----\n".repeat(200)
    }

    #[test]
    fn brotli_round_trips_a_certificate_sized_payload() {
        let input = sample();
        let out = round_trip(Brotli.compress(), Brotli.decompress(), &input);
        assert_eq!(out, input, "brotli did not round-trip");
    }

    #[test]
    fn zlib_round_trips_a_certificate_sized_payload() {
        let input = sample();
        let out = round_trip(Zlib.compress(), Zlib.decompress(), &input);
        assert_eq!(out, input, "zlib did not round-trip");
    }

    #[test]
    fn both_actually_compress() {
        // A codec that grew the input would still round-trip, so assert the
        // thing the extension exists for.
        let input = sample();
        for (name, compress) in [("brotli", Brotli.compress()), ("zlib", Zlib.compress())] {
            let mut compressed = Vec::new();
            match compress {
                Codec::Pointer(f) => f(&input, &mut compressed).expect("compress"),
                Codec::Dynamic(f) => f(&input, &mut compressed).expect("compress"),
            }
            assert!(
                compressed.len() < input.len(),
                "{name} did not compress: {} -> {}",
                input.len(),
                compressed.len()
            );
        }
    }

    #[test]
    fn the_advertised_algorithms_are_the_ones_the_browsers_offer() {
        // These identifiers are what appear in the ClientHello, so they are the
        // part that has to be right.
        assert_eq!(Brotli.algorithm(), CertificateCompressionAlgorithm::BROTLI);
        assert_eq!(Zlib.algorithm(), CertificateCompressionAlgorithm::ZLIB);
    }

    #[test]
    fn decompression_refuses_to_expand_without_limit() {
        // A zip bomb: a tiny compressed payload that expands past the ceiling.
        let bomb = vec![0u8; MAX_DECOMPRESSED + 1];
        let mut compressed = Vec::new();
        match Zlib.compress() {
            Codec::Pointer(f) => f(&bomb, &mut compressed).expect("compress"),
            Codec::Dynamic(f) => f(&bomb, &mut compressed).expect("compress"),
        }
        assert!(
            compressed.len() < bomb.len() / 100,
            "the sample should be highly compressible"
        );

        let mut out = Vec::new();
        let result = match Zlib.decompress() {
            Codec::Pointer(f) => f(&compressed, &mut out),
            Codec::Dynamic(f) => f(&compressed, &mut out),
        };
        assert!(result.is_err(), "an oversized expansion was allowed");
    }
}
