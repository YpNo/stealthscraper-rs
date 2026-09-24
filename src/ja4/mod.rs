//! JA4 TLS client fingerprinting: parse a `ClientHello` and summarise it.
//!
//! This module is pure domain logic — no I/O, no browser, no TLS backend — so
//! it builds with no features enabled and is unit-testable in isolation.
//!
//! It exists to make the crate's central stealth claim *verifiable*. The egress
//! client asserts a JA4 signature matching the impersonated browser; with this
//! module that assertion can be measured against the bytes actually put on the
//! wire, instead of being taken on trust.
//!
//! # Example
//!
//! ```no_run
//! use stealthscraper_rs::ja4::{ClientHello, Ja4, Transport};
//!
//! # fn example(captured: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let hello = ClientHello::parse(captured)?;
//! let fingerprint = Ja4::from_client_hello(&hello, Transport::Tcp);
//! println!("{fingerprint}");
//! # Ok(())
//! # }
//! ```

mod fingerprint;
mod parse;

pub use fingerprint::{Ja4, Transport, is_grease};
pub use parse::ClientHello;

use thiserror::Error;

/// A failure while parsing a `ClientHello`.
///
/// The input arrives off a socket and is untrusted, so every malformed shape is
/// a typed error rather than a panic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Ja4Error {
    /// The buffer ended before the structure it declared was complete.
    #[error("ClientHello is truncated or fragmented across TLS records")]
    Truncated,

    /// The message was well-formed but is not a `ClientHello`.
    #[error("expected a ClientHello, found message type 0x{0:02x}")]
    NotClientHello(u8),

    /// A length or field violated the wire format.
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
}

#[cfg(test)]
mod tests;
