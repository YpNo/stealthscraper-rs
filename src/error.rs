//! The crate's error type, covering the browser, proxy, challenge, and state layers.

use thiserror::Error;

/// The main error type for the `rs-cloudscraper` library.
#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while generating or interacting with the underlying stealth browser.
    #[error("Browser automation error: {0}")]
    BrowserError(String),

    /// An error during realistic mouse/keyboard interaction emulation.
    #[error("Interaction emulation error: {0}")]
    InteractionError(String),

    /// An error occurred setting up or running the local TLS proxy.
    #[error("Proxy initialization failed: {0}")]
    ProxyBindFailed(#[from] std::io::Error),

    /// An error occurred within the HTTP/TLS impersonation client.
    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] wreq::Error),

    /// A bot-protection challenge was detected but could not be solved.
    #[error("Unsolved challenge: {0}")]
    Challenge(String),

    /// The persistent state store failed to read or write.
    #[error("State store error: {0}")]
    StateStore(String),

    /// Missing or invalid configuration state.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// An error occurred while spawning or joining background tasks.
    #[error("Internal join error: {0}")]
    JoinError(String),

    /// An error occurred during TLS configuration or handshake.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// A generic internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let err = Error::BrowserError("Failed to launch".to_string());
        assert_eq!(
            err.to_string(),
            "Browser automation error: Failed to launch"
        );

        let err2 = Error::ConfigError("Missing timeout".to_string());
        assert_eq!(err2.to_string(), "Configuration error: Missing timeout");

        let err3 = Error::Internal("Crash".to_string());
        assert_eq!(err3.to_string(), "Internal error: Crash");

        let err4 = Error::TlsError("handshake timeout".to_string());
        assert_eq!(err4.to_string(), "TLS error: handshake timeout");
    }
}
