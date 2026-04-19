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
    HttpClientError(#[from] rquest::Error),

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
