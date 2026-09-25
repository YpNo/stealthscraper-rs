#![warn(missing_docs)]
#![forbid(unsafe_code)]
//! Stealthy Rust web scraping that defeats modern bot protection (Cloudflare,
//! Akamai, DataDome) on two fronts at once:
//!
//! - **JavaScript / CDP probing** — a real headless Chrome instance is driven via
//!   the Chrome DevTools Protocol, with stealth scripts masking `navigator`,
//!   WebGL, Canvas, and Audio fingerprints.
//! - **Network (JA3/JA4) fingerprinting** — a local MITM proxy
//!   ([`TlsSpoofingProxy`]) re-emits the browser's traffic through `wreq` so the
//!   TLS `ClientHello` and HTTP/2 settings match the impersonated browser.
//!
//! # Capabilities
//!
//! - **Challenge handling** ([`challenge`]) — classify a page with [`detect`] and
//!   choose a retry/rotate [`Action`] via [`MitigationPolicy`].
//! - **Proxy rotation** ([`proxy_pool`]) — a rotatable [`ProxyPool`]; the MITM
//!   upstream client is hot-swapped so the egress IP changes without relaunching
//!   the browser.
//! - **Geo/locale consistency** ([`geo`]) — derive `Accept-Language`,
//!   `navigator.languages`, and the timezone from the egress proxy's country so
//!   the IP and locale never contradict each other.
//! - **Profile rotation** — relaunch under a fresh [`BrowserProfile`] when the
//!   fingerprint identity itself is burned (the `browser` feature's `CloudScraper`).
//! - **Session state** ([`state`]) — per-domain outcomes and cooldowns behind a
//!   [`StateStore`]; durable via [`JsonStateStore`] with no extra dependency, or
//!   via the `redb`-backed store under the `persistence` feature.
//! - **Observability** ([`events`]) — a [`ScraperEvent`] / [`EventSink`] stream.
//!
//! # Feature flags
//!
//! - `browser` *(off by default)* — the headless-Chrome API (`CloudScraper`,
//!   `solve_challenge`, profile rotation, human-behavior helpers). Required for
//!   the quick start below.
//! - `persistence` *(off by default)* — the `redb`-backed state store, for
//!   sharing one state file between processes or for large host sets.
//!   [`JsonStateStore`] already provides durable state without it.
//!
//! With no features enabled the crate builds only the pure, dependency-light core
//! ([`challenge`], [`proxy_pool`], [`geo`], the [`state`] model, [`events`]) for
//! embedding into your own pipeline.
//!
//! # Quick start
//!
#![cfg_attr(feature = "browser", doc = "```no_run")]
#![cfg_attr(not(feature = "browser"), doc = "```ignore")]
//! use stealthscraper_rs::{BrowserProfile, CloudScraper};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), stealthscraper_rs::Error> {
//! // The builder spins up the MITM proxy and launches a stealth browser whose
//! // JA4 fingerprint matches the chosen profile.
//! let scraper = CloudScraper::builder()
//!     .profile(BrowserProfile::random())
//!     .build()
//!     .await?;
//!
//! // The page starts blank so the stealth hooks are installed before any
//! // document loads, then navigates and waits for the load event.
//! let page = scraper.new_stealth_page().await?;
//! page.navigate_and_wait(
//!     "https://protected.example.com",
//!     std::time::Duration::from_secs(30),
//! )
//! .await?;
//!
//! // Detect and wait out / solve any bot-protection challenge on the page.
//! let signal = scraper.solve_challenge(&page).await?;
//! println!("page cleared (challenge: {:?})", signal.kind);
//! # Ok(())
//! # }
//! ```
//!
//! The browser is driven over this crate\'s own asynchronous CDP client, so no
//! call blocks a worker thread and none of this needs `spawn_blocking`.

/// Emulation of human-like interaction patterns (typing delays, mouse curves).
#[cfg(feature = "browser")]
pub mod behavior;
/// The MITM certificate authority: one CA per process, leaves cached per host.
pub mod ca;
/// Async Chrome DevTools Protocol client (launcher, transport, session).
#[cfg(feature = "browser")]
pub mod cdp;
/// Pure detection and mitigation policy for bot-protection challenges.
/// Certificate compression codecs for the TLS handshake.
pub mod cert_compression;

/// Building an impersonating HTTP client without a browser.
pub mod client;

pub mod challenge;
/// User-Agent Client Hints derived from the profile.
pub mod client_hints;
/// Browser TLS fingerprints verified by measurement.
pub mod emulation;
/// Strong typed Error enums for the scraper and underlying HTTP proxy.
pub mod error;
/// Observability events and sinks emitted during a scrape.
pub mod events;
/// Geo/locale consistency: country codes, locale table, and a resolver port.
pub mod geo;
/// The lightweight HTTP-only transport, sharing the browser's fingerprint.
#[cfg(feature = "browser")]
pub mod http_scraper;
/// The portable session identity and the transport-switching policy.
pub mod identity;
/// JA4 TLS client fingerprinting: ClientHello parsing and fingerprint computation.
pub mod ja4;
/// Management of browser fingerprints, user agents, and localized hardware characteristics.
pub mod profile;
/// Local MITM TLS spoofing proxy using Hyper and Rustls.
pub mod proxy;
/// Rotatable pool of upstream proxies with selection strategy (pure domain logic).
pub mod proxy_pool;
/// Core headless Chrome browser lifecycle and orchestration.
#[cfg(feature = "browser")]
pub mod scraper;
/// The dual-mode session that moves between the browser and plain HTTP.
#[cfg(feature = "browser")]
pub mod session;
/// Automated solvers for bypassing common JavaScript challenges.
#[cfg(feature = "browser")]
pub mod solver;
/// Per-domain session state: model, store port, and adapters.
pub mod state;
/// Injection scripts to mask navigator and WebGL hooks.
pub mod stealth;
/// Passive capture of intercepted TLS handshakes for fingerprint observation.
pub mod tls_capture;

pub use challenge::{
    Action, ChallengeKind, ChallengeSignal, Confidence, DetectionInput, MitigationPolicy, detect,
};
pub use client::impersonation_client;
pub use client_hints::ClientHints;

pub use error::Error;
pub use events::{EventSink, LogEventSink, NoopEventSink, ScraperEvent};
pub use geo::{CountryCode, GeoResolver, Locale};
#[cfg(feature = "browser")]
pub use http_scraper::{HttpResponse, HttpScraper};
pub use identity::{
    Cookie, DemoteReason, EgressRef, EscalateReason, SameSite, SessionMode, SessionPolicy,
    StealthIdentity, Transition,
};
pub use profile::{BrowserKind, BrowserProfile};
pub use proxy::TlsSpoofingProxy;
pub use proxy_pool::{ProxyPool, RotationStrategy};
#[cfg(feature = "browser")]
pub use scraper::{CloudScraper, CloudScraperBuilder};
#[cfg(feature = "browser")]
pub use session::{StealthSession, StealthSessionBuilder};
#[cfg(feature = "browser")]
pub use solver::GenericSolver;
pub use state::{DomainState, InMemoryStateStore, JsonStateStore, Outcome, StateStore};
/// The `wreq` HTTP client this crate impersonates with, re-exported.
///
/// [`impersonation_client`] hands back a [`wreq::ClientBuilder`], so a consumer
/// needs `wreq`'s own types to finish configuring it. Using this re-export
/// instead of a direct dependency guarantees the version matches the one the
/// emulation was measured against — two `wreq` majors in one graph would mean
/// the builder and the types could not meet.
pub use wreq;
