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
//!   [`StateStore`]; durable with the `persistence` feature.
//! - **Observability** ([`events`]) — a [`ScraperEvent`] / [`EventSink`] stream.
//!
//! # Feature flags
//!
//! - `browser` *(off by default)* — the headless-Chrome API (`CloudScraper`,
//!   `solve_challenge`, profile rotation, human-behavior helpers). Required for
//!   the quick start below.
//! - `persistence` *(off by default)* — the durable, `redb`-backed state store.
//!
//! With no features enabled the crate builds only the pure, dependency-light core
//! ([`challenge`], [`proxy_pool`], [`geo`], the [`state`] model, [`events`]) for
//! embedding into your own pipeline.
//!
//! # Quick start
//!
#![cfg_attr(feature = "browser", doc = "```no_run")]
#![cfg_attr(not(feature = "browser"), doc = "```ignore")]
//! use rs_cloudscraper::{BrowserProfile, CloudScraper};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), rs_cloudscraper::Error> {
//! // The builder spins up the MITM proxy and launches a stealth browser whose
//! // JA4 fingerprint matches the chosen profile.
//! let scraper = CloudScraper::builder()
//!     .profile(BrowserProfile::random())
//!     .build()
//!     .await?;
//!
//! let tab = scraper.new_stealth_tab()?;
//! tab.navigate_to("https://protected.example.com").expect("navigate");
//! tab.wait_until_navigated().expect("wait");
//!
//! // Detect and wait out / solve any bot-protection challenge on the page.
//! let signal = scraper.solve_challenge(&tab)?;
//! println!("page cleared (challenge: {:?})", signal.kind);
//! # Ok(())
//! # }
//! ```
//!
//! `solve_challenge` is synchronous and blocking; on an async runtime call it from
//! `tokio::task::spawn_blocking` and run the proxy on a multi-threaded runtime.

/// Emulation of human-like interaction patterns (typing delays, mouse curves).
#[cfg(feature = "browser")]
pub mod behavior;
/// Pure detection and mitigation policy for bot-protection challenges.
pub mod challenge;
/// Strong typed Error enums for the scraper and underlying HTTP proxy.
pub mod error;
/// Observability events and sinks emitted during a scrape.
pub mod events;
/// Geo/locale consistency: country codes, locale table, and a resolver port.
pub mod geo;
/// Management of browser fingerprints, user agents, and localized hardware characteristics.
pub mod profile;
/// Local MITM TLS spoofing proxy using Hyper and Rustls.
pub mod proxy;
/// Rotatable pool of upstream proxies with selection strategy (pure domain logic).
pub mod proxy_pool;
/// Core headless Chrome browser lifecycle and orchestration.
#[cfg(feature = "browser")]
pub mod scraper;
/// Automated solvers for bypassing common JavaScript challenges.
#[cfg(feature = "browser")]
pub mod solver;
/// Per-domain session state: model, store port, and adapters.
pub mod state;
/// Injection scripts to mask navigator and WebGL hooks.
pub mod stealth;

pub use challenge::{
    Action, ChallengeKind, ChallengeSignal, Confidence, DetectionInput, MitigationPolicy, detect,
};
pub use error::Error;
pub use events::{EventSink, LogEventSink, NoopEventSink, ScraperEvent};
pub use geo::{CountryCode, GeoResolver, Locale};
pub use profile::BrowserProfile;
pub use proxy::TlsSpoofingProxy;
pub use proxy_pool::{ProxyPool, RotationStrategy};
#[cfg(feature = "browser")]
pub use scraper::{CloudScraper, CloudScraperBuilder};
#[cfg(feature = "browser")]
pub use solver::GenericSolver;
pub use state::{DomainState, InMemoryStateStore, Outcome, StateStore};
