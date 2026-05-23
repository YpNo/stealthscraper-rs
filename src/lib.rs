#![warn(missing_docs)]
//! A sophisticated Rust library for simulating human browser behavior on secured websites.
//!
//! This library provides a high-level API for web scraping using a CDP-driven headless browser
//! approach. It includes tools for:
//! - Browser fingerprint spoofing (`profile`, `stealth`)
//! - Human-like interaction behavior (`behavior`)
//! - Bypassing common bot protection mechanisms (`solver`)
//!
//! `rs-cloudscraper` aims to provide an un-detectable scraping environment by randomizing browser
//! profiles, simulating human interaction patterns (like realistic typing delays and Bezier-curve mouse movements),
//! and injecting stealth JavaScript to mask headless browser signatures.

/// Emulation of human-like interaction patterns (typing delays, mouse curves).
#[cfg(feature = "browser")]
pub mod behavior;
/// Pure detection and mitigation policy for bot-protection challenges.
pub mod challenge;
/// Strong typed Error enums for the scraper and underlying HTTP proxy.
pub mod error;
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
/// Injection scripts to mask navigator and WebGL hooks.
pub mod stealth;

pub use challenge::{
    Action, ChallengeKind, ChallengeSignal, Confidence, DetectionInput, MitigationPolicy, detect,
};
pub use error::Error;
pub use profile::BrowserProfile;
pub use proxy::TlsSpoofingProxy;
pub use proxy_pool::{ProxyPool, RotationStrategy};
#[cfg(feature = "browser")]
pub use scraper::{CloudScraper, CloudScraperBuilder}; // Expose builder
#[cfg(feature = "browser")]
pub use solver::GenericSolver; // Added Error export
