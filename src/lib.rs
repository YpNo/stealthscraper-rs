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

pub mod profile;
pub mod stealth;
pub mod scraper;
pub mod behavior;
pub mod solver;
pub mod proxy;
pub mod error; // Added error module

pub use profile::BrowserProfile;
pub use scraper::{CloudScraper, CloudScraperBuilder}; // Expose builder
pub use solver::GenericSolver;
pub use proxy::TlsSpoofingProxy;
pub use error::Error; // Added Error export
