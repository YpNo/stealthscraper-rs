//! Bot-protection challenge detection and mitigation policy.
//!
//! This module is pure domain logic — no I/O, no transport types — so it is
//! available in every build (it does not require the `browser` feature) and is
//! exhaustively unit-tested. It answers two questions:
//!
//! 1. *What* are we looking at? [`detect`] classifies a response/page into a
//!    [`ChallengeSignal`].
//! 2. *What should we do?* [`MitigationPolicy::decide`] maps that signal plus an
//!    attempt count to an [`Action`].
//!
//! The headless-browser orchestration that consumes these decisions lives in
//! [`crate::scraper`] (behind the `browser` feature).

mod detect;
mod mitigation;
mod types;

pub use detect::detect;
pub use mitigation::{Action, MitigationPolicy};
pub use types::{ChallengeKind, ChallengeSignal, Confidence, DetectionInput};
