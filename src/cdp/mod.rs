//! An async Chrome DevTools Protocol client built for stealth.
//!
//! This exists because a conventional driver's defaults work against the rest
//! of the crate. It replaces them on three counts, each a signal a page can
//! observe or a property of how the browser is driven:
//!
//! - the browser is launched without `--enable-automation`, so
//!   `navigator.webdriver` is never set at the C++ level in the first place;
//! - CDP runs over inherited file descriptors rather than a TCP port, so there
//!   is no local endpoint for a page to discover;
//! - CDP domains are enabled only when a call needs them, so the
//!   `Runtime.enable` leak that bot-detection scripts look for is not emitted
//!   as a side effect of opening a tab.
//!
//! See [`launch`](crate::cdp::launch()) for the command line and the reasoning
//! behind each flag.

pub mod launch;
pub mod session;
pub mod transport;

pub use launch::{LaunchConfig, LaunchedBrowser, ProfileDir, build_args, find_chrome, launch};
pub use session::{BrowserHandle, Page};
pub use transport::{CdpEvent, CdpTransport, DEFAULT_CALL_TIMEOUT};
