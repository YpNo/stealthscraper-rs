//! Observability events emitted during a scrape, and sinks that consume them.
//!
//! [`ScraperEvent`] is a lightweight, borrowed value describing something that
//! just happened (a challenge was detected, a proxy was rotated, a solve
//! finished). [`EventSink`] is the output port; the scraper emits to whatever
//! sink is configured. Two adapters ship:
//!
//! - [`NoopEventSink`] — the zero-overhead default.
//! - [`LogEventSink`] — forwards events to the `log` crate at sensible levels.
//!
//! Implement [`EventSink`] yourself to wire events into metrics/telemetry.

use std::fmt;
use std::time::Duration;

use crate::challenge::ChallengeKind;

/// Something noteworthy that happened during a scrape.
///
/// Fields borrow to keep emission allocation-free on the hot path. `host` is
/// optional because it may not always be derivable (e.g. an `about:blank` tab).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScraperEvent<'a> {
    /// A bot-protection challenge was identified on the page.
    ChallengeDetected {
        /// Target host, if known.
        host: Option<&'a str>,
        /// The classified challenge kind.
        kind: ChallengeKind,
    },
    /// Waiting for a challenge to clear before re-checking.
    Waiting {
        /// Target host, if known.
        host: Option<&'a str>,
        /// The challenge being waited on.
        kind: ChallengeKind,
        /// How long the scraper will wait before re-checking.
        delay: Duration,
    },
    /// The egress proxy was rotated after a hard block.
    ProxyRotated {
        /// Target host, if known.
        host: Option<&'a str>,
        /// The newly selected upstream proxy URL, if any.
        upstream: Option<&'a str>,
    },
    /// The browser profile (fingerprint identity) was rotated via a relaunch.
    ProfileRotated {
        /// The User-Agent of the newly applied profile.
        user_agent: &'a str,
    },
    /// The page was cleared (no challenge remaining).
    SolveSucceeded {
        /// Target host, if known.
        host: Option<&'a str>,
        /// Number of retry attempts taken.
        attempts: u32,
        /// Whether any challenge had to be cleared along the way.
        challenged: bool,
    },
    /// The challenge could not be cleared.
    SolveFailed {
        /// Target host, if known.
        host: Option<&'a str>,
        /// The challenge kind at the point of failure.
        kind: ChallengeKind,
        /// Human-readable failure reason.
        reason: &'a str,
    },
}

impl fmt::Display for ScraperEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = |h: &Option<&str>| h.unwrap_or("<unknown>").to_string();
        match self {
            ScraperEvent::ChallengeDetected { host: h, kind } => {
                write!(f, "challenge detected on {}: {kind:?}", host(h))
            }
            ScraperEvent::Waiting {
                host: h,
                kind,
                delay,
            } => {
                write!(f, "waiting {delay:?} for {kind:?} on {}", host(h))
            }
            ScraperEvent::ProxyRotated { host: h, upstream } => {
                write!(
                    f,
                    "rotated egress proxy to {} for {}",
                    upstream.unwrap_or("<none>"),
                    host(h)
                )
            }
            ScraperEvent::ProfileRotated { user_agent } => {
                write!(f, "rotated browser profile (user-agent: {user_agent})")
            }
            ScraperEvent::SolveSucceeded {
                host: h,
                attempts,
                challenged,
            } => write!(
                f,
                "solve succeeded on {} (attempts={attempts}, challenged={challenged})",
                host(h)
            ),
            ScraperEvent::SolveFailed {
                host: h,
                kind,
                reason,
            } => write!(f, "solve failed on {} ({kind:?}): {reason}", host(h)),
        }
    }
}

/// Output port for scrape observability events.
///
/// Must be cheap to share across threads; the scraper holds one behind an `Arc`.
pub trait EventSink: Send + Sync {
    /// Consume a single event. Implementations must not block for long.
    fn emit(&self, event: &ScraperEvent<'_>);
}

/// The default sink: discards every event with zero overhead.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit(&self, _event: &ScraperEvent<'_>) {}
}

/// Forwards events to the `log` crate, choosing a level per event kind.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogEventSink;

impl EventSink for LogEventSink {
    fn emit(&self, event: &ScraperEvent<'_>) {
        match event {
            ScraperEvent::SolveFailed { .. } => log::warn!("{event}"),
            ScraperEvent::ChallengeDetected { .. }
            | ScraperEvent::ProxyRotated { .. }
            | ScraperEvent::ProfileRotated { .. }
            | ScraperEvent::SolveSucceeded { .. } => log::info!("{event}"),
            ScraperEvent::Waiting { .. } => log::debug!("{event}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<String>>,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, event: &ScraperEvent<'_>) {
            self.events.lock().unwrap().push(event.to_string());
        }
    }

    #[test]
    fn recording_sink_captures_emitted_events() {
        let sink = RecordingSink::default();
        sink.emit(&ScraperEvent::ChallengeDetected {
            host: Some("example.com"),
            kind: ChallengeKind::Turnstile,
        });
        sink.emit(&ScraperEvent::SolveSucceeded {
            host: Some("example.com"),
            attempts: 2,
            challenged: true,
        });

        let recorded = sink.events.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].contains("challenge detected on example.com: Turnstile"));
        assert!(recorded[1].contains("attempts=2, challenged=true"));
    }

    #[test]
    fn display_handles_unknown_host() {
        let ev = ScraperEvent::SolveFailed {
            host: None,
            kind: ChallengeKind::AccessDenied,
            reason: "blocked",
        };
        assert_eq!(
            ev.to_string(),
            "solve failed on <unknown> (AccessDenied): blocked"
        );
    }

    #[test]
    fn noop_and_log_sinks_do_not_panic() {
        let ev = ScraperEvent::ProxyRotated {
            host: Some("h"),
            upstream: Some("http://p:1"),
        };
        NoopEventSink.emit(&ev);
        LogEventSink.emit(&ev);
    }

    #[test]
    fn profile_rotated_display() {
        let ev = ScraperEvent::ProfileRotated {
            user_agent: "Mozilla/5.0 Test",
        };
        assert_eq!(
            ev.to_string(),
            "rotated browser profile (user-agent: Mozilla/5.0 Test)"
        );
        LogEventSink.emit(&ev);
    }
}
