//! Per-domain session state model.
//!
//! Pure, serializable value types describing what we have learned about a host
//! across requests (and across process restarts, when a persistent store is
//! used): the last outcome, which egress proxy was in play, success/failure
//! tallies, and an optional rate-limit cooldown.
//!
//! All time is expressed as Unix seconds and supplied by the caller, so the
//! model stays free of `SystemTime::now()` and remains trivially testable.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The result of an attempt against a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The page loaded cleanly with no bot-protection challenge.
    Success,
    /// A challenge was encountered (and possibly cleared) on the page.
    Challenged,
    /// The host hard-blocked the request (e.g. Cloudflare error 1020).
    Blocked,
    /// The host rate-limited the request (HTTP 429 / error 1015).
    RateLimited,
}

/// Accumulated knowledge about a single host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainState {
    /// The host this state describes (e.g. `example.com`).
    pub host: String,
    /// The most recently recorded outcome, if any.
    pub last_outcome: Option<Outcome>,
    /// The egress proxy URL used on the most recent recorded attempt.
    pub last_proxy: Option<String>,
    /// Count of successful attempts.
    pub successes: u32,
    /// Count of failed attempts (challenged/blocked/rate-limited).
    pub failures: u32,
    /// Unix timestamp (secs) before which the host should not be hit again.
    pub cooldown_until: Option<u64>,
    /// Unix timestamp (secs) of the last update.
    pub updated_at: u64,
}

impl DomainState {
    /// Create a fresh, empty state for `host`.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            last_outcome: None,
            last_proxy: None,
            successes: 0,
            failures: 0,
            cooldown_until: None,
            updated_at: 0,
        }
    }

    /// Returns a new state reflecting `outcome` recorded at `now` (Unix secs).
    ///
    /// `proxy` is the egress in play (kept if `None`). Counting:
    /// - [`Outcome::Success`] and [`Outcome::Challenged`] increment `successes` —
    ///   in both cases the page was ultimately obtained (a challenge that cleared
    ///   is a success, not a failure).
    /// - [`Outcome::Blocked`] and [`Outcome::RateLimited`] increment `failures`.
    ///
    /// `cooldown_until` models the rate-limit back-off window: it is set only by
    /// [`Outcome::RateLimited`] and cleared by every other outcome, so it always
    /// reflects the most recent outcome. The receiver is left untouched
    /// (immutable update).
    pub fn record(
        &self,
        outcome: Outcome,
        proxy: Option<String>,
        now: u64,
        rate_limit_cooldown: Duration,
    ) -> Self {
        let mut next = self.clone();
        next.last_outcome = Some(outcome);
        if proxy.is_some() {
            next.last_proxy = proxy;
        }
        next.updated_at = now;
        match outcome {
            Outcome::Success | Outcome::Challenged => {
                next.successes = next.successes.saturating_add(1);
                next.cooldown_until = None;
            }
            Outcome::RateLimited => {
                next.failures = next.failures.saturating_add(1);
                next.cooldown_until = Some(now.saturating_add(rate_limit_cooldown.as_secs()));
            }
            Outcome::Blocked => {
                next.failures = next.failures.saturating_add(1);
                next.cooldown_until = None;
            }
        }
        next
    }

    /// Whether the host is still within its cooldown window at `now`.
    pub fn in_cooldown(&self, now: u64) -> bool {
        self.cooldown_until.is_some_and(|until| now < until)
    }

    /// Remaining cooldown at `now`, if any.
    pub fn cooldown_remaining(&self, now: u64) -> Option<Duration> {
        self.cooldown_until
            .and_then(|until| until.checked_sub(now))
            .filter(|&secs| secs > 0)
            .map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_success_increments_and_clears_cooldown() {
        let s = DomainState::new("example.com").record(
            Outcome::RateLimited,
            None,
            100,
            Duration::from_secs(60),
        );
        assert!(s.in_cooldown(120));

        let s = s.record(
            Outcome::Success,
            Some("http://p:1".into()),
            200,
            Duration::ZERO,
        );
        assert_eq!(s.successes, 1);
        assert_eq!(s.last_outcome, Some(Outcome::Success));
        assert_eq!(s.last_proxy.as_deref(), Some("http://p:1"));
        assert!(!s.in_cooldown(200));
        assert_eq!(s.cooldown_until, None);
    }

    #[test]
    fn record_rate_limited_sets_cooldown() {
        let s = DomainState::new("h").record(
            Outcome::RateLimited,
            None,
            1_000,
            Duration::from_secs(30),
        );
        assert_eq!(s.failures, 1);
        assert!(s.in_cooldown(1_029));
        assert!(!s.in_cooldown(1_030));
        assert_eq!(s.cooldown_remaining(1_010), Some(Duration::from_secs(20)));
        assert_eq!(s.cooldown_remaining(1_030), None);
    }

    #[test]
    fn record_keeps_proxy_when_none_passed() {
        let s = DomainState::new("h")
            .record(Outcome::Success, Some("http://a".into()), 1, Duration::ZERO)
            .record(Outcome::Blocked, None, 2, Duration::ZERO);
        assert_eq!(s.last_proxy.as_deref(), Some("http://a"));
        assert_eq!(s.failures, 1);
        assert_eq!(s.last_outcome, Some(Outcome::Blocked));
    }

    #[test]
    fn no_cooldown_by_default() {
        let s = DomainState::new("h");
        assert!(!s.in_cooldown(0));
        assert_eq!(s.cooldown_remaining(0), None);
    }

    #[test]
    fn challenged_counts_as_success_and_clears_cooldown() {
        // A challenge that ultimately cleared is a success, not a failure.
        let s =
            DomainState::new("h").record(Outcome::RateLimited, None, 100, Duration::from_secs(60));
        assert!(s.in_cooldown(120));

        let s = s.record(Outcome::Challenged, None, 200, Duration::ZERO);
        assert_eq!(s.successes, 1);
        assert_eq!(s.failures, 1); // the earlier rate-limit
        assert_eq!(s.last_outcome, Some(Outcome::Challenged));
        assert!(!s.in_cooldown(200));
    }

    #[test]
    fn blocked_counts_as_failure_and_clears_stale_cooldown() {
        let s =
            DomainState::new("h").record(Outcome::RateLimited, None, 100, Duration::from_secs(60));
        assert!(s.in_cooldown(120));

        // A subsequent hard block is a different condition; the stale rate-limit
        // cooldown must not linger.
        let s = s.record(Outcome::Blocked, None, 130, Duration::ZERO);
        assert_eq!(s.failures, 2);
        assert_eq!(s.successes, 0);
        assert!(!s.in_cooldown(130));
        assert_eq!(s.cooldown_until, None);
    }
}
