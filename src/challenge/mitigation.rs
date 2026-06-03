//! Pure decision policy that maps a detected challenge to a recommended action.

use std::time::Duration;

use super::types::{ChallengeKind, ChallengeSignal};

/// Default number of attempts before a challenge is declared unsolved.
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Default base back-off between attempts.
const DEFAULT_BASE_DELAY: Duration = Duration::from_secs(2);
/// Default ceiling for the exponential back-off.
const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(15);

/// The action recommended after detecting (or re-checking) a challenge.
///
/// The variant set is intentionally small: it only models actions the current
/// real-browser flow can actually execute. Proxy/profile rotation will be added
/// as variants when the proxy-pool layer (Phase 2) exists, rather than shipping
/// dead variants now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No (further) challenge — continue using the page.
    Proceed,
    /// Wait `delay`, then re-check. `attempt` is the next attempt number.
    Wait {
        /// How long to wait before the next re-check.
        delay: Duration,
        /// The attempt counter to use on the next iteration.
        attempt: u32,
    },
    /// Retire the current egress proxy, switch to the next one, then re-check.
    RotateProxy {
        /// The attempt counter to use on the next iteration.
        attempt: u32,
    },
    /// Give up: the challenge cannot be handled with current capabilities.
    Fail {
        /// Human-readable reason, suitable for an error message.
        reason: String,
    },
}

/// Pure policy mapping a [`ChallengeSignal`] plus an attempt count to an [`Action`].
#[derive(Debug, Clone, Copy)]
pub struct MitigationPolicy {
    /// Maximum number of wait/re-check attempts before failing.
    pub max_attempts: u32,
    /// Base delay for the exponential back-off.
    pub base_delay: Duration,
    /// Upper bound on a single back-off delay.
    pub max_delay: Duration,
    /// Whether egress-proxy rotation is available (a pool with a fallback exists).
    pub can_rotate_proxy: bool,
}

impl Default for MitigationPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_delay: DEFAULT_BASE_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
            can_rotate_proxy: false,
        }
    }
}

impl MitigationPolicy {
    /// Construct a policy with a custom attempt budget, keeping default delays.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            ..Self::default()
        }
    }

    /// Enable or disable egress-proxy rotation as a remedy for hard blocks.
    pub fn with_proxy_rotation(mut self, can_rotate_proxy: bool) -> Self {
        self.can_rotate_proxy = can_rotate_proxy;
        self
    }

    /// Decide the next action for `signal`, given the number of attempts already made.
    ///
    /// `attempt` is zero-based: pass `0` on the first decision, then feed back the
    /// `attempt` returned in [`Action::Wait`].
    pub fn decide(&self, signal: &ChallengeSignal, attempt: u32) -> Action {
        match signal.kind {
            ChallengeKind::None => Action::Proceed,
            // Hard block: the current egress IP is burned. Rotate to another
            // proxy if one is available, otherwise there is nothing left to try.
            ChallengeKind::AccessDenied => {
                if self.can_rotate_proxy && attempt < self.max_attempts {
                    Action::RotateProxy {
                        attempt: attempt + 1,
                    }
                } else {
                    Action::Fail {
                        reason: "access denied (e.g. Cloudflare error 1020); \
                                 no healthy proxy left to rotate to"
                            .to_string(),
                    }
                }
            }
            kind => {
                if attempt >= self.max_attempts {
                    return Action::Fail {
                        reason: format!(
                            "challenge {kind:?} still present after {} attempt(s)",
                            self.max_attempts
                        ),
                    };
                }
                Action::Wait {
                    delay: self.backoff(attempt),
                    attempt: attempt + 1,
                }
            }
        }
    }

    /// Exponential back-off (`base * 2^attempt`) capped at `max_delay`.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u64.saturating_pow(attempt);
        let secs = self
            .base_delay
            .as_secs()
            .saturating_mul(factor)
            .min(self.max_delay.as_secs());
        Duration::from_secs(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{ChallengeSignal, Confidence};

    fn signal(kind: ChallengeKind) -> ChallengeSignal {
        ChallengeSignal {
            kind,
            confidence: Confidence::High,
            evidence: vec![],
        }
    }

    #[test]
    fn decide_no_challenge_proceeds() {
        let policy = MitigationPolicy::default();
        assert_eq!(
            policy.decide(&signal(ChallengeKind::None), 0),
            Action::Proceed
        );
    }

    #[test]
    fn decide_access_denied_fails_without_rotation() {
        let policy = MitigationPolicy::default(); // can_rotate_proxy = false
        assert!(matches!(
            policy.decide(&signal(ChallengeKind::AccessDenied), 0),
            Action::Fail { .. }
        ));
    }

    #[test]
    fn decide_access_denied_rotates_when_available() {
        let policy = MitigationPolicy::new(3).with_proxy_rotation(true);
        assert_eq!(
            policy.decide(&signal(ChallengeKind::AccessDenied), 0),
            Action::RotateProxy { attempt: 1 }
        );
    }

    #[test]
    fn decide_access_denied_fails_once_rotation_budget_exhausted() {
        let policy = MitigationPolicy::new(2).with_proxy_rotation(true);
        assert!(matches!(
            policy.decide(&signal(ChallengeKind::AccessDenied), 2),
            Action::Fail { .. }
        ));
    }

    #[test]
    fn decide_js_challenge_waits_while_budget_remains() {
        let policy = MitigationPolicy::new(3);
        match policy.decide(&signal(ChallengeKind::JsChallenge), 0) {
            Action::Wait { delay, attempt } => {
                assert_eq!(delay, Duration::from_secs(2)); // base * 2^0
                assert_eq!(attempt, 1);
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn decide_fails_once_attempts_exhausted() {
        let policy = MitigationPolicy::new(2);
        assert!(matches!(
            policy.decide(&signal(ChallengeKind::Turnstile), 2),
            Action::Fail { .. }
        ));
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        let policy = MitigationPolicy {
            max_attempts: 10,
            base_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(15),
            can_rotate_proxy: false,
        };
        assert_eq!(policy.backoff(0), Duration::from_secs(2));
        assert_eq!(policy.backoff(1), Duration::from_secs(4));
        assert_eq!(policy.backoff(2), Duration::from_secs(8));
        // 2 * 2^3 = 16, capped to 15.
        assert_eq!(policy.backoff(3), Duration::from_secs(15));
        // Large attempt must not overflow.
        assert_eq!(policy.backoff(64), Duration::from_secs(15));
    }

    #[test]
    fn new_overrides_attempts_keeps_default_delays() {
        let policy = MitigationPolicy::new(7);
        assert_eq!(policy.max_attempts, 7);
        assert_eq!(policy.base_delay, DEFAULT_BASE_DELAY);
        assert_eq!(policy.max_delay, DEFAULT_MAX_DELAY);
    }
}
