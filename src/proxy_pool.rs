//! Pure upstream-proxy pool and rotation strategy.
//!
//! This is domain logic — no I/O — so it lives outside the `browser` feature
//! and is fully unit-tested. The pool tracks a set of upstream proxy URLs,
//! which one is currently selected, and per-endpoint health. When the
//! orchestration layer detects that the current egress is blocked it calls
//! [`ProxyPool::rotate`], which retires the current proxy and selects the next
//! healthy one according to the configured [`RotationStrategy`].

use rand::RngExt;

use crate::geo::CountryCode;

/// How [`ProxyPool::rotate`] picks the next healthy endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RotationStrategy {
    /// Cycle through endpoints in declaration order.
    #[default]
    RoundRobin,
    /// Pick uniformly at random among the healthy endpoints.
    Random,
}

/// A single upstream proxy and its current health flag.
#[derive(Debug, Clone)]
struct ProxyEndpoint {
    url: String,
    country: Option<CountryCode>,
    healthy: bool,
}

/// A rotatable pool of upstream proxy URLs.
#[derive(Debug, Clone)]
pub struct ProxyPool {
    endpoints: Vec<ProxyEndpoint>,
    strategy: RotationStrategy,
    current: Option<usize>,
}

impl ProxyPool {
    /// Build a pool from upstream proxy URLs (untagged). Duplicate and empty URLs
    /// are dropped.
    ///
    /// The initially selected endpoint is the first one for
    /// [`RotationStrategy::RoundRobin`], or a random one for
    /// [`RotationStrategy::Random`].
    pub fn new(urls: impl IntoIterator<Item = String>, strategy: RotationStrategy) -> Self {
        Self::with_endpoints(urls.into_iter().map(|url| (url, None)), strategy)
    }

    /// Build a pool from `(url, country)` pairs, where `country` tags the proxy's
    /// exit country for proxy-led locale derivation. Duplicate/empty URLs dropped.
    pub fn with_endpoints(
        endpoints: impl IntoIterator<Item = (String, Option<CountryCode>)>,
        strategy: RotationStrategy,
    ) -> Self {
        let mut collected: Vec<ProxyEndpoint> = Vec::new();
        for (url, country) in endpoints {
            let url = url.trim().to_string();
            if url.is_empty() || collected.iter().any(|e| e.url == url) {
                continue;
            }
            collected.push(ProxyEndpoint {
                url,
                country,
                healthy: true,
            });
        }

        let current = if collected.is_empty() {
            None
        } else {
            match strategy {
                RotationStrategy::RoundRobin => Some(0),
                RotationStrategy::Random => Some(rand::rng().random_range(0..collected.len())),
            }
        };

        Self {
            endpoints: collected,
            strategy,
            current,
        }
    }

    /// Total number of endpoints in the pool (healthy or not).
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Returns `true` when the pool holds no endpoints.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Number of endpoints currently marked healthy.
    pub fn healthy_count(&self) -> usize {
        self.endpoints.iter().filter(|e| e.healthy).count()
    }

    /// The currently selected upstream proxy URL, if any.
    pub fn selected(&self) -> Option<&str> {
        self.current.map(|i| self.endpoints[i].url.as_str())
    }

    /// The tagged exit country of the currently selected proxy, if any.
    pub fn selected_country(&self) -> Option<CountryCode> {
        self.current.and_then(|i| self.endpoints[i].country)
    }

    /// Retire the current endpoint and select the next healthy one.
    ///
    /// Marks the current endpoint unhealthy (so rotation never returns to a
    /// known-blocked proxy), then selects the next healthy endpoint per the
    /// [`RotationStrategy`]. Returns the newly selected URL, or `None` when no
    /// healthy endpoints remain.
    pub fn rotate(&mut self) -> Option<String> {
        if let Some(cur) = self.current {
            self.endpoints[cur].healthy = false;
        }

        let next = match self.strategy {
            RotationStrategy::RoundRobin => self.next_round_robin(),
            RotationStrategy::Random => self.next_random(),
        };

        self.current = next;
        next.map(|i| self.endpoints[i].url.clone())
    }

    fn next_round_robin(&self) -> Option<usize> {
        let n = self.endpoints.len();
        if n == 0 {
            return None;
        }
        let start = self.current.unwrap_or(0);
        (1..=n)
            .map(|step| (start + step) % n)
            .find(|&idx| self.endpoints[idx].healthy)
    }

    fn next_random(&self) -> Option<usize> {
        let healthy: Vec<usize> = self
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, e)| e.healthy)
            .map(|(i, _)| i)
            .collect();
        if healthy.is_empty() {
            return None;
        }
        Some(healthy[rand::rng().random_range(0..healthy.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(urls: &[&str], strategy: RotationStrategy) -> ProxyPool {
        ProxyPool::new(urls.iter().map(|s| s.to_string()), strategy)
    }

    #[test]
    fn new_empty_pool_has_no_selection() {
        let p = ProxyPool::new(Vec::<String>::new(), RotationStrategy::RoundRobin);
        assert!(p.is_empty());
        assert_eq!(p.selected(), None);
        assert_eq!(p.healthy_count(), 0);
    }

    #[test]
    fn new_dedups_and_trims() {
        let p = pool(
            &["http://a", " http://a ", "http://b", ""],
            RotationStrategy::RoundRobin,
        );
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn round_robin_selects_first_then_advances() {
        let mut p = pool(
            &["http://a", "http://b", "http://c"],
            RotationStrategy::RoundRobin,
        );
        assert_eq!(p.selected(), Some("http://a"));
        assert_eq!(p.rotate().as_deref(), Some("http://b"));
        assert_eq!(p.rotate().as_deref(), Some("http://c"));
    }

    #[test]
    fn rotate_retires_current_and_skips_it_when_wrapping() {
        let mut p = pool(&["http://a", "http://b"], RotationStrategy::RoundRobin);
        // a -> b (a retired)
        assert_eq!(p.rotate().as_deref(), Some("http://b"));
        // b retired, a already retired -> none healthy left
        assert_eq!(p.rotate(), None);
        assert_eq!(p.healthy_count(), 0);
        assert_eq!(p.selected(), None);
    }

    #[test]
    fn rotate_on_empty_pool_is_none() {
        let mut p = ProxyPool::new(Vec::<String>::new(), RotationStrategy::RoundRobin);
        assert_eq!(p.rotate(), None);
    }

    #[test]
    fn healthy_count_decreases_on_rotate() {
        let mut p = pool(
            &["http://a", "http://b", "http://c"],
            RotationStrategy::RoundRobin,
        );
        assert_eq!(p.healthy_count(), 3);
        p.rotate();
        assert_eq!(p.healthy_count(), 2);
    }

    #[test]
    fn endpoints_carry_country_tags_through_rotation() {
        let de = CountryCode::new("DE");
        let fr = CountryCode::new("FR");
        let mut p = ProxyPool::with_endpoints(
            [("http://a".to_string(), de), ("http://b".to_string(), fr)],
            RotationStrategy::RoundRobin,
        );
        assert_eq!(p.selected(), Some("http://a"));
        assert_eq!(p.selected_country(), de);
        assert_eq!(p.rotate().as_deref(), Some("http://b"));
        assert_eq!(p.selected_country(), fr);
    }

    #[test]
    fn untagged_pool_has_no_country() {
        let p = pool(&["http://a"], RotationStrategy::RoundRobin);
        assert_eq!(p.selected_country(), None);
    }

    #[test]
    fn random_strategy_selects_a_member_and_exhausts() {
        let urls = ["http://a", "http://b", "http://c"];
        let mut p = pool(&urls, RotationStrategy::Random);
        assert!(urls.contains(&p.selected().unwrap()));
        // Rotate through all remaining; every result is a valid member, then None.
        let mut seen = 0;
        while let Some(url) = p.rotate() {
            assert!(urls.contains(&url.as_str()));
            seen += 1;
        }
        assert_eq!(seen, 2); // 3 endpoints, initial selection consumed one
        assert_eq!(p.healthy_count(), 0);
    }
}
