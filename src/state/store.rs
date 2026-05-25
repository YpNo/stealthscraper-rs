//! The [`StateStore`] output port and an in-memory adapter.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::Error;

use super::model::DomainState;

/// Output port for persisting [`DomainState`] keyed by host.
///
/// Implementations must be cheap to share across threads (`Send + Sync`); the
/// scraper holds one behind an `Arc`. Methods are synchronous to match embedded
/// stores like `redb`.
pub trait StateStore: Send + Sync {
    /// Fetch the stored state for `host`, if any.
    fn get(&self, host: &str) -> Result<Option<DomainState>, Error>;
    /// Insert or replace the state for `state.host`.
    fn put(&self, state: &DomainState) -> Result<(), Error>;
    /// Delete any stored state for `host` (no-op if absent).
    fn remove(&self, host: &str) -> Result<(), Error>;

    /// Atomically read-modify-write the state for `host`.
    ///
    /// `update` receives the current state (or a fresh [`DomainState`] for
    /// `host` if none exists) and returns the new value to persist. The returned
    /// state is stored and handed back.
    ///
    /// The default implementation is a non-atomic `get` + `put` and is therefore
    /// subject to lost updates under concurrency; adapters that can do better
    /// (a single lock or transaction) should override it. The built-in
    /// [`InMemoryStateStore`] and `RedbStateStore` do.
    fn update(
        &self,
        host: &str,
        update: &mut dyn FnMut(DomainState) -> DomainState,
    ) -> Result<DomainState, Error> {
        let current = self.get(host)?.unwrap_or_else(|| DomainState::new(host));
        let next = update(current);
        self.put(&next)?;
        Ok(next)
    }
}

/// Ephemeral, in-process [`StateStore`]. The default when no persistent backend
/// is configured; also handy in tests.
#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    inner: Mutex<HashMap<String, DomainState>>,
}

impl InMemoryStateStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for InMemoryStateStore {
    fn get(&self, host: &str) -> Result<Option<DomainState>, Error> {
        Ok(self
            .inner
            .lock()
            .expect("state store lock poisoned")
            .get(host)
            .cloned())
    }

    fn put(&self, state: &DomainState) -> Result<(), Error> {
        self.inner
            .lock()
            .expect("state store lock poisoned")
            .insert(state.host.clone(), state.clone());
        Ok(())
    }

    fn remove(&self, host: &str) -> Result<(), Error> {
        self.inner
            .lock()
            .expect("state store lock poisoned")
            .remove(host);
        Ok(())
    }

    fn update(
        &self,
        host: &str,
        update: &mut dyn FnMut(DomainState) -> DomainState,
    ) -> Result<DomainState, Error> {
        let mut guard = self.inner.lock().expect("state store lock poisoned");
        let current = guard
            .get(host)
            .cloned()
            .unwrap_or_else(|| DomainState::new(host));
        let next = update(current);
        guard.insert(next.host.clone(), next.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Outcome;
    use std::time::Duration;

    #[test]
    fn in_memory_round_trips_state() {
        let store = InMemoryStateStore::new();
        assert_eq!(store.get("example.com").unwrap(), None);

        let state = DomainState::new("example.com").record(
            Outcome::Success,
            Some("http://p:1".into()),
            10,
            Duration::ZERO,
        );
        store.put(&state).unwrap();

        let loaded = store.get("example.com").unwrap().unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn in_memory_update_creates_then_modifies() {
        let store = InMemoryStateStore::new();

        // First update on a missing host starts from a fresh state.
        let s1 = store
            .update("example.com", &mut |cur| {
                cur.record(Outcome::Blocked, None, 1, Duration::ZERO)
            })
            .unwrap();
        assert_eq!(s1.failures, 1);
        assert_eq!(s1.host, "example.com");

        // Second update sees the persisted value.
        let s2 = store
            .update("example.com", &mut |cur| {
                cur.record(Outcome::Success, None, 2, Duration::ZERO)
            })
            .unwrap();
        assert_eq!(s2.failures, 1);
        assert_eq!(s2.successes, 1);
        assert_eq!(store.get("example.com").unwrap().unwrap(), s2);
    }

    #[test]
    fn in_memory_remove_deletes() {
        let store = InMemoryStateStore::new();
        store.put(&DomainState::new("h")).unwrap();
        store.remove("h").unwrap();
        assert_eq!(store.get("h").unwrap(), None);
        // Removing a missing host is a no-op.
        store.remove("h").unwrap();
    }
}
