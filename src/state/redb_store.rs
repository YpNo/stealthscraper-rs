//! Persistent [`StateStore`] backed by an embedded `redb` database.

#![cfg(feature = "persistence")]

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::Error;

use super::model::DomainState;
use super::store::StateStore;

/// Single table mapping host -> JSON-serialized [`DomainState`].
const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("domain_state");

/// A durable [`StateStore`] persisting domain state to a `redb` file.
///
/// `redb` is a pure-Rust embedded key/value store, so this adds no C toolchain
/// requirement. State is JSON-encoded with `serde_json` for forward-compatible,
/// human-inspectable records.
pub struct RedbStateStore {
    db: Database,
}

impl RedbStateStore {
    /// Open (creating if absent) a state database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = Database::create(path).map_err(|e| store_err("open database", e))?;

        // Ensure the table exists so reads on a fresh DB don't fail.
        let write = db.begin_write().map_err(|e| store_err("begin write", e))?;
        {
            write
                .open_table(TABLE)
                .map_err(|e| store_err("open table", e))?;
        }
        write.commit().map_err(|e| store_err("commit", e))?;

        Ok(Self { db })
    }
}

impl StateStore for RedbStateStore {
    fn get(&self, host: &str) -> Result<Option<DomainState>, Error> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| store_err("begin read", e))?;
        let table = read
            .open_table(TABLE)
            .map_err(|e| store_err("open table", e))?;
        match table.get(host).map_err(|e| store_err("get", e))? {
            Some(guard) => {
                let state =
                    serde_json::from_slice(guard.value()).map_err(|e| store_err("decode", e))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    fn put(&self, state: &DomainState) -> Result<(), Error> {
        let bytes = serde_json::to_vec(state).map_err(|e| store_err("encode", e))?;
        let write = self
            .db
            .begin_write()
            .map_err(|e| store_err("begin write", e))?;
        {
            let mut table = write
                .open_table(TABLE)
                .map_err(|e| store_err("open table", e))?;
            table
                .insert(state.host.as_str(), bytes.as_slice())
                .map_err(|e| store_err("insert", e))?;
        }
        write.commit().map_err(|e| store_err("commit", e))?;
        Ok(())
    }

    fn remove(&self, host: &str) -> Result<(), Error> {
        let write = self
            .db
            .begin_write()
            .map_err(|e| store_err("begin write", e))?;
        {
            let mut table = write
                .open_table(TABLE)
                .map_err(|e| store_err("open table", e))?;
            table.remove(host).map_err(|e| store_err("remove", e))?;
        }
        write.commit().map_err(|e| store_err("commit", e))?;
        Ok(())
    }

    fn update(
        &self,
        host: &str,
        update: &mut dyn FnMut(DomainState) -> DomainState,
    ) -> Result<DomainState, Error> {
        // A single write transaction makes the read-modify-write atomic.
        let write = self
            .db
            .begin_write()
            .map_err(|e| store_err("begin write", e))?;
        let next = {
            let mut table = write
                .open_table(TABLE)
                .map_err(|e| store_err("open table", e))?;
            let current = match table.get(host).map_err(|e| store_err("get", e))? {
                Some(guard) => {
                    serde_json::from_slice(guard.value()).map_err(|e| store_err("decode", e))?
                }
                None => DomainState::new(host),
            };
            let next = update(current);
            let bytes = serde_json::to_vec(&next).map_err(|e| store_err("encode", e))?;
            table
                .insert(next.host.as_str(), bytes.as_slice())
                .map_err(|e| store_err("insert", e))?;
            next
        };
        write.commit().map_err(|e| store_err("commit", e))?;
        Ok(next)
    }
}

fn store_err(op: &str, e: impl std::fmt::Display) -> Error {
    Error::StateStore(format!("redb {op}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Outcome;
    use std::time::Duration;

    fn temp_db_path() -> std::path::PathBuf {
        let unique = format!(
            "rs_cloudscraper_state_{}_{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn redb_persists_across_reopen() {
        let path = temp_db_path();

        let state = DomainState::new("example.com").record(
            Outcome::RateLimited,
            Some("http://p:1".into()),
            500,
            Duration::from_secs(60),
        );

        {
            let store = RedbStateStore::open(&path).unwrap();
            assert_eq!(store.get("example.com").unwrap(), None);
            store.put(&state).unwrap();
        }

        // Re-open the same file: state must survive.
        {
            let store = RedbStateStore::open(&path).unwrap();
            assert_eq!(store.get("example.com").unwrap(), Some(state));
            store.remove("example.com").unwrap();
            assert_eq!(store.get("example.com").unwrap(), None);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn redb_overwrites_and_isolates_hosts() {
        let path = temp_db_path();
        let store = RedbStateStore::open(&path).unwrap();

        let a1 = DomainState::new("a.com").record(Outcome::Blocked, None, 1, Duration::ZERO);
        store.put(&a1).unwrap();
        store
            .put(&DomainState::new("b.com").record(Outcome::Success, None, 2, Duration::ZERO))
            .unwrap();

        // Overwrite a.com with a newer record.
        let a2 = a1.record(Outcome::Success, Some("http://p".into()), 3, Duration::ZERO);
        store.put(&a2).unwrap();

        assert_eq!(store.get("a.com").unwrap().unwrap(), a2);
        assert_eq!(
            store.get("b.com").unwrap().unwrap().last_outcome,
            Some(Outcome::Success)
        );
        assert_eq!(store.get("missing.com").unwrap(), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn redb_update_is_atomic_create_then_modify() {
        let path = temp_db_path();
        let store = RedbStateStore::open(&path).unwrap();

        // First update on a missing host starts from a fresh state and persists.
        let s1 = store
            .update("a.com", &mut |cur| {
                cur.record(Outcome::RateLimited, None, 1, Duration::from_secs(60))
            })
            .unwrap();
        assert_eq!(s1.failures, 1);
        assert_eq!(store.get("a.com").unwrap().unwrap(), s1);

        // Second update sees the persisted value and a Success clears the cooldown.
        let s2 = store
            .update("a.com", &mut |cur| {
                cur.record(Outcome::Success, None, 2, Duration::ZERO)
            })
            .unwrap();
        assert_eq!(s2.failures, 1);
        assert_eq!(s2.successes, 1);
        assert_eq!(s2.cooldown_until, None);
        assert_eq!(store.get("a.com").unwrap().unwrap(), s2);

        let _ = std::fs::remove_file(&path);
    }
}
