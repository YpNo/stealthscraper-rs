//! Durable [`StateStore`] backed by a single JSON file.
//!
//! The adapter's contract is documented on [`JsonStateStore`] itself, since this
//! module is private and re-exported from [`super`].

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::Error;

use super::model::DomainState;
use super::store::StateStore;

/// A durable [`StateStore`] persisting domain state to a JSON file.
///
/// Needs no dependency beyond `serde_json`, which the crate already uses, so
/// durable per-domain state is available in the **default** build — where the
/// only other option is the ephemeral
/// [`InMemoryStateStore`](super::InMemoryStateStore).
///
/// # When to prefer `RedbStateStore`
///
/// This store is the right default for a single process with a bounded set of
/// hosts. The `persistence` feature's `RedbStateStore` remains the
/// recommendation when either assumption breaks:
///
/// - **More than one process may open the same file.** Neither store supports
///   concurrent writers, but they fail very differently: `redb` takes an
///   exclusive, non-blocking file lock and the second opener fails immediately
///   with `DatabaseAlreadyOpen`, whereas this store has no lock at all and is
///   silently last-writer-wins, losing the other process's records. When a
///   second process is possible, prefer being told about it.
/// - **A large host set.** Every mutation rewrites the whole file, so write
///   cost is `O(hosts)`; `redb` writes only the pages it touches.
///
/// # Durability
///
/// The in-memory map is authoritative while the store is alive; each mutation
/// serializes it to a temporary file in the same directory, flushes that file to
/// disk, and `rename`s it over the target. Because `rename` is atomic, a crash
/// at any point leaves either the previous complete file or the new one — never
/// a partial record. The directory entry itself is not flushed, so a power loss
/// immediately after a write may lose that *last* write; it cannot corrupt the
/// file.
///
/// # Format
///
/// A JSON array of [`DomainState`], pretty-printed and sorted by host so it can
/// be read, diffed and edited by hand. A missing file reads as an empty store
/// (it is created on first write). On load, a host appearing more than once
/// keeps its last occurrence.
///
/// # Examples
///
/// ```no_run
/// use stealthscraper_rs::{DomainState, JsonStateStore, Outcome, StateStore};
/// use std::time::Duration;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let store = JsonStateStore::open("domain-state.json")?;
/// store.update("example.com", &mut |state| {
///     state.record(Outcome::Success, None, 1_700_000_000, Duration::ZERO)
/// })?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JsonStateStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, DomainState>>,
}

impl JsonStateStore {
    /// Open the store at `path`, loading any existing records.
    ///
    /// A missing file is not an error: the store starts empty and the file is
    /// created on the first write. A file that exists but does not parse *is* an
    /// error, so corrupt state is reported rather than silently discarded.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let inner = Mutex::new(load(&path)?);
        Ok(Self { path, inner })
    }

    /// The file this store persists to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serialize `map` over the target file, atomically.
    fn flush(&self, map: &HashMap<String, DomainState>) -> Result<(), Error> {
        // Sort by host so the file has a stable order across writes: it keeps
        // hand-inspection and any external diffing meaningful.
        let mut records: Vec<&DomainState> = map.values().collect();
        records.sort_by(|a, b| a.host.cmp(&b.host));
        let bytes = serde_json::to_vec_pretty(&records).map_err(|e| store_err("encode", e))?;

        // The temporary file must share the target's directory so that `rename`
        // stays within one filesystem (and therefore stays atomic).
        let tmp = self.temp_path();
        let write_then_rename = || -> std::io::Result<()> {
            let mut file = fs::File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &self.path)
        };
        write_then_rename().map_err(|e| {
            // Never leave a stray temporary behind on failure.
            let _ = fs::remove_file(&tmp);
            store_err("write state file", e)
        })
    }

    /// A sibling temporary path, unique per process and call.
    fn temp_path(&self) -> PathBuf {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "state.json".to_string());
        let unique = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        match self.path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(unique),
            _ => PathBuf::from(unique),
        }
    }
}

impl StateStore for JsonStateStore {
    fn get(&self, host: &str) -> Result<Option<DomainState>, Error> {
        Ok(self.lock().get(host).cloned())
    }

    fn put(&self, state: &DomainState) -> Result<(), Error> {
        let mut guard = self.lock();
        guard.insert(state.host.clone(), state.clone());
        self.flush(&guard)
    }

    fn remove(&self, host: &str) -> Result<(), Error> {
        let mut guard = self.lock();
        if guard.remove(host).is_none() {
            // Nothing changed, so there is nothing to rewrite.
            return Ok(());
        }
        self.flush(&guard)
    }

    fn update(
        &self,
        host: &str,
        update: &mut dyn FnMut(DomainState) -> DomainState,
    ) -> Result<DomainState, Error> {
        // Holding the lock across the read, the closure, and the write makes the
        // read-modify-write atomic, as the port's contract asks.
        let mut guard = self.lock();
        let current = guard
            .get(host)
            .cloned()
            .unwrap_or_else(|| DomainState::new(host));
        let next = update(current);
        guard.insert(next.host.clone(), next.clone());
        self.flush(&guard)?;
        Ok(next)
    }
}

impl JsonStateStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, DomainState>> {
        self.inner.lock().expect("state store lock poisoned")
    }
}

/// Read `path` into a host-keyed map, treating a missing file as empty.
fn load(path: &Path) -> Result<HashMap<String, DomainState>, Error> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(store_err("read state file", e)),
    };
    // An empty file is equivalent to a missing one; it is what a truncated
    // create leaves behind and carries no records to lose.
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(HashMap::new());
    }
    let records: Vec<DomainState> =
        serde_json::from_slice(&bytes).map_err(|e| store_err("decode", e))?;
    Ok(records
        .into_iter()
        .map(|state| (state.host.clone(), state))
        .collect())
}

fn store_err(op: &str, e: impl std::fmt::Display) -> Error {
    Error::StateStore(format!("json state {op}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Outcome;
    use std::time::Duration;

    /// A unique path in the temp dir; the file is not created.
    fn temp_path() -> PathBuf {
        let unique = format!(
            "stealthscraper_rs_state_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    /// Paths left behind in the target directory by a store at `path`.
    fn siblings(path: &Path) -> Vec<String> {
        let dir = path.parent().unwrap();
        let stem = path.file_name().unwrap().to_string_lossy().into_owned();
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(&stem))
            .collect()
    }

    #[test]
    fn missing_file_opens_as_an_empty_store() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();

        assert_eq!(store.get("example.com").unwrap(), None);
        // Opening must not create the file; only a write does.
        assert!(!path.exists());
    }

    #[test]
    fn state_survives_a_reopen() {
        let path = temp_path();
        let state = DomainState::new("example.com").record(
            Outcome::RateLimited,
            Some("http://p:1".into()),
            500,
            Duration::from_secs(60),
        );

        {
            let store = JsonStateStore::open(&path).unwrap();
            store.put(&state).unwrap();
        }

        {
            let store = JsonStateStore::open(&path).unwrap();
            assert_eq!(store.get("example.com").unwrap(), Some(state));
            store.remove("example.com").unwrap();
            assert_eq!(store.get("example.com").unwrap(), None);
        }

        // The removal is durable too, not just in-memory.
        let store = JsonStateStore::open(&path).unwrap();
        assert_eq!(store.get("example.com").unwrap(), None);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn update_is_atomic_create_then_modify() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();

        // The first update on a missing host starts from a fresh state.
        let s1 = store
            .update("a.com", &mut |cur| {
                cur.record(Outcome::RateLimited, None, 1, Duration::from_secs(60))
            })
            .unwrap();
        assert_eq!(s1.failures, 1);
        assert_eq!(s1.host, "a.com");

        // The second sees the persisted value, and a Success clears the cooldown.
        let s2 = store
            .update("a.com", &mut |cur| {
                cur.record(Outcome::Success, None, 2, Duration::ZERO)
            })
            .unwrap();
        assert_eq!((s2.failures, s2.successes), (1, 1));
        assert_eq!(s2.cooldown_until, None);

        // ...and it reached the file, not just the map.
        let reopened = JsonStateStore::open(&path).unwrap();
        assert_eq!(reopened.get("a.com").unwrap().unwrap(), s2);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn hosts_are_isolated_and_overwritten_in_place() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();

        let a1 = DomainState::new("a.com").record(Outcome::Blocked, None, 1, Duration::ZERO);
        store.put(&a1).unwrap();
        store
            .put(&DomainState::new("b.com").record(Outcome::Success, None, 2, Duration::ZERO))
            .unwrap();

        let a2 = a1.record(Outcome::Success, Some("http://p".into()), 3, Duration::ZERO);
        store.put(&a2).unwrap();

        let reopened = JsonStateStore::open(&path).unwrap();
        assert_eq!(reopened.get("a.com").unwrap().unwrap(), a2);
        assert_eq!(
            reopened.get("b.com").unwrap().unwrap().last_outcome,
            Some(Outcome::Success)
        );
        assert_eq!(reopened.get("missing.com").unwrap(), None);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn writes_leave_no_temporary_files_behind() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();

        for i in 0..3 {
            store
                .put(&DomainState::new(format!("h{i}.com")).record(
                    Outcome::Success,
                    None,
                    i,
                    Duration::ZERO,
                ))
                .unwrap();
        }
        store.remove("h1.com").unwrap();

        // Exactly the target file, no `.tmp` siblings.
        let found = siblings(&path);
        assert_eq!(
            found,
            vec![path.file_name().unwrap().to_string_lossy().into_owned()],
            "stray temporaries left in the state directory"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_a_missing_host_does_not_create_the_file() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();

        store.remove("absent.com").unwrap();

        // No record changed, so no write happened.
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_file_is_reported_not_discarded() {
        let path = temp_path();
        fs::write(&path, b"{ this is not the state file }").unwrap();

        let err = JsonStateStore::open(&path).unwrap_err();
        assert!(
            matches!(&err, Error::StateStore(msg) if msg.contains("decode")),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_empty_file_reads_as_an_empty_store() {
        // A zero-length file is what an interrupted create leaves; it holds no
        // records, so it must not be treated as corruption.
        let path = temp_path();
        fs::write(&path, b"").unwrap();

        let store = JsonStateStore::open(&path).unwrap();
        assert_eq!(store.get("anything").unwrap(), None);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_file_is_a_readable_json_array() {
        let path = temp_path();
        let store = JsonStateStore::open(&path).unwrap();
        store
            .put(&DomainState::new("b.com").record(Outcome::Success, None, 2, Duration::ZERO))
            .unwrap();
        store
            .put(&DomainState::new("a.com").record(Outcome::Blocked, None, 1, Duration::ZERO))
            .unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let array = parsed.as_array().expect("top level is an array");
        assert_eq!(array.len(), 2);
        // Sorted by host, so the file's order is stable across writes.
        assert_eq!(array[0]["host"], "a.com");
        assert_eq!(array[1]["host"], "b.com");
        // Pretty-printed, for hand inspection.
        assert!(text.contains('\n'));

        let _ = fs::remove_file(&path);
    }
}
