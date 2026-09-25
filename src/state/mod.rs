//! Per-domain session state: model, the [`StateStore`] port, and adapters.
//!
//! The model ([`DomainState`], [`Outcome`]) and both dependency-free adapters
//! are always available: [`InMemoryStateStore`] (ephemeral) and
//! [`JsonStateStore`] (durable, one JSON file). The `redb` adapter
//! (`RedbStateStore`) is gated behind the `persistence` feature.
//!
//! Prefer `RedbStateStore` when a second process might open the same file (it
//! takes an exclusive lock and refuses, where the JSON store silently overwrites)
//! or when the host set is large enough that rewriting the whole file per
//! mutation matters; [`JsonStateStore`] covers the single-process case with no
//! dependency at all.

mod json_store;
mod model;
mod store;

#[cfg(feature = "persistence")]
mod redb_store;

pub use json_store::JsonStateStore;
pub use model::{DomainState, Outcome};
pub use store::{InMemoryStateStore, StateStore};

#[cfg(feature = "persistence")]
pub use redb_store::RedbStateStore;
