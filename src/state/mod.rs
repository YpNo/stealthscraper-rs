//! Per-domain session state: model, the [`StateStore`] port, and adapters.
//!
//! The model ([`DomainState`], [`Outcome`]) and the in-memory adapter are
//! always available. The durable `redb` adapter (`RedbStateStore`) is gated
//! behind the `persistence` feature so the default build pulls no extra
//! dependencies.

mod model;
mod store;

#[cfg(feature = "persistence")]
mod redb_store;

pub use model::{DomainState, Outcome};
pub use store::{InMemoryStateStore, StateStore};

#[cfg(feature = "persistence")]
pub use redb_store::RedbStateStore;
