//! Namespace fence: a durable, operation-owned control record that an external operation (for
//! example, moving a database between servers) uses as the data-plane authority boundary for
//! one namespace.
//!
//! `docs/NAMESPACE_FENCE.md` is the contract and the design. This module holds the states and
//! permission matrix ([`state`]), the stable outcome codes and their protocol mappings
//! ([`outcome`]), commands and their canonical fingerprint ([`command`]), records, receipts and
//! markers with their strict durable encoding ([`record`]), the pure transition function
//! ([`transition`]), the metastore tables, compare-and-swap and marker file that persist them
//! ([`store`], driven by `MetaStore::apply_fence_command`), and the in-memory authority built
//! on them: the per-namespace [`controller`] with its gate and read leases, the positive write
//! [`drain`], the source [`read`] fence and its
//! [`stream`] leases for dump and replication, the [`registry`] that holds the controllers outside the
//! namespace cache, and the test [`hooks`] on their paths.

// The persistence, controller and protocol layers that consume these types land in the
// following commits of this series; until then most of the module is unused by the rest of
// the crate. This attribute is removed once they are wired.
#![allow(dead_code)]

pub mod command;
pub mod controller;
pub mod drain;
pub mod hooks;
pub mod outcome;
pub mod read;
pub mod record;
pub mod registry;
pub mod state;
pub mod store;
pub mod stream;
pub mod transition;

#[cfg(test)]
mod tests;

#[allow(clippy::all)]
pub(crate) mod proto {
    include!("../../generated/namespace_fence.rs");
}

/// Version of the fence admin protocol reported by capability discovery.
pub const FENCE_PROTOCOL_VERSION: u32 = 1;
