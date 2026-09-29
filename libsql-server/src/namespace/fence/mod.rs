//! Namespace fence: a durable, operation-owned control record that an external operation (for
//! example, moving a database between servers) uses as the data-plane authority boundary for
//! one namespace.
//!
//! `docs/NAMESPACE_FENCE.md` is the contract and the design. This module holds the parts with
//! no I/O: the states and permission matrix ([`state`]), the stable outcome codes and their
//! protocol mappings ([`outcome`]), commands and their canonical fingerprint ([`command`]),
//! records, receipts and markers with their strict durable encoding ([`record`]), the pure
//! transition function ([`transition`]), and the metastore tables, compare-and-swap and marker
//! file that persist them ([`store`], driven by `MetaStore::apply_fence_command`).

// The persistence, controller and protocol layers that consume these types land in the
// following commits of this series; until then most of the module is unused by the rest of
// the crate. This attribute is removed once they are wired.
#![allow(dead_code)]

pub mod command;
pub mod outcome;
pub mod record;
pub mod state;
pub mod store;
pub mod transition;

#[allow(clippy::all)]
pub(crate) mod proto {
    include!("../../generated/namespace_fence.rs");
}

/// Version of the fence admin protocol reported by capability discovery.
pub const FENCE_PROTOCOL_VERSION: u32 = 1;
