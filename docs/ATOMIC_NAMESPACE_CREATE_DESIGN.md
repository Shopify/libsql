# Atomic namespace creation for `libsql-server`

Stacked on `tszymczyszyn/streaming-dump-importer` (PR #51). Fixes the pre-existing lifecycle gap described in PR #51's design doc §13 and the review walkthrough: a failed, cancelled or crashed `POST /v1/namespaces/:ns/create` could leave a *ghost* namespace (metastore row without data), a directory without a row, or both. Sections marked *as built* note where the implementation differs from the sketches; §9 records what the adversarial review of PR #53 changed.

---

## 1. Problem


`NamespaceStore::create` persists the namespace config **first** and only then runs the configurator's `setup` (directory, logger, connections, dump import). Three resources are mutated without a common commit point:

| Resource | Written at | Cleaned on error | Cleaned on cancellation | Cleaned after crash |
|---|---|---|---|---|
| metastore row (`namespace_configs`) | start of `create` | **no** | **no** | n/a (persisted) |
| `dbs/<ns>/` + `.sentinel` + SQLite/WAL/log files | during `setup` | primary only, if the dir was fresh | **no** (future dropped, `Err` branch never runs) | **no** |
| cache entry (`NamespaceEntry`) | end of `load_namespace` | n/a | n/a | n/a |

Consequences: a failed create reserves the name forever (`NamespaceAlreadyExist` on retry) while user traffic lazily materialises an **empty** database; a cancelled create can leave any prefix of the resources; a client cannot tell from a non-200 whether the namespace now exists. `SchemaConfigurator::setup` has no cleanup at all. `fork` has a drop guard for the row but uses `block_in_place`, which panics on a current-thread runtime.

Both dump importers run inside this sequence; the problem is independent of PR #51.

## 2. Goals

- **Contract:** after `create` returns a non-2xx, or the connection is lost, the namespace is either *absent* (no row, no data, name reusable) or *complete* (row persisted, data complete, serving). Never partial.
- Cancellation-safe (dropping the request future cleans up) and crash-tolerant (a process crash mid-import never blocks a retry).
- No lock-step changes to clients, replication, the metastore schema or the `DatabaseConfig` protobuf.
- Small: reuse the pattern `fork` already uses; one mechanism for `create` and `fork`.

Non-goals: a server-side import timeout; idempotency keys / async create jobs; bottomless (not used in our deployment; untested with this change). The moka eviction hazard shared with `reset`/`fork` turned out to need fixing (§8).

## 3. Design in one paragraph


Make the **metastore write the commit point** and make everything before it reversible. `create` reserves the name by write-locking its cache entry, puts the config in the metastore's *in-memory* map only (so `setup` can read it), runs `setup`, and only on success **flushes the row** and installs the namespace. A `Reservation` drop guard undoes the in-memory config if the future ends any other way — error *or* cancellation — and releases the lock only after that, so waiters never observe a half-built namespace. The filesystem gets the same treatment one layer down: `setup` wraps a brand-new directory in a `FreshDir` guard that removes it on drop. For crashes, a brand-new directory carries an `.incomplete` marker until the row is flushed; the next `create` of that name discards a marked directory.

```
create(name, restore, config)
│
├─ Reservation::acquire(name)            lock cache entry; reject if loaded or row exists
├─ handle = metadata.handle(name)        ─┐ in-memory only; nothing on disk
├─ handle.store_and_maybe_flush(cfg, false) ┘
├─ configurator.discard_incomplete(name) remove `dbs/<name>` if it carries `.incomplete`
├─ ns = make_namespace(...)              setup: FreshDir::begin → mkdir + marker … import … keep()
├─ handle.flush()                        ◄── COMMIT POINT: row persisted
├─ ns.mark_complete()                    remove `.incomplete` (best effort)
└─ reservation.publish(ns)               entry := Some(ns); lock released
      any Err / drop above ⇒ Reservation::drop ⇒ metadata.remove(name), then release lock
      any Err / drop inside setup       ⇒ FreshDir::drop     ⇒ remove_dir_all(dbs/<name>)
```

## 4. Components

### 4.1 `Reservation` (store.rs) — replaces `fork`'s ad-hoc `Bomb`

```rust
/// A namespace name reserved for a creation or fork in progress.
///
/// Holding it holds the name's cache entry write-locked: user requests, a second create,
/// destroy and shutdown all wait until the outcome is known. `publish` installs the finished
/// namespace. Dropping it unpublished (error or cancelled request) removes the in-memory
/// config and only then releases the lock, so waiters see "doesn't exist", never a partial one.
struct Reservation {
    guard: Option<RwLockWriteGuardArc<Option<Namespace>>>,
    metadata: MetaStore,
    name: NamespaceName,
}

impl Reservation {
    async fn acquire(store: &NamespaceStore, name: NamespaceName) -> crate::Result<Self> {
        let entry = store.inner.store.get_with(name.clone(), async { Default::default() }).await;
        let guard = entry.write_arc().await;
        if guard.is_some() || store.inner.metadata.exists(&name).await {
            return Err(Error::NamespaceAlreadyExist(name.to_string()));
        }
        Ok(Self { guard: Some(guard), metadata: store.inner.metadata.clone(), name })
    }

    fn publish(mut self, ns: Namespace) {
        self.guard.take().expect("published once").replace(ns);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(guard) = self.guard.take() else { return };
        let (metadata, name) = (self.metadata.clone(), self.name.clone());
        tracing::warn!(namespace = %name, "namespace creation did not complete; discarding it");
        let cleanup = move || {
            if let Err(e) = metadata.remove(name.clone()) {
                tracing::error!(namespace = %name, "failed to discard namespace config: {e}");
            }
            drop(guard); // release only once the name no longer exists
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => { rt.spawn_blocking(cleanup); }
            Err(_) => cleanup(),
        }
    }
}
```

Why `write_arc`: the guard must outlive the `create` future (it moves into the cleanup task). Requires `async-lock = "3"` in `libsql-server/Cargo.toml` (3.4.0 is already in the lockfile transitively; `proxy.rs`'s `RwLockUpgradableReadGuard::upgrade` is unchanged in 3.x).

`MetaStore::remove` takes blocking locks, hence `spawn_blocking` (no `block_in_place`, so it also works on turmoil's current-thread runtime). It deletes the row if one exists and the in-memory entry; both are what we want in every abort path, including "flush succeeded but publish didn't" (then the row is deleted again and the complete directory becomes a marked orphan, see §6).

### 4.2 `create` (store.rs)

```rust
pub async fn create(&self, namespace, restore_option, db_config) -> crate::Result<()> {
    shutdown check — unchanged
    shared_schema_name ⇒ fork(…) — unchanged (fork now uses Reservation, §4.6)

    // Single-namespace mode / default namespace: `create` is an idempotent config upsert of a
    // namespace that always exists. Keep today's path for it, but only for `Latest`: creating
    // *from a dump* must never silently skip the import because the namespace is already loaded
    // (today it does), so dump creates always take the reserving path below.
    if (self.inner.allow_lazy_creation || namespace == NamespaceName::default())
        && matches!(restore_option, RestoreOption::Latest)
    {
        let handle = self.inner.metadata.handle(namespace.clone()).await;
        handle.store(Arc::new(db_config)).await?;
        self.load_namespace(&namespace, handle, restore_option).await?;
        return Ok(());
    }

    let reservation = Reservation::acquire(self, namespace.clone()).await?;
    let handle = self.inner.metadata.handle(namespace.clone()).await;
    handle.store_and_maybe_flush(Some(Arc::new(db_config)), false).await?;
    self.get_configurator(&handle.get()).discard_incomplete(&namespace).await?;
    let ns = self.make_namespace(&namespace, handle.clone(), restore_option).await?;
    handle.flush().await?;                       // commit point
    if let Err(e) = ns.mark_complete().await {   // cosmetic from here on
        tracing::warn!(namespace = %namespace, "could not remove creation marker: {e}");
    }
    reservation.publish(ns);
    Ok(())
}
```

Ordering that matters: `acquire` before `handle()` (`handle()` inserts into the in-memory map, which is what `exists()` reads — so the name becomes visible only while it is already locked); `flush` before `publish` (durable before visible); `publish` consumes the reservation (no double cleanup).

### 4.3 `FreshDir` (configurator/helpers.rs) — cancellation-safe directory

> *As built (review):* `begin` is synchronous (guard constructed before anything is created, no await between `mkdir` and the marker), and `Drop` does not delete in place: it calls `incomplete::discard_dir`, which atomically **renames the directory into `<base>/.discarded/<name>-<uuid>`** and deletes the tombstone in the background. The path under `dbs/` is therefore free the instant the guard drops, a retry can never race a half-finished `remove_dir_all`, and files a still-running import executor recreates land in the tombstone. The sketch below shows the original idea.

```rust
/// Directory of a namespace that does not exist yet. Removed again if dropped before `keep`:
/// on error, or when the request creating the namespace is cancelled.
pub(super) struct FreshDir { path: Option<Arc<Path>> }

impl FreshDir {
    /// `None` if a namespace already lives at `db_path`.
    pub(super) async fn begin(db_path: &Arc<Path>) -> crate::Result<Option<Self>> {
        if db_path.try_exists()? { return Ok(None); }
        tokio::fs::create_dir_all(db_path).await?;
        tokio::fs::File::create(db_path.join(INCOMPLETE_MARKER)).await?;
        Ok(Some(Self { path: Some(db_path.clone()) }))
    }
    pub(super) fn keep(mut self) { self.path.take(); }
}

impl Drop for FreshDir {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else { return };
        let rm = async move {
            match tokio::fs::remove_dir_all(&*path).await {
                Ok(()) | Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => tracing::error!(path = %path.display(), "failed to remove unfinished namespace directory: {e}"),
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => { rt.spawn(rm); }
            Err(_) => { let _ = std::fs::remove_dir_all(&*path); }
        }
    }
}
```

Used by `PrimaryConfigurator::setup` and `SchemaConfigurator::setup` (which gains cleanup it never had):

```rust
let db_path: Arc<Path> = self.base.base_path.join("dbs").join(name.as_str()).into();
let fresh = FreshDir::begin(&db_path).await?;
let ns = self.try_new_primary(…).await?;   // on Err or drop, `fresh` removes the directory
if let Some(fresh) = fresh { fresh.keep(); }
Ok(ns)
```

`try_new_primary`'s own `create_dir_all` becomes redundant for the fresh case and stays harmless for existing directories. The `remove_dir_all`-on-error branch in `setup` is replaced by the guard (drop order: the `try_new_primary` future and its `JoinSet` are dropped before `fresh`, so background tasks are aborted before the directory goes).

### 4.4 `.incomplete` marker — crash tolerance

> *As built (review):* the protocol lives in `namespace/incomplete.rs` (`INCOMPLETE_MARKER`, `create_marked_dir`, `discard_dir`, `discard_if_incomplete`, `sweep`). `sweep` runs at startup (`lib.rs`, after the store is built): it deletes leftover tombstones and discards marked directories of names the metastore does not know. `fork` writes the marker into its temporary directory before renaming it into place, so an unfinished fork is discarded like any other unfinished creation. The order at the end of a creation is **flush → publish → remove marker** (not flush → mark → publish): a marker that outlives publication is harmless, a complete directory without one is not.

- `pub(crate) const INCOMPLETE_MARKER: &str = ".incomplete";` in `namespace/mod.rs`.
- Created by `FreshDir::begin` for every brand-new directory.
- Removed by `Namespace::mark_complete(&self)` (`remove_file(self.path.join(MARKER))`, `NotFound` ok), called (a) by `create` after `flush`, (b) by `load_namespace`'s init after `make_namespace` — a namespace opened from the metastore is complete by definition, so lazily loaded namespaces (and single-namespace-mode auto-creation) never keep a marker.
- Acted upon only for a name the metastore does **not** know: by `ConfigureNamespace::discard_incomplete(name)` (new trait method, default no-op; primary and schema delegate to `incomplete::discard_if_incomplete`), which `create` calls after `acquire` — i.e. with no row and nothing loaded — and by the startup `sweep` under the same condition. That is the only situation in which a marked directory is unambiguously garbage. Lazy loads never act on it, so a stale marker on a published namespace (crash between `flush` and unmark) is removed, never acted upon. The metastore's filesystem recovery (`maybe_recover_from_fs`, empty metastore only) skips marked directories rather than adopting them.
- `MetaStoreInner::maybe_recover_from_fs` (metastore empty ⇒ adopt `dbs/*`) skips directories carrying the marker, so a crash during the very first creation on a fresh server does not get adopted as a namespace at the next start.

A directory **without** a marker and without a row keeps today's semantics (`Dump` ⇒ `LoadDumpExistingDb`; `Latest` ⇒ adopted). Such directories can only come from pre-marker servers or manual intervention; being destructive there is not worth it.

### 4.5 `Namespace::mark_complete` (namespace/mod.rs)

```rust
pub(crate) async fn mark_complete(&self) -> std::io::Result<()> {
    match tokio::fs::remove_file(self.path.join(INCOMPLETE_MARKER)).await {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
```

### 4.6 `fork` (store.rs)

Replace the `Bomb` + manual `to_lock` with `Reservation::acquire(to)`; order becomes `configurator.fork(…)` → `handle.flush()` → `reservation.publish(ns)` (today it publishes *then* flushes, so a flush failure leaves a running namespace without a row). Net code removal; same semantics otherwise. `ForkTask`'s temp-dir + rename stays, plus the marker (§4.4). *As built:* the source namespace is looked up with the side-effect-free `MetaStore::existing_handle` (§9).

## 5. Flow for a dump import (streaming or buffered)

1. Admin handler resolves `dump_url` (errors here touch nothing).
2. `create` → `Reservation::acquire` (`NamespaceAlreadyExist`, HTTP 400, if the name is loaded or has a row).
3. In-memory config; `discard_incomplete` (removes a crashed previous attempt, if any).
4. `setup`: `FreshDir::begin` (mkdir + marker) → logger, WAL, connection maker → `load_dump` → `keep()`.
5. `flush` — the namespace now exists durably.
6. `mark_complete`, `publish` — the namespace is now visible; waiters proceed.

## 6. Failure matrix

| Interrupted at | Error (returned) | Cancellation (future dropped) | Crash (process dies) |
|---|---|---|---|
| 1 | nothing to undo | nothing to undo | nothing |
| 2–3 (before `setup`) | `Reservation` removes in-memory config | same | nothing persisted; nothing on disk |
| 4, inside `setup` (incl. import) | `FreshDir` removes dir; `Reservation` removes config; executor rolls back SQLite | same (importer executor is uncancelled: closes channel → ROLLBACK → connection released; dir removal races with it benignly on POSIX, see §9) | marked orphan dir, no row ⇒ invisible; next `create` discards it |
| between `setup` and `flush` | config removed; **complete dir, marked** ⇒ next `create` discards and redoes | same | same |
| `flush` fails | row never written (single SQLite statement); as above | — | — |
| between `flush` and `publish` | `Reservation` deletes the row again; marked complete dir ⇒ discarded with it | same | row + marker + complete data ⇒ namespace **exists and serves**; marker removed on first lazy load |
| between `publish` and marker removal | — (published; a stale marker is harmless) | same | row + marker + complete data ⇒ serves; marker removed on first lazy load |
| after `publish` | — | response may be lost ⇒ client retries ⇒ `NamespaceAlreadyExist` ⇒ by the contract, complete | same |

Client rule: **2xx ⇒ complete; anything else ⇒ retry; `NamespaceAlreadyExist` on retry ⇒ complete.** No inspection of tables needed. (For namespaces *created* through this path. The single-namespace-mode config upsert of the default namespace, and ghost rows left by older binaries, are outside it.)

## 7. Concurrency

- **Second `create` of the same name:** waits on the write lock; then `AlreadyExist` (first succeeded) or proceeds (first failed). Previously: `AlreadyExist` even after the first failed.
- **User request during creation (`with`)**: `exists()` is true (in-memory config), `try_get_with` finds the locked entry, `read()` waits; then sees the namespace or `None ⇒ NamespaceDoesntExist`. Same waiting behaviour as during `fork`/`reset` today.
- **`destroy` during creation:** `metadata.remove` succeeds (in-memory only), then waits on the pinned entry's lock; when creation finishes, `install` notices the config is gone and hands the namespace to that entry, `destroy` takes and destroys it. Net: created then destroyed, in that order (`destroy_during_creation_destroys_the_result`).
- **Store shutdown during creation:** `shutdown` waits on the entry lock, then shuts the finished namespace down normally.
- **`handle()` side effect:** `MetaStore::handle` inserts a default config into the in-memory map (pre-existing). Keeping `acquire` strictly before `handle()` is what makes the reservation airtight; documented in code.

## 8. Cache eviction during an operation (*as built*: fixed, not merely inherited)

The reservation is the cache entry's lock, but moka knows nothing about that lock. If the cache evicts the entry during a long operation (capacity pressure: `--max-active-namespaces`, default 100, is reached and more namespaces get loaded; the 24 h idle expiry is irrelevant), three things used to go wrong — for `fork` and `reset` since before this change, and for `create` once it adopted the same reservation (previously `create` ran inside moka's `try_get_with`, which deduplicates in-flight inits and is immune):

1. **Split-brain.** The cache slot is empty, so a concurrent lookup (`exists()` is true: the config is in memory) runs a lazy load and opens the directory the operation is writing to — a second live instance on the same files.
2. **Stalled maintenance.** moka 0.12 has no background thread: maintenance runs inline inside whatever cache operation trips it, and it *awaits* async eviction listeners. The listener did `entry.write().await`, i.e. it waited for the operation to finish. The unrelated request that happened to run maintenance hung for the duration; once the write-op channel filled, every namespace load on the node blocked.
3. **Self-deadlock.** If the operation holding the lock touched the cache itself (`fork` does: `load_namespace(from)`), maintenance could pick up the eviction of its own entry and wait on its own lock. The first version of the unit test below reproduced exactly this.

Fix, in three parts:

- **Pin.** `NamespaceStoreInner::in_flight: Mutex<HashMap<NamespaceName, NamespaceEntry>>`. `Reservation::acquire` (create, fork) and `reset` pin the locked entry; `load_namespace` consults the map *before* `try_get_with` and waits on the pinned entry instead of loading. If the entry ends up empty — the operation failed, or published elsewhere — the lookup falls through: `NamespaceDoesntExist` if the metastore no longer knows the name, otherwise the regular cache path. Unpin happens after the config removal (abort) or after the namespace is visible (publish), so no lookup can slip into a lazy load in between. `destroy` consults the map too.
- **Non-blocking eviction listener.** The listener spawns the shutdown on its own task and returns immediately, so maintenance never waits for an operation in progress.
- **Publish into a fresh entry when evicted.** `NamespaceStore::install` checks (by `Arc::ptr_eq`) that the locked entry is still the cache's entry for the name; if not, the namespace goes into a fresh entry and the orphaned one stays empty, so the spawned listener finds nothing to shut down and waiters fall through to the cache. Used by `create`, `fork` and `reset`.

Unit tests (`namespace::store::test`) build a real `NamespaceStore`, start a streaming import fed from a channel, `invalidate` the reserved entry (same code path as eviction, including the listener) and check that a concurrent lookup waits and then sees the imported data (or `NamespaceDoesntExist` if the import fails), that the namespace ends up in the cache, and that nothing stays pinned. Without the pin the lookup returns early with an empty database; without the non-blocking listener the test deadlocks.

## 9. Adversarial review of PR #53 — what changed (*as built*)

Reviewers (correctness, architecture, testing, operations) plus a manual pass found the following; all fixed in the fourth commit.

| Sev | Finding | Resolution |
|---|---|---|
| HIGH | Directory removal was spawned and unordered against releasing the name: a retry "right away" (the documented contract) could race `remove_dir_all`; tests hid it with `wait_until_gone`. | `discard_dir`: atomic rename into `.discarded/` (sync, in `Drop`), background delete, startup `sweep`. Error paths now `await` the reservation's cleanup (`Reservation::abort`); `Drop` is for cancellation only. `retry_right_after_failure_starts_clean` asserts the path and the name are free the moment the error is returned. |
| HIGH | `MetaStore::remove` returns early (`HasLinkedDbs`, `PendingMigrationOnSchema`) **before** dropping the in-memory config; reachable for a linked-DB create whose flush fails ⇒ ghost. | `MetaStore::discard_blocking`: unconditional, goes through the metastore's own change queue (so it is also ordered after a config store that was still queued when the request was cancelled). `discard_ignores_the_guards_of_remove`. |
| HIGH | `install`'s `Arc::ptr_eq` fallback could not tell eviction from `destroy`: destroy-during-create re-inserted a live namespace whose directory destroy had just removed; name wedged. | Fallback re-checks `exists()`: config gone ⇒ hand the namespace to the old entry (destroy is waiting on it); `destroy` prefers the pinned entry. `destroy_during_creation_destroys_the_result`. |
| HIGH | Cancellation between `flush` and `publish` after `mark_complete` ⇒ row deleted, complete dir **unmarked** ⇒ `LoadDumpExistingDb` forever. | Order is flush → publish → remove marker. |
| HIGH | Fork's destination (renamed temp dir) carried no marker ⇒ a cancelled fork left an unmarked orphan and `ENOTEMPTY` on retry. | Marker written into the temp dir. |
| HIGH (found while testing) | A rejected `acquire` (`AlreadyExist` for an existing but unloaded namespace, e.g. a retry after restart) left the empty entry its `get_with` inserted ⇒ every lookup found the empty entry instead of loading ⇒ namespace unreachable until eviction. `checkpoint` has had the same latent bug. | `acquire` invalidates the empty entry it created; `load_namespace` treats an empty, unlocked entry as a miss and reloads (self-heals `checkpoint`/failed-`reset` leftovers too). `marker_on_published_namespace_is_ignored` creates before any lookup after a restart. |
| MED | ABBA: `remove` takes `conn` then `configs`; `process`'s flush branch held `configs` across `try_process` (`conn`). Now on every create. | `configs` released before `try_process`. |
| MED | Spawning the eviction listener unconditionally dropped moka's per-key serialisation for *normal* evictions (reload could overlap the old instance's shutdown). | Listener awaits inline unless the entry is pinned (`in_flight` shared with the closure). |
| MED | `shutdown` waited on an in-flight create's lock; `create` never re-checked `has_shutdown`. | Pinned entries skipped at shutdown (warn); `has_shutdown` re-checked before the commit point. |
| MED | `with()` called `MetaStore::handle`, which *inserts* into the map `exists()` reads: a lookup racing the end of a failed creation resurrected the name. | `MetaStore::existing_handle` (non-inserting) for namespaces that must exist; lazy init re-checks `exists()`. |
| MED | `FreshDir::begin` had two awaits before the guard existed. | Synchronous; guard first. |
| MED | Cancel tests could fire before the creation started (turmoil latency) and so pass vacuously; the restart test never reached the `\|\| exists` guard. | Cancel once `dbs/foo/.incomplete` exists; create before any lookup after restart; "usable afterwards" assertion restored. |
| LOW | Marked orphans were only reclaimed by a `create` of the same name; `maybe_recover_from_fs` skip untested; success not logged. | Startup `sweep`; `recovery_from_fs_skips_marked_directories`, `sweep_cleans_leftovers_of_a_crash`; `info!("namespace created")` with elapsed, `warn!` with the error on failure, distinct message on cancellation. |

LOW items closed in the follow-up commit: `publish` keeps the guard inside the reservation across `install`'s awaits, so a cancellation there undoes the creation instead of leaking the pin; `remove_incomplete_marker` stats before taking the blocking-pool hop (every cold load passes through it); a failure to remove the marker after publish is logged at `error`; `FreshDir`'s log is `info` (every failed create, including client errors, passes through it); `acquire` logs when it has to wait; store-level `aborted_creation_is_undone` test (`JoinHandle::abort` mid-import); the restart test drops the first server before starting the second; the unmarked-directory test asserts the outcome.

Also closed: the marker and its directory entry are fsynced on creation (`mark_incomplete`), so the marker is durable before anything else in the directory can be; `checkpoint` no longer mints an empty cache entry for an unloaded namespace (the pre-existing source of the same wedge); `ForkTask::fork` only removes a failed fork's destination if it carries the marker.

Not changed: after an *abort* the (empty) cache entry stays until a lookup heals it or the cache evicts it — it counts toward capacity but is never served; a metastore rebuilt from the filesystem (`destroy_on_error` + `allow_recover_from_fs`) in the milliseconds between a namespace's flush and its unmark would skip that namespace. Bottomless is not used in our deployment and this change is untested with it.

**Upgrade / downgrade.** Ghost rows and unmarked orphan directories left by failed creates on *older* binaries are untouched (everything here is marker-gated); for them the old remedy stays: `DELETE /v1/namespaces/:ns`, then create again. Downgrading the binary is safe: the metastore schema and the config protobuf are unchanged; an old binary ignores `.incomplete` and `.discarded/` (it may adopt a marked orphan via `maybe_recover_from_fs` on an empty metastore, as it always could with any leftover directory).

## 10. Interaction with the streaming importer

On cancellation the reader future is dropped, the executor thread sees the closed channel, rolls back and drops its connection — concurrently with the directory being discarded. The directory is renamed, not deleted in place, so whatever the executor still writes lands in the tombstone; on POSIX, renaming a directory with open files in it is harmless. The tombstone is deleted in the background, or by `sweep` at the next start.

## 11. Observability

- `warn!` on every abort path (`Reservation`: "namespace creation did not complete; discarding it"; `FreshDir`: "… removing its directory"; `discard_incomplete`: "discarding namespace directory left by an interrupted creation"), with the namespace / path.
- Counters `libsql_server_namespace_create_aborted` and `libsql_server_namespace_create_discarded_incomplete` (*as built:* no `stage` label — the logs carry the detail).
- The contract of §6 is stated in `docs/ADMIN_API.md` under namespace creation.

## 12. Tests (turmoil, `tests/namespaces/lifecycle.rs` and `dumps.rs`)

*As built.* 9 of the 11 integration tests fail on the unfixed code; the other two pin behaviour that must hold both before and after.

1. `failed_create_leaves_no_trace{,_streaming,_shared_schema}`: invalid dump ⇒ 400; `GET /v1/namespaces/foo/config` ⇒ 404 (was 200); hrana ⇒ "doesn't exist" (was "no such table"); `dbs/foo` gone; `create` again with a valid dump ⇒ 200, data present, no marker.
2. `cancelled_create_leaves_no_trace{,_streaming}` (replaces `streaming_cancelled_request_rolls_back`, which tolerated "OK or BAD_REQUEST" on retry): request abandoned mid-transfer ⇒ config 404, hrana "doesn't exist", directory gone, retry from the same dump ⇒ 200 with all rows.
3. `concurrent_requests_wait_for_creation`: a second `create` and a user query issued during a ~2 s import wait; afterwards the second gets `already exists` and the query sees all rows. `concurrent_create_succeeds_after_failure`: the import fails ⇒ the waiting query gets "doesn't exist" and a new `create` succeeds.
4. `crash_remnant_is_discarded`: `dbs/foo/{.incomplete,.sentinel,data,wallog}` exists before the server starts ⇒ not adopted by the metastore (config 404), `create foo` from a dump ⇒ 200. `unmarked_directory_is_left_alone`: a marker-less `dbs/foo/keep.txt` survives a `create`. `marker_on_published_namespace_is_ignored`: marker added to a published namespace ⇒ `create` ⇒ `already exists`, data served; after a restart the marker is gone.
5. `single_namespace_mode_rejects_dump_into_existing_namespace`: config upsert of `default` still works; `create default` from a dump ⇒ `already exists` (was: 200, dump silently skipped).
6. Unit (`configurator::helpers::test`): `FreshDir` removed on drop and when its enclosing future is dropped, kept on `keep()`; `discard_incomplete` removes only marked directories.
7. `fork_namespace`, `shared_schema::*` and all dump tests unchanged.
8. `namespace::store::test::lookup_{waits_for_creation,sees_failure_of_creation}_even_if_the_entry_was_evicted` (§8), `destroy_during_creation_destroys_the_result`, `retry_right_after_failure_starts_clean`, `discard_ignores_the_guards_of_remove`; `namespace::incomplete::test::*` (§9).

Slow-transfer tests use `make_slow_dump_store` (64-byte chunks, 100 ms apart): with turmoil's random 0–100 ms message latency, concurrent requests are issued 500 ms in and the import lasts ~2 s.

## 13. Scope

| File | Change |
|---|---|
| `libsql-server/Cargo.toml` | `async-lock = "3"` |
| `namespace/store.rs` | `Reservation` (+ `abort`); `create`/`fork` reserving paths; `load_namespace` (pinned entries, empty-entry healing, `mark_complete`); `in_flight` pin map, pin-aware eviction listener, `install`, `shutdown` (§8, §9) |
| `namespace/incomplete.rs` | marker, `discard_dir` (tombstones), `discard_if_incomplete`, `sweep` |
| `namespace/meta_store.rs` | `ChangeMsg` enum with `Discard`, `discard_blocking`, `existing_handle`, lock-order fix |
| `lib.rs` | startup `sweep` |
| `namespace/mod.rs` | `remove_incomplete_marker`, `Namespace::mark_complete` |
| `namespace/configurator/mod.rs` | `ConfigureNamespace::discard_incomplete` (default no-op) |
| `namespace/configurator/helpers.rs` | `FreshDir`, `discard_incomplete` helper |
| `namespace/configurator/{primary,schema,fork}.rs` | use `FreshDir`; implement `discard_incomplete`; drop ad-hoc cleanup; fork marks its temp dir |
| `namespace/meta_store.rs` | skip marked dirs in `maybe_recover_from_fs` |
| `docs/ADMIN_API.md`, PR #51 design doc §13 | contract; mark the lifecycle item as fixed |
| tests | §11 |

Branch `tszymczyszyn/atomic-namespace-create` off `tszymczyszyn/streaming-dump-importer`; the PR targets the importer branch until #51 merges, then retargets `v0.9.30-shopify-patches`.

## 14. Alternatives considered

- **Row first with a lifecycle state (`creating`/`ready`).** Needs a metastore schema or protobuf change that replicates to replicas via the config handshake, plus a startup sweep that knows configurator paths. More moving parts for the same guarantee.
- **Import into a temp directory and rename.** The logger, stats and connection maker capture the path at open; publishing would require close → rename → reopen, and bottomless would see a restore decision on reopen. `fork` can do it because it only writes a raw `data` file before opening.
- **Dedup via moka `try_get_with` instead of an explicit lock.** When the initialising future is dropped, moka lets another waiter run *its* init — a lazy `with()` would then create an empty namespace. The explicit reservation makes waiters observe the outcome instead.
- **Making `with()` fail fast ("namespace is being created") instead of waiting.** Cleaner UX for minute-long imports, but changes behaviour for `reset`/`fork` too; can be layered on later without touching this design.
