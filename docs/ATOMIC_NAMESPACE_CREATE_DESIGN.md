# Atomic namespace creation for `libsql-server`

Stacked on `tszymczyszyn/streaming-dump-importer` (PR #51). Fixes the pre-existing lifecycle gap described in PR #51's design doc §13 and the review walkthrough: a failed, cancelled or crashed `POST /v1/namespaces/:ns/create` could leave a *ghost* namespace (metastore row without data), a directory without a row, or both. Sections marked *as built* note where the implementation differs from the sketches.

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

Non-goals: a server-side import timeout; idempotency keys / async create jobs; bottomless remote cleanup for aborted imports (remote objects under a never-published db_id are inert junk, as today); the moka eviction hazard shared with `reset`/`fork` (§8).

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

- `pub(crate) const INCOMPLETE_MARKER: &str = ".incomplete";` in `namespace/mod.rs`.
- Created by `FreshDir::begin` for every brand-new directory.
- Removed by `Namespace::mark_complete(&self)` (`remove_file(self.path.join(MARKER))`, `NotFound` ok), called (a) by `create` after `flush`, (b) by `load_namespace`'s init after `make_namespace` — a namespace opened from the metastore is complete by definition, so lazily loaded namespaces (and single-namespace-mode auto-creation) never keep a marker.
- Consulted in exactly one place: `ConfigureNamespace::discard_incomplete(name)` (new trait method, default no-op; primary and schema share `helpers::discard_incomplete(base, name)` = `if dbs/<name>/.incomplete exists → remove_dir_all`). `create` calls it after `acquire`, i.e. only for a name with **no row and no loaded namespace** — the only situation in which a marked directory is unambiguously garbage. Lazy loads never see it, so a stale marker on a published namespace (crash between `flush` and `mark_complete`) is removed, never acted upon.
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

Replace the `Bomb` + manual `to_lock` with `Reservation::acquire(to)`; order becomes `configurator.fork(…)` → `handle.flush()` → `reservation.publish(ns)` (today it publishes *then* flushes, so a flush failure leaves a running namespace without a row). Net code removal; same semantics otherwise. `ForkTask`'s own temp-dir + rename stays as is.

## 5. Flow for a dump import (streaming or buffered)

1. Admin handler resolves `dump_url` (errors here touch nothing).
2. `create` → `Reservation::acquire` (409-class error if the name is loaded or has a row).
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
| between `flush` and `publish` | `Reservation` deletes the row again; marked complete dir ⇒ redone next time | same | row + marker + complete data ⇒ namespace **exists and serves**; marker removed on first lazy load |
| after `publish` | — | response may be lost ⇒ client retries ⇒ `NamespaceAlreadyExist` ⇒ by the contract, complete | same |

Client rule: **2xx ⇒ complete; anything else ⇒ retry; `NamespaceAlreadyExist` on retry ⇒ complete.** No inspection of tables needed.

## 7. Concurrency

- **Second `create` of the same name:** waits on the write lock; then `AlreadyExist` (first succeeded) or proceeds (first failed). Previously: `AlreadyExist` even after the first failed.
- **User request during creation (`with`)**: `exists()` is true (in-memory config), `try_get_with` finds the locked entry, `read()` waits; then sees the namespace or `None ⇒ NamespaceDoesntExist`. Same waiting behaviour as during `fork`/`reset` today.
- **`destroy` during creation:** `metadata.remove` succeeds (in-memory only), then waits on the lock; when creation finishes, `flush` is a no-op (config gone), `publish` installs, `destroy` takes and destroys it. Net: created then destroyed, in that order. Acceptable; no worse than today.
- **Store shutdown during creation:** `shutdown` waits on the entry lock, then shuts the finished namespace down normally.
- **`handle()` side effect:** `MetaStore::handle` inserts a default config into the in-memory map (pre-existing). Keeping `acquire` strictly before `handle()` is what makes the reservation airtight; documented in code.

## 8. Known limitation inherited from `fork`/`reset`

The reservation is the cache entry's lock. If moka evicts that entry during a long import (capacity pressure; TTI is 24 h), a concurrent `with()` re-inserts a fresh entry and lazily opens the directory being written. This exists today for `reset` and `fork` and is unchanged here. The structural fix is an in-flight-operations map outside the cache; separate change.

## 9. Interaction with the streaming importer

On cancellation the reader future is dropped, the executor thread sees the closed channel, rolls back and drops its connection — concurrently with `FreshDir`'s `remove_dir_all`. On POSIX, unlinking files that SQLite still has open is harmless (writes go to unlinked inodes; `-shm`/log unlinks return `ENOENT`, which SQLite tolerates). If removal fails because a background task recreated a file in the window, the directory stays **marked** and is discarded by the next `create` — the marker makes cleanup eventually consistent, so no ordering between the guard and the executor is required.

## 10. Observability

- `warn!` on every abort path (`Reservation`: "namespace creation did not complete; discarding it"; `FreshDir`: "… removing its directory"; `discard_incomplete`: "discarding namespace directory left by an interrupted creation"), with the namespace / path.
- Counters `libsql_server_namespace_create_aborted` and `libsql_server_namespace_create_discarded_incomplete` (*as built:* no `stage` label — the logs carry the detail).
- The contract of §6 is stated in `docs/ADMIN_API.md` under namespace creation.

## 11. Tests (turmoil, `tests/namespaces/lifecycle.rs` and `dumps.rs`)

*As built.* 9 of the 11 integration tests fail on the unfixed code; the other two pin behaviour that must hold both before and after.

1. `failed_create_leaves_no_trace{,_streaming,_shared_schema}`: invalid dump ⇒ 400; `GET /v1/namespaces/foo/config` ⇒ 404 (was 200); hrana ⇒ "doesn't exist" (was "no such table"); `dbs/foo` gone; `create` again with a valid dump ⇒ 200, data present, no marker.
2. `cancelled_create_leaves_no_trace{,_streaming}` (replaces `streaming_cancelled_request_rolls_back`, which tolerated "OK or BAD_REQUEST" on retry): request abandoned mid-transfer ⇒ config 404, hrana "doesn't exist", directory gone, retry from the same dump ⇒ 200 with all rows.
3. `concurrent_requests_wait_for_creation`: a second `create` and a user query issued during a ~2 s import wait; afterwards the second gets `already exists` and the query sees all rows. `concurrent_create_succeeds_after_failure`: the import fails ⇒ the waiting query gets "doesn't exist" and a new `create` succeeds.
4. `crash_remnant_is_discarded`: `dbs/foo/{.incomplete,.sentinel,data,wallog}` exists before the server starts ⇒ not adopted by the metastore (config 404), `create foo` from a dump ⇒ 200. `unmarked_directory_is_left_alone`: a marker-less `dbs/foo/keep.txt` survives a `create`. `marker_on_published_namespace_is_ignored`: marker added to a published namespace ⇒ `create` ⇒ `already exists`, data served; after a restart the marker is gone.
5. `single_namespace_mode_rejects_dump_into_existing_namespace`: config upsert of `default` still works; `create default` from a dump ⇒ `already exists` (was: 200, dump silently skipped).
6. Unit (`configurator::helpers::test`): `FreshDir` removed on drop and when its enclosing future is dropped, kept on `keep()`; `discard_incomplete` removes only marked directories.
7. `fork_namespace`, `shared_schema::*` and all dump tests unchanged.

Slow-transfer tests use `make_slow_dump_store` (64-byte chunks, 100 ms apart): with turmoil's random 0–100 ms message latency, concurrent requests are issued 500 ms in and the import lasts ~2 s.

## 12. Scope

| File | Change |
|---|---|
| `libsql-server/Cargo.toml` | `async-lock = "3"` |
| `namespace/store.rs` | `Reservation`; `create` reserving path; `fork` on `Reservation`; `load_namespace` init calls `mark_complete` |
| `namespace/mod.rs` | `INCOMPLETE_MARKER`, `Namespace::mark_complete` |
| `namespace/configurator/mod.rs` | `ConfigureNamespace::discard_incomplete` (default no-op) |
| `namespace/configurator/helpers.rs` | `FreshDir`, `discard_incomplete` helper |
| `namespace/configurator/{primary,schema}.rs` | use `FreshDir`; implement `discard_incomplete`; drop ad-hoc cleanup |
| `namespace/meta_store.rs` | skip marked dirs in `maybe_recover_from_fs` |
| `docs/ADMIN_API.md`, PR #51 design doc §13 | contract; mark the lifecycle item as fixed |
| tests | §11 |

Branch `tszymczyszyn/atomic-namespace-create` off `tszymczyszyn/streaming-dump-importer`; the PR targets the importer branch until #51 merges, then retargets `v0.9.30-shopify-patches`.

## 13. Alternatives considered

- **Row first with a lifecycle state (`creating`/`ready`).** Needs a metastore schema or protobuf change that replicates to replicas via the config handshake, plus a startup sweep that knows configurator paths. More moving parts for the same guarantee.
- **Import into a temp directory and rename.** The logger, stats and connection maker capture the path at open; publishing would require close → rename → reopen, and bottomless would see a restore decision on reopen. `fork` can do it because it only writes a raw `data` file before opening.
- **Dedup via moka `try_get_with` instead of an explicit lock.** When the initialising future is dropped, moka lets another waiter run *its* init — a lazy `with()` would then create an empty namespace. The explicit reservation makes waiters observe the outcome instead.
- **Making `with()` fail fast ("namespace is being created") instead of waiting.** Cleaner UX for minute-long imports, but changes behaviour for `reset`/`fork` too; can be layered on later without touching this design.
