# Namespace fence: contract and design

This document describes the **namespace fence** in `libsql-server`: a durable, operation-owned control record that an external operation (for example, a tool that moves a database from one server to another) uses as the data-plane authority boundary for one namespace.

It is both the contract a client of the fence can rely on and the design the implementation follows. Sections marked **Contract** are behaviour clients may depend on. Sections marked **Design** describe how the server delivers it and may change without notice.

Status: the contract below is the target of the implementation series that starts with this document. The *Code-path coverage* table (section 14) and the *Acceptance tests* map (section 17) are kept in step with the code as it lands.

## 1. What the fence is for

A move of a namespace from a **source** server to a **target** server needs one place that decides, durably and inspectably, who may read and write each copy. The existing `block_reads` / `block_writes` / `block_reason` fields of `DatabaseConfig` cannot be that place:

- they are process configuration, not owned by any operation, so two operators can overwrite each other;
- `CoreConnection::run` snapshots them once per program, so a program admitted before the flag changed can still write;
- the connection manager exposes no admission cutoff and no positive "no pre-cutoff writer remains" signal;
- the metastore's `MetaStoreHandle::version()` resets to zero on restart and cannot be a compare-and-swap revision;
- lifecycle operations (create, delete, fork, reset, restore, config), `/dump`, the admin shell, schema migrations and replication streams are not covered by statement blocking.

The fence lets one operation:

1. stop new source mutations and positively prove that no transaction admitted before the cutoff can still commit;
2. create a target that is quarantined from its first externally visible instant, and import into it through a server-created capability;
3. make the validated target readable while its writes stay closed during routing convergence;
4. stop source SQL, dump and replication reads before target write authority is published; and
5. publish target writes with an idempotent compare-and-swap transition whose result can be inspected after a restart or a lost response.

The fence is the data-plane authority. Routing and client-side controls remain defence in depth.

### Non-goals

- Orchestrating a move: selecting a target, advancing phases, routing, pausing change streams, network policy.
- Choosing or implementing a bulk copy format. The fence provides the quarantine and import capability a copy uses (section 11); streamed export and memory-bounded import are separate work.
- Deleting the source, routing back after target publication, or cleaning up an abandoned target.
- Treating connection drain, `block_writes`, the schema scheduler's `block_writes` flag, `txn_timeout` or a single rejected probe as proof of drain.
- Revoking frames already held by embedded replicas that are offline. Proving that every client has converged on the new route is the operation's responsibility, not the server's.

## 2. Safety invariants (Contract)

1. **Single owner.** At most one `operation_id` owns a namespace fence. Ownership has no TTL and never fails open. Recovery resumes the same operation; another operation cannot steal or overwrite it, except through the audited adoption command (section 12), which keeps every gate closed.
2. **Live authoritative gate.** Every logical write is checked at the WAL write-transaction boundary. Statement classification may reject earlier but is never the authority.
3. **Positive source drain.** Once acquisition reports `SOURCE_WRITE_FENCED`, no transaction admitted before or after the cutoff can subsequently commit a logical mutation.
4. **No deferred writes.** A queued program or a read transaction created under an older admission generation can never become a writer, including after the fence is released or target writes are enabled. It must fail and begin a fresh transaction.
5. **Quarantine from birth.** A target's namespace row and its `TARGET_QUARANTINED` fence row commit in one metastore transaction before any connection, dump, replication stream or lifecycle operation can observe the namespace.
6. **No generic bypass.** Import and validation use a server-created `MigrationCapability` bound to `operation_id`, purpose and fence revision, never a caller-supplied header, the ordinary admin credential or the admin shell.
7. **Durable publication.** State, revision and receipt commit before a transition's response. Startup and in-process reload install the gate before the namespace is exposed. Unknown, corrupt or indeterminate control state fails closed.
8. **Irreversible target publication.** `TARGET_WRITABLE` has no reverse transition. A lost `EnableTargetWrites` response is resolved by replaying the same command or inspecting; if neither is possible the caller must treat the result as unknown and must not route back.
9. **Lifecycle coverage.** Config mutation, delete, reset, fork, restore, import, schema migration and every other logical mutation path are denied in states that deny them.
10. **Read-fence completeness.** A `SOURCE_READ_FENCED` acknowledgement means new normal SQL, dump and replication reads are denied, and every data-serving transaction or stream that was open before has ended or been explicitly aborted.

A probe is evidence of a fence only when the server returns the expected fence code (section 6). Authentication failures, timeouts, `404`s and connection errors prove nothing.

## 3. State model (Contract)

A fence record exists per namespace once any operation has acted on it. A namespace with no record is `UNFENCED` (a source) or `ABSENT` (no namespace).

### 3.1 States

| State | Role | Durable | Meaning |
|---|---|---|---|
| `UNFENCED` | — | no row | Ordinary namespace. |
| `SOURCE_DRAINING` | source | yes | Write admission closed; waiting for pre-cutoff writers to finish. |
| `SOURCE_WRITE_FENCED` | source | yes | No write can commit; frozen replication boundary recorded; reads still served. |
| `SOURCE_READ_DRAINING` | source | yes | Reads closed for new work; waiting for old readers and streams to end. |
| `SOURCE_READ_FENCED` | source | yes | No read, dump or replication is served. |
| `RELEASED` | source | yes | Precommit rollback finished; the namespace is ordinary again. Terminal for the operation. |
| `TARGET_QUARANTINED` | target | yes | Created by the operation; only its import capability may write. |
| `TARGET_IMPORT_DRAINING` | target | yes | Import sealed; no new import work; waiting for import writers to finish. |
| `TARGET_VALIDATING` | target | yes | Import finished; only the operation's read-only validation is served. |
| `TARGET_WRITE_FENCED` | target | yes | Validated; readable and replicable; writes closed. |
| `TARGET_WRITABLE` | target | yes | Published. Terminal for the operation; no reverse transition. |
| `TARGET_ABORTED` | target | yes | Abandoned before publication. Normal traffic stays denied until a separately authorised cleanup. Terminal for the operation. |
| `UNKNOWN_UNAVAILABLE` | any | derived | The server cannot establish the control state (corrupt or unsupported payload, incomplete target creation, metastore rollback detected, indeterminate commit after restart). Every data-plane and lifecycle operation is denied. Never written as a normal transition. |

`INSTALLING` is an in-memory gate state, never persisted and never reported as a durable state: it closes write admission while a closing transition is being persisted (section 8.1).

### 3.2 Transitions

```text
Source:
  UNFENCED | RELEASED | TARGET_WRITABLE (finished op)
    --AcquireSourceWriteFence--> SOURCE_DRAINING --(drain proven)--> SOURCE_WRITE_FENCED
  SOURCE_WRITE_FENCED --SetSourceReadFence--> SOURCE_READ_DRAINING --(leases zero)--> SOURCE_READ_FENCED
  SOURCE_READ_DRAINING | SOURCE_READ_FENCED --ClearSourceReadFence--> SOURCE_WRITE_FENCED
  SOURCE_DRAINING | SOURCE_WRITE_FENCED --ReleaseSourceWriteFence--> RELEASED

Target:
  ABSENT --CreateTargetQuarantined--> TARGET_QUARANTINED
  TARGET_QUARANTINED --SealTargetImport--> TARGET_IMPORT_DRAINING --(import writers zero)--> TARGET_VALIDATING
  TARGET_VALIDATING --RecordTargetValidation--> TARGET_VALIDATING   (stores the validation receipt)
  TARGET_VALIDATING (with a successful validation receipt) --PublishTargetReadableWriteFenced--> TARGET_WRITE_FENCED
  TARGET_WRITE_FENCED --EnableTargetWrites--> TARGET_WRITABLE
  TARGET_QUARANTINED | TARGET_IMPORT_DRAINING | TARGET_VALIDATING | TARGET_WRITE_FENCED
    --AbortQuarantinedTarget--> TARGET_ABORTED

Any state owned by an unfinished operation --AdoptFence--> same state, new owner
```

Rules:

- `TARGET_WRITABLE` never transitions to a frozen, aborted or absent state for the same operation. A *new* operation may later acquire the namespace as a source, which is a new move, not a reversal.
- `RELEASED` and `TARGET_WRITABLE` finish the operation. `TARGET_ABORTED` finishes the operation but does not free the namespace: only cleanup, which is outside this contract, may remove it.
- Once `SealTargetImport` has been applied, import can never resume for that target.
- `ReleaseSourceWriteFence` is a precommit rollback. After a caller has dispatched `EnableTargetWrites` on the target, it must never release the source: the source server cannot know whether a transition committed on another server, and the no-route-back rule is the operation's to enforce.
- Nothing expires. No state advances or releases because an operator, a router or the caller is unavailable.
- A restart in `SOURCE_DRAINING` or `TARGET_IMPORT_DRAINING` may complete only the drain that was already requested, and only when the same command is replayed (section 8.4). It never advances further.

### 3.3 Permission matrix

| State | Normal SQL read | Dump / replication | Normal logical write | Generic lifecycle / config | Operation-owned work |
|---|---|---|---|---|---|
| `UNFENCED`, `RELEASED` | allow | allow | allow | existing policy | acquire only |
| `SOURCE_DRAINING` | allow | allow | deny | deny | status, drain, release |
| `SOURCE_WRITE_FENCED` | allow | allow | deny | deny | export/validation reads, status, read fence, release |
| `SOURCE_READ_DRAINING`, `SOURCE_READ_FENCED` | deny | deny; open streams terminated | deny | deny | status, clear read fence |
| `TARGET_QUARANTINED` | deny | deny | deny | deny | import capability, status, seal, abort |
| `TARGET_IMPORT_DRAINING` | deny | deny | deny | deny | existing import writers finish; no new capability |
| `TARGET_VALIDATING` | deny | deny | deny | deny | read-only validation capability, status |
| `TARGET_WRITE_FENCED` | allow | allow | deny | deny | read-only validation, status, enable writes |
| `TARGET_WRITABLE` | allow | allow | allow | existing policy | status and receipts |
| `TARGET_ABORTED` | deny | deny | deny | deny except separately authorised cleanup | status |
| `UNKNOWN_UNAVAILABLE` | deny | deny | deny | deny | status, adoption |

"Deny" on the lifecycle column covers: `POST /v1/namespaces/:ns/config`, delete, reset, fork (as source or destination), create over an existing record, restore of any kind, dump load, shared-schema linking and schema migration. Maintenance that cannot change logical contents is a separate class and continues in every state: WAL `TRUNCATE` checkpoint, bottomless WAL upload, the storage monitor, the replication logger's own connection and log compaction. **`VACUUM` is not maintenance** (it takes a write transaction and produces replicated frames) and is skipped in every state whose normal-write column is "deny".

## 4. Admin API (Contract)

The fence API is served on the admin listener (`--admin-listen-addr`) under the existing admin authentication. It is present only when the server is started with `--enable-namespace-fence` (section 13). There is no generic "set state" endpoint: each command is its own route.

### 4.1 Authentication and preconditions

- Every fence route requires admin authentication. **Mutating fence routes refuse to run when no admin auth key is configured** (`FENCE_PRECONDITION_FAILED`, reason `admin_auth_required`), because without a key the admin listener is unauthenticated. `operation_id` is ownership identity, not authentication.
- Authentication is checked first. Then, under the namespace's transition lock, the server looks up `(operation_id, command_id)`; replay handling (section 5.3) precedes every owner, role, state and revision check.
- Namespaces that are, or are linked to, a shared schema are rejected with `FENCE_PRECONDITION_FAILED`, reason `shared_schema_unsupported`.
- On a replica-kind server every fence route returns `FENCE_PRECONDITION_FAILED`, reason `not_primary`. Fences live on the primary that owns the WAL.

### 4.2 Common request fields

Every mutating request body is JSON and carries:

```json
{
  "operation_id": "5f0c8a1e-...-uuid",
  "command_id": "a41d...-uuid",
  "expected_state": "SOURCE_WRITE_FENCED",
  "expected_revision": 3
}
```

`expected_state` for a namespace with no record is `UNFENCED` (source) or `ABSENT` (target); `expected_revision` is then `0`.

### 4.3 Common response

Success (`APPLIED`, `ALREADY_APPLIED`) is `200`; `DRAINING` is `202`. Every response, success or error, carries the current fence view:

```json
{
  "outcome": "APPLIED",
  "replayed": false,
  "fence": {
    "namespace": "db1",
    "role": "SOURCE",
    "state": "SOURCE_WRITE_FENCED",
    "revision": 4,
    "operation_id": "5f0c8a1e-...",
    "incarnation": { "log_id": "…uuid…", "target_incarnation_id": null },
    "admission": { "write": "closed", "read": "open", "generation": 7 },
    "frozen_boundary": { "log_id": "…uuid…", "frame_no": 1234 },
    "drain_policy": { "deadline_ms": 30000, "on_deadline": "fail" },
    "created_at": "2026-01-01T00:00:00Z",
    "last_transition_at": "2026-01-01T00:00:05Z",
    "server": { "build": "<version> (<git sha>)", "instance_id": "…uuid…" },
    "provenance": {
      "metastore_restored_from_backup": false,
      "metastore_restored_generation": null,
      "marker": "consistent"
    }
  },
  "receipt": {
    "operation_id": "5f0c8a1e-...",
    "command_id": "a41d...",
    "command": "AcquireSourceWriteFence",
    "fingerprint": "sha256:…",
    "outcome": "APPLIED",
    "revision_before": 3,
    "revision_after": 4,
    "applied_at": "2026-01-01T00:00:05Z"
  },
  "drain": { "active_writers": 0, "read_leases": { "sql": 0, "dump": 0, "replication": 0 }, "import_writers": 0 }
}
```

`frozen_boundary.frame_no` is the last frame committed to the source's replication log, or `null` when the log has no frames.

`provenance.metastore_restored_from_backup` is `true` when this server restored its metastore from the metastore's bottomless backup at startup, with the backup generation in `metastore_restored_generation`; a record reported then may be older than one the server acknowledged before the restore, unless the marker comparison (section 13.3) caught it. `provenance.marker` is `consistent` when the record and its marker agree, `null` when there is no record, and the detail of section 13.3 for `UNKNOWN_UNAVAILABLE`.

Errors use the same shape with `"outcome": "<CODE>"`, plus `"error": "<human message>"` and, where useful, `"detail"` (a bounded reason string such as `role_mismatch` or `namespace_identity_mismatch`).

### 4.4 Routes

```HTTP
GET /v1/fence/capabilities
```

Read-only; served whenever the admin API is, even when the fence is disabled, so preflight can reject a server that cannot take part. Returns:

```json
{
  "fence_protocol_version": 1,
  "enabled": true,
  "commands": ["InspectFence", "AcquireSourceWriteFence", "..."],
  "states": ["SOURCE_DRAINING", "..."],
  "proxy_stable_code": true,
  "server": { "build": "…", "instance_id": "…" },
  "active_fences": 2,
  "metastore": { "restored_from_backup": false, "restored_generation": null }
}
```

`active_fences` counts records not in `UNFENCED`, `RELEASED` or `TARGET_WRITABLE`. Deployment tooling must refuse to roll back to a server without fence support while it is non-zero.

```HTTP
GET /v1/namespaces/:namespace/fence
```

`InspectFence`. Returns the persisted record, the last receipts of the owning operation (and, with `?receipts=all`, every retained receipt), and the live drain counters. Read-only: it never completes a drain, advances a state or refreshes anything. `404` if the namespace does not exist and has no record.

```HTTP
POST /v1/namespaces/:namespace/fence/source/acquire-write-fence
```

`AcquireSourceWriteFence`. Extra body fields: `expected_namespace_identity: { "log_id": "<uuid>" }` (the replication log id the caller observed) and `drain_policy: { "deadline_ms": <u64>, "on_deadline": "fail" | "force_rollback" }`. Returns `APPLIED` with `SOURCE_WRITE_FENCED` and the frozen boundary, or `DRAINING` with `SOURCE_DRAINING` if the deadline passed under `fail`, or if the request was cut short. Replaying the same command resumes the same drain.

```HTTP
POST /v1/namespaces/:namespace/fence/source/set-read-fence
POST /v1/namespaces/:namespace/fence/source/clear-read-fence
POST /v1/namespaces/:namespace/fence/source/release-write-fence
```

`SetSourceReadFence` (extra: `drain_policy` for readers; at the deadline, SQL work is cancelled and streams are terminated, see section 9), `ClearSourceReadFence`, `ReleaseSourceWriteFence`.

```HTTP
POST /v1/namespaces/:namespace/fence/target/create-quarantined
POST /v1/namespaces/:namespace/fence/target/seal-import
POST /v1/namespaces/:namespace/fence/target/validation-receipt
POST /v1/namespaces/:namespace/fence/target/publish-readable
POST /v1/namespaces/:namespace/fence/target/enable-writes
POST /v1/namespaces/:namespace/fence/target/abort
```

`CreateTargetQuarantined` (extra: the subset of namespace configuration a create accepts — `max_db_size`, `jwt_key`, `txn_timeout_s`, `allow_attach`, `durability_mode`, `bottomless_db_id`; a `dump_url` or any restore option is rejected, because import goes through the capability), `SealTargetImport` (extra: `drain_policy` for import writers), `RecordTargetValidation` (extra: `result: "ok" | "failed"`, `summary` — an opaque caller string of at most 4 KiB kept in the receipt; the server adds the target's current `log_id`, `frame_no` and page count), `PublishTargetReadableWriteFenced`, `EnableTargetWrites`, `AbortQuarantinedTarget`.

```HTTP
POST /v1/namespaces/:namespace/fence/target/validation-query
```

Runs one read-only SQL program under the operation's validation capability in `TARGET_VALIDATING` or `TARGET_WRITE_FENCED`. Body: common fields without `command_id`, plus `stmts` in the `/v1/execute` shape. The connection is opened with `PRAGMA query_only=1` and holds a validation capability; a write is denied at the WAL.

```HTTP
POST /v1/namespaces/:namespace/fence/adopt
```

`AdoptFence` (section 12).

Import itself is not an admin route in this series. It is an internal API (section 11) that the bulk import work exposes over its own route.

### 4.5 Implementation notes

The routes are in `libsql-server/src/http/admin/fence.rs`, behind the admin listener's authentication middleware.

- **Availability.** `GET /v1/fence/capabilities` is always served. Command routes and `validation-query` answer `404` unless `--enable-namespace-fence` is on. `InspectFence` is also served while the metastore holds fence tables with the flag off (fences are enforced either way, section 13.1), and answers `404` on a server that never used fences.
- **Order of checks.** Admin authentication (middleware, `401`), then the `404` above, then `not_primary` on a replica-kind server, then `admin_auth_required` for command routes and `validation-query` when no admin auth key is configured (`InspectFence` is read-only and does not need one), then the request body. Every command runs through `NamespaceStore::execute_fence_command` (which routes `CreateTargetQuarantined` to the atomic creation and adds the server's validation snapshot to `RecordTargetValidation`), so replay handling precedes every other check as section 5.3 requires.
- **Request bodies** are strict: an unparsable body, a malformed id, an unknown `expected_state`, a missing required field or an unknown field is `FENCE_PRECONDITION_FAILED` with detail `invalid_argument`. `drain_policy.on_deadline` defaults to `fail`. `create-quarantined` refuses `dump_url`, `restore`, `restore_option`, `timestamp` and `from_backup` with `restore_not_allowed`, and `shared_schema` / `shared_schema_name` with `shared_schema_unsupported`; `max_db_size` takes the same byte-size values as `/v1/namespaces/:namespace/create`, and a `jwt_key` is parsed before anything is written.
- **Fence view.** Beyond the fields of section 4.3 it reports `incarnation.current_log_id` (the replication log id of the namespace as loaded now, `null` when it is not loaded; a caller can take `expected_namespace_identity.log_id` from it), `admission.indeterminate`, `drain_started_at`, the owning operation's latest `validation` (with the server snapshot), `last_command_id`, `written_by`, `adoptions`, and for `UNKNOWN_UNAVAILABLE` the `detail`, `reason` and the record the marker holds (`marker_record`). A namespace being created as a target reports `TARGET_QUARANTINED` with the durable revision it has so far. `provenance` reports the metastore's restore provenance as recorded at startup (`MetaStore::restore_provenance`, section 13.3), the same for every namespace. Error responses carry the live view from the namespace's controller when it has one, otherwise what the metastore holds, or `null` when the namespace name itself is invalid.
- **`InspectFence`** reads the metastore and the live controller; it neither loads the namespace nor creates a controller, so `drain` counters are zero for a namespace that is not loaded. Without `?receipts=all` only the owning operation's receipts are listed; `?receipts` with any other value is `invalid_argument`.
- **`validation-query`** opens a `ValidationSession` (section 10.3) for the request and closes it afterwards. `stmts` follow the `/v1/execute` statement shape (`sql`, positional `args` or `named_args`, `want_rows`; `sql_id` is not supported). The response is `{"results": [<StmtResult>...], "fence": ..., "drain": ...}`, one result per statement with `cols` and `rows` in the Hrana value encoding. A request whose statements return more than 10 000 rows in total is refused with `invalid_argument` rather than truncated, so a validation never looks at part of a result. A statement that tries to write is `OPERATION_CAPABILITY_REQUIRED` (`403`); other SQLite errors are `invalid_argument`. `expected_state`, when given, must match the live state (`FENCE_REVISION_MISMATCH` otherwise).
- **Capability discovery** lists in `commands` the commands this server serves (including `AdoptFence`, which is served, and refused, even where no adoption key is configured; section 12), every state in `states`, and counts `active_fences` from the fence registry, which is seeded from the metastore at startup: records in any state but `RELEASED` or `TARGET_WRITABLE`, unavailable names, targets being created and indeterminate commits. `proxy_stable_code` reports whether the proxy's `stable_code` (section 6.1) is supported. `metastore` reports whether the metastore was restored from its backup at startup and the generation it was restored from (`restored_generation`, `null` when it was not restored).

## 5. Durable state (Design, with contract points marked)

### 5.1 Metastore schema

Two additive tables are created in the metastore by `setup_connection` when the fence is enabled, or found and loaded whenever they exist:

```sql
CREATE TABLE IF NOT EXISTS namespace_fences (
    namespace TEXT NOT NULL PRIMARY KEY,
    format_version INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    record BLOB NOT NULL,
    FOREIGN KEY (namespace) REFERENCES namespace_configs (namespace)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE IF NOT EXISTS namespace_fence_receipts (
    namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    revision_after INTEGER NOT NULL,
    applied_at INTEGER NOT NULL,
    receipt BLOB NOT NULL,
    PRIMARY KEY (namespace, operation_id, command_id)
);
```

- `record` and `receipt` are protobuf messages defined in `libsql-server/proto/namespace_fence.proto` and generated into `libsql-server/src/generated/` by the existing `tests/bootstrap.rs` pattern. `format_version` is `1`. A reader that meets an unknown `format_version`, an undecodable payload, or a `revision` column that disagrees with the payload marks the namespace `UNKNOWN_UNAVAILABLE` and logs an operator error; it never guesses.
- The foreign key makes the row a guard even for code that does not know about fences: the metastore connection runs with `PRAGMA foreign_keys=ON`, so any `DELETE FROM namespace_configs` of a fenced namespace fails.
- **Contract:** `revision` starts at `1` on the first transition and increases by one on every applied transition, including `RecordTargetValidation` and `AdoptFence`. It is stored, so it survives restart. `MetaStoreHandle::version()` is not used.

### 5.2 Record contents

`NamespaceFenceRecord`: namespace name; role; state; revision; `operation_id`; identity (`log_id` for a source, captured at acquisition and checked against `expected_namespace_identity`; for a target, a server-generated `target_incarnation_id` plus the `log_id` once the namespace exists); admission summary; drain policy and deadline; frozen boundary (`log_id`, `frame_no`) once written; the last successful validation receipt (target); the pre-fence values of `block_reads`, `block_writes` and `block_reason` (for the legacy mirror, section 13.2); the operation's command history pointer; creation and last-transition timestamps; server build and the `instance_id` of the process that wrote it; adoption history.

`CommandReceipt`: `operation_id`, `command_id`, command kind, canonical request fingerprint, outcome, revision before and after, timestamp, server instance id, and for adoption the approvers and incident reference.

### 5.3 Command processing order (Contract)

For every mutating command, under the per-namespace transition lock:

1. Authenticate (admin auth) and check the deployment flag.
2. Compute the fingerprint: SHA-256 over the deterministic protobuf encoding of the command *including* namespace, `operation_id`, command kind, `expected_state`, `expected_revision` and every argument, *excluding* `command_id`.
3. Look up `(namespace, operation_id, command_id)`:
   - found, same fingerprint, final outcome: return the stored result with `"replayed": true`. This holds even though the revision has since advanced.
   - found, same fingerprint, in-progress (`DRAINING`, or an indeterminate commit being reconciled): resume that same command (section 8.4).
   - found, different fingerprint: `FENCE_COMMAND_CONFLICT`. Nothing changes.
4. Only a non-replay proceeds. A namespace whose control state cannot be established refuses everything with `FENCE_STATE_UNAVAILABLE`, except the two commands that reconcile it: a replay of the `CreateTargetQuarantined` that left the marker (section 10.1), and `AdoptFence` after a metastore rollback (section 12).
5. Owner check (`FENCE_OWNED_BY_ANOTHER_OPERATION`) against an unfinished record.
6. A command from the owner that asks for the state the record is already in (for example `EnableTargetWrites` when already `TARGET_WRITABLE`) returns `ALREADY_APPLIED`, records a receipt so its own replay is stable, and does not change the revision. This is checked before the revision, because the caller's expectation is typically the state before a response it never received. Likewise, a new command from the owner that asks for the drain the record is already in (for example `AcquireSourceWriteFence` in `SOURCE_DRAINING`, after an adoption or a lost `command_id`) records a `DRAINING` receipt without changing the revision and joins that drain.
7. Role and transition check (`INVALID_FENCE_TRANSITION`, with `detail: role_mismatch` where the role is wrong, or `operation_finished` when the owner has already finished with the namespace), `expected_state` and `expected_revision` (`FENCE_REVISION_MISMATCH`), then command-specific preconditions (`FENCE_PRECONDITION_FAILED`).

The pure part of this — steps 3 to 7 as `apply(current, stored receipt, request, env) -> decision`, and the completion of a drain as `complete_drain(record, draining receipt, evidence) -> (next record, final receipt)` — is a function with no I/O (`namespace/fence/transition.rs`) and is unit-tested exhaustively over every state and command.

### 5.4 Transaction domain

All namespace-config writes already pass through the metastore's single `MetaStoreInner.conn`. The schema scheduler holds a second metastore connection, so the real serialisation point is SQLite's write lock. A fence transition therefore:

1. takes `inner.conn` (same lock order as today: `conn` before `configs`);
2. `BEGIN IMMEDIATE`;
3. reads the fence row, the relevant receipts and the config row;
4. runs `apply`;
5. writes the fence row, the receipt, and the legacy mirror of `block_*` into the config row;
6. `COMMIT`;
7. only then updates the in-memory registry and publishes the gate.

Ordinary config writes (`try_process`) and `remove` read the fence row inside their own transaction and refuse when the state denies lifecycle operations. Because both take `BEGIN IMMEDIATE` on the same database, a config write cannot interleave with a fence transition.

While a record is in force, the stored config row carries the legacy mirror (section 13.2) and the in-memory config is the namespace's own configuration: a transition overlays the mirror on the config row *as read inside its transaction*, so a config change committed by another metastore connection is preserved underneath it, and loading the metastore puts the saved `block_*` values back into the in-memory config. Once the operation has finished (`RELEASED`, `TARGET_WRITABLE`) the row holds the namespace's own values again, including any config written since, so loading the metastore uses the row as it is (`fence_store::own_config`) rather than the values saved when the fence was acquired. A namespace whose fence cannot be established keeps its stored row, mirror included, in memory.

A fence command that returns an error writes nothing. The store answers a replay or a resumed drain without writing; otherwise it commits the record (when it changed), the receipt and the mirror together, writes the marker, and only then returns. `CreateTargetQuarantined` returns the created namespace config without publishing it; the caller publishes it after installing the target's gate (section 10.1).

`try_process` today publishes the new config to the in-memory watch even when persisting failed. That is fixed for all config writes: the watch is updated only after commit, and the error is returned.

### 5.5 Receipt retention (Contract)

Receipts of the operation that currently owns a record are never pruned. Receipts of finished operations (`RELEASED`, `TARGET_WRITABLE`, or superseded by adoption) are kept for at least `--namespace-fence-receipt-retention-s` (default 30 days) and are pruned only inside a later transition on the same namespace. Delete of a namespace in `UNFENCED`, `RELEASED` or `TARGET_WRITABLE` removes its fence row and receipts in the same transaction and logs them; its marker is removed before that transaction commits, so a crash in between leaves a record without a marker (repaired on load) rather than a marker without a record.

### 5.6 On-disk marker

Each fenced namespace directory holds a small file `dbs/<namespace>/.fence` containing `format_version` and a copy of the last committed record (so its `operation_id`, role, state, revision and the `command_id` that produced it). It is written (and fsynced) **after** the metastore commit of each transition, and **before** the metastore transaction for `CreateTargetQuarantined` (section 10.1). It exists so that recovery paths that lose or roll back the metastore can tell a fenced namespace from a legacy one:

- metastore row present, marker absent or older: the metastore is authoritative; the marker is rewritten on load (a crash between commit and marker write);
- marker present, metastore row absent or at a lower revision: the metastore was lost or rolled back; the namespace is `UNKNOWN_UNAVAILABLE`, with provenance `metastore_behind_marker`;
- marker says `TARGET_QUARANTINED` revision 1 and no metastore rows exist: an incomplete target creation; `UNKNOWN_UNAVAILABLE`, reconciled only by replaying the same `CreateTargetQuarantined`.

## 6. Outcome codes (Contract)

Stable, machine-readable codes. Clients match on the code, never on the message.

| Code | Kind | Admin HTTP | User HTTP (`/`, `/v1`, `/v2`, `/v3`, `/dump`) | Hrana error `code` | gRPC (RPC, proxy connect, replication) | Proxy `Error.stable_code` |
|---|---|---|---|---|---|---|
| `APPLIED` | success | 200 | — | — | — | — |
| `ALREADY_APPLIED` | success | 200 | — | — | — | — |
| `DRAINING` | in progress | 202 | — | — | — | — |
| `MIGRATION_WRITE_FENCED` | data plane | 423 | 423 | `MIGRATION_WRITE_FENCED` | `FAILED_PRECONDITION` | `MIGRATION_WRITE_FENCED` |
| `MIGRATION_READ_FENCED` | data plane | 423 | 423 | `MIGRATION_READ_FENCED` | `FAILED_PRECONDITION` | `MIGRATION_READ_FENCED` |
| `MIGRATION_TARGET_QUARANTINED` | data plane | 423 | 423 | `MIGRATION_TARGET_QUARANTINED` | `FAILED_PRECONDITION` | `MIGRATION_TARGET_QUARANTINED` |
| `FENCE_STATE_UNAVAILABLE` | data plane / control | 423 | 423 | `FENCE_STATE_UNAVAILABLE` | `FAILED_PRECONDITION` | `FENCE_STATE_UNAVAILABLE` |
| `OPERATION_CAPABILITY_REQUIRED` | control | 403 | — | — | `FAILED_PRECONDITION` (admin shell) | — |
| `FENCE_OWNED_BY_ANOTHER_OPERATION` | control | 409 | — | — | — | — |
| `FENCE_REVISION_MISMATCH` | control | 409 | — | — | — | — |
| `INVALID_FENCE_TRANSITION` | control | 409 | — | — | — | — |
| `FENCE_COMMAND_CONFLICT` | control | 409 | — | — | — | — |
| `FENCE_COMMIT_INDETERMINATE` | control | 409 | — | — | — | — |
| `FENCE_PRECONDITION_FAILED` | control | 412 | — | — | — | — |

Notes:

- `FENCE_COMMAND_CONFLICT`: a `command_id` reused with a different request fingerprint.
- `FENCE_COMMIT_INDETERMINATE`: the server could not establish whether its own commit landed (for example an I/O error on `COMMIT`). Admission stays closed; only a replay of the same `command_id` reconciles it; every other command on the namespace receives this code until then.
- `FENCE_PRECONDITION_FAILED` carries `detail`, one of: `admin_auth_required`, `fence_disabled`, `not_primary`, `shared_schema_unsupported`, `namespace_identity_mismatch`, `namespace_exists`, `validation_receipt_required`, `restore_not_allowed`, `adoption_not_authorised`, `namespace_config_missing`, `invalid_argument`. `INVALID_FENCE_TRANSITION` may carry `role_mismatch` or `operation_finished`. `FENCE_STATE_UNAVAILABLE` carries the reason the state cannot be established: `corrupt_record`, `unsupported_format_version`, `incomplete_target_creation`, `metastore_behind_marker` or `indeterminate_commit`. `MIGRATION_WRITE_FENCED` carries `stale_transaction` when the gate itself admits writes but the transaction (or the program) attempting one began under an earlier write generation (section 8.1): the client must roll back and begin a new transaction.
- **Data-plane denials are never `500`, `503`, `429` or gRPC `UNAVAILABLE`.** `423 Locked` is chosen because common HTTP clients do not retry it. The JSON error body of the user HTTP API gains an additive `"code"` field (`{"error": "...", "code": "MIGRATION_WRITE_FENCED"}`); the existing `Blocked` error (from `block_reads`/`block_writes`) keeps its current mapping.
- gRPC statuses carry the code in the `x-libsql-fence-code` metadata entry and as the message prefix `"<CODE>: "`.
- Authentication (`401`), missing namespace (`404`), timeouts and transport errors are distinct from all of the above.

### 6.0 How each user protocol reports a denial (implementation)

A fence denial reaches the protocol layer as `Error::NamespaceFence` in one of two places: as the error of one **step** (a write refused by the early check or at the WAL, section 8.1), or as the error of the whole **program** (a read refused at program start, section 9, or a namespace refused before a connection exists: quarantined creation, unknown fence state). Each protocol maps both:

| Entry point | Step denial | Whole-request denial |
|---|---|---|
| Legacy `/` | The batch is answered as a whole: `423` with `{"error", "code", "detail"?}`. The legacy API has no per-step codes, and the statements after the refused one did not run (an open transaction was rolled back). | `423` with the same body. |
| `/v1/execute` | `423` with the Hrana 1 error body `{"message", "code"}`. | Same. |
| `/v1/batch` | `200`; the step's entry in `step_errors` carries the code, like any step error. | `423` with `{"message", "code"}`. |
| Hrana `/v2`, `/v3` pipeline, `/dev/.../pipeline` | The request's result is `{"type": "error", "error": {"message", "code"}}`; in a batch, the step's `step_errors` entry. The stream (baton) stays usable. | The request's result is an error with the code (the stream stays usable). A namespace refused before a connection exists is `423` with `{"error", "code", "detail"?}`. |
| Hrana `/v3/cursor` | A `step_error` entry with the code. | An `error` entry with the code. |
| Hrana WebSocket | `response_error` with the code; in a batch, the step's `step_errors` entry. The connection and the stream stay usable. | `response_error` with the code. |
| `/dump` | — | Refused before the export starts: `423` with `{"error", "code"}`. Cancelled by the read drain while running: the response body fails, so the client sees an aborted response and never a trailing `COMMIT;` (section 9). |
| Admin routes (config, create, fork, delete) | — | `423` with `{"error", "code", "detail"?}`. |

`Error::fence_error()` finds the denial through the wrappers it can arrive in (`Ref`, `Anyhow`, a schema `Migration` error); `FenceError::http_status` and `FenceError::http_error_body` are the single mapping both HTTP APIs use. Hrana's `StmtError::Fence` and `BatchError::Fence` carry the error, and their `code()` is the stable code. Authentication failures (`401`) and missing namespaces (`404`) are unchanged and carry no fence code.

### 6.1 Proxy protocol addition

`libsql-replication/proto/proxy.proto`:

```proto
message Error {
    enum ErrorCode { SQL_ERROR = 0; TX_BUSY = 1; TX_TIMEOUT = 2; INTERNAL = 3; }
    ErrorCode code = 1;
    string message = 2;
    int32 extended_code = 3;
    // Stable machine-readable outcome, e.g. "MIGRATION_WRITE_FENCED". Absent from older servers.
    optional string stable_code = 4;
}
```

This is additive in proto3: older peers skip the unknown field; a newer replica treats an absent field as "no typed outcome". An error without a stable code encodes exactly as before. For fence denials the primary sets `code = SQL_ERROR` and `stable_code`. The replica threads `stable_code` through `Error::RpcQueryError` into the same user HTTP status and Hrana code the primary would have returned. A fence denial at proxy connection creation is returned as `FAILED_PRECONDITION` with the metadata above, never `UNAVAILABLE`, so the replica's write-proxy reconnect loop (which retries `UNAVAILABLE` without bound) does not spin on it.

Capability discovery reports `proxy_stable_code: true` only once a server both fills the field on fence denials and maps it on the replica side; a server that has the field in its protocol but does neither reports `false`. This server reports `true`.

Implementation:

- **Primary.** `From<Error> for proxy::Error` sets `code = SQL_ERROR` and `stable_code` for any error whose `Error::fence_error()` is a data-plane denial, so a write refused at the WAL (a step error) and a read refused at program start (a program error) both carry it, on the streaming (`stream_exec`) and the unary (`execute`) service alike. Everything else is encoded as before. A fence error before a program runs — the namespace lookup (including the lookup of its JWT key), connection creation, or a unary program refused as a whole — is the typed `FAILED_PRECONDITION` status (`FenceError::to_grpc_status`), where it used to be `INTERNAL`, `UNAVAILABLE` or `PERMISSION_DENIED`.
- **Replica.** `Error::from_proxy_error` turns a step or program error whose `stable_code` names a data-plane denial into `Error::NamespaceFence`, and `Error::from_proxy_status` does the same for the typed status at proxy connection creation. From there the replica answers exactly as the primary would (section 6.0: `423` + `code` on HTTP, the stable code on Hrana). The peer's message is kept; the bounded `detail` is not carried by the proxy protocol. An error without `stable_code` (an older primary), or with a code this server does not know, keeps its old mapping (`Error::RpcQueryError`). The write proxy's connection loop retries only `UNAVAILABLE`, so a denial is answered at once; each refused write is delegated to the primary exactly once.
- **Replica proxy for embedded replicas** (`rpc/replica_proxy.rs`) forwards requests and responses unchanged, so the primary's `stable_code` and typed statuses reach the embedded replica as they are.

### 6.2 Replicated configuration addition

`libsql-replication/proto/metadata.proto` `DatabaseConfig` gains `optional ReplicatedFence fence = 14;` with `state` (the state name, e.g. `SOURCE_WRITE_FENCED`) and `revision` (the record's revision). A configuration without it encodes exactly as before.

- **Filled only by `hello`, only while a fence is active.** The primary's `hello` sets it from the published gate (`GateSnapshot::replicated`): the state and revision of any state other than `UNFENCED`, `RELEASED` and `TARGET_WRITABLE`, and nothing otherwise. It is never part of a stored configuration: converting a `DatabaseConfig` for the metastore leaves it empty, and converting a received one drops it.
- **The rest of the configuration is the namespace's own.** `hello` sends the logical configuration unchanged; the legacy `block_*` mirror of section 13.2 exists only in the stored config row, for an older binary reading the metastore.
- **When a replica sees it.** The dump/replication column of the permission matrix equals the normal-read column, so `hello` is answered only in states whose normal reads are allowed; in every state that denies reads, `hello` is refused and open streams end with the typed terminal status of section 9. A replica therefore learns of a read fence from that status, and of the fence in general (state and revision) from `hello`. A newer replica server uses both to deny its own local reads in states whose normal-read column is "deny".
- **A fence change does not move the configuration version**, so it does not by itself invalidate a replica's session token or make it call `hello` again; the read fence reaches a replica by ending its streams.
- **Older replica servers** skip the field. The read fence still stops their replication (refused `hello`, ended streams), but not their local reads of data they already hold (section 18).

Implementation on a replica server (`namespace/fence/replica.rs`, `replication/replicator_client.rs`, `namespace/configurator/replica.rs`):

- **Local read denial.** The replicator publishes what it learns on the namespace's fence controller on the replica (`FenceController::observe_primary`), as `GateSnapshot::primary_denial`. While set, normal reads and streams of the local copy are refused with the primary's code (`MIGRATION_READ_FENCED`, `MIGRATION_TARGET_QUARANTINED` or `FENCE_STATE_UNAVAILABLE`), so every user protocol reports it exactly as section 6.0 describes; writes keep going to the primary, which refuses them itself (section 6.1). Publishing the denial asks every read lease held on the replica to stop, under the lease lock, so a read admitted concurrently is either refused or cancelled. It never moves the write generation and is never persisted.
- **What sets and clears it.** A `hello`, `log_entries` or `snapshot` call refused with the typed status, or a stream the primary ended with it, sets it (`PrimaryFenceRefusal`; any other status keeps its existing handling). A `hello` the primary answers clears it, unless its replicated fence names a state whose normal-read column denies (the primary does not send one; a state this server does not know is not treated as a denial, because the answer itself shows the primary admits replication). A replica that cannot reach its primary at all keeps what it last learned.
- **Paced reconnects.** A fence refusal is returned to the replica's replication loop instead of being retried by the handshake loop every second. The loop waits 1 s after the first refusal, doubling to at most 15 s between attempts, until the primary answers `hello` again, so a replica of a read-fenced namespace makes a handful of calls a minute, and resumes serving at most about 15 s after the read fence is cleared. Each refused call is counted (`libsql_server_replica_fence_refusals_total{code}`); the replica logs once when the denial is installed and once when it is lifted.
- **Asynchronous by nature.** The replica learns of the fence when its stream ends, which the primary's read drain waits for; it installs the denial as the terminal status arrives, not before the primary's drain completes. The drain proves that the primary serves nothing more; it does not prove that a replica has stopped serving its copy (section 18).

## 7. FenceController (Design)

### 7.1 Registry

`FenceRegistry` (in `NamespaceStore`, outside the moka cache) maps `NamespaceName -> Arc<FenceController>`. It is seeded from `MetaStore::load_fences()` (fence rows, markers, and the namespaces startup could not recover) in `NamespaceStore::new`, before any namespace is served. Namespaces without a record get an `UNFENCED` controller lazily, on first load. Because the registry is not the cache value, cache eviction and lazy reload reinstall the same controller (section 8.5). Deleting a namespace, which deletes its fence state in the same metastore transaction, removes its controller.

### 7.2 Controller state

Per namespace:

- `transition_lock`: a `tokio::sync::Mutex` serialising commands on this namespace. A command holds it from its first check to its response (`FenceController::begin_transition` returns a `Transition` that owns the guard).
- `gate`: a `tokio::sync::watch` of `GateSnapshot { fence, write_generation, indeterminate, installing, closing_reads, creating_target }`, where `fence` is the durable fence as last published (a record, no record, or `UNKNOWN_UNAVAILABLE` with its detail) and `installing` is the in-memory `INSTALLING` gate of a closing command being persisted (section 8.3), which denies normal writes, vacuum, import writes and lifecycle work on top of `fence`. State, revision, owning operation and every admission (`permits(class)`, `write()`, `read()`) are derived from it through the permission matrix. The WAL wrapper, `CoreConnection`, dump, replication and lifecycle code read it without locks. The live capability set is kept beside it (`capabilities`, below).
- `write_generation: u64`, in the snapshot, **incremented on every publication that changes the fence state, the owning operation, or the indeterminate flag**. That covers every transition that closes or opens write admission (acquire, release, create, seal, publish, enable, abort, adopt), and is conservative for the others. A replay that publishes the same durable state does not move it.
- `indeterminate: Option<(operation_id, command_id)>`: set when a command's `COMMIT` failed (or the task running it died) so that whether it applied is unknown. While set, every class except `Maintenance` and `Observability` is denied with `FENCE_STATE_UNAVAILABLE` / `indeterminate_commit`, and every other command is refused with `FENCE_COMMIT_INDETERMINATE`. A replay of the same command is answered by the metastore from the durable row (replayed if it had committed, applied if it had not) and clears it (section 8.4).
- the write-drain sources of the namespace's primary connection makers (`register_write_drain`): each maker's connection manager, held weakly, and its replication log id and last-committed-frame reader, which the write drain waits on and reads the boundary from (section 8.3).
- the write queues of the namespace's connection managers: each `MakeLegacyConnection` registers a waker (`register_write_queue`) that the controller calls after every publication that moves `write_generation`, after the new gate is visible. A waker holds its manager weakly and is dropped once the manager is gone (for example after eviction). Writer tracking itself is the connection manager's (section 8.2).
- `creating_target` (in the snapshot): the in-memory target-creation gate of a `CreateTargetQuarantined` being persisted (section 10.1), which denies every class except `Maintenance` and `Observability` with `MIGRATION_TARGET_QUARANTINED`, and makes `FenceRegistry::check_available` refuse the name, so nothing sets the namespace up, serves it or stores a config for it. Never persisted; it moves `write_generation`; the publication of the committed record replaces it, it is removed when the command is proven not to have committed, and it stays (with `indeterminate`) when the outcome is unknown.
- `closing_reads` (in the snapshot): the in-memory read-closing gate of a `SetSourceReadFence` being persisted (section 9, step 2), which denies `NormalRead` and `Stream` with `MIGRATION_READ_FENCED` on top of `fence`. Never persisted; every publication clears it; it does not move `write_generation` (writes are already closed wherever a read fence can be set).
- `read_leases`: the live read leases, each with its kind (`sql`, `dump`, `replication`), a cancel handle and a cancelled flag, and a `Notify` on every release. `FenceController::acquire_read_lease(class, kind, cancel)` checks the gate **under the lease lock** and registers the lease, so a lease is either refused by a read-closing gate published before it, or counted by a drain that closes admission after it; once admission is closed the set can only shrink. A `ReadLease` is released when dropped.
- `capabilities`: the live `MigrationCapability` set and an import-writer counter (the import calls running now, section 10.2), under a lock that may be taken before a gate borrow and never under one. `issue_capability` checks the gate under this lock and registers the capability; every publication of a transition drops the capabilities whose state, owner or revision no longer match; dropping a session revokes its capability. `begin_import_write` checks the capability against the gate and the live set under the same lock and counts the call, so a call is either refused by a seal that closed admission before it or counted by that seal.
- in `cfg(test)` builds only, a `FenceTestHooks` (section 16).

`FenceController::apply_command` runs the command on its own task: a caller that goes away after the commit (a lost response) does not prevent the publication. The metastore maps a failed `COMMIT` to `FENCE_COMMIT_INDETERMINATE`; any other error (a refusal by the transition function, a busy metastore, a failure before `COMMIT`) proves nothing was written and leaves the gate exactly as it was.

### 7.3 Operation classes

Every write-transaction request at the WAL, every read lease and every lifecycle call names a class:

| Class | Examples | Allowed when |
|---|---|---|
| `NormalWrite` | SQL over HTTP, Hrana, RPC, proxy; admin shell; schema migration; dump load outside the capability | normal-write column allows |
| `Maintenance` | `TRUNCATE` checkpoint, the manager's checkpoint slot, storage monitor | always |
| `Vacuum` | `vacuum_if_needed`, `Namespace::checkpoint`, snapshot at shutdown | normal-write column allows; otherwise skipped with a debug log. `CoreConnection::vacuum_if_needed_above` checks the gate first and also reports a WAL refusal of the `VACUUM` itself (the fence closing between the check and the statement) as skipped, not failed |
| `CapabilityImport` | import session writes | `TARGET_QUARANTINED`, matching `operation_id`, capability revision equal to the record's, capability live (issued by this server, not revoked, not invalidated by a transition); checked at the WAL in `admit_write` on every write transaction, and up front by every `ImportSession` call |
| `CapabilityValidate` | validation reads (never writes: the WAL refuses every write transaction of a validation connection) | `TARGET_VALIDATING`, `TARGET_WRITE_FENCED` |
| `NormalRead` | SQL programs, Hrana cursors, `/beta/listen`, ATTACH of this namespace | normal-read column allows |
| `Stream` | `/dump`, `hello`, `log_entries`, `batch_log_entries`, `snapshot` | dump/replication column allows |
| `Observability` | stats, `/v1/jobs`, metrics | always; never counted as a read lease |

### 7.4 Per-connection fence state

Every `LegacyConnection` receives a `FenceConnState` shared by its `ManagedConnectionWalWrapper` and its `CoreConnection`: the connection's class and capability (if any), `program_generation`, `txn_generation`, and a `denial` slot for the typed outcome of the last WAL refusal.

- `begin_program()` records `program_generation` and clears the denial slot. It is called at the start of every `CoreConnection::run`, of every `with_raw` call (admin shell, schema migration, dump load, the configurators' own uses) and of `vacuum_if_needed`, so every way of running SQL on the connection is a program.
- A capability connection (an import or validation session, section 11) is built with `FenceConnState::with_capability`: its class is the capability's, and `admit_write` additionally requires the capability to match the fence (state its purpose admits, owner, revision) and to be live.
- `begin_read_txn()` records `txn_generation`. The WAL wrapper calls it from `begin_read_txn` **before** the snapshot is taken, so a transition racing with it leaves the transaction with the older generation, which can only refuse a later upgrade.
- `admit_write()` is the check of section 8.1 (2). A refusal is stored in the denial slot and returned.

## 8. Write admission and positive drain (Design)

### 8.1 The two checks

1. **Program and lifecycle admission (early).** `CoreConnection::run` records `program_generation` at program start. Before each statement classified as `Write` or `DDL` runs, the `Vm` reads the *live* gate and, if it denies the connection's class, fails that step with `Error::NamespaceFence` (the step fails, as a `block_writes` denial does; read steps of the same batch are unaffected). Checking per statement rather than once per program also refuses the remaining writes of a batch the fence arrived in the middle of. Lifecycle entry points check the gate the same way.
2. **WAL `begin_write_txn` (authoritative).** In `ManagedConnectionWalWrapper::begin_write_txn`, **before** `acquire()`, the wrapper requires: the gate permits the connection's class (and capability), and `program_generation == txn_generation == gate.write_generation`. On refusal it writes the typed outcome into the `denial` slot and returns `SQLITE_AUTH` — a non-`BUSY` code, so SQLite's busy handler does not retry it, and before `acquire()`, so no slot is released that was never held. `Vm::try_step` turns an `SQLITE_AUTH` with a filled `denial` slot into `Error::NamespaceFence(outcome)`; without a filled slot (for example the `SQLITE_AUTH` of an authorizer) the SQLite error is returned unchanged. A `with_raw` caller sees the bare `SQLITE_AUTH` and can take the typed reason from the slot. When the gate admits writes but a generation is stale, the outcome is `MIGRATION_WRITE_FENCED` with detail `stale_transaction`.

This makes the WAL gate independent of statement classification: DDL, misclassified PRAGMAs, `with_raw` users (admin shell, schema migrations, dump load), a program that snapshotted config before the fence, and read-to-write upgrades all converge on `begin_write_txn`.

**No deferred writes.** A read transaction opened at generation *g* cannot upgrade after any transition, because the generation has moved on. An explicit transaction opened in one program and continued in a later program fails when the later program tries to write if a transition happened in between, and the client must begin a fresh transaction.

### 8.2 Connection manager changes

- Queue entries and the write slot carry the operation class and the connection id. A write transaction asks for the slot with its connection's class (`NormalWrite`, later `CapabilityImport`); checkpoints ask with `acquire(Maintenance)`.
- `acquire(class)` re-checks the connection's write admission (`admit_write`, section 8.1) every time it takes the manager's `current` lock, for every class but `Maintenance`. A refusal fills the denial slot and returns `SQLITE_AUTH`; if the slot had already been handed to this connection it is passed on first (and the release notification fires), so a refused waiter never holds or leaks the slot.
- On every write-generation change the controller wakes the whole write queue, in the shape of the existing `sync_token` queue sync: under the `current` lock the manager increments a `fence_token`, steals every queue entry and unparks it. Each woken waiter re-checks as above and, if denied, returns the typed error instead of waiting for a release; one that is still admitted (a checkpoint) sees the token moved and queues again. Because the wake takes the `current` lock after the gate is published, a writer admitted under the old gate is either stolen and woken, or sees the new gate when it next takes the lock, or already holds the slot and is the active writer the drain waits for. The checkpoint's own queue sync tolerates entries a concurrent fence wake has already taken.
- The manager exposes `active_writer() -> Option<(ConnId, OperationClass)>` (a slot handed to a queued connection that has not taken it yet counts as held), `released()`, a `tokio::sync::Notify` notified with `notify_waiters` on every release or hand-on (a waiter enables its `Notified` before it reads `active_writer`), and `abort_active()`, which calls the active writer's registered rollback handle and returns its id. `Abort::abort` no longer panics when the connection is gone: a connection that has closed has released (or is releasing) its slot, so there is nothing to roll back. `MakeLegacyConnection::connection_manager()` hands the manager to the drain.
- The active writer's lease lasts until `release()`. Because `ReplicationLoggerWalWrapper::insert_frames` commits the log and publishes the new frame number before `end_write_txn` → `release()`, observing "no `NormalWrite` or `CapabilityImport` holder" under the manager's `current` lock means the committed `log_id` and `frame_no` are final.

### 8.3 Source write drain, step by step

`AcquireSourceWriteFence` runs through `FenceController::execute` (`namespace/fence/drain.rs`), on a task of its own and under the transition lock for all seven steps. `NamespaceStore::execute_fence_command` loads the namespace first, so that its primary connection maker has registered a *write-drain source* with the controller: the maker's connection manager (held weakly) and its replication log (`log_id` and the last committed frame). Sources whose manager is gone are dropped; after an eviction and a lazy reload there can be more than one live source for a while, and the drain waits for all of them. The drain policy is the request's, or `--namespace-fence-default-write-drain-ms` (default 30 s) with `on_deadline: fail`.

1. Replay handling and checks (section 5.3), including `expected_namespace_identity.log_id == ReplicationLogger::log_id()` (the log id of the newest live source) and the shared-schema rejection. These run inside the metastore transaction of step 4.
2. If the gate still admits normal writes, publish the in-memory `INSTALLING` gate (`GateSnapshot::installing`): normal writes, vacuum, import writes and lifecycle work are refused with `MIGRATION_WRITE_FENCED`, and `write_generation += 1`. Where writes are already closed (a resumed drain, a command being reconciled after an indeterminate commit, a fenced namespace) nothing is installed.
3. The publication wakes the write queues (section 8.2). Queued writers fail with `MIGRATION_WRITE_FENCED`.
4. CAS `SOURCE_DRAINING` in the metastore with receipt outcome `DRAINING`.
   - Committed: the commit publishes `SOURCE_DRAINING` in place of the `INSTALLING` gate (write admission never reopens in between). Continue.
   - A replay of a finished acquisition, or `ALREADY_APPLIED`: publish the durable state, respond with the stored result.
   - A replay of the `DRAINING` receipt, or a new command of the owner joining the drain the record is in: nothing is written; continue at step 5.
   - Proven not committed (the transition function refused it, or the transaction failed before `COMMIT`): remove the `INSTALLING` gate, which moves the generation again, and return the error. A transaction opened while it was up therefore cannot write afterwards.
   - Unknown (error on `COMMIT`, the task died): the gate closes as indeterminate (section 7.2) and the response is `FENCE_COMMIT_INDETERMINATE`. It is never treated as not applied.
5. For each live source, wait until its connection manager has no connection holding the write slot for a write (a checkpoint, `Maintenance`, may hold it): enable the manager's release `Notify`, check `has_writer()`, and wait for the notification. Elapsed time and `txn_timeout` are never evidence; with admission closed nobody queues behind the holder, so its slot is not stolen by the timeout either. Because admission is closed, a manager seen without a writer stays without one, so the managers are waited for in turn.
   - Deadline reached with `on_deadline: fail`: respond with the `DRAINING` commit. The durable state stays `SOURCE_DRAINING` and admission stays closed.
   - Deadline reached with `on_deadline: force_rollback`: `abort_active()` on every manager that still has a writer (on a blocking task: the rollback takes the connection's lock, which a running program holds), then keep waiting for the actual release, for one more deadline but at least 10 seconds (a rollback releases at once unless a program is still running on the connection); if the writer has still not released, respond `DRAINING`. That bound only decides when to answer `DRAINING`; it is never evidence of a drain.
   - No live source (no loaded primary, so the replication log cannot be read): respond `DRAINING`; a replay once the namespace is loaded completes it.
6. Hook point `BeforeBoundaryCapture`. Then, under each manager's `current` lock (`ConnectionManager::with_no_writer`), observe that no writer holds the slot and read that source's last committed frame. The frozen boundary is the newest source's `log_id` and the highest of those frames; `frame_no` is absent when the log has no frames. If a writer were seen here the drain would wait again rather than guess.
7. CAS `SOURCE_WRITE_FENCED` with the boundary (`complete_fence_drain`, keyed by the `DRAINING` receipt); the receipt becomes `APPLIED`; the marker is written; the gate is published; respond.

### 8.4 Reconciliation and resumption

- Replay of a command whose receipt says `DRAINING` resumes at step 5, with the request's own deadline counted from the replay. After a restart there is no pre-cutoff writer (SQLite recovery discards uncommitted work), so it completes at once.
- Replay of a command held `Indeterminate` re-reads the metastore: if the row shows the command applied, it continues from that durable point; if it shows it did not, it retries the same CAS. Other commands receive `FENCE_COMMIT_INDETERMINATE` until then. After a restart the gate reflects whatever is durable, which by definition was never acknowledged as open.
- Opening transitions (`ReleaseSourceWriteFence`, `EnableTargetWrites`) follow **commit → publish the exact revision to the gate → respond `APPLIED`**. A crash after commit and before publication sends no success, and startup recovers the committed gate before exposing the namespace.

### 8.5 Restart and eviction

- At startup the registry is built from the metastore and markers before `NamespaceStore` serves anything. `make_namespace` takes the controller from the registry and passes it into the configurator's `setup()` (primary, schema and replica), down to `MakeLegacyConnection::new`, which binds a `FenceConnState` to it for every `LegacyConnection` it opens, **starting with** the maker's held `_db` connection. The `Namespace` keeps the same controller (`Namespace::fence()`), which is how dump, replication and lifecycle code, all of which reach a namespace through `NamespaceStore::with`, read its gate.
- `NamespaceStore::with` and `make_namespace` check the registry before `lookup()`, `handle()` or any setup: `UNKNOWN_UNAVAILABLE` is refused before any setup work.
- Idle or capacity eviction shuts the namespace down but leaves the controller in the registry; a lazy reload reinstalls the identical gate, revision and generation. A drain waiter that holds the evicted manager sees its connections close and is notified. `tests::fence::lifecycle::evicted_namespace_reloads_same_gate` exercises this over the user/admin protocols with a one-entry cache and capacity pressure from four other namespaces.
- Namespaces in `SOURCE_DRAINING`, `SOURCE_READ_DRAINING` or `TARGET_IMPORT_DRAINING` after a restart stay closed until the same command is replayed. Nothing advances in the background. No reader, stream or import call survives a restart, so the replay completes the drain at once.
- A restart at any persistence boundary recovers either the state before the command or the state it committed, never anything in between, and never an open namespace unless an opening transition had committed: the `INSTALLING` gate and an indeterminate flag are in memory only, so a crash before the commit recovers the prior state (which was never acknowledged as closed), and a crash after it recovers the committed one. A marker that fell behind (a crash between the metastore commit and the marker write) is repaired when the fence is loaded.
- **A crash rebuilds the source's replication log.** A namespace that was not shut down cleanly is recovered by rebuilding its replication log from the database file under a new `log_id` (existing behaviour, not specific to fences). For the fence this means:
  - Crash before `SOURCE_DRAINING` committed: nothing was written or acknowledged. A replay of the same acquisition is refused with `FENCE_PRECONDITION_FAILED`/`namespace_identity_mismatch`, before anything is written, because the log id the caller observed is gone; the caller reads the new identity and acquires with a new command.
  - Crash in `SOURCE_DRAINING`: the replay completes the drain at once, and the frozen boundary names the rebuilt log (its `log_id` and last frame). The record's `identity.log_id` keeps the log the caller acquired against; the two differ exactly when the log was rebuilt during the drain. Write admission was durably closed from the `SOURCE_DRAINING` commit on and the lifecycle paths that could replace the database are denied, so the data at the boundary is what was committed before the cutoff. The server logs a warning when it records such a boundary.
  - Crash after `SOURCE_WRITE_FENCED` committed: the stored boundary names the log that was live when the drain was proven. After the restart the live log has a new id but the same data (writes stayed closed). A caller that compares the boundary's `log_id` with the source's current log id sees the rebuild and copies from a snapshot of the unchanged database rather than from the old log's frames. The current log id is `incarnation.current_log_id` in `InspectFence` and in every admin response (section 4.5), so no separate probe is needed.

## 9. Source read fence (Design)

`SetSourceReadFence` runs through `FenceController::execute` (`namespace/fence/read.rs`), on a task of its own and under the transition lock for all five steps. The drain policy is the request's, or `--namespace-fence-default-read-drain-ms` (default 30 s); `on_deadline` does not apply to reads, which are always cancelled at the deadline.

1. Checks (section 5.3).
2. If the source is `SOURCE_WRITE_FENCED` and the gate still admits reads, publish the in-memory read-closing gate (`GateSnapshot::closing_reads`). New SQL programs, dump requests, replication calls and ATTACHes of this namespace fail with `MIGRATION_READ_FENCED`. Where reads are already closed (a resumed drain, a command being reconciled) nothing is closed. A command the checks refuse reopens it.
3. CAS `SOURCE_READ_DRAINING` (receipt `DRAINING`); its publication replaces the read-closing gate.
4. Wait for all read leases to be released:
   - **SQL:** a lease is held for the duration of each running program (`CoreConnection::run`, `FenceConnState::begin_read_program`), including a Hrana cursor that is still producing rows, and for each `describe`. A connection that is idle with an open transaction holds no lease; its next program consults the live gate, fails with `MIGRATION_READ_FENCED`, and rolls the transaction back. Idle upgraded Hrana WebSocket and HTTP streams may therefore stay open. The admin shell, which runs raw SQL, takes a lease per query and is cancelled through the connection's interrupt handle.
   - **ATTACH:** attaching a namespace is a `NormalRead` of the attached namespace (its controller comes with the resolved path). The attaching program takes a lease on it; because an attachment outlives the program that made it, the connection remembers it (by schema alias, pruned against `PRAGMA database_list` when a program starts) and every later program on the connection takes a lease on each attached namespace as well, and is refused while any of them denies reads.
   - **Dump:** `/dump` is admitted as a `Stream` by the gate before any connection is created (a refusal is the typed `MIGRATION_READ_FENCED`, and a connection that cannot be created is an error, not a panic), and the export holds a `Dump` lease until it has stopped and its read transaction is gone (`http/user/dump.rs` `dump_stream`). A dump that is running when the read fence starts is allowed to finish, like a SQL program, and the drain waits for it. At the deadline it is cancelled: the exporter (`export_dump_cancellable`) checks the cancel before every row and before its final `COMMIT;`, and the pipe to the HTTP body fails its pending write at once, so an export blocked because the peer is not reading stops too and the lease is released without the peer's help. A cancelled dump ends its body stream with the fence error, which aborts the HTTP response (the chunked transfer is not completed), so a client never receives a dump that looks complete; the dump text never reaches its final `COMMIT;`.
   - **Replication:** every call (`hello`, `log_entries`, `batch_log_entries`, `snapshot`) is refused at its start with `FAILED_PRECONDITION` carrying `MIGRATION_READ_FENCED` (and `x-libsql-fence-code`) when the gate does not admit streams. `log_entries`, `snapshot` and the frames of `batch_log_entries` are served through a `FencedStream` (`namespace/fence/stream.rs`) that holds a `Replication` lease. A watcher task per stream ends it as soon as the gate stops admitting streams (the read-closing gate of step 2 does), or when the drain cancels it at its deadline: the watcher drops the inner stream and the lease itself, so the lease is released even if the peer never polls again, and the stream's next poll yields the terminal status and ends. Frames the stream had not yet handed to the transport are never served. Tailing streams never finish on their own, so ending them on the gate is what lets the drain complete before its deadline. Both replication services use the same code: the internal one used by replica servers and the external one on the user port.
   - At the deadline, SQL programs are cancelled through the connection's existing progress-handler cancel flag (a cancelled program rolls back any transaction and reports `MIGRATION_READ_FENCED`, not an interruption), dumps are cancelled, and streams are terminated. The command keeps waiting for the actual releases, for one more deadline but at least 10 seconds; if a lease still does not release, the result stays `DRAINING`, read admission stays closed, and a replay of the same command resumes the wait. That bound only decides when to answer `DRAINING`.
   - **`/beta/listen`:** refused at request start where reads are denied (the gate is read without loading the namespace), and the event stream ends with an error event as soon as the gate denies reads. It holds no lease: it serves change notifications, not data, and no change can happen while writes are fenced.
5. CAS `SOURCE_READ_FENCED`; respond.

`ClearSourceReadFence` reopens reads (writes stay fenced) with a new revision.

Covered surfaces: HTTP (`/`, `/v1/execute`, `/v1/batch`), Hrana over HTTP (`/v2`, `/v3`, cursors), Hrana over WebSocket, the gRPC proxy (`execute`, `stream_exec`, `describe`), the admin shell (which runs raw SQL and is checked per query), `/beta/listen`, ATTACH from other namespaces, `/dump`, and both replication services (the internal one used by replica servers and the external one on the user port). A replica server that receives the terminal status installs a local read denial for that namespace, so it stops serving its local copy, and paces its reconnects (section 6.2).

Transport keepalive: when the fence is enabled (`--enable-namespace-fence`), the RPC server and the user-port HTTP server (which carries the user-facing gRPC services), including connections upgraded to `h2c`, send HTTP/2 keepalive pings (`--namespace-fence-keepalive-interval-s`, default 30 s; a ping unanswered for 20 s closes the connection) so dead peers are detected; lease release does not depend on it.

Replication calls denied by the fence are counted (`libsql_server_fence_denials_total{code, surface = "replication"}`) and logged at most once per namespace per minute, so repeated reconnects of replicas that do not understand the typed code are observable rather than noisy. Replica-side handling of the typed code (a local read denial, capped back-off) is described in section 6.2.

Internal work that must keep running is classed `Maintenance` or `Observability` and holds no read lease: bottomless WAL upload, the storage monitor's read transaction, stats and metrics.

This fence stops future service from the source. It cannot recall bytes a peer has already received, frames stored by an embedded replica, or data served by a replica server that is partitioned from the primary; the operation must prove client and replica convergence separately.

## 10. Target lifecycle (Design)

### 10.1 CreateTargetQuarantined

`NamespaceStore::create_target_quarantined(CreateTargetRequest, ServerIdentity)` (the admin route calls the same code through `execute_fence_command`) runs on its own task under the namespace's transition lock:

1. Checks. A name without fence state that the server already knows — its config is in the in-memory map, or the namespace cache holds it (loaded, or a fork in flight) — is refused with `FENCE_PRECONDITION_FAILED`, `namespace_exists`, without touching its gate. Otherwise the controller (get-or-create in the registry) publishes the in-memory **target-creation gate** (section 7.2): from here on every class but maintenance and observability is refused and `check_available` refuses the name, so `with()`, `make_namespace`, `create` and the fork destination refuse it before storing or setting anything up. The in-use check is repeated with the gate in place, which closes the race with a create or fork that had not stored anything yet. The metastore then checks section 5.3 and requires no config row, no fence row and no marker (`namespace_exists`). A name that already has fence state (a replay, a creation interrupted after its marker, a refusal) keeps the gate its state implies and goes straight to the metastore.
2. Inside the metastore transaction, create `dbs/<namespace>/` and write the marker (`TARGET_QUARANTINED`, revision 1).
3. In the same transaction: insert the config row (with the legacy mirror `block_reads = block_writes = true`), the fence row (`TARGET_QUARANTINED`, revision 1, new `target_incarnation_id`) and the receipt; commit.
4. The controller publishes the committed record, whose quarantine gate replaces the creation gate (commit → publish, as for every command). A command proven not to have committed removes the creation gate; one whose commit is unknown keeps it with the indeterminate flag.
5. Only now `MetaStore::publish_target_config` puts the config into the in-memory map (which is what makes `exists()` and `lookup()` find it): the stored row with the record's own `block_*` values in place of the legacy mirror, replacing any entry a refused create or fork of the same name had left there. An empty namespace-cache entry left by a refused fork is dropped, and the namespace is loaded; its first connection maker is created with the quarantine gate already in place, in a directory that until then held only the marker. The response is `APPLIED`.

A replay of the same command returns the stored receipt and repeats step 5, which completes a creation whose commit was not acknowledged. A crash after step 2 leaves a marker with no rows: `UNKNOWN_UNAVAILABLE` (`incomplete_target_creation`) until the same command is replayed, which completes it with the incarnation id the marker announced. A crash after step 3 recovers `TARGET_QUARANTINED` from the metastore, and startup publishes its config.

The target's replication `log_id` is not written back into the record: rewriting a record at the same revision would make a marker written before the rewrite look like `metastore_behind_marker` after a crash between the two. The log id is the namespace's own and is read live where it is needed (a later `AcquireSourceWriteFence` on the published target checks the caller's `expected_log_id` against it).

### 10.2 SealTargetImport

`seal_target_import` (routed from `FenceController::execute`) runs under the transition lock:

1. For a seal that can apply (the owner, at the current revision, of a `TARGET_QUARANTINED` target, with nothing indeterminate or installing), publish the in-memory `INSTALLING` gate: new import calls and import write transactions are refused, the write generation moves (so every transaction opened before it is stale) and queued import writers are woken and refused. A command that cannot apply does not touch the gate, so it cannot disturb a running import.
2. CAS `TARGET_IMPORT_DRAINING` (revision + 1). Its publication replaces the `INSTALLING` gate and drops every issued import capability: none can be issued again for the target. A command proven not to have committed removes the `INSTALLING` gate.
3. Wait, on release notifications and never on elapsed time, for the running import calls (the controller's import-writer counter) to end, then for every connection manager of the target to have no writer holding its write slot (an import transaction admitted before step 1, including one an idle session left open). With `on_deadline: force_rollback` the seal rolls back the transaction still holding the slot at the deadline (a running call ends its own; the rollback waits for the connection's lock) and waits again for the same deadline, at least 10 s. The request's drain policy applies; without one, `--namespace-fence-default-write-drain-ms`. A target without a loaded connection maker has no connection that could write.
4. CAS `TARGET_VALIDATING` (`complete_drain`, `DrainCompletion::TargetImport`).

A deadline reached before step 4 answers `DRAINING` and leaves `TARGET_IMPORT_DRAINING` durable and closed, also across a restart. Only the owning operation resumes it: a replay of the same command, or a new seal of the owner, which joins the drain (section 5.3); another operation is refused. Import never resumes.

### 10.3 Validation and publication

`NamespaceStore::open_validation_session` issues a server-owned `Validate` capability and opens a capability connection for the owning operation at the current revision. The connection has SQLite `query_only` enabled; `ValidationSession::with_raw` re-checks the capability before every call, and the WAL independently refuses every write transaction of class `CapabilityValidate`. Dropping the session revokes its capability. A session is valid in `TARGET_VALIDATING` or `TARGET_WRITE_FENCED`; every transition that moves the revision invalidates it, so the operation opens a new session at the returned revision when it needs more validation reads.

For a new `RecordTargetValidation`, `NamespaceStore::execute_fence_command` observes the target's current replication-log id and frame and its SQLite page count through a validation session, and stores that snapshot with the caller's result and bounded summary in the record. The durable command key is checked before collecting the snapshot and again if a concurrent copy invalidates the capability: exact replay and command-id conflict always reach the metastore's replay/fingerprint check without requiring a fresh capability or observation. `PublishTargetReadableWriteFenced` requires that the most recent `RecordTargetValidation` of the owning operation has `result: ok`; otherwise `FENCE_PRECONDITION_FAILED`, `validation_receipt_required`. Publication makes normal reads visible, keeps writes fenced and clears the durable legacy `block_reads` mirror.

`EnableTargetWrites` is CAS from `TARGET_WRITE_FENCED`; commit, publish the gate with a new generation, respond. The durable legacy mirror is restored to the values given at creation. Replays return the stored result; a new command asking for the same thing returns `ALREADY_APPLIED`. Every other command on a `TARGET_WRITABLE` record from the same operation is `INVALID_FENCE_TRANSITION`. A transaction opened under the prior generation cannot upgrade to a write after publication; a fresh transaction can.

`AbortQuarantinedTarget` moves to `TARGET_ABORTED`; all normal traffic stays denied.

## 11. Reusable import capability API (Design, for bulk import)

The bulk import work consumes this internal Rust API, which does not depend on any HTTP route:

```rust
// namespace::fence
pub enum TargetState { Quarantined, ImportDraining, Validating, WriteFenced, Writable, Aborted }

/// CreateTargetQuarantined; the expectation is always ABSENT at revision 0.
pub struct CreateTargetRequest {
    pub namespace: NamespaceName,
    pub operation_id: Uuid,
    pub command_id: Uuid,             // idempotency key: a replay returns the stored result
    pub config: TargetConfig,
}

pub struct MigrationCapability {      // server-created, not constructible outside the module
    id: Uuid,
    namespace: NamespaceName,
    operation_id: Uuid,
    purpose: CapabilityPurpose,       // Import | Validate
    fence_revision: u64,
}

impl NamespaceStore {
    /// CreateTargetQuarantined, atomic with namespace creation (section 10.1). Fence refusals
    /// are `Error::NamespaceFence(FenceError)` with their stable outcome code.
    pub async fn create_target_quarantined(&self, req: CreateTargetRequest,
        server: ServerIdentity) -> crate::Result<FenceCommit>;

    /// Issue an import capability and a capability-bearing connection. Valid only in
    /// TARGET_QUARANTINED for the owning operation at `expected_revision`; loads the target.
    /// Fence refusals are `Error::NamespaceFence(FenceError)`: OPERATION_CAPABILITY_REQUIRED in
    /// any other state, FENCE_OWNED_BY_ANOTHER_OPERATION, FENCE_REVISION_MISMATCH.
    pub async fn open_import_session(&self, namespace: NamespaceName, operation_id: Uuid,
        expected_revision: u64) -> crate::Result<ImportSession>;

    /// Issue a read-only validation capability and a `query_only` capability connection. Valid
    /// in TARGET_VALIDATING or TARGET_WRITE_FENCED for the owner at `expected_revision`; loads
    /// the target. Fence refusals use the same `Error::NamespaceFence` shape as import.
    pub async fn open_validation_session(&self, ns: NamespaceName, operation_id: Uuid,
        expected_revision: u64) -> crate::Result<ValidationSession>;

    pub async fn apply_fence_command(&self, ns: NamespaceName, cmd: FenceCommand)
        -> Result<FenceResponse, FenceError>;

    pub async fn inspect_fence(&self, ns: NamespaceName) -> Result<FenceView, FenceError>;
}

impl MigrationCapability {                // read-only accessors
    pub fn id(&self) -> Uuid;
    pub fn namespace(&self) -> &NamespaceName;
    pub fn operation_id(&self) -> Uuid;
    pub fn purpose(&self) -> CapabilityPurpose;
    pub fn fence_revision(&self) -> u64;
}

pub struct ImportSession { /* capability, controller, capability connection */ }
impl ImportSession {
    pub fn capability(&self) -> &MigrationCapability;
    /// Run a closure with the raw connection inside the capability. Refused up front once the
    /// capability is no longer valid; counted as an import writer until the closure returns;
    /// writes are admitted by the WAL only while the capability is valid, and a write the WAL
    /// refused is returned as that FenceError.
    pub async fn with_raw<R: Send + 'static>(&mut self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static) -> Result<R, FenceError>;
    /// The server's dump loader (`load_dump_sql`, the loader a namespace created from a dump
    /// uses) run inside `with_raw`. Dump errors are `Error::LoadDumpError`.
    pub async fn load_dump<S>(&mut self, dump: S) -> crate::Result<()>
        where S: Stream<Item = std::io::Result<Bytes>> + Unpin;
pub struct ValidationSession { /* capability, controller, query_only capability connection */ }
impl ValidationSession {
    pub fn capability(&self) -> &MigrationCapability;
    /// Re-check the live validation capability, then run one raw read call. The WAL still
    /// refuses a write if the closure disables `query_only`.
    pub async fn with_raw<R: Send + 'static>(&mut self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static) -> Result<R, FenceError>;
}
```

`FenceError` carries a `FenceOutcome` (section 6) and converts into the server's `Error`, so a route built on top returns the same codes. The import-writer count is of running calls: a session that is not running a call cannot start a write once the seal has moved the revision, and a transaction it left open holds the write slot, which the seal waits for as well (section 10.2). Dropping either session revokes its capability and closes its connection; dropping an `ImportSession` therefore rolls back a transaction it left open and releases the slot. Capability connections share the target's WAL and replication log and are not counted by the connection throttle. The loader holds the connection for the whole dump and re-renders each statement it runs (as it does for a namespace created from a dump), so the stored SQL text of schema objects differs from the source's in case and spacing. Streaming and memory bounds are not part of this series.

## 12. Incident adoption (Contract)

`AdoptFence` transfers ownership of an unfinished operation's record to a new `operation_id` when the original control-plane record is lost. It:

- requires the admin credential **and** the separate adoption key configured with `--namespace-fence-adoption-key` (absent: adoption is disabled, `FENCE_PRECONDITION_FAILED`, `adoption_not_authorised`), passed in the `x-libsql-fence-adoption-key` header;
- requires `approvers`: two distinct, non-empty identity strings, an `incident_ref` and a `reason`, all stored in the receipt and emitted in a structured audit log line;
- requires `expected_state`, `expected_revision` and the current `operation_id` of the record;
- changes the owner and appends to the adoption history, with revision + 1, and **changes nothing else**: gates stay exactly as they were. It cannot open source writes, move out of any state, or act on `TARGET_WRITABLE` or `TARGET_ABORTED`;
- also applies to `UNKNOWN_UNAVAILABLE` caused by a metastore rollback, where it re-establishes the record in the state the marker last recorded (the marker is written only after a commit), with the adopting operation as owner.

The server cannot verify who the approvers are: the admin API has one shared key and no principal. "Two-person" is enforced as a separate secret plus a recorded two-approver request; real two-person control belongs to whatever holds those secrets.

Request body: the common fields of section 4.2 (`operation_id` is the adopting operation), plus `current_operation_id`, `approvers` (an array of exactly two strings, distinct after trimming and neither empty), `incident_ref` and `reason` (neither empty after trimming). Unknown fields are refused like on every other route.

Implementation (`http/admin/fence.rs`, `NamespaceStore::execute_fence_command_authorised`, `namespace/fence/audit.rs`):

- **The key.** `--namespace-fence-adoption-key` (env `SQLD_NAMESPACE_FENCE_ADOPTION_KEY`, hidden from `--help`; an empty value is a startup error) is kept only as its SHA-256 digest, and the header's value is hashed and compared digest to digest without an early exit. Whether it matched is handed to the transition function, so the order of section 5.3 holds: a replay of a committed adoption returns its receipt even without the key (it changes nothing), and the key, the approvers, the incident reference and the reason are checked after the owner (`current_operation_id` must be the record's owner, `FENCE_OWNED_BY_ANOTHER_OPERATION` otherwise), after the finished-operation check and after `expected_state` / `expected_revision`, all of which the admin credential already lets a caller read with `InspectFence`. An operation cannot adopt its own fence.
- **What changes.** The owner, the revision, `last_command_id`, `written_by` and the appended adoption entry; the receipt carries the same entry. The state, and so every admission, is unchanged, as are the identity, the frozen boundary, the validation and the saved legacy values; the legacy mirror in the config row names the new owner. Because the owner changed, the write generation moves (section 7.2: nothing can write in a state adoption can act on, so this refuses nothing that was admitted) and every capability issued to the old owner is revoked: the old owner's import or validation session stops working and the new owner opens its own. `RELEASED`, `TARGET_WRITABLE` and `TARGET_ABORTED` are refused with `INVALID_FENCE_TRANSITION` / `operation_finished`.
- **After a metastore rollback.** When the marker is ahead of the metastore (`metastore_behind_marker`: the fence row is missing or older), the adoption names the marker's state, revision and owner (the `marker_record` that `InspectFence` reports), and commits the marker's record with the new owner at the marker's revision + 1, as an update of the older row or an insert when the row is gone. The name leaves the unavailable set, its gate is the re-established record's, and its in-memory config gets the namespace's own `block_*` values back (the saved values in the record), as startup does for every established record. No other unavailable reason can be adopted: a corrupt record, an unsupported format version, an interrupted target creation (which only its own replay completes) and an indeterminate commit (which only its own replay reconciles) keep refusing it.
- **A name the metastore holds no configuration for.** A metastore restored from a backup older than the namespace itself has neither the fence row nor the config row. Adoption is then refused with `FENCE_PRECONDITION_FAILED` / `namespace_config_missing`, after the authorisation checks, and writes nothing; the name stays `UNKNOWN_UNAVAILABLE`. The marker holds the fence record, not the namespace's configuration (its JWT key, size limit, durability mode, backup id, attach and shared-schema settings), and re-creating the config row from defaults would silently change who can read the namespace and how it is stored once it is released. Recovering such a namespace is an operator decision outside the fence: put its config row back (for example from a newer metastore backup), after which the adoption applies; or discard the namespace directory, marker included.
- **Audit.** Every committed adoption (not a replay, not a refusal) emits one `info` event with target `libsql_server::fence::audit` and `event = "namespace_fence_adopted"`, carrying the namespace, command, outcome, state, previous and new operation id, command id, approvers, incident reference, reason, revisions before and after and the server instance. Every other command answer is an event under the same target (section 15); a replay of an adoption is an ordinary command event.

## 13. Deployment and compatibility (Contract)

### 13.1 Deployment flag

`--enable-namespace-fence` (env `SQLD_ENABLE_NAMESPACE_FENCE`), **default off**. The flag controls *use*, not enforcement:

- Off, and no fence tables exist: behaviour is unchanged, except the `try_process` persistence fix (section 5.4). The capability endpoint reports `enabled: false`; fence routes return `404`.
- Off, but fence tables or markers exist (the flag was turned off after use): fences are still loaded and enforced; mutating routes are disabled.
- On: tables are created, routes are served, and the fail-closed recovery rules of section 13.3 apply.

Related flags: `--namespace-fence-receipt-retention-s`, `--namespace-fence-adoption-key`, `--namespace-fence-keepalive-interval-s`, and default drain deadlines `--namespace-fence-default-write-drain-ms` and `--namespace-fence-default-read-drain-ms` (used when a request has no `drain_policy`).

Upgrade order: deploy a binary with capability discovery and proxy `stable_code` support on every primary and replica; confirm with `GET /v1/fence/capabilities`; then enable the flag; then use fences. Rollback to a binary without fence support is refused by deployment tooling while `active_fences > 0`.

### 13.2 Protection against an older binary

An older binary does not know the fence tables. While a record is active:

- the config row's `block_reads`, `block_writes` and `block_reason` are mirrored from the fence state in the same transaction (`block_writes` in every state that denies writes, `block_reads` in every state that denies reads, `block_reason = "namespace fence: <STATE> (operation <id>)"`), and restored when the operation finishes (`ReleaseSourceWriteFence`, `EnableTargetWrites`). Nothing else in the row changes, and while the fence denies lifecycle work a config write through the metastore is refused in its transaction, so it cannot overwrite the mirror. After the operation has finished, config writes follow the existing policy again and the row holds whatever they store;
- the foreign key from `namespace_fences` to `namespace_configs` (`ON DELETE RESTRICT`) makes an older binary's namespace delete fail with `FOREIGN KEY constraint failed` (the older binary enables foreign keys on its metastore connection). The fence row, and so the guard, stays until this binary deletes the namespace, which removes the fence row and its receipts in the same transaction: an older binary cannot delete a namespace whose operation has finished either.

This is best effort. An older binary applies `block_*` at statement level only, lets its admin shell and `/dump` bypass them, and would let a config update overwrite them. It is a mitigation for an accidental rollback, not a guarantee; the guarantee is the deployment order above.

### 13.3 Fail-closed metastore recovery

Recovery fails closed when the flag is on, when the fence tables exist, or when any namespace directory holds a marker. Otherwise (a server that never used fences) recovery behaves as before. Startup scans `dbs/` for markers first; a marker in a directory whose name is not a valid namespace name stops startup with an operator error.

A namespace that startup cannot recover is registered `UNKNOWN_UNAVAILABLE` in memory. It is never given a default config, never default-created, and every lookup, config write and delete of it is refused with `FENCE_STATE_UNAVAILABLE` and a detail. `InspectFence` and the fence list report it. Nothing is written for it: the registration is recomputed from the metastore and the markers at every start, and a fence command that commits for the name (the replay that completes an interrupted target creation, or an adoption after a metastore rollback, section 12) settles it.

- `MetaStore::handle()` no longer default-creates entries on read paths. `NamespaceStore::with` (and so every SQL, Hrana, dump and replication entry point), fork's source and ATTACH authorisation (`check_program_auth`) use the non-creating `MetaStore::lookup`, which returns the existing handle, nothing, or the fence error. Only create, fork destination, reset, the default namespace and lazy creation call `handle()`, which refuses a registered name, and a name without a config whose directory holds a marker (a target being created, or a namespace the metastore lost). `NamespaceStore::checkpoint` does not touch the metastore and needs no lookup.
- `restore()`: an undecodable config row marks its namespace `UNKNOWN_UNAVAILABLE` (`corrupt_record`) and the row is left as it is. An undecodable namespace name cannot be addressed by any request, so a legacy row is still skipped; if the metastore holds a fence row for such a name, startup fails with an operator error. An undecodable, unknown-version or inconsistent fence row, or an unreadable marker, marks the namespace `UNKNOWN_UNAVAILABLE` (section 5.6).
- `maybe_recover_from_fs`: a directory with a marker is not recovered from `config.json` (or a default); it is registered `UNKNOWN_UNAVAILABLE` (`metastore_behind_marker`). Directories without markers keep today's behaviour: they are legacy, unfenced namespaces.
- `destroy_on_error`: the broken metastore is renamed to `metastore.broken-<unix-ms>` rather than deleted (if the rename fails, startup fails instead), and directories with markers are registered `UNKNOWN_UNAVAILABLE` after the rebuild. Without fences it still deletes, as before.
- A metastore without fence tables next to a directory that holds a marker (rebuilt, recovered, or restored from a backup taken before the tables existed) makes that namespace `UNKNOWN_UNAVAILABLE`, even when its config row is present.
- Metastore restore from backup: the marker comparison (section 5.6) makes any namespace whose record went backwards or disappeared `UNKNOWN_UNAVAILABLE`. A restored record is never trusted over a newer marker. The restore itself is reported: `metastore_connection_maker_with_provenance` keeps what the bottomless restore returns (whether it recovered the database, and the generation it restored from, which is the replicator's generation before a new one is started), and the server records it on the metastore right after opening it (`MetaStore::record_restore_provenance`). It is surfaced in the capability endpoint (`metastore`), in every fence view (`provenance`), in the `libsql_server_metastore_restored_from_backup` gauge (0 or 1, set at every start) and, after a restore, in a startup warning naming the generation and the number of namespaces startup registered `UNKNOWN_UNAVAILABLE`. When `destroy_on_error` rebuilds the metastore, the rebuilt metastore is restored from the backup again, and that second restore is what is reported.
- Replica-kind servers: lazy creation of a name the primary refuses with a fence code (a quarantined or aborted target, a read-fenced source, a fence state the primary cannot establish) does not create a local namespace. The refusal arrives as the typed status of the replication `hello` (section 6.2), not through the write proxy. `ReplicaConfigurator::setup` fails at once with that code (`Error::NamespaceFence`, so the client gets `423` and the code of section 6.0) instead of retrying the handshake, and removes the namespace directory if the setup created it (a directory that was already there is left as it is). `NamespaceStore::with` then forgets what the attempt left in memory: the metastore entry `handle()` added (`MetaStore::forget_unstored`, only when no config row is stored for the name and no other handle is subscribed to it, so a concurrent creation or a persisted config keeps it) and the name's controller (`FenceRegistry::forget_idle`, only when it holds no fence record and no in-memory gate and nothing else refers to it). `exists()` and `lookup()` therefore do not report the name, and a later request, once the primary admits the name, creates it normally.

### 13.4 Shared schema

v1 does not fence shared-schema databases or namespaces linked to one, because schema migration fan-out would have to obey the fence on every linked namespace. Acquisition and target creation reject them with `FENCE_PRECONDITION_FAILED`, `shared_schema_unsupported`. While a fence is active, config mutation (which includes linking to a shared schema) is denied.

The two sets therefore never meet: acquisition reads the config row in the same metastore transaction that writes the record, and linking writes the config row in a transaction that checks the fence. Registering a schema migration job still checks the schema and every namespace linked to it (under the schema's exclusive lock) and registers nothing if any of them denies lifecycle work, so a link made by a binary that does not know fences cannot lead to a migration step being refused at a fenced namespace's WAL halfway through a job.

### 13.5 Lifecycle interlocks (implementation)

`NamespaceStore::check_lifecycle` is the one check: the namespace's gate in the registry must permit `Lifecycle` (section 3.3). It reads the registry only, so it never loads or creates the namespace, and it sees the in-memory gates as well as the durable state: a closing transition being installed, a target being created, an indeterminate commit and an unavailable state all refuse lifecycle work. A name without a controller has no fence state and is left to the existing checks.

| Operation | Where it is refused |
|---|---|
| Config `POST` | Before the namespace is loaded (`http/admin/mod.rs`), and in the metastore transaction that would store it (`try_process`). A config written without a flush is only a fork destination's, which is checked below. |
| Delete | In the metastore transaction of `MetaStore::remove`. |
| Create over an existing record, with or without `dump_url`, and linking to a shared schema at creation | Before a dump is fetched (`http/admin/mod.rs`), first in `NamespaceStore::create`, and in the metastore transaction that stores the config. |
| Fork, as source | Under the source's transition lock, held for the whole fork. A fork reads the source's log without a read lease; holding the lock means a write or read fence command on the source either finished before the check (and the fork is refused) or starts after the fork has finished. |
| Fork, as destination | Before anything is stored, and again with the destination's namespace entry held, which no fence command can load past. Without it, a fork onto an existing fenced namespace that is not loaded would publish its config in memory and replace its directory. |
| Reset (the replica's reset callback) | Under the namespace's transition lock, before its entry is taken and its data destroyed. Reset writes nothing to the metastore, so this is its only check; a refused reset is logged. |
| Schema migration | When the job is registered (section 13.4). |

Lock order is transition lock, then namespace entry, everywhere: fence commands that load a namespace (`CreateTargetQuarantined`) take them in that order, `AcquireSourceWriteFence` releases the entry before it takes the transition lock, and fork and reset take the transition lock first.

## 14. Code-path coverage

How each path that can reach namespace data or lifecycle is covered. File references are to `libsql-server/src/`.

| Path | Coverage |
|---|---|
| `connection/connection_core.rs` `CoreConnection::run`, `describe` | Early live-gate check and `program_generation` capture at program start; SQL read lease for the program (and on each attached namespace), refused with `MIGRATION_READ_FENCED` and the open transaction rolled back; cancellation through the progress-handler flag; `Error::NamespaceFence` from the WAL denial slot in `Vm::try_step`. `describe` holds a read lease. |
| `connection_core.rs` `checkpoint`, `vacuum_if_needed`, `force_rollback` | Checkpoint is `Maintenance`; vacuum is `Vacuum` and skipped while writes are fenced; `force_rollback` is the drain's abort. |
| `connection/connection_manager.rs` | Authoritative gate in `begin_write_txn` before `acquire()`, generation check, non-`BUSY` refusal; classed queue entries; queue wake on generation change; active-writer query, release notification, `abort_active()`. |
| `connection/legacy.rs` | `FenceConnState` wired into every `LegacyConnection`; the controller is passed to `MakeLegacyConnection::new` before the first connection. `with_raw` users are covered by the WAL gate. |
| HTTP `/`, `/v1/execute`, `/v1/batch`, Hrana `/v2`, `/v3`, cursors, WebSocket, dev route | Core checks and WAL gate; typed status and `code` field; Hrana codes, for step and whole-request denials alike, with the stream left usable (section 6.0). |
| `rpc/proxy.rs`, `rpc/streaming_exec.rs`, `rpc/replica_proxy.rs`, `connection/write_proxy.rs` | `stable_code` set on the primary for step and program denials (streamed and unary); namespace-lookup, JWT-key-lookup, connection-creation and unary whole-program denials are `FAILED_PRECONDITION` with the code, never `UNAVAILABLE`; the replica maps both back to `Error::NamespaceFence` and never retries them; the replica proxy forwards them unchanged (section 6.1). |
| `namespace/meta_store.rs` `handle()`, `restore()`, `maybe_recover_from_fs`, `destroy_on_error`, `process`/`try_process`, `remove`, bottomless metastore restore | Non-creating lookups; fail-closed decoding; marker-aware recovery; rename-aside; publish only after commit; fence check inside the config and remove transactions; the bottomless restore's outcome is kept (`metastore_connection_maker_with_provenance`) and reported in the admin API, a gauge and a startup warning (section 13.3). |
| `namespace/store.rs` `with`, `load_namespace`, `make_namespace`, eviction | Registry check before setup; controller passed into setup; eviction keeps the registry entry. |
| `store.rs` `create`, `destroy`, `reset`, `fork`, `checkpoint`, restore options | `check_lifecycle` (section 13.5): create refuses a name whose fence denies lifecycle work; `CreateTargetQuarantined` is the atomic quarantined create; destroy is refused in the metastore transaction; reset and fork as source are checked under the namespace's transition lock; fork's destination is checked before anything is stored and again under its entry lock; every restore (create with a dump, reset, fork to a point in time) is one of these paths and is refused there; checkpoint uses a non-creating lookup and skips vacuum. |
| `http/admin/mod.rs` config, create, fork, delete, checkpoint, stats | Config POST and create (before a `dump_url` is fetched) are checked before the namespace is loaded; fork and delete are refused by the store; all of them return the fence error with `423`. Config GET, stats and checkpoint are allowed. Fence routes live in `http/admin/fence.rs`. |
| `http/admin/fence.rs` | Fence routes (section 4.5): capability discovery, `InspectFence`, one route per command through `NamespaceStore::execute_fence_command` (`AdoptFence` through `execute_fence_command_authorised` with the result of the adoption key check, section 12), and `validation-query` through `open_validation_session`; admin auth key and primary required for every route that changes state or uses a capability. |
| `http/user/dump.rs`, `connection/dump/exporter.rs` | Gate check (`Stream`) before connection creation (typed, no panic on create error); `Dump` lease held by the export; cancel checked before every row and by the pipe's pending write; the body stream ends with the fence error (aborted response) on cancellation. |
| `rpc/replication/replication_log.rs` `hello`, `log_entries`, `batch_log_entries`, `snapshot` | Denied at request start (`FAILED_PRECONDITION` + `x-libsql-fence-code`, counted, rate-limited log); `FencedStream` replication leases for both streams and the batch; typed terminal status when the gate closes or at the deadline, lease released without the peer; `ReplicatedFence` in `hello`'s config while a fence is active (section 6.2; the gate is read without a lease, since `hello` streams no data). |
| `replication/replicator_client.rs`, `namespace/configurator/replica.rs` (replica servers) | A fence status from `hello`, `log_entries` or `snapshot`, or a stream ended with one, installs the local read denial (`FenceController::observe_primary`) and is returned as `PrimaryFenceRefusal`; the replication loop backs off 1 s → 15 s instead of reconnecting every second; an answered `hello` lifts the denial (section 6.2). A lazy creation whose first `hello` the primary refuses fails at once with the code and leaves no directory, metastore entry or controller behind (section 13.3). |
| `admin_shell.rs` | Writes denied at the WAL (no capability); reads checked against the gate, and a read lease held, per query (cancelled through the connection's interrupt handle). |
| `schema/scheduler.rs`, `database/schema.rs` | Shared schema excluded from fencing; registering a migration job is refused while the schema or a linked namespace denies lifecycle work (section 13.4); migration writes are WAL-gated; the scheduler's `block_writes` flag is not treated as drain evidence. |
| `namespace/configurator/helpers.rs` `load_dump`, `http/admin/mod.rs` `dump_stream_from_url` | Restore options and dump URLs are refused for fenced namespaces before the dump is fetched (section 13.5); outside a capability the loader's writes are refused at the WAL. Import goes through `ImportSession::load_dump`, which runs the same loader (`load_dump_sql`) on the capability connection. |
| `connection/program.rs` ATTACH resolution | `check_program_auth` uses a non-creating lookup; the resolver returns the attached namespace's controller, the attachment is admitted as `NormalRead` of it with a read lease, and the connection keeps a lease on it for every later program until it is detached. |
| `http/user/listen.rs` `/beta/listen` | `NormalRead`, read from the registry without loading the namespace; denied where reads are denied; the stream ends with an error event when reads are fenced. |
| Raw internal connections (storage monitor, periodic checkpoint, shutdown checkpoint, replication logger, `checkpoint_db`, bottomless) | `Maintenance` / `Observability`; not leases; never blocked. |
| DDL, autocommit, explicit transactions, batches, PRAGMAs, read-to-write upgrades | All converge on `begin_write_txn`; classification is only the early check. |

## 15. Observability (Contract)

Metrics (labels are bounded; namespace, operation id, command id, revision and caller never appear as labels):

- `libsql_server_fence_transitions_total{command, outcome}`
- `libsql_server_fence_drain_duration_seconds{kind = write | read | import}` (histogram)
- `libsql_server_fence_forced_total{kind = rollback | sql_cancel | dump_cancel | stream_termination}`
- `libsql_server_fence_replays_total{result = replay | conflict}`
- `libsql_server_fence_denials_total{code, surface = http | hrana | rpc | proxy | dump | replication | admin_shell | lifecycle}`
- `libsql_server_fence_namespaces{role, state}` (gauge)
- `libsql_server_fence_oldest_active_age_seconds` (gauge)
- `libsql_server_fence_adoptions_total`
- `libsql_server_metastore_restored_from_backup` (gauge, 0 or 1)

Every transition emits one structured log event (target `libsql_server::fence::audit`) with namespace, operation id, command id, command, outcome, revisions, state before and after, drain duration and forced actions, replay/conflict, server instance, and for adoption the approvers and incident reference.

Implementation (`namespace/fence/audit.rs`):

- **One event per command answered.** `FenceController::execute` (every command but `CreateTargetQuarantined`) and `NamespaceStore::create_target_quarantined` run the command on their own task under the transition lock and, before releasing it, emit one `info` event and count it in `libsql_server_fence_transitions_total{command, outcome}`: `event = "namespace_fence_command"` for an answer (`APPLIED`, `ALREADY_APPLIED`, `DRAINING`, with `replay = none | replay | resume`, where `resume` is a replay of a `DRAINING` command that picks its drain up again), `"namespace fence command refused"` for a refusal (the outcome code and `detail`, the expected revision, the error text, `replay = conflict` for `FENCE_COMMAND_CONFLICT`); a committed adoption is `event = "namespace_fence_adopted"` with the fields of section 12. `state_before` is the published state when the command took the lock; `drain`/`drain_ms` and `forced` are what the command's drain did. A command refused before it reaches the controller (a namespace that cannot be loaded for an acquisition, an admin request that fails validation) is not a transition and emits nothing. A non-fence failure is counted with `outcome = "ERROR"`.
- **Drain duration** is observed when a drain is proven, from the start of the wait (after the `*_DRAINING` commit, or the replay that resumes it) to the proof; a drain that answers `DRAINING` is not observed.
- **Forced actions** are counted when the drain acts: `rollback` per connection manager holding a writer when `force_rollback` fires (write and import drains); `sql_cancel`, `dump_cancel` and `stream_termination` per read lease the read drain asks to stop at its deadline.
- **Replays**: `result = replay` for an answer that was a replay or a resumption, `result = conflict` for a command-id reuse.
- **Denials** are counted at the surface that refuses: `http` (every fence error answered as an HTTP error body: legacy `/`, the admin API's lifecycle refusals, schema errors), `hrana` (step and request errors on `/v1`, `/v2`, `/v3`, cursors and WebSocket), `rpc` (the primary's proxy service: step errors carrying `stable_code` and typed statuses), `proxy` (a replica mapping a denial its primary returned), `dump` (refused or cancelled `/dump`), `replication` (the replication service), `admin_shell` (a query the admin shell's read admission refuses; a write the WAL gate refuses inside the admin shell is not counted separately) and `lifecycle` (the lifecycle checks of section 13.5 and the metastore's config-write and delete refusals). A denial is counted once at each surface it crosses: a lifecycle refusal over the admin API is `lifecycle` and `http`; a write through a replica is `rpc` on the primary and `proxy` plus the user protocol on the replica.
- **Gauges** are computed from the fence registry when `/metrics` is read: `libsql_server_fence_namespaces{role = source | target | unknown, state}` for every state a record or an unavailable namespace can be in (each pair is written, so an emptied state reads 0; `unknown` is `UNKNOWN_UNAVAILABLE`), and `libsql_server_fence_oldest_active_age_seconds` from the oldest active record's creation time (0 when there is none).
- `libsql_server_fence_adoptions_total` counts committed adoptions; `libsql_server_metastore_restored_from_backup` is set at startup (section 13.3).

## 16. Test strategy (Design)

- **No new dependency.** The crate has no failpoint library. Race tests use `#[cfg(test)]` hooks: `FenceTestHooks` holds named points (`AfterInstallingGate`, `AfterClosingReads`, `BeforeReadLeaseCancel`, `BeforeMetastoreCommit`, `AfterMetastoreCommit`, `BeforeGatePublish`, `InBeginWriteTxnAfterCheck`, `AfterManagerRelease`, `BeforeBoundaryCapture`, `AfterTargetRowsCommitted`, `BeforeResponse`), each able to park the task on a pair of `Notify`s (`pause_at` returns handles to wait until the task arrives and to release it) or to inject an error or an indeterminate commit. An armed point fires once. `BeforeMetastoreCommit` is reached immediately before the metastore transaction is started (an injected error there is a failure before commit); an injected indeterminate outcome at `AfterMetastoreCommit` is a commit that happened but was not acknowledged. Hooks compile only in the library's own test build, so they cost nothing in release builds; integration tests under `tests/` cover protocol behaviour and do not rely on hooks.
- **Restart** at a boundary: reopen `MetaStore` and rebuild the registry on the same temporary directory, the way existing metastore tests do; integration tests stop and start a `TestServer` on the same path.
- **Restart** at a boundary, as a crash: `namespace::fence::tests` runs each server lifetime on a runtime of its own and ends it by shutting the runtime down without any shutdown code and leaking the `NamespaceStore`, with the command parked at the hook point; the next lifetime opens a new `NamespaceStore` (metastore and registry) on the same directory. The namespace's `.sentinel` stays behind, so the restart takes the real dirty-recovery path.
- **Response loss**: the test drops the command future after `AfterMetastoreCommit` and then replays or inspects.
- An armed `Indeterminate` at `BeforeMetastoreCommit` reports a commit as indeterminate without running it: a commit that failed without applying but whose outcome the controller cannot know.
- **Representative schemas**: synthetic multi-table schemas with indexes, triggers, views and an FTS5 table (FTS5 is compiled in).
- `TXN_TIMEOUT` is 100 ms in test builds; drain tests that hold a writer longer than that use their own `txn_timeout` or a hook, never a sleep.

## 17. Acceptance tests map

Planned test names; the table is updated as tests land.

| # | Requirement | Planned tests |
|---|---|---|
| 1 | Concurrent acquisition by two operations: one owner, typed conflict for the loser | landed: `namespace::fence::drain::tests::acquire_race_single_owner` (the first acquisition is parked after closing admission while the second waits on the transition lock); over the admin API: `tests::fence::admin::concurrent_acquire_one_owner` (two operations acquire at once over HTTP: one `200 APPLIED`, the other `409 FENCE_OWNED_BY_ANOTHER_OPERATION` with the winner in its fence view); admin walks: `tests::fence::admin::{source_walk_over_http, target_walk_over_http, inspect_reports_drain_counters, mutating_routes_require_admin_key}` |
| 2 | Active writer commits or is rolled back before freeze acknowledgement; nothing commits after | landed: `namespace::fence::drain::tests::{active_writer_commits_before_ack, forced_rollback_before_ack, no_commit_after_ack}` (the boundary equals the last committed replication frame and no frame follows it; autocommit, `BEGIN IMMEDIATE`, DDL and a pre-fence read transaction upgrading are refused), `installing_gate_closes_writes_before_persisting`, `refused_acquire_reopens_writes`, `release_reopens_with_new_generation` |
| 3 | Autocommit, explicit transactions, queued writers, batches, DDL, schema jobs, old WebSockets, read-to-write upgrades cannot bypass | landed: `connection::connection_manager::fence_tests::{fence_rejects_read_to_write_upgrade, fence_rejects_ddl_and_pragma, fence_rejects_raw_with_raw_write}` (autocommit, explicit transactions, DDL, header-writing pragma, `BEGIN IMMEDIATE`, `VACUUM`, `with_raw` users); `connection::connection_manager::fence_tests::fence_rejects_queued_writer` (a writer parked in the queue behind an open transaction leaves it with `MIGRATION_WRITE_FENCED` when the fence changes, and the holder keeps the slot); maintenance and vacuum under a fence: `queued_checkpoint_survives_fence_wake`, `checkpoint_allowed_while_fenced`, `vacuum_skipped_while_fenced`; drain primitives: `abort_active_tolerates_closed_connection`, `release_notifies_drain_waiters`, `fence::controller::tests::write_queues_are_woken_on_every_generation_change`; schema jobs: `schema::scheduler::test::fence::{acquire_rejects_shared_schema (a shared schema and a linked namespace cannot be fenced; a fenced namespace cannot be linked by create or config), migration_not_registered_while_linked_namespace_fenced}`; old WebSockets and batches over the protocols: `tests::fence::protocol::{old_ws_session_cannot_write (a WebSocket session whose transaction began before the fence cannot write while fenced nor after the release; after a rollback the same session writes), batch_denied_mid_batch (the read before the write runs, the write step gets the code, a step conditional on it is skipped and one conditional on its failure runs)}` |
| 4 | Program that captured config before the fence is rejected at the WAL | landed: `connection::connection_manager::fence_tests::wal_gate_rejects_program_admitted_before_fence` (a SQL function parks the program between admission and its write while the fence is acquired and released) |
| 5 | Pre-fence transactions cannot write after release or publication | landed: `connection::connection_manager::fence_tests::stale_generation_cannot_write_after_release`, `namespace::fence::target::tests::stale_generation_cannot_write_after_enable_writes`; unfenced behaviour unchanged: `unfenced_namespace_is_unchanged` |
| 6 | Acquisition timeout returns `DRAINING`, admission stays closed | landed: `namespace::fence::drain::tests::{deadline_returns_draining_and_stays_closed, replay_of_draining_resumes_and_completes}` |
| 7 | Restart at every persistence boundary; indeterminate persistence keeps the gate closed until same-command reconciliation | landed: `namespace::fence::tests::restart_at_each_boundary` (a crash at each of 17 boundaries of `AcquireSourceWriteFence` and `ReleaseSourceWriteFence`: after the `INSTALLING` gate, before, at and after each metastore commit, with and without a lagging marker, before publication, before boundary capture and before the response; the restart recovers the prior or the committed state, admits writes only if an opening transition committed, repairs the marker, and a replay finishes the command), `restart_in_draining_waits_for_the_same_command` (a writer active at the crash; nothing advances until the same command is replayed, which completes at once), `indeterminate_commit_keeps_gate_closed` (through the drain path, both when the commit happened and when it did not), `acquire_response_loss_resolved_by_replay_and_inspect`; `fence::controller::tests::{indeterminate_commit_keeps_writes_closed_until_replayed, indeterminate_commit_that_did_not_apply_is_retried_by_replay, failed_before_commit_leaves_gate_unchanged, publication_happens_before_the_response, committed_command_is_published_when_the_caller_goes_away}`, `namespace::store::fence_tests::restart_installs_the_durable_gate_before_serving`; the read fence, the seal and write enable: `namespace::fence::tests::read_and_target_boundaries::restart_at_each_read_and_target_boundary` (a crash at each of 29 boundaries of `SetSourceReadFence`, `SealTargetImport` and `EnableTargetWrites`: after the read-closing or `INSTALLING` gate, before, at and after each metastore commit, with and without a lagging marker, before publication, before the response, and while the drain waits for a reader or an import call that was running when it started; the restart recovers the prior or the committed state with no in-memory gate, reader or import call surviving, keeps reads closed once `SOURCE_READ_DRAINING` committed and import closed once `TARGET_IMPORT_DRAINING` committed, admits target writes only if `TARGET_WRITABLE` committed, repairs the marker, and a replay completes an interrupted drain at once or returns the stored result); the rebuilt log after a restart: `namespace::fence::tests::current_log_id_is_the_rebuilt_log_after_restart` (the stored record keeps the acquisition log and its boundary; the controller's `current_log_id`, which the admin view reports, names the rebuilt log); integration restarts: `tests::fence::lifecycle::{restart_keeps_fence (a graceful same-path TestServer restart reconstructs SOURCE_WRITE_FENCED, SOURCE_READ_FENCED, TARGET_QUARANTINED and TARGET_WRITE_FENCED admission before traffic, exact command replays return their stored receipts, and the user protocol observes the same denials), restart_after_enable_writes_stays_writable (TARGET_WRITABLE stays readable/writable after restart and exact EnableTargetWrites replay returns the stored receipt)}` |
| 8 | Evict and lazily reload a fenced namespace; identical admission | landed: `tests::fence::lifecycle::evicted_namespace_reloads_same_gate` (a one-entry namespace cache is put under capacity pressure by four other loaded namespaces; a user-protocol reload of the fenced namespace keeps the exact revision and generation, serves reads and returns `423 MIGRATION_WRITE_FENCED` for writes); unit-level identity: `namespace::store::fence_tests::evicted_namespace_reloads_with_the_same_controller`, `fence::registry::tests::seeded_from_load_fences_including_recovered_names` |
| 9 | Filesystem recovery, `destroy_on_error`, undecodable records, missing target quarantine, metastore backup rollback fail closed with provenance | `meta_store::fence_tests::recovery::{fs_recovery_with_marker_unavailable, destroy_on_error_keeps_fenced_unavailable, undecodable_row_unavailable, incomplete_target_unavailable, metastore_rollback_detected_by_marker, lookup_never_creates, undecodable_name_with_fence_fails_startup, marker_in_invalid_directory_fails_startup}`; legacy behaviour kept: `destroy_on_error_without_fences_is_unchanged`, `undecodable_row_without_fences_is_skipped_as_before`; `meta_store::fence_tests::corrupt_fence_row_fails_closed`; restore provenance: `namespace::meta_store::fence_tests::provenance::{bottomless_restore_is_reported (a real bottomless restore against a local S3 endpoint: a metastore opened on an empty directory from a backup reports the restore and its generation and holds the backed-up namespace; one opened with nothing to restore does not), generation_only_after_a_recovery, not_restored_until_recorded_and_first_record_wins}`, `http::admin::fence::tests::restore_provenance_is_reported` (fence view and capability `metastore` object), `tests::fence::admin::capabilities` (not restored: capability endpoint, fence views and the gauge report it) |
| 10 | Wrong owner, stale revision, invalid role/state, replay, command-id reuse; replay before revision check | `fence::transition::tests::*` (exhaustive over states × commands) |
| 11 | Target creation raced with SQL, dump, replication, lifecycle never observable as writable or readable | landed: `namespace::fence::target::tests::create_race_never_observable` (parked after the rows commit and before the config is published and the namespace loaded: SQL connections, stats, replication `hello` (never `UNAVAILABLE`), create, delete and fork of the name are denied or find nothing; afterwards the target is loaded behind the quarantine gate, SQL reads and WAL writes are refused, and lifecycle and replication are refused with `MIGRATION_TARGET_QUARANTINED`), `creating_gate_refuses_before_commit` (parked before the metastore transaction: the same attempts are refused and no database file is created), `create_replay_completes_interrupted_creation` (marker only, after a restart), `create_completes_when_the_caller_goes_away`, `indeterminate_create_is_completed_by_replay`, `create_rejects_existing_name` (a loaded or cold existing name, whose gate never moves, and another operation's target), `abort_keeps_traffic_denied` (also across a restart) |
| 12 | Only the matching import capability writes a quarantined target; admin credentials and admin shell cannot | landed: `namespace::fence::import::tests::import_requires_matching_capability` (plain connections with and without raw access, as the admin shell uses; issuing to another operation or at another revision; at the WAL, capabilities the server never issued, of another operation, at another revision, for validation, and revoked); `namespace::fence::target::tests::{create_race_never_observable, abort_keeps_traffic_denied}` (raw DDL refused); planned: `tests::fence::admin::admin_shell_cannot_write_quarantined` |
| 13 | Seal enters `TARGET_IMPORT_DRAINING`, waits, reaches `TARGET_VALIDATING`, cannot resume import; only a durable validation receipt permits idempotent publication | seal landed: `namespace::fence::import::tests::{seal_waits_for_import_writers (an import call parked inside its write transaction: import is closed at once, the transaction commits, and the seal reaches its completion commit only afterwards), seal_deadline_leaves_import_draining_until_replayed (an idle session's open transaction; `DRAINING`, also across a restart; another operation refused, the owner's new seal joins; the replay completes), seal_force_rollback_ends_open_import_transaction, sealed_target_rejects_import}`; validation/publication landed: `namespace::fence::target::tests::{validation_session_is_read_only (query-only plus WAL defence, live capability checks, server snapshot and a concurrent exact replay while the receipt is committed but not published), publish_requires_validation_receipt, publish_is_idempotent}` |
| 14 | Enable writes idempotent, survives restart and response loss, irreversible | landed: `namespace::fence::target::tests::{enable_writes_idempotent_and_irreversible, enable_writes_survives_restart}` |
| 15 | Lost `EnableTargetWrites` response resolved from receipt/state | landed: `namespace::fence::target::tests::enable_writes_response_loss_resolved` |
| 16 | Read fence drains SQL, dump, `log_entries`, `snapshot`, including dead peers and forced termination | SQL landed: `namespace::fence::read::tests::{read_fence_waits_for_running_program, program_after_closing_gate_is_refused (parked after the read-closing gate, before the CAS), read_fence_cancels_at_deadline, unreleased_lease_answers_draining_and_replay_completes, idle_txn_fails_on_next_program, clear_read_fence_reopens_reads_not_writes, refused_read_fence_reopens_reads, attach_of_read_fenced_namespace_denied}`, `admin_shell::fence_tests::admin_shell_read_denied`; dump and replication landed: `namespace::fence::stream::tests::{dump_lease_released_on_cancel (a dump blocked mid-row on a peer that stopped reading is cancelled at the deadline, its lease released without the peer, the fence acknowledged, and the body ends with the fence error and no `COMMIT;`), read_fence_waits_for_dump, dump_refused_while_read_fenced, log_entries_stream_ends_typed, stream_lease_released_without_peer_read (a dead peer), snapshot_stream_ends_typed, replication_calls_denied_while_read_fenced, read_fence_forced_termination}`; the response `/dump` returns: `namespace::fence::stream::tests::dump_response_aborted_on_cancel` (a dump cancelled by the read drain fails its response body, with the fence error and no `COMMIT;`); over HTTP: `tests::fence::protocol::dump_codes` (complete under a write fence; `423` + code under a read fence and on a quarantined target) |
| 17 | Delete, reset, fork, restore, config, schema mutation rejected | landed: `tests::fence::lifecycle::lifecycle_rejected_while_fenced` (over the admin API, for a write-fenced source and a quarantined target: delete, fork as source and as destination, create with a `dump_url` whose file does not exist, create over the record, linking to a shared schema at creation and config `POST` are all `423` with the fence code; state, revision and data are unchanged and no copy exists; a target cannot be created with a shared schema; after release the source takes writes and config, fork and delete work again); `namespace::store::fence_tests::{reset_refused_while_fenced (called directly and as the replicator's reset callback; after release reset works and wipes the data), lifecycle_refused_while_fenced (fork either side, create over, delete, config and shared-schema link in the metastore transaction)}`; `schema::scheduler::test::fence::{acquire_rejects_shared_schema, migration_not_registered_while_linked_namespace_fenced}` |
| 18 | Codes through HTTP, Hrana, RPC, dump, replication, replica write proxy; distinguishable from auth/timeout/not-found; old peers compatible; no retry loops | user protocols landed: `tests::fence::protocol::{http_codes (legacy `/`, `/v1/execute`, `/v1/batch` for a write-fenced write, a read-fenced read, a quarantined target and a namespace whose marker cannot be decoded: `423` with `code`, and `detail` where there is one), hrana_http_codes (`/v2`, `/v3` pipelines and `/v3/cursor`: step and whole-request errors carry the code and the baton stays usable), hrana_ws_codes (the same over a WebSocket, whose stream reads again after the read fence is cleared), dump_codes, auth_and_not_found_distinct (`401` without or with a wrong credential and `404` for a missing namespace, with no fence code, on the same fenced server)}`, `error::fence_tests::fence_errors_carry_code` (the body through every wrapper; `block_*`'s `Blocked` keeps its mapping); RPC and replica write proxy landed: `rpc::proxy::fence_tests::rpc_codes` (on the primary's proxy service: a write-fenced write is a step error with `SQL_ERROR` + `stable_code`, reads are served, a read-fenced read is a program error with the code when streamed and the typed `FAILED_PRECONDITION` status when unary, and a namespace whose fence state is unknown is refused with the typed status before any connection), `rpc::proxy::fence_tests::replica_maps_proxied_denials` (step, program and connection-status denials become the fence error on the replica; an older primary's error without `stable_code`, an unknown code and other errors keep their mapping), `namespace::fence::outcome::tests::peer_denials_round_trip`, `tests::fence::protocol::{replica_proxy_preserves_code (writes through a replica to a write-fenced primary: `423` + `MIGRATION_WRITE_FENCED` on legacy `/` and `/v1/execute`, the step error on `/v1/batch`, the Hrana error code on `/v2` and `/v3`; reads on the replica served; writes through the replica work after release), denial_not_retried (each refused write is delegated exactly once and answered well within the write proxy's first retry backoff)}`; capability: `tests::fence::admin::capabilities` asserts `proxy_stable_code: true`; replication and replica servers landed: `tests::fence::protocol::{replication_codes (a raw peer of the primary's internal replication service: `hello` carries the write fence's state and revision, an open `log_entries` stream ends with `FAILED_PRECONDITION` + `x-libsql-fence-code` `MIGRATION_READ_FENCED` under the read fence, `hello`, `log_entries` and `snapshot` are then refused with it, `hello` is answered again after the clear and carries no fence after release, and a quarantined target refuses `hello` with `MIGRATION_TARGET_QUARANTINED`), replica_reads_denied_while_source_read_fenced (the replica refuses local reads with `423` + `MIGRATION_READ_FENCED` on legacy `/` and `/v1/execute` and the Hrana code on `/v2` within 500 ms of simulated time after the read fence is acknowledged, and still 30 s later), replica_backs_off_on_fence_code (4 to 9 refused, counted attempts over 60 s of simulated time; a fixed 1 s retry makes 57), replica_resumes_after_clear_read_fence (reads served again within 16 s of the clear, and a write after release is replicated), replica_lazy_creation_refused_by_fence (a read of a quarantined target through a replica that has never loaded it answers `423` + `MIGRATION_TARGET_QUARANTINED` within 500 ms of simulated time, twice, leaving no `dbs/<name>` directory; a directory that was already there is kept; after publication the replica creates and serves the name, and after enable-writes a write through it succeeds)}`, `namespace::meta_store::fence_tests::forget_unstored_only_unused_unstored_entries`, `namespace::fence::registry::tests::forget_idle_only_unreferenced_plain_controllers`, `namespace::fence::replica::tests::{refusal_from_typed_status_only, hello_fence_denies_only_read_denying_states, backoff_doubles_to_its_cap, observed_denial_refuses_local_reads_and_cancels_leases}`; landed: `libsql-replication` `rpc::test::{proxy_error_stable_code_is_additive, replicated_fence_is_additive}` (each new field is skipped by a peer that does not know it, absent from an older peer's message, and absent fields encode exactly as before), `namespace::fence::stream::tests::hello_carries_replicated_fence` (no fence before acquisition and after release; state and revision while write-fenced; the stored configuration never carries it) |
| 19 | Corrupt or unknown durable fence state fails closed | `fence::store::tests::corrupt_payload_fails_closed`, `unknown_format_version_fails_closed` |
| 20 | Metrics and audit logs | landed: `namespace::fence::audit::tests::{audit_event_fields (one event per answer: a committed drain with state before and after, revisions, drain kind and duration and forced actions; a replay; a command-id conflict with its code; a non-fence failure), adoption_event_fields, metrics_and_bounded_labels (every metric of section 15 with its labels, denials at all eight surfaces, the gauges per role and state including zeroed states and the oldest active age; no label value is a namespace, operation or command id)}`; over a running server: `tests::fence::observability::metrics_and_labels` (a write drain with a forced rollback, a replay, a conflict, a Hrana write denial and a lifecycle refusal over the admin API: transitions, replays, forced, drain histogram, denials under `hrana`, `lifecycle` and `http`, the namespace gauge and oldest-age gauge before and after release, and only bounded label keys and values) |
| 21 | Capability discovery and mixed-version protection | capability discovery landed: `tests::fence::admin::{capabilities, capabilities_when_disabled}`; legacy mirror and foreign-key guard landed: `namespace::fence::tests::legacy_mirror::legacy_mirror_and_fk_guard` (a source and two targets walked through every stored state: the config row's `block_*` fields hold the mirror of section 13.2 and nothing else in the row changes, a config write is refused and changes nothing, an older binary's delete fails on the foreign key; release and write enable restore the namespace's own values, later config writes are stored as written, and after a restart the rows are unchanged and the in-memory config holds the namespace's own values, including a config written after the release); an older binary is not run (bounded, see section 18) |
| 22 | Adoption is two-person/audited, keeps admission closed, cannot reverse publication | landed: `namespace::fence::tests::adoption::{adopt_requires_key_and_two_approvers (no key, one approver, duplicate or blank approvers, three approvers, blank incident or reason: `adoption_not_authorised`, nothing changes), adopt_keeps_gates_closed (write-fenced source: owner and revision move, state, admissions, boundary and saved values do not, writes still refused, replay with or without the key returns the receipt, old owner `FENCE_OWNED_BY_ANOTHER_OPERATION`, new owner releases), adopt_quarantined_target (the import capability moves to the new owner; SQL still `MIGRATION_TARGET_QUARANTINED`), adopt_cannot_touch_writable (`TARGET_WRITABLE`, `TARGET_ABORTED`), adopt_cannot_touch_released, adopt_recovers_metastore_rollback (fence row gone, and fence row at an older revision: re-established from the marker, served again behind the same gate, own `block_*` values back in memory, new owner finishes), adopt_recovered_name_without_config_row (`namespace_config_missing`, nothing written, still unavailable), adoption_key_matching}`, `namespace::fence::audit::tests::adoption_event_fields`; pure transition: `namespace::fence::transition::tests::{adopt_requires_key_and_two_approvers, adopt_keeps_gates_closed}`; over HTTP: `tests::fence::admin::{adopt_over_http (no key, wrong key, no admin credential, bad approvers, unknown field, success, replay, old and new owner, finished operation), adopt_disabled_without_key}` |
| — | Import API usable by bulk import | landed: `namespace::fence::import::tests::import_session_loads_dump_into_quarantined_target` (a dump exported by the server from a source with tables, keys, a foreign key, an index, an autoincrement table, a trigger, a view and an FTS5 table loads through `ImportSession::load_dump`; after the seal the target's schema, rows, view and full-text results equal the source's) |

## 18. Limits

What this design and its tests do not prove:

- **Mixed-version behaviour** is tested at the data and wire level (legacy mirror, foreign-key guard, proto unknown-field handling, capability endpoint), not by running an older binary against the same metastore.
- **Representative data** is synthetic. Real production schemas are not part of the test suite.
- **Client retry policy** of SDKs was not audited; the server guarantees only that fence denials use codes that are not conventionally retried.
- **"Commit unknown"** is the caller's classification when neither replay nor inspection answers; the server's part is that replay and inspection always answer when the server is reachable.
- **Two-person adoption** is a separate secret plus a recorded two-approver request, not verified identities.
- **Delivered data** cannot be recalled: bytes already sent, frames held by embedded replicas, and a replica server partitioned from the primary are outside the server's reach.
- **Older replica servers** stop replicating under a read fence but keep serving local reads of what they already hold; only a replica server that understands the replicated fence (section 6.2) denies them.
- **A replica server's local read denial is not part of the positive read drain.** The primary proves that its own reads and streams have ended; a newer replica installs its denial when its ended stream reaches it, a moment after the drain completes, and one partitioned from the primary keeps serving what it holds. The operation proves replica convergence separately.
- **Metastore rollback detection** relies on the namespace directory's marker. If both the metastore and the namespace directory are lost or restored from backup together, the server cannot detect that a newer fence existed; the caller's durable intent is authoritative then.
- **Release and pinning** of a server build that contains the fence are outside this change.

## 19. Module layout and commit series (Design)

```text
libsql-server/proto/namespace_fence.proto
libsql-server/src/generated/namespace_fence.rs
libsql-server/src/namespace/fence/
    mod.rs          re-exports, FENCE_PROTOCOL_VERSION
    state.rs        Role, FenceState, OperationClass, permission matrix
    outcome.rs      FenceOutcome, FenceError, protocol mappings
    command.rs      FenceCommand, fingerprint
    transition.rs   pure apply()
    record.rs       NamespaceFenceRecord, CommandReceipt, encode/decode
    store.rs        metastore tables, fence CAS, marker file
    registry.rs     FenceRegistry
    controller.rs   FenceController, GateSnapshot, generations, leases
    drain.rs        FenceController::execute, source write drain
    read.rs         source read fence and its drain
    stream.rs       stream leases: FencedStream for replication, dump cancel
    replica.rs      a replica server's view of the primary's fence, reconnect back-off
    target.rs       quarantined target creation, ValidationSession
    capability.rs   MigrationCapability, CapabilityPurpose, ImportWriter
    import.rs       ImportSession, SealTargetImport drain
    audit.rs        audit events and metrics
    hooks.rs        cfg(test) FenceTestHooks
libsql-server/src/http/admin/fence.rs
```

Planned commits, each leaving the crate building with its tests passing:

1. `libsql-server: document namespace fence contract` (this document)
2. `libsql-server: add namespace fence types and transition logic`
3. `libsql-server: persist namespace fences in the metastore`
4. `libsql-server: fail closed on ambiguous metastore recovery`
5. `libsql-server: add fence registry and controller, install before first connection`
6. `libsql-server: gate write transactions at the WAL by admission generation`
7. `libsql-server: positive source write drain`
8. `libsql-server: source read fence with read and stream leases`
9. `libsql-server: quarantined target lifecycle and migration capabilities`
10. `libsql-server: namespace fence admin API and capability discovery`
11. `libsql-server: deny lifecycle operations on fenced namespaces`
12. `libsql-replication: add stable error code and replicated fence to protocols`
13. `libsql-server: typed fence outcomes across HTTP, Hrana, RPC, dump and replication`
14. `libsql-server: test legacy fence mirror and read/target crash boundaries`; `libsql-server: fence restart and eviction integration tests`
15. `libsql-server: namespace fence adoption`
16. `libsql-server: namespace fence metrics and audit log`

## 20. Positions on specific hazards

| Hazard | Position |
|---|---|
| One WAL choke point for primary connections | The gate lives in `ManagedConnectionWalWrapper::begin_write_txn`; nothing else is authoritative. |
| Writers outside the wrapper (logger's raw connection, `checkpoint_db`, bottomless restore, fork copy) | Logger and `checkpoint_db` are maintenance and never change logical contents. Bottomless restore and fork copy are lifecycle operations and are denied at the lifecycle layer. |
| Fresh transactions are visible at `begin_read_txn` | Used to capture `txn_generation`. |
| `SQLITE_BUSY` is retried and the error path releases a slot it may not hold | Check before `acquire()`, return `SQLITE_AUTH`, carry the typed reason out of band. |
| Waking queued writers | Reuse the `sync_token` mass-wake shape. |
| Frozen boundary | Captured with no writer holding the manager slot, after `insert_frames` published it. |
| `VACUUM` | Not maintenance; skipped while writes are fenced. |
| ATTACH of a fenced namespace | Checked as a `NormalRead` of the attached namespace through a non-creating lookup. |
| Open-default `handle()`, including ATTACH authorisation and replica lazy creation | Non-creating lookups on read paths; creating paths refuse names with a record or marker; a replica's lazy creation that the primary's fence refuses fails with the code and is undone (section 13.3). |
| `process()` publishing unpersisted config | Fixed for all config writes. |
| The scheduler's second metastore connection | Fence CAS and config writes use `BEGIN IMMEDIATE`; shared schema is excluded. |
| Replica servers inherit config | Additive `ReplicatedFence` in `hello`; the typed terminal status installs a local read denial on a newer replica server, with a capped reconnect back-off (section 6.2). The legacy `block_*` mirror exists only in the stored config row (section 13.2), so it does not reach replica servers. |
| Proxy errors lose their type | Additive `stable_code = 4`. |
| Write proxy retries `UNAVAILABLE` forever | Fence denials are never `UNAVAILABLE`. |
| Admin API has no principal and may have no key | Fence mutators require a configured key; adoption requires a second key and two recorded approvers. |
