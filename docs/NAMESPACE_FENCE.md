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
    "provenance": { "metastore_restored_from_backup": false, "marker": "consistent" }
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
2. Compute the fingerprint: SHA-256 over the deterministic protobuf encoding of the command *including* namespace, `operation_id`, command kind and every argument, *excluding* `command_id`.
3. Look up `(namespace, operation_id, command_id)`:
   - found, same fingerprint, final outcome: return the stored result with `"replayed": true`. This holds even though the revision has since advanced.
   - found, same fingerprint, in-progress (`DRAINING`, or an indeterminate commit being reconciled): resume that same command (section 8.4).
   - found, different fingerprint: `FENCE_COMMAND_CONFLICT`. Nothing changes.
4. Only a non-replay proceeds: owner check (`FENCE_OWNED_BY_ANOTHER_OPERATION`), role and transition check (`INVALID_FENCE_TRANSITION`, with `detail: role_mismatch` where the role is wrong), `expected_state` and `expected_revision` (`FENCE_REVISION_MISMATCH`), then command-specific preconditions (`FENCE_PRECONDITION_FAILED`).
5. A command from the owner that asks for the state the record is already in (for example `EnableTargetWrites` when already `TARGET_WRITABLE`) returns `ALREADY_APPLIED`, records a receipt so its own replay is stable, and does not change the revision.

The pure part of this — steps 3 to 5 as `apply(record, receipts, command) -> (next record, receipt, outcome)` — is a function with no I/O and is unit-tested exhaustively.

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

`try_process` today publishes the new config to the in-memory watch even when persisting failed. That is fixed for all config writes: the watch is updated only after commit, and the error is returned.

### 5.5 Receipt retention (Contract)

Receipts of the operation that currently owns a record are never pruned. Receipts of finished operations (`RELEASED`, `TARGET_WRITABLE`, or superseded by adoption) are kept for at least `--namespace-fence-receipt-retention` (default 30 days) and are pruned only inside a later transition on the same namespace. Delete of a namespace in `UNFENCED`, `RELEASED` or `TARGET_WRITABLE` removes its fence row and receipts in the same transaction and logs them.

### 5.6 On-disk marker

Each fenced namespace directory holds a small file `dbs/<namespace>/.fence` containing `format_version`, `operation_id`, role, state and revision. It is written (and fsynced) **after** the metastore commit of each transition, and **before** the metastore transaction for `CreateTargetQuarantined` (section 10.1). It exists so that recovery paths that lose or roll back the metastore can tell a fenced namespace from a legacy one:

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
- `FENCE_PRECONDITION_FAILED` carries `detail`, one of: `admin_auth_required`, `fence_disabled`, `not_primary`, `shared_schema_unsupported`, `namespace_identity_mismatch`, `namespace_exists`, `validation_receipt_required`, `restore_not_allowed`, `adoption_not_authorised`.
- **Data-plane denials are never `500`, `503`, `429` or gRPC `UNAVAILABLE`.** `423 Locked` is chosen because common HTTP clients do not retry it. The JSON error body of the user HTTP API gains an additive `"code"` field (`{"error": "...", "code": "MIGRATION_WRITE_FENCED"}`); the existing `Blocked` error (from `block_reads`/`block_writes`) keeps its current mapping.
- gRPC statuses carry the code in the `x-libsql-fence-code` metadata entry and as the message prefix `"<CODE>: "`.
- Authentication (`401`), missing namespace (`404`), timeouts and transport errors are distinct from all of the above.

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

This is additive in proto3: older peers skip the unknown field; a newer replica treats an absent field as "no typed outcome". For fence denials the primary sets `code = SQL_ERROR` and `stable_code`. The replica threads `stable_code` through `Error::RpcQueryError` into the same user HTTP status and Hrana code the primary would have returned. A fence denial at proxy connection creation is returned as `FAILED_PRECONDITION` with the metadata above, never `UNAVAILABLE`, so the replica's write-proxy reconnect loop (which retries `UNAVAILABLE` without bound) does not spin on it.

### 6.2 Replicated configuration addition

`libsql-replication/proto/metadata.proto` `DatabaseConfig` gains `optional ReplicatedFence fence = 14;` with `state` (string) and `revision` (uint64). The primary fills it from the gate in `hello`; a newer replica server uses it to deny local reads in states whose normal-read column is "deny". Older replicas ignore it and still see the legacy `block_*` mirror.

## 7. FenceController (Design)

### 7.1 Registry

`FenceRegistry` (in `NamespaceStore`, outside the moka cache) maps `NamespaceName -> Arc<FenceController>`. It is loaded from the metastore (and markers) at startup, before any namespace is served, and changes only after a durable commit. Namespaces without a record get an `UNFENCED` controller lazily. Because the registry is not the cache value, cache eviction and lazy reload reinstall the same controller (section 8.5).

### 7.2 Controller state

Per namespace:

- `transition_lock`: a `tokio::sync::Mutex` serialising commands on this namespace.
- `gate`: a `tokio::sync::watch` of `GateSnapshot { state, revision, write: Open | Closed(code), read: Open | Closed(code), write_generation, capabilities }`. The WAL wrapper, `CoreConnection`, dump, replication and lifecycle code read it without locks.
- `write_generation: u64`, stored in the snapshot and **incremented on every transition that closes or opens write admission** (acquire, release, create, seal, publish, enable, abort, adopt).
- writer tracking, provided by the namespace's `ManagedConnectionWalManager` (section 8.2).
- `read_leases`: counters and cancel handles per lease class (`sql`, `dump`, `replication`), with a `Notify` on every release.
- `capabilities`: the live `MigrationCapability` set and an import-writer counter.
- in `cfg(test)` builds only, an optional `FenceTestHooks` (section 16).

### 7.3 Operation classes

Every write-transaction request at the WAL, every read lease and every lifecycle call names a class:

| Class | Examples | Allowed when |
|---|---|---|
| `NormalWrite` | SQL over HTTP, Hrana, RPC, proxy; admin shell; schema migration; dump load outside the capability | normal-write column allows |
| `Maintenance` | `TRUNCATE` checkpoint, the manager's checkpoint slot, storage monitor | always |
| `Vacuum` | `vacuum_if_needed`, `Namespace::checkpoint`, snapshot at shutdown | normal-write column allows; otherwise skipped with a debug log |
| `CapabilityImport` | import session writes | `TARGET_QUARANTINED`, matching `operation_id`, capability revision equal to the record's, capability not invalidated |
| `CapabilityValidate` | validation reads (never writes) | `TARGET_VALIDATING`, `TARGET_WRITE_FENCED` |
| `NormalRead` | SQL programs, Hrana cursors, `/beta/listen`, ATTACH of this namespace | normal-read column allows |
| `Stream` | `/dump`, `hello`, `log_entries`, `batch_log_entries`, `snapshot` | dump/replication column allows |
| `Observability` | stats, `/v1/jobs`, metrics | always; never counted as a read lease |

### 7.4 Per-connection fence state

Every `LegacyConnection` receives a `FenceConnState` shared by its `ManagedConnectionWalWrapper` and its `CoreConnection`: the connection's class and capability (if any), `program_generation` (captured at program start), `txn_generation` (captured at `begin_read_txn` when a new read transaction starts), and a `denial` slot for the typed outcome of the last WAL refusal.

## 8. Write admission and positive drain (Design)

### 8.1 The two checks

1. **Program and lifecycle admission (early).** `CoreConnection::run` reads the *live* gate at program start. If the program contains a statement that can write and the gate denies it, it fails at once with the typed error. It records `program_generation`. Lifecycle entry points check the gate the same way.
2. **WAL `begin_write_txn` (authoritative).** In `ManagedConnectionWalWrapper::begin_write_txn`, **before** `acquire()`, the wrapper requires: the gate permits the connection's class (and capability), and `program_generation == txn_generation == gate.write_generation`. On refusal it writes the typed outcome into the `denial` slot and returns `SQLITE_AUTH` — a non-`BUSY` code, so SQLite's busy handler does not retry it, and before `acquire()`, so no slot is released that was never held. `Vm::try_step` turns an `SQLITE_AUTH` with a filled `denial` slot into `Error::Fence(outcome)`; without a filled slot the SQLite error is returned unchanged.

This makes the WAL gate independent of statement classification: DDL, misclassified PRAGMAs, `with_raw` users (admin shell, schema migrations, dump load), a program that snapshotted config before the fence, and read-to-write upgrades all converge on `begin_write_txn`.

**No deferred writes.** A read transaction opened at generation *g* cannot upgrade after any transition, because the generation has moved on. An explicit transaction opened in one program and continued in a later program fails when the later program tries to write if a transition happened in between, and the client must begin a fresh transaction.

### 8.2 Connection manager changes

- Queue entries carry the operation class (`NormalWrite`, `Maintenance`, `CapabilityImport`) and the connection id. `acquire()` for checkpoints becomes `acquire(Maintenance)`.
- On every write-generation change the controller wakes the whole write queue using the existing `sync_token` shape; each woken waiter re-checks the gate and, if denied, returns the typed error instead of waiting for a release.
- The manager exposes `active_writer() -> Option<(ConnId, OperationClass)>`, notifies a `Notify` from `release()`, and offers `abort_active()` that uses the registered rollback handle. `Abort::abort` currently panics if the connection is gone; the drain path tolerates a concurrently closing connection.
- The active writer's lease lasts until `release()`. Because `ReplicationLoggerWalWrapper::insert_frames` commits the log and publishes the new frame number before `end_write_txn` → `release()`, observing "no `NormalWrite` or `CapabilityImport` holder" under the manager's `current` lock means the committed `log_id` and `frame_no` are final.

### 8.3 Source write drain, step by step

`AcquireSourceWriteFence`, under the transition lock:

1. Replay handling and checks (section 5.3), including `expected_namespace_identity.log_id == ReplicationLogger::log_id()` and the shared-schema rejection.
2. Publish the in-memory `INSTALLING` gate: write admission closed, `write_generation += 1`. New write admissions now fail with `MIGRATION_WRITE_FENCED`.
3. Wake the write queue (section 8.2). Queued writers fail with `MIGRATION_WRITE_FENCED`.
4. CAS `SOURCE_DRAINING` in the metastore with receipt outcome `DRAINING`.
   - Committed: continue.
   - Proven not committed (the transaction failed before `COMMIT` for a precondition or constraint reason): remove the `INSTALLING` gate, bump the generation, return the error.
   - Unknown (error on `COMMIT`, task cancelled, timeout): the gate stays closed, the controller enters `Indeterminate(command_id)`, the response is `FENCE_COMMIT_INDETERMINATE`. It is never treated as not applied.
5. Wait for the active pre-cutoff writer to commit or roll back, on the manager's release notification. Elapsed time and `txn_timeout` are never evidence.
   - Deadline reached with `on_deadline: fail`: respond `DRAINING`. The durable state stays `SOURCE_DRAINING` and admission stays closed.
   - Deadline reached with `on_deadline: force_rollback`: `abort_active()`, then keep waiting for the release notification.
6. Under the manager's `current` lock, observe no writer holding the slot and read the frozen boundary (`log_id`, current `frame_no`).
7. CAS `SOURCE_WRITE_FENCED` with the boundary; update the receipt to `APPLIED`; write the marker; respond.

### 8.4 Reconciliation and resumption

- Replay of a command whose receipt says `DRAINING` resumes at step 5. After a restart there is no pre-cutoff writer (SQLite recovery discards uncommitted work), so it completes at once.
- Replay of a command held `Indeterminate` re-reads the metastore: if the row shows the command applied, it continues from that durable point; if it shows it did not, it retries the same CAS. Other commands receive `FENCE_COMMIT_INDETERMINATE` until then. After a restart the gate reflects whatever is durable, which by definition was never acknowledged as open.
- Opening transitions (`ReleaseSourceWriteFence`, `EnableTargetWrites`) follow **commit → publish the exact revision to the gate → respond `APPLIED`**. A crash after commit and before publication sends no success, and startup recovers the committed gate before exposing the namespace.

### 8.5 Restart and eviction

- At startup the registry is built from the metastore and markers before `NamespaceStore` serves anything. `make_namespace` takes the controller from the registry and passes it into the configurator's `setup()`, down to `MakeLegacyConnection::new` and every `LegacyConnection`, **before** the first connection (the maker's held `_db` connection) is created. The replication logger, dump and replication services get the same controller.
- `NamespaceStore::with` checks the registry before `handle()` or `load_namespace`: `UNKNOWN_UNAVAILABLE` is refused before any setup work.
- Idle or capacity eviction shuts the namespace down but leaves the controller in the registry; a lazy reload reinstalls the identical gate, revision and generation. A drain waiter that holds the evicted manager sees its connections close and is notified.
- Namespaces in `SOURCE_DRAINING` or `TARGET_IMPORT_DRAINING` after a restart stay closed until the same command is replayed. Nothing advances in the background.

## 9. Source read fence (Design)

`SetSourceReadFence`, under the transition lock:

1. Checks (section 5.3).
2. Close read admission in memory. New SQL programs, dump requests, replication calls and ATTACHes of this namespace fail with `MIGRATION_READ_FENCED`.
3. CAS `SOURCE_READ_DRAINING` (receipt `DRAINING`).
4. Wait for all read leases to be released:
   - **SQL:** a lease is held for the duration of each running program (including a Hrana cursor that is still producing rows). A connection that is idle with an open transaction holds no lease; its next program consults the live gate, fails, and rolls the transaction back. Idle upgraded Hrana WebSocket and HTTP streams may therefore stay open.
   - **Dump:** a lease is held for the dump stream. The exporter checks a cancel flag between rows. A cancelled dump aborts the HTTP body (the chunked transfer is not completed), so a client never receives a dump that looks complete; the dump text also never reaches its final `COMMIT;`.
   - **Replication:** `log_entries` and `snapshot` streams register a lease when created. The stream wrapper selects on the gate; on read fence it yields a terminal `FAILED_PRECONDITION` status carrying `MIGRATION_READ_FENCED` and ends. On cancel the wrapper drops the inner stream synchronously, so the lease is released even if the peer never reads again. `hello` and `batch_log_entries` are unary and are simply denied.
   - At the deadline, SQL programs are cancelled through the connection's existing progress-handler cancel flag, dumps are cancelled, and streams are terminated. The command keeps waiting for the actual releases; if a lease does not release, the result stays `DRAINING`.
5. CAS `SOURCE_READ_FENCED`; respond.

`ClearSourceReadFence` reopens reads (writes stay fenced) with a new revision.

Covered surfaces: HTTP (`/`, `/v1/execute`, `/v1/batch`), Hrana over HTTP (`/v2`, `/v3`, cursors), Hrana over WebSocket, the gRPC proxy (`execute`, `stream_exec`, `describe`), the admin shell (which runs raw SQL and is checked per query), `/beta/listen`, ATTACH from other namespaces, `/dump`, and both replication services (the internal one used by replica servers and the external one on the user port). A replica server that receives the terminal status installs a local read denial for that namespace, so it stops serving its local copy.

Transport keepalive: when the fence is enabled, the RPC server and the user-port gRPC service set HTTP/2 keepalive (`--namespace-fence-keepalive-interval`, default 30 s; timeout 20 s) so dead peers are detected; lease release does not depend on it.

Denied replication calls from old replicas are logged at most once per namespace per minute and counted, so repeated reconnects are observable rather than noisy. Newer replicas back off on the typed code (capped exponential, at most 60 s).

Internal work that must keep running is classed `Maintenance` or `Observability` and holds no read lease: bottomless WAL upload, the storage monitor's read transaction, stats and metrics.

This fence stops future service from the source. It cannot recall bytes a peer has already received, frames stored by an embedded replica, or data served by a replica server that is partitioned from the primary; the operation must prove client and replica convergence separately.

## 10. Target lifecycle (Design)

### 10.1 CreateTargetQuarantined

1. Checks (section 5.3). The name must have no config row, no fence row and no marker (`FENCE_PRECONDITION_FAILED`, `namespace_exists`).
2. Create `dbs/<namespace>/` and write the marker (`TARGET_QUARANTINED`, revision 1).
3. One metastore transaction: insert the config row (with the legacy mirror `block_reads = block_writes = true`), the fence row (`TARGET_QUARANTINED`, revision 1, new `target_incarnation_id`) and the receipt.
4. Install the controller in the registry with the quarantine gate.
5. Only now insert the config into the metastore's in-memory map (which is what makes `exists()` true) and call `load_namespace`. The first connection maker is created with the quarantine gate already in place.
6. Record the new `log_id` in the record (same revision, informational) and respond `APPLIED`.

A crash after step 2 leaves a marker with no rows: `UNKNOWN_UNAVAILABLE` until the same command is replayed, which completes it. A crash after step 3 recovers `TARGET_QUARANTINED` from the metastore.

### 10.2 SealTargetImport

CAS `TARGET_IMPORT_DRAINING` (revision + 1, so every issued import capability is invalidated and no new one can be issued); wait for the import-writer count and the manager's `CapabilityImport` holder to reach zero (same mechanism as section 8.3, with the drain policy from the request); CAS `TARGET_VALIDATING`. A timeout leaves `TARGET_IMPORT_DRAINING` durable and closed; only a replay of the same command resumes it.

### 10.3 Validation and publication

In `TARGET_VALIDATING` the operation reads through the validation capability (`validation-query`, or the internal API). `RecordTargetValidation` stores the result in the record and receipt. `PublishTargetReadableWriteFenced` requires that the most recent `RecordTargetValidation` of the owning operation has `result: ok`; otherwise `FENCE_PRECONDITION_FAILED`, `validation_receipt_required`. Publication clears the legacy `block_reads` mirror.

`EnableTargetWrites` is CAS from `TARGET_WRITE_FENCED`; commit, publish the gate with a new generation, respond. The legacy mirror is restored to the values given at creation. Replays return the stored result; a new command asking for the same thing returns `ALREADY_APPLIED`. Every other command on a `TARGET_WRITABLE` record from the same operation is `INVALID_FENCE_TRANSITION`.

`AbortQuarantinedTarget` moves to `TARGET_ABORTED`; all normal traffic stays denied.

## 11. Reusable import capability API (Design, for bulk import)

The bulk import work consumes this internal Rust API, which does not depend on any HTTP route:

```rust
// namespace::fence
pub enum TargetState { Quarantined, ImportDraining, Validating, WriteFenced, Writable, Aborted }

pub struct MigrationCapability {      // server-created, not constructible outside the module
    id: Uuid,
    namespace: NamespaceName,
    operation_id: Uuid,
    purpose: CapabilityPurpose,       // Import | Validate
    fence_revision: u64,
}

impl NamespaceStore {
    /// CreateTargetQuarantined, atomic with namespace creation.
    pub async fn create_target_quarantined(&self, req: CreateTargetRequest)
        -> Result<FenceResponse, FenceError>;

    /// Issue an import capability and a capability-bearing connection. Valid only in
    /// TARGET_QUARANTINED for the owning operation at `expected_revision`.
    pub async fn open_import_session(&self, ns: NamespaceName, operation_id: Uuid,
        expected_revision: u64) -> Result<ImportSession, FenceError>;

    /// Read-only validation connection (`query_only`), TARGET_VALIDATING or TARGET_WRITE_FENCED.
    pub async fn open_validation_session(&self, ns: NamespaceName, operation_id: Uuid,
        expected_revision: u64) -> Result<ValidationSession, FenceError>;

    pub async fn apply_fence_command(&self, ns: NamespaceName, cmd: FenceCommand)
        -> Result<FenceResponse, FenceError>;

    pub async fn inspect_fence(&self, ns: NamespaceName) -> Result<FenceView, FenceError>;
}

pub struct ImportSession { /* capability, connection, import-writer guard */ }
impl ImportSession {
    pub fn capability(&self) -> &MigrationCapability;
    /// Run a closure with the raw connection inside the capability; writes are admitted by the
    /// WAL only while the capability is valid.
    pub async fn with_raw<R: Send + 'static>(&mut self,
        f: impl FnOnce(&mut rusqlite::Connection) -> R + Send + 'static) -> Result<R, FenceError>;
}
```

`FenceError` carries a `FenceOutcome` (section 6) and converts into the server's `Error`, so a route built on top returns the same codes. Dropping an `ImportSession` decrements the import-writer count and wakes a waiting seal. The existing dump loader (`load_dump`) can run inside `ImportSession::with_raw`; this series includes a test that imports a small dump into a quarantined target that way. Streaming and memory bounds are not part of this series.

## 12. Incident adoption (Contract)

`AdoptFence` transfers ownership of an unfinished operation's record to a new `operation_id` when the original control-plane record is lost. It:

- requires the admin credential **and** the separate adoption key configured with `--namespace-fence-adoption-key` (absent: adoption is disabled, `FENCE_PRECONDITION_FAILED`, `adoption_not_authorised`), passed in the `x-libsql-fence-adoption-key` header;
- requires `approvers`: two distinct, non-empty identity strings, an `incident_ref` and a `reason`, all stored in the receipt and emitted in a structured audit log line;
- requires `expected_state`, `expected_revision` and the current `operation_id` of the record;
- changes the owner and appends to the adoption history, with revision + 1, and **changes nothing else**: gates stay exactly as they were. It cannot open source writes, move out of any state, or act on `TARGET_WRITABLE` or `TARGET_ABORTED`;
- also applies to `UNKNOWN_UNAVAILABLE` caused by a metastore rollback, where it re-establishes the record in the state the marker last recorded (the marker is written only after a commit), with the adopting operation as owner.

The server cannot verify who the approvers are: the admin API has one shared key and no principal. "Two-person" is enforced as a separate secret plus a recorded two-approver request; real two-person control belongs to whatever holds those secrets.

## 13. Deployment and compatibility (Contract)

### 13.1 Deployment flag

`--enable-namespace-fence` (env `SQLD_ENABLE_NAMESPACE_FENCE`), **default off**. The flag controls *use*, not enforcement:

- Off, and no fence tables exist: behaviour is unchanged, except the `try_process` persistence fix (section 5.4). The capability endpoint reports `enabled: false`; fence routes return `404`.
- Off, but fence tables or markers exist (the flag was turned off after use): fences are still loaded and enforced; mutating routes are disabled.
- On: tables are created, routes are served, and the fail-closed recovery rules of section 13.3 apply.

Related flags: `--namespace-fence-receipt-retention`, `--namespace-fence-adoption-key`, `--namespace-fence-keepalive-interval`, and default drain deadlines `--namespace-fence-default-write-drain-ms` and `--namespace-fence-default-read-drain-ms` (used when a request has no `drain_policy`).

Upgrade order: deploy a binary with capability discovery and proxy `stable_code` support on every primary and replica; confirm with `GET /v1/fence/capabilities`; then enable the flag; then use fences. Rollback to a binary without fence support is refused by deployment tooling while `active_fences > 0`.

### 13.2 Protection against an older binary

An older binary does not know the fence tables. While a record is active:

- the config row's `block_reads`, `block_writes` and `block_reason` are mirrored from the fence state in the same transaction (`block_writes` in every state that denies writes, `block_reads` in every state that denies reads, `block_reason = "namespace fence: <STATE> (operation <id>)"`), and restored when the operation finishes;
- the foreign key from `namespace_fences` to `namespace_configs` makes an older binary's namespace delete fail.

This is best effort. An older binary applies `block_*` at statement level only, lets its admin shell and `/dump` bypass them, and would let a config update overwrite them. It is a mitigation for an accidental rollback, not a guarantee; the guarantee is the deployment order above.

### 13.3 Fail-closed metastore recovery

With the flag on, or whenever fence tables or markers exist:

- `MetaStore::handle()` no longer default-creates entries on read paths. `NamespaceStore::with`, `checkpoint`, ATTACH authorisation and `check_program_auth` use a non-creating lookup; only create, fork destination and replica lazy creation create, and they refuse names that have a fence record or marker.
- `restore()`: an undecodable namespace name, config or fence row marks that namespace `UNKNOWN_UNAVAILABLE` (when the name is decodable) or fails startup with an operator error (when it is not), instead of skipping the row.
- `maybe_recover_from_fs`: a directory with a marker is registered `UNKNOWN_UNAVAILABLE`; directories without markers keep today's behaviour (they are legacy, unfenced namespaces).
- `destroy_on_error`: the broken metastore is renamed aside rather than deleted, and directories with markers are registered `UNKNOWN_UNAVAILABLE` after the rebuild.
- Metastore restore from backup: the provenance (`restored_from_backup`, backup generation) is surfaced in the capability endpoint, in `InspectFence`, as a metric and in a startup log line; the marker comparison (section 5.6) makes any namespace whose record went backwards `UNKNOWN_UNAVAILABLE`. A restored record is never trusted over a newer marker.
- Replica-kind servers: lazy creation of a name refused by the primary with a fence code does not create a local default namespace.

### 13.4 Shared schema

v1 does not fence shared-schema databases or namespaces linked to one, because schema migration fan-out would have to obey the fence on every linked namespace. Acquisition and target creation reject them with `FENCE_PRECONDITION_FAILED`, `shared_schema_unsupported`. While a fence is active, config mutation (which includes linking to a shared schema) is denied.

## 14. Code-path coverage

How each path that can reach namespace data or lifecycle is covered. File references are to `libsql-server/src/`.

| Path | Coverage |
|---|---|
| `connection/connection_core.rs` `CoreConnection::run` | Early live-gate check and `program_generation` capture at program start; SQL read lease for the program; `Error::Fence` from the WAL denial slot in `Vm::try_step`. |
| `connection_core.rs` `checkpoint`, `vacuum_if_needed`, `force_rollback` | Checkpoint is `Maintenance`; vacuum is `Vacuum` and skipped while writes are fenced; `force_rollback` is the drain's abort. |
| `connection/connection_manager.rs` | Authoritative gate in `begin_write_txn` before `acquire()`, generation check, non-`BUSY` refusal; classed queue entries; queue wake on generation change; active-writer query, release notification, `abort_active()`. |
| `connection/legacy.rs` | `FenceConnState` wired into every `LegacyConnection`; the controller is passed to `MakeLegacyConnection::new` before the first connection. `with_raw` users are covered by the WAL gate. |
| HTTP `/`, `/v1/execute`, `/v1/batch`, Hrana `/v2`, `/v3`, cursors, WebSocket, dev route | Core checks and WAL gate; typed status and `code` field; Hrana codes. |
| `rpc/proxy.rs`, `rpc/streaming_exec.rs`, `rpc/replica_proxy.rs`, `connection/write_proxy.rs` | `stable_code` set on the primary and carried back on the replica; connection-creation denials are `FAILED_PRECONDITION`, not `UNAVAILABLE`. |
| `namespace/meta_store.rs` `handle()`, `restore()`, `maybe_recover_from_fs`, `destroy_on_error`, `process`/`try_process`, `remove`, bottomless metastore restore | Non-creating lookups; fail-closed decoding; marker-aware recovery; rename-aside; publish only after commit; fence check inside the config and remove transactions; restore provenance surfaced. |
| `namespace/store.rs` `with`, `load_namespace`, `make_namespace`, eviction | Registry check before setup; controller passed into setup; eviction keeps the registry entry. |
| `store.rs` `create`, `destroy`, `reset`, `fork`, `checkpoint`, restore options | Create refuses names with a record; `CreateTargetQuarantined` is the atomic quarantined create; destroy, reset, fork (either side) and any restore are denied while lifecycle is denied; checkpoint uses a non-creating lookup and skips vacuum. |
| `http/admin/mod.rs` config, create, fork, delete, checkpoint, stats | Config POST, create, fork, delete follow the lifecycle column; config GET, stats and checkpoint are allowed. Fence routes live in `http/admin/fence.rs`. |
| `http/user/dump.rs` | Gate check before connection creation (typed, no panic on create error); dump stream lease; cancel flag in the exporter; aborted body on termination. |
| `rpc/replication/replication_log.rs` `hello`, `log_entries`, `batch_log_entries`, `snapshot` | Denied at request start; stream leases; typed terminal status for open streams; `ReplicatedFence` in `hello`'s config. |
| `admin_shell.rs` | Writes denied at the WAL (no capability); reads checked against the gate per query. |
| `schema/scheduler.rs`, `database/schema.rs` | Shared schema excluded from fencing; migration writes are WAL-gated; the scheduler's `block_writes` flag is not treated as drain evidence. |
| `namespace/configurator/helpers.rs` `load_dump`, `http/admin/mod.rs` `dump_stream_from_url` | Restore options and dump URLs are refused for fenced namespaces; import goes through `ImportSession`. |
| `connection/program.rs` ATTACH resolution | The attached namespace's gate is checked (`NormalRead`), through a non-creating lookup. |
| `http/user/listen.rs` `/beta/listen` | `NormalRead`; denied where reads are denied; ended by the read fence. |
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

## 16. Test strategy (Design)

- **No new dependency.** The crate has no failpoint library. Race tests use `#[cfg(test)]` hooks: `FenceTestHooks` holds named points (`AfterInstallingGate`, `BeforeMetastoreCommit`, `AfterMetastoreCommit`, `BeforeGatePublish`, `InBeginWriteTxnAfterCheck`, `AfterManagerRelease`, `BeforeBoundaryCapture`, `AfterTargetRowsCommitted`, `BeforeResponse`), each able to park the task on a `tokio::sync::Barrier` or `Notify` or to inject an error or an indeterminate commit. Hooks compile only in the library's own test build, so they cost nothing in release builds; integration tests under `tests/` cover protocol behaviour and do not rely on hooks.
- **Restart** at a boundary: reopen `MetaStore` and rebuild the registry on the same temporary directory, the way existing metastore tests do; integration tests stop and start a `TestServer` on the same path.
- **Response loss**: the test drops the command future after `AfterMetastoreCommit` and then replays or inspects.
- **Representative schemas**: synthetic multi-table schemas with indexes, triggers, views and an FTS5 table (FTS5 is compiled in).
- `TXN_TIMEOUT` is 100 ms in test builds; drain tests that hold a writer longer than that use their own `txn_timeout` or a hook, never a sleep.

## 17. Acceptance tests map

Planned test names; the table is updated as tests land.

| # | Requirement | Planned tests |
|---|---|---|
| 1 | Concurrent acquisition by two operations: one owner, typed conflict for the loser | `fence::tests::acquire_race_single_owner`; `tests::fence::admin::concurrent_acquire_one_owner` |
| 2 | Active writer commits or is rolled back before freeze acknowledgement; nothing commits after | `fence::drain::tests::active_writer_commits_before_ack`, `forced_rollback_before_ack`, `no_commit_after_ack` |
| 3 | Autocommit, explicit transactions, queued writers, batches, DDL, schema jobs, old WebSockets, read-to-write upgrades cannot bypass | `connection_manager::tests::fence_rejects_queued_writer`, `fence_rejects_read_to_write_upgrade`, `fence_rejects_ddl_and_pragma`, `fence_rejects_raw_with_raw_write`; `tests::fence::protocol::old_ws_session_cannot_write`, `batch_denied_mid_batch`; `fence::tests::acquire_rejects_shared_schema` |
| 4 | Program that captured config before the fence is rejected at the WAL | `connection_core::tests::wal_gate_rejects_program_admitted_before_fence` |
| 5 | Pre-fence transactions cannot write after release or publication | `fence::tests::stale_generation_cannot_write_after_release`, `stale_generation_cannot_write_after_enable_writes` |
| 6 | Acquisition timeout returns `DRAINING`, admission stays closed | `fence::drain::tests::deadline_returns_draining_and_stays_closed` |
| 7 | Restart at every persistence boundary; indeterminate persistence keeps the gate closed until same-command reconciliation | `fence::tests::restart_at_each_boundary` (parameterised over hook points), `indeterminate_commit_keeps_gate_closed` |
| 8 | Evict and lazily reload a fenced namespace; identical admission | `tests::fence::lifecycle::evicted_namespace_reloads_same_gate` |
| 9 | Filesystem recovery, `destroy_on_error`, undecodable records, missing target quarantine, metastore backup rollback fail closed with provenance | `meta_store::tests::fs_recovery_with_marker_unavailable`, `destroy_on_error_keeps_fenced_unavailable`, `undecodable_row_unavailable`, `incomplete_target_unavailable`, `metastore_rollback_detected_by_marker` |
| 10 | Wrong owner, stale revision, invalid role/state, replay, command-id reuse; replay before revision check | `fence::transition::tests::*` (exhaustive over states × commands) |
| 11 | Target creation raced with SQL, dump, replication, lifecycle never observable as writable or readable | `fence::target::tests::create_race_never_observable` |
| 12 | Only the matching import capability writes a quarantined target; admin credentials and admin shell cannot | `fence::target::tests::import_requires_matching_capability`; `tests::fence::admin::admin_shell_cannot_write_quarantined` |
| 13 | Seal enters `TARGET_IMPORT_DRAINING`, waits, reaches `TARGET_VALIDATING`, cannot resume import; only a durable validation receipt permits idempotent publication | `fence::target::tests::seal_waits_for_import_writers`, `sealed_target_rejects_import`, `publish_requires_validation_receipt`, `publish_is_idempotent` |
| 14 | Enable writes idempotent, survives restart and response loss, irreversible | `fence::target::tests::enable_writes_idempotent_and_irreversible`, `enable_writes_survives_restart` |
| 15 | Lost `EnableTargetWrites` response resolved from receipt/state | `fence::target::tests::enable_writes_response_loss_resolved` |
| 16 | Read fence drains SQL, dump, `log_entries`, `snapshot`, including dead peers and forced termination | `fence::read::tests::*`; `tests::fence::protocol::read_fence_ends_dump`, `read_fence_ends_log_entries_typed`, `read_fence_ends_snapshot`, `read_fence_forced_termination` |
| 17 | Delete, reset, fork, restore, config, schema mutation rejected | `tests::fence::lifecycle::lifecycle_rejected_while_fenced` |
| 18 | Codes through HTTP, Hrana, RPC, dump, replication, replica write proxy; distinguishable from auth/timeout/not-found; old peers compatible; no retry loops | `tests::fence::protocol::{http_codes, hrana_http_codes, hrana_ws_codes, rpc_codes, dump_codes, replication_codes, replica_proxy_preserves_code, auth_and_not_found_distinct, denial_not_retried}`; `libsql-replication` `proxy_error_stable_code_is_additive` |
| 19 | Corrupt or unknown durable fence state fails closed | `fence::store::tests::corrupt_payload_fails_closed`, `unknown_format_version_fails_closed` |
| 20 | Metrics and audit logs | `tests::fence::observability::metrics_and_labels`; `fence::audit::tests::audit_event_fields` |
| 21 | Capability discovery and mixed-version protection | `tests::fence::admin::capabilities`; `fence::store::tests::legacy_mirror_and_fk_guard` (bounded, see section 18) |
| 22 | Adoption is two-person/audited, keeps admission closed, cannot reverse publication | `fence::tests::adopt_requires_key_and_two_approvers`, `adopt_keeps_gates_closed`, `adopt_cannot_touch_writable` |
| — | Import API usable by bulk import | `fence::target::tests::import_session_loads_dump_into_quarantined_target` |

## 18. Limits

What this design and its tests do not prove:

- **Mixed-version behaviour** is tested at the data and wire level (legacy mirror, foreign-key guard, proto unknown-field handling, capability endpoint), not by running an older binary against the same metastore.
- **Representative data** is synthetic. Real production schemas are not part of the test suite.
- **Client retry policy** of SDKs was not audited; the server guarantees only that fence denials use codes that are not conventionally retried.
- **"Commit unknown"** is the caller's classification when neither replay nor inspection answers; the server's part is that replay and inspection always answer when the server is reachable.
- **Two-person adoption** is a separate secret plus a recorded two-approver request, not verified identities.
- **Delivered data** cannot be recalled: bytes already sent, frames held by embedded replicas, and a replica server partitioned from the primary are outside the server's reach.
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
    drain.rs        write, read and import drains
    target.rs       target lifecycle, MigrationCapability, ImportSession, ValidationSession
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
14. `libsql-server: legacy-binary protection and restart/eviction tests`
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
| Open-default `handle()`, including ATTACH authorisation and replica lazy creation | Non-creating lookups on read paths; creating paths refuse names with a record or marker. |
| `process()` publishing unpersisted config | Fixed for all config writes. |
| The scheduler's second metastore connection | Fence CAS and config writes use `BEGIN IMMEDIATE`; shared schema is excluded. |
| Replica servers inherit config | Legacy `block_*` mirror plus additive `ReplicatedFence`; typed terminal status installs a local read denial. |
| Proxy errors lose their type | Additive `stable_code = 4`. |
| Write proxy retries `UNAVAILABLE` forever | Fence denials are never `UNAVAILABLE`. |
| Admin API has no principal and may have no key | Fence mutators require a configured key; adoption requires a second key and two recorded approvers. |
