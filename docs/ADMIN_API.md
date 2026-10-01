# Libsql-server admin API documentation

This document describes the admin API endpoints.

The admin API is used to manage namespaces on a `sqld` instance. Namespaces are isolated database within a same sqld instance.

To enable the admin API, and manage namespaces, two extra flags need to be passed to `sqld`:

- `--admin-listen-addr <addr>:<port>`: the address and port on which the admin API should listen. It must be different from the user API listen address (which defaults to port 8080).
- `--enable-namespaces`: enable namespaces for the instance. By default namespaces are disabled.

## Namespace names

Namespace names must be non-empty single filesystem components. `.` and `..`,
forward/backward slashes, and NUL are rejected, including percent-encoded path
parameters after HTTP decoding. Safe existing names with spaces, punctuation,
and Unicode remain supported. On Windows, invalid Win32 characters, trailing
ASCII dots/spaces, and reserved device names are also rejected. These rules
also apply to fork source/destination and shared-schema names. Invalid names
return `400 Bad Request` on the admin API.

On upgrade, invalid namespace names or configs in the metastore (including
invalid shared-schema names) prevent startup instead of being treated as absent
or allowing their rows to be overwritten; this holds even
with `--meta-store-destroy-on-error`. Filesystem recovery skips invalid and
symlinked directory entries without deleting them. An invalid persisted
migration job/task stops its scheduler without marking that work complete.
Back up and inspect metastore and namespace files before repairing these entries
explicitly.

Validation prevents path traversal *through a namespace string*. Directory
ownership checks additionally reserve new namespace/fork directories atomically,
reject any existing entry (including aliases and orphan directories), and
require an unloaded persisted namespace's actual directory entry to match its
stored name. A legacy alias or symlink is refused rather than opened or
deleted. These checks assume the data directory is trusted; they do not make
filesystem operations atomic against a privileged external process replacing
paths or symlinks outside the server's coordination locks.

A cancelled create/fork or failed cleanup can retain a newly reserved directory
as quarantine after metadata has been removed, so delayed writes cannot reach
a retry. Inspect it and the metastore after the work stops before repairing or
retrying. Per-name operation locks allow unrelated namespace administration to
continue during slow restores. Shutdown signals in-flight create/fork work to
stop and permits a bounded drain before reporting an error. A replica detecting
an incompatible log moves its old files to `replica-log-quarantine/` outside
`dbs/`, retaining the namespace directory identity, then retries once. Inspect
quarantined files before removal. Destroy/reset confirms remote backups before
moving a directory to `namespace-teardown-quarantine/`; backup failure before
confirmation leaves the old directory and metastore row in place. After
confirmation, independently draining workers own the name lock even if the HTTP
request is cancelled. Destroy then removes metadata and the old directory.
Before deleting metadata, destroy atomically publishes a fully written `namespace-destroy-intents/` record identifying the
old directory; unpublished temporary records are discarded on startup.
Reconciliation rolls back an uncommitted intent or finishes a committed delete
before namespaces are served. A mismatched/missing live inode or unexpected
quarantine fails startup for operator repair rather than opening a blank DB.
Incomplete intents also fence create, fork, replica load, and reset until
recovered. Reset separately publishes a `namespace-reset-intents/` record with
the old inode and persisted config before detaching the old directory. The old
files remain quarantined while the replacement is set up. A pending reset
rejects changing its shared-schema membership: the original link must keep the
old schema available, and a second link would incorrectly enlist the partial
database in schema migrations. A reset waits for the schema registration lock
and refuses an existing migration; new migrations are rejected while a linked
tenant or the schema namespace itself has a pending reset intent, avoiding
scheduler retry exhaustion. Only a
durable commit marker permits release of this restriction and deletion of the
old files. Before that marker, a crash
restores the old files and config and preserves partial new files under
`namespace-reset-abandoned/` for inspection. A setup error keeps the name
fenced until process restart, when all late setup workers have stopped;
rollback during the live process could otherwise redirect late path opens into
the old database. Invalid identities or interrupted recovery fail closed.
Unix directory fsync orders the intent ahead of the SQLite commit;
sudden power-loss durability is not guaranteed on Windows (which has no
portable directory fsync here), nor is macOS physical flush guaranteed by
ordinary fsync. Process-crash recovery is supported on both. Short filesystem
identity scans and renames remain synchronous under the filesystem lock:
offloading only the syscalls would allow cancellation to release a name lock
while late writes are still running. Large directories can therefore briefly
stall a current-thread runtime pending a separately coordinated offload. Stale
config/replication handles from a prior incarnation cannot reinsert rows or
links after deletion; a fresh create/reset uses a new generation. Unexpected
identity changes are preserved for explicit operator repair. Inspect remaining
quarantine files after interrupted teardown.

## Routes

```HTTP
POST /v1/namespaces/:namespace/create
```

Create a namespace named `:namespace`. Explicit creation rejects an existing
namespace, including `default`; internal startup/lazy loading of `default`
reuses its persisted config rather than replacing it.
body:

```json
{
    "dump_url"?: string,
}
```

```HTTP
DELETE /v1/namespaces/:namespace
```

Delete the namespace named `:namespace`.

```HTTP
POST /v1/namespaces/:namespace/fork/:to
```

Fork `:namespace` into new namespace `:to`
