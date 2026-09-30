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
moving a directory to `namespace-teardown-quarantine/` for local removal;
backup failure/cancellation before confirmation leaves the old directory and
metastore row in place; after confirmation an independently draining worker
owns the name lock through metadata removal and identity-checked teardown even
if the HTTP request is cancelled. Stale config/replication handles from a
prior incarnation cannot reinsert rows or links after deletion; a fresh
create/reset uses a new generation. Unexpected identity changes are preserved
for explicit operator repair. Inspect remaining quarantine files after
interrupted teardown.

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
