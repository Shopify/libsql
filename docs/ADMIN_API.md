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
also apply to fork source/destination and shared-schema names.

Invalid names change the API contract: config, delete, fork, and stats routes
return `400 Bad Request` with JSON `{"error":"Invalid namespace"}` (where
previously some unsafe non-empty names returned `404 Not Found`). Create and
checkpoint path parameters return `400` with plain-text `Invalid URL: ...` from
the path extractor. An invalid `shared_schema_name` in a create JSON body
returns `422 Unprocessable Entity` with a plain-text JSON-rejection message.
On the user API, an invalid `x-namespace` returns `400` with JSON; an invalid
Host-derived name returns `400` only with `--disable-default-namespace`,
otherwise routing falls back to `default`. gRPC rejects invalid names with
`InvalidArgument`. A JWT with even one invalid namespace in its legacy `id`
claim or `ns` scopes fails validation of the whole token (`401 JwtInvalid`),
not just that scope.

On upgrade, invalid namespace names or configs in the metastore (including
invalid shared-schema names) prevent startup instead of being treated as absent
or allowing their rows to be overwritten; this holds even
with `--meta-store-destroy-on-error`. Filesystem recovery skips invalid and
symlinked directory entries without deleting them. An invalid persisted
migration job/task name or unreadable migration program is left unfinished and
isolated in the scheduler: unrelated schema migrations continue, but the
affected schema cannot accept another migration until its job is repaired.
On restart, the scheduler checks the row again. Back up and inspect metastore
and namespace files before repairing these entries explicitly.

Before rollout, inspect each pod's metastore for names that would now be
rejected (including rows in `jobs` and `pending_tasks`):

```sql
SELECT 'namespace_configs' AS source, namespace AS name FROM namespace_configs
WHERE namespace GLOB '*[/\]*' OR namespace IN ('', '.', '..')
   OR instr(namespace, char(0)) > 0
UNION ALL
SELECT 'jobs', schema FROM jobs
WHERE schema GLOB '*[/\]*' OR schema IN ('', '.', '..')
   OR instr(schema, char(0)) > 0
UNION ALL
SELECT 'pending_tasks', target_namespace FROM pending_tasks
WHERE target_namespace GLOB '*[/\]*' OR target_namespace IN ('', '.', '..')
   OR instr(target_namespace, char(0)) > 0;
```

This SQL checks common unsafe path syntax, not the complete platform-specific
name policy or the JSON stored in `jobs.migration`. It also cannot decode the
protobuf `namespace_configs.config` blob: an undecodable config or an invalid
`shared_schema_name` in that blob will still prevent startup. Inspect those
blobs with the server's decoder (or validate a backed-up copy with this
version) before rollout; do not delete or rewrite rows without checking their
linked namespaces and backups.

This validation prevents path traversal *through a namespace string*. It does
not establish ownership of existing directories or protect against symlinks,
case/normalization aliases, or filesystem replacement races. Only trusted
operators should have write access to the data directory; additional directory
reservation and ownership protection is addressed separately.

## Routes

```HTTP
POST /v1/namespaces/:namespace/create
```

Create a namespace named `:namespace`.
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
