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
Back up and inspect
metastore and namespace files before repairing these entries explicitly.

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
