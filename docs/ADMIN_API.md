# Libsql-server admin API documentation

This document describes the admin API endpoints.

The admin API is used to manage namespaces on a `sqld` instance. Namespaces are isolated database within a same sqld instance.

To enable the admin API, and manage namespaces, two extra flags need to be passed to `sqld`:

- `--admin-listen-addr <addr>:<port>`: the address and port on which the admin API should listen. It must be different from the user API listen address (which defaults to port 8080).
- `--enable-namespaces`: enable namespaces for the instance. By default namespaces are disabled.

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

`dump_url` initializes the new namespace from a SQLite SQL dump (`sqlite3 db .dump` or this
server's `GET /dump` output). Supported schemes are `file:` (an absolute path on the server
host) and `http(s):`. The dump must run inside a transaction and end with `COMMIT`; `ATTACH` is
rejected.

Creation is all-or-nothing. The namespace becomes visible, and its configuration is persisted,
only after it has been fully set up (including the dump import). If the request fails, is
cancelled by the client, or the server dies while it is in flight, the namespace either does not
exist (its name can be created again right away: a failed attempt is fully undone before the
error is returned) or is complete, never partially imported. Requests addressed to a namespace
while it is being created wait for the outcome. Directories of creations the server died in the
middle of are discarded at the next start (`<db-path>/.discarded/` holds them until they are
deleted). For callers:

- `2xx`: the namespace is complete;
- any other outcome, including a lost connection: retry the same request; a
  `400 Namespace already exists` on the retry means the earlier attempt did complete. (Once
  the configuration is persisted, the creation finishes even if the client has gone away.)

In single-namespace mode (`--disable-namespaces`) creating the default namespace is a
configuration upsert and always succeeds, except with a `dump_url`: a dump can only be imported
into a namespace that does not exist yet, so that request is rejected like any other.

See `docs/ATOMIC_NAMESPACE_CREATE_DESIGN.md`.

```HTTP
DELETE /v1/namespaces/:namespace
```

Delete the namespace named `:namespace`.

```HTTP
POST /v1/namespaces/:namespace/fork/:to
```

Fork `:namespace` into new namespace `:to`
