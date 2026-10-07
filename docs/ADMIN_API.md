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
    "dump_importer"?: "buffered" | "streaming",
}
```

`dump_url` initializes the new namespace from a SQLite SQL dump (`sqlite3 db .dump` or this
server's `GET /dump` output). Supported schemes are `file:` (an absolute path on the server
host) and `http(s):`. The dump must run inside a transaction and end with `COMMIT`; `ATTACH` is
rejected.

`dump_importer` selects how the dump is loaded (it requires `dump_url`):

- `buffered` (historical): the whole dump is read into memory, parsed, then executed. Memory
  usage is proportional to the dump size.
- `streaming`: statements are framed with `sqlite3_complete()` and executed while the dump is
  still being read. Memory usage is bounded by the server's queue settings plus the largest
  single statement (see `--dump-import-*` flags); a statement larger than
  `--dump-import-max-statement-size` is rejected with `413`.

When omitted, the server's `--dump-importer` setting (`SQLD_DUMP_IMPORTER`, default `buffered`)
applies. Values are matched case-insensitively; an unknown value is rejected with `422`.

Both importers produce the same data. Known differences:

- the streaming importer stores the schema SQL exactly as written in the dump, whereas the
  buffered importer stores the parser's normalized rendering;
- a dump whose *data* contains the word "attach" is rejected by the buffered importer (substring
  check) but accepted by the streaming one (statement-level check); a standalone `DETACH`
  statement is rejected with `400` by the streaming importer and fails at execution (`500`) with
  the buffered one;
- invalid UTF-8 or NUL bytes yield `400` (buffered: `500`), and statements that return rows are
  executed with their rows discarded (buffered: `500`).

```HTTP
DELETE /v1/namespaces/:namespace
```

Delete the namespace named `:namespace`.

```HTTP
POST /v1/namespaces/:namespace/fork/:to
```

Fork `:namespace` into new namespace `:to`
