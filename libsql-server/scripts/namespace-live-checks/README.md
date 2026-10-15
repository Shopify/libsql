# Namespace live checks

Scripts that run a built `sqld` locally and check how the namespace store
behaves under load, during shutdown, and across the admin API. They exist
because the interesting failures here are races: an entry emptied under a
request, a shutdown while requests are in flight, a destroy racing a lookup.
Unit tests pin each race deterministically; these scripts show the same
races against a real server, and let two binaries be compared.

Nothing here touches a remote system. Everything listens on `127.0.0.1`.

## Requirements

`bash` 3.2 or newer, `curl`, `python3`, `lsof`. A debug build is fine and
widens the race windows, which is what you want.

```
cargo build -p libsql-server --bin sqld
```

## Scripts

| Script | What it does |
|---|---|
| `load.py` | Keep-alive clients driving `POST /v2/pipeline`; tallies status codes per phase, with an optional SIGTERM or shell action at a given time. |
| `scenario.sh` | One focused scenario: `evict` (cache capacity far below the hot set) or `sigterm` (signal under load). Prints the tally, the namespace-store counters and the grouped store log lines. |
| `regress.sh` | A 65-check matrix across the admin and user APIs, one primary and one primary plus replica, optionally mixed versions. Writes `results.tsv`. |
| `compare.py` | Side-by-side diff of two `results.tsv` files. |

## Comparing two binaries

```
S=libsql-server/scripts/namespace-live-checks
$S/scenario.sh target/debug/sqld evict            # expect 0 non-200 answers
$S/scenario.sh target/debug/sqld sigterm          # expect 503s after the signal, no 404s

$S/regress.sh /path/to/old/sqld old /path/to/new/sqld
$S/regress.sh /path/to/new/sqld new /path/to/old/sqld
$S/compare.py namespace-live-checks-out/old/results.tsv namespace-live-checks-out/new/results.tsv old new
```

`regress.sh` writes server logs next to the results (`<label>/p.log`,
`r.log`, `d.log`). When a line differs, those logs say why.

## What a healthy run looks like

- `scenario.sh ... evict`: every answer is 200. `libsql_server_namespace_emptied_entry`
  is well above zero (the race happened and was retried) and
  `libsql_server_namespace_emptied_entry_gave_up` is absent (never incremented).
- `scenario.sh ... sigterm`: after the signal only 503 `Namespace store has shutdown`,
  then connection errors once the port closes. No 404.
- `regress.sh`: unknown namespaces answer 404 everywhere; deleted namespaces
  answer 404 and their directory is gone; data survives a restart; the
  replica catches up, proxies writes, and resumes after a primary restart.

## Reading the output

- A counter that was never incremented is not listed by `/metrics`; absent
  means zero.
- `conn_error` in a tally covers refused, reset and timed-out connections.
  After a SIGTERM it is the expected tail. Elsewhere it usually means the
  server closed the connection after an error answer.
- The admin port is gone after a SIGTERM; `scenario.sh` reads `/metrics`
  only when the server is still up.
- Under eviction churn the server logs `unable to remove .sentinel file`
  for namespaces reopened while the evicted instance is still shutting
  down. That is independent of the namespace store and shows on every
  version.

## Ports

Defaults: user HTTP 18080, admin 19090, gRPC 15001; replica 18081 and
19091. Override with `PORT`/`ADMIN` (`scenario.sh`) or `P_HTTP`, `P_ADMIN`,
`P_GRPC`, `R_HTTP`, `R_ADMIN` (`regress.sh`). Both scripts refuse to start
when a port is already in use, because a stale server answering the health
check would silently invalidate the run.
