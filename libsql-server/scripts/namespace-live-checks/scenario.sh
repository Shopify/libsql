#!/bin/bash
# Run one focused scenario against a sqld binary and report the status codes
# clients saw, the namespace-store counters, and the store's log lines.
#
# Usage: scenario.sh <path/to/sqld> <evict|sigterm> [label]
#
#   evict    cache capacity far below the hot set, so entries are evicted
#            under requests all the time (--max-active-namespaces 2, 6
#            namespaces, 24 clients, 20 s)
#   sigterm  20 namespaces under 32 clients; SIGTERM the server at 3 s and
#            keep requesting until the port closes
#
# Works with bash 3.2. Needs curl and python3.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1; SCENARIO=$2; LABEL=${3:-$(basename "$BIN")}
PORT=${PORT:-18080}; ADMIN=${ADMIN:-19090}
OUT=${OUT:-./namespace-live-checks-out}; mkdir -p "$OUT"
DIR=$OUT/$LABEL-$SCENARIO; LOG=$DIR.log
rm -rf "$DIR" "$LOG"; mkdir -p "$DIR"

case $SCENARIO in
  evict)   MAX_ACTIVE=2;   NS=6;  THREADS=24; DURATION=20; ACTION="" ;;
  sigterm) MAX_ACTIVE=100; NS=20; THREADS=32; DURATION=12; ACTION="--sigterm-after 3" ;;
  *) echo "unknown scenario: $SCENARIO (evict|sigterm)"; exit 2 ;;
esac

for port in $PORT $ADMIN; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is busy; stop the process that holds it first"; exit 1
  fi
done

export RUST_LOG=${RUST_LOG:-info,libsql_server::namespace::store=debug}
"$BIN" --db-path "$DIR" --http-listen-addr 127.0.0.1:"$PORT" --admin-listen-addr 127.0.0.1:"$ADMIN" \
  --enable-namespaces --max-active-namespaces "$MAX_ACTIVE" --no-welcome >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for _ in $(seq 1 100); do
  kill -0 $PID 2>/dev/null || { echo "sqld exited at start:"; tail -3 "$LOG"; exit 1; }
  curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 0.1
done
echo "sqld ($LABEL) pid $PID up"

for i in $(seq 0 $((NS - 1))); do
  curl -sf --max-time 10 -X POST -H 'content-type: application/json' -d '{}' \
    "http://127.0.0.1:$ADMIN/v1/namespaces/ns$i/create" >/dev/null
  curl -sf --max-time 10 -X POST -H 'content-type: application/json' -H "x-namespace: ns$i" \
    -d '{"requests":[{"type":"execute","stmt":{"sql":"create table t(x)"}},{"type":"execute","stmt":{"sql":"insert into t select value from generate_series(1,2000)"}},{"type":"close"}]}' \
    "http://127.0.0.1:$PORT/v2/pipeline" >/dev/null
done
echo "created $NS namespaces"

if [ "$SCENARIO" = sigterm ]; then ACTION="$ACTION --pid $PID"; fi
# shellcheck disable=SC2086
python3 "$HERE/load.py" --port "$PORT" --namespaces "$NS" --threads "$THREADS" --duration "$DURATION" $ACTION

echo
echo "=== namespace-store counters (absent = zero) ==="
curl -s --max-time 2 "http://127.0.0.1:$ADMIN/metrics" 2>/dev/null \
  | grep -E "^libsql_server_namespace_(emptied|left_empty)|^libsql_server_user_http_(fault|response)" || echo "(admin port closed)"
echo
echo "=== store log lines (grouped) ==="
grep -E "WARN|ERROR|emptied|left empty|giving up|dropped a different" "$LOG" \
  | sed 's/^.*Z  *//; s/req_id=[0-9a-f-]*//' | sort | uniq -c | sort -rn | head -12
echo "log: $LOG"
