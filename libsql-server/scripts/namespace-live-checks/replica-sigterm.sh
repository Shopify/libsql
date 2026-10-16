#!/bin/bash
# What embedded replicas (the `libsql` crate) see when their primary restarts.
#
# Usage: replica-sigterm.sh <path/to/sqld> [label]
#
# Starts sqld with 20 namespaces loaded, runs 8 embedded replicas (one per
# namespace, syncing in a tight loop; see libsql/examples/replica_sync_loop.rs),
# sends SIGTERM at 4 s, starts the same server again at about 7 s, and prints
# every distinct error the replicas saw with the time it was first seen.
#
# Needs the example built: cargo build -p libsql --example replica_sync_loop
# Override its path with SYNC_LOOP. Works with bash 3.2. Needs curl.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1; LABEL=${2:-$(basename "$BIN")}
PORT=${PORT:-18080}; ADMIN=${ADMIN:-19090}
SYNC_LOOP=${SYNC_LOOP:-$HERE/../../../target/debug/examples/replica_sync_loop}
OUT=${OUT:-./namespace-live-checks-out}; DIR=$OUT/$LABEL-replica-sigterm
rm -rf "$DIR"; mkdir -p "$DIR"; LOG=$DIR/server.log

[ -x "$SYNC_LOOP" ] || { echo "replica_sync_loop not found at $SYNC_LOOP; build it with: cargo build -p libsql --example replica_sync_loop"; exit 2; }
for port in $PORT $ADMIN; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is busy; stop the process that holds it first"; exit 1
  fi
done

start_server() {
  RUST_LOG=${RUST_LOG:-info} "$BIN" --db-path "$DIR/db" --http-listen-addr 127.0.0.1:"$PORT" --admin-listen-addr 127.0.0.1:"$ADMIN" \
    --enable-namespaces --max-active-namespaces 100 --no-welcome >>"$LOG" 2>&1 &
  echo $!
}
wait_up() {
  for _ in $(seq 1 100); do
    kill -0 "$1" 2>/dev/null || { echo "sqld exited at start:"; tail -3 "$LOG"; exit 1; }
    curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/health" && return; sleep 0.1
  done
}
PID=$(start_server); wait_up "$PID"
trap 'kill $PID 2>/dev/null || true; [ -f "$DIR/pid2" ] && kill "$(cat "$DIR/pid2")" 2>/dev/null || true' EXIT

for i in $(seq 0 19); do
  curl -sf --max-time 10 -X POST -H 'content-type: application/json' -d '{}' \
    "http://127.0.0.1:$ADMIN/v1/namespaces/ns$i/create" >/dev/null
  curl -sf --max-time 10 -X POST -H 'content-type: application/json' -H "x-namespace: ns$i" \
    -d '{"requests":[{"type":"execute","stmt":{"sql":"select 1"}},{"type":"close"}]}' \
    "http://127.0.0.1:$PORT/v2/pipeline" >/dev/null
done
echo "sqld ($LABEL) pid $PID up with 20 namespaces loaded"

(
  sleep 4; echo "[+4s] SIGTERM $PID"; kill -TERM "$PID"; wait "$PID" 2>/dev/null || true
  echo "[+$(( SECONDS ))s] server exited"; sleep 2.5
  PID2=$(start_server); echo "$PID2" > "$DIR/pid2"; echo "[+$(( SECONDS ))s] server started again (pid $PID2)"
) &
TIMER=$!

echo
echo "=== what the replicas saw ==="
PORT=$PORT REPLICAS=${REPLICAS:-8} DURATION=${DURATION:-12} "$SYNC_LOOP" 2>"$DIR/client.log"
wait $TIMER

echo
echo "=== server: shutdown timing ==="
sed "s/$(printf '\033')\[[0-9;]*m//g" "$LOG" | grep -E "Got SIGTERM|shutdown gracefully" | sed -E 's/^([^ ]+) .*(Got SIGTERM|shutdown gracefully).*/\1 \2/' | head -4
echo
echo "=== replicator log lines ==="
sed "s/$(printf '\033')\[[0-9;]*m//g" "$DIR/client.log" | grep -E "WARN|ERROR" | grep -v "Unusually long" | sed -E 's/^.*Z  *//; s/ns[0-9]+/nsN/g' | sort | uniq -c | sort -rn | head -6 || true
echo "logs: $LOG, $DIR/client.log"
