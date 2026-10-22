#!/bin/bash
# How long the shutdown window is, against the number of loaded namespaces.
#
# Usage: window.sh <path/to/sqld> <namespaces> [label]
#
# Creates and loads N namespaces (each with a table and a row, so each has a
# WAL), then runs load.py against all of them with a SIGTERM at 3 s. The
# window is the time from the first 503 to the port closing; compare it with
# your clients' retry budgets. Setup takes about 45 s per 1,000 namespaces.
#
# Works with bash 3.2. Needs curl and python3.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1; N=$2; LABEL=${3:-$(basename "$BIN")-$N}
PORT=${PORT:-18080}; ADMIN=${ADMIN:-19090}
OUT=${OUT:-./namespace-live-checks-out}; DIR=$OUT/$LABEL-window
rm -rf "$DIR"; mkdir -p "$DIR"; LOG=$DIR/server.log

for port in $PORT $ADMIN; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $port is busy; stop the process that holds it first"; exit 1
  fi
done

RUST_LOG=${RUST_LOG:-info} "$BIN" --db-path "$DIR/db" --http-listen-addr 127.0.0.1:"$PORT" --admin-listen-addr 127.0.0.1:"$ADMIN" \
  --enable-namespaces --max-active-namespaces $(( N * 2 )) --no-welcome >"$LOG" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 100); do
  kill -0 $PID 2>/dev/null || { echo "sqld exited at start:"; tail -3 "$LOG"; exit 1; }
  curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 0.1
done

T0=$SECONDS
# A few threads only: more trips sqld's connection-creation throttle (429
# DbCreateTimeout) while namespaces are being created.
python3 - "$N" "$PORT" "$ADMIN" <<'PY'
import sys, json, http.client, concurrent.futures
n, port, admin = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
def one(i):
    c = http.client.HTTPConnection("127.0.0.1", admin, timeout=30)
    c.request("POST", f"/v1/namespaces/ns{i}/create", body="{}", headers={"content-type": "application/json"})
    c.getresponse().read(); c.close()
    u = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    body = json.dumps({"requests": [
        {"type": "execute", "stmt": {"sql": "create table if not exists t(x)"}},
        {"type": "execute", "stmt": {"sql": "insert into t values (1)"}},
        {"type": "close"}]})
    u.request("POST", "/v2/pipeline", body=body, headers={"content-type": "application/json", "x-namespace": f"ns{i}"})
    r = u.getresponse(); r.read(); u.close()
    return r.status
with concurrent.futures.ThreadPoolExecutor(6) as ex:
    statuses = list(ex.map(one, range(n)))
bad = sum(1 for s in statuses if s != 200)
print(f"loaded {n} namespaces" + (f"; {bad} setup writes were not 200 (usually 429 DbCreateTimeout; the namespace is still loaded)" if bad else ""))
PY
echo "setup took $(( SECONDS - T0 ))s; sqld rss $(ps -o rss= -p $PID | awk '{printf "%.0f MB", $1/1024}')"

python3 "$HERE/load.py" --port "$PORT" --namespaces "$N" --threads 32 --duration 25 --sigterm-after 3 --pid $PID
wait $PID 2>/dev/null || true
echo
echo "=== server: shutdown timing ==="
sed "s/$(printf '\033')\[[0-9;]*m//g" "$LOG" | grep -E "Got SIGTERM|shutdown gracefully" | sed -E 's/^([^ ]+) .*(Got SIGTERM|shutdown gracefully).*/\1 \2/'
echo "The window is the time from the first 503 to the first conn_error above."
echo "log: $LOG"
