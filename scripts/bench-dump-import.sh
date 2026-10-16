#!/usr/bin/env bash
#
# Compare the buffered and streaming dump importers on ONE running libsql-server instance.
#
# For each importer it creates a namespace from the same dump, samples the server's RSS while
# the import runs, records wall time and on-disk size, then checks that both namespaces export
# the same data and pass PRAGMA integrity_check.
#
# Usage:
#   scripts/bench-dump-import.sh <dump.sql> [admin_url] [user_host:port] [sqld_pid]
#
#   dump.sql         absolute path readable by the server (it is passed as a file: URL)
#   admin_url        default http://127.0.0.1:9090
#   user_host:port   default 127.0.0.1:8080 (namespaces are selected with x-namespace)
#   sqld_pid         default: pgrep -x sqld (RSS sampling is skipped if unavailable)
#
# Start the server with e.g.:
#   sqld --enable-namespaces --admin-listen-addr 127.0.0.1:9090 --http-listen-addr 127.0.0.1:8080
#
# Linux reads VmRSS from /proc; macOS falls back to `ps -o rss`. Requires curl and python3.

set -euo pipefail

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 2; }
done

DUMP=${1:?usage: $0 <dump.sql> [admin_url] [user_host:port] [sqld_pid]}
ADMIN=${2:-http://127.0.0.1:9090}
USER_HOST=${3:-127.0.0.1:8080}
PID=${4:-$(pgrep -x sqld | head -n1 || true)}
RUN_ID=$(date +%s)
OUT=${BENCH_OUT:-/tmp/bench-dump-import-$RUN_ID}
mkdir -p "$OUT"

case "$DUMP" in
  /*) ;;
  *) echo "dump path must be absolute: $DUMP" >&2; exit 2 ;;
esac

if [ -n "$PID" ]; then
  # Refuse to sample an unrelated process (e.g. a container-local PID passed from the host).
  comm=$(ps -o comm= -p "$PID" 2>/dev/null | tr -d ' ' || true)
  case "$comm" in
    *sqld*) ;;
    *) echo "PID $PID is not a sqld process (comm=${comm:-?}); RSS sampling disabled" >&2; PID= ;;
  esac
fi

now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

rss_kb() {
  if [ -z "$PID" ]; then echo 0; return; fi
  if [ -r "/proc/$PID/status" ]; then
    awk '/^VmRSS:/ {print $2}' "/proc/$PID/status"
  else
    ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || echo 0
  fi
}

sample_rss() { # $1 = output csv; samples every 200ms until killed
  while :; do
    printf '%s,%s\n' "$(now_ms)" "$(rss_kb)"
    sleep 0.2
  done >"$1"
}

import_with() { # $1 = importer, $2 = namespace
  local importer=$1 ns=$2 sampler=
  local csv="$OUT/rss_$importer.csv"
  local baseline; baseline=$(rss_kb)
  if [ -n "$PID" ]; then sample_rss "$csv" & sampler=$!; fi
  local start; start=$(now_ms)
  local code
  code=$(curl -sS -o "$OUT/create_$importer.json" -w '%{http_code}' \
    -X POST "$ADMIN/v1/namespaces/$ns/create" \
    -H 'content-type: application/json' \
    -d "{\"dump_url\":\"file://$DUMP\",\"dump_importer\":\"$importer\"}") \
    || { echo "request to $ADMIN failed (is the admin API reachable?)" >&2; exit 2; }
  local end; end=$(now_ms)
  if [ -n "$sampler" ]; then kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true; fi
  local peak=0
  if [ -s "$csv" ]; then peak=$(cut -d, -f2 "$csv" | sort -n | tail -n1); fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$importer" "$ns" "$code" "$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.2f", (e - s) / 1000 }')" \
    "$baseline" "$peak" "$(( (peak - baseline) / 1024 ))" \
    >>"$OUT/results.tsv"
  [ "$code" = 200 ] || { echo "import with $importer failed ($code): $(cat "$OUT/create_$importer.json")" >&2; exit 1; }
}

data_lines() { # print the INSERT/DELETE lines of a dump that are not inside a CREATE statement
  awk '
    mode == 0 {
      if ($0 ~ /^CREATE (TEMP |TEMPORARY )?TRIGGER/) { if ($0 !~ /END;[[:space:]]*$/) mode = 2; next }
      if ($0 ~ /^CREATE /)                           { if ($0 !~ /;[[:space:]]*$/)    mode = 1; next }
      if ($0 ~ /^(INSERT INTO|DELETE FROM)/) print
      next
    }
    mode == 1 && $0 ~ /;[[:space:]]*$/    { mode = 0 }
    mode == 2 && $0 ~ /END;[[:space:]]*$/ { mode = 0 }
  ' "$1"
}

printf 'importer\tnamespace\thttp\twall_s\trss_baseline_kb\trss_peak_kb\trss_delta_mb\n' >"$OUT/results.tsv"

# streaming first: on Linux VmHWM is a lifetime high-water mark, and the buffered importer's
# peak would otherwise hide the streaming one.
import_with streaming "bench_streaming_$RUN_ID"
import_with buffered "bench_buffered_$RUN_ID"

echo
echo "== results ($OUT/results.tsv)"
column -t -s $'\t' "$OUT/results.tsv"

echo
echo "== validation"
for importer in buffered streaming; do
  ns="bench_${importer}_$RUN_ID"
  curl -sS -H "x-namespace: $ns" "http://$USER_HOST/dump?preserve_row_ids=true" >"$OUT/dump_$importer.sql"
  # data rows only: the buffered importer stores parser-normalized DDL text, the streaming one
  # stores the dump's DDL verbatim, so schema lines may legitimately differ in whitespace
  # (including a trigger body spread over several lines, whose INSERTs are not data).
  data_lines "$OUT/dump_$importer.sql" >"$OUT/data_$importer.sql"
  integrity=$(curl -sS -H "x-namespace: $ns" -H 'content-type: application/json' \
    -X POST "http://$USER_HOST/v2/pipeline" \
    -d '{"requests":[{"type":"execute","stmt":{"sql":"PRAGMA integrity_check"}},{"type":"close"}]}' \
    | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"][0]; print(r["response"]["result"]["rows"][0][0]["value"] if r["type"]=="ok" else r)') \
    || { echo "integrity_check request for $ns failed" >&2; exit 2; }
  echo "$importer: integrity_check=$integrity rows=$(wc -l <"$OUT/data_$importer.sql") size=$(wc -c <"$OUT/dump_$importer.sql")"
done
if cmp -s "$OUT/data_buffered.sql" "$OUT/data_streaming.sql"; then
  echo "data: identical"
else
  echo "data: DIFFERENT (see $OUT/data_*.sql)" >&2
  exit 1
fi

echo
echo "== server metrics"
curl -sS "$ADMIN/metrics" | grep -E '^libsql_server_dump_import' || echo "(metrics disabled or unavailable)"
