#!/bin/bash
# Regression matrix for the namespace store, run against a sqld binary.
#
# Usage: regress.sh <path/to/sqld> [label] [path/to/other/sqld]
#
# Starts servers (one primary; later one primary plus one replica), drives
# them through the admin and user HTTP APIs, and records one line per check
# in $OUT/<label>/results.tsv: scenario, check, observed value. Run it once
# per binary and diff the two results with compare.py.
#
# If a second binary is given, S10 pairs this binary as the primary with the
# other as the replica (mixed versions). Otherwise S10 is skipped.
#
# Scenarios: S1 lifecycle and real 404s; S2 checkpoint; S3 fork; S4 create
# from a dump; S5 shared schema; S6 delete under load; S7 persistence across
# SIGTERM with and without --snapshot-at-shutdown; S8 SIGTERM under load with
# namespaces disabled; S9 primary plus replica; S10 mixed versions.
#
# Works with bash 3.2. Needs curl, python3 and lsof.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1; LABEL=${2:-$(basename "$1")}; BIN_OTHER=${3:-}
OTHER=$([ -n "$BIN_OTHER" ] && basename "$BIN_OTHER" || echo none)
OUT=${OUT:-./namespace-live-checks-out}
ROOT=$OUT/$LABEL; rm -rf "$ROOT"; mkdir -p "$ROOT"
RESULTS=$ROOT/results.tsv; : > "$RESULTS"
P_HTTP=${P_HTTP:-18080}; P_ADMIN=${P_ADMIN:-19090}; P_GRPC=${P_GRPC:-15001}
R_HTTP=${R_HTTP:-18081}; R_ADMIN=${R_ADMIN:-19091}
LOAD=$HERE/load.py
export RUST_LOG=${RUST_LOG:-info}

rec() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" | tee -a "$RESULTS"; }

# ---- server control -------------------------------------------------------
for port in $P_HTTP $P_ADMIN $P_GRPC $R_HTTP $R_ADMIN; do
  if lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then echo "!! port $port is busy; kill the stale process first"; lsof -nP -iTCP:$port -sTCP:LISTEN; exit 1; fi
done
pid_of() { cat "$ROOT/$1.pid" 2>/dev/null; }
forget() { rm -f "$ROOT/$1.pid"; }
start() { # start NAME BIN DIR HTTP ADMIN [extra args...]
  local name=$1 bin=$2 dir=$3 http=$4 admin=$5; shift 5
  mkdir -p "$dir"
  "$bin" --db-path "$dir" --http-listen-addr 127.0.0.1:$http --admin-listen-addr 127.0.0.1:$admin --no-welcome "$@" \
    >>"$ROOT/$name.log" 2>&1 &
  local pid=$!; echo $pid > "$ROOT/$name.pid"
  for _ in $(seq 1 200); do
    kill -0 $pid 2>/dev/null || { echo "!! $name exited at start"; tail -3 "$ROOT/$name.log"; return 1; }
    curl -sf --max-time 2 -o /dev/null "http://127.0.0.1:$http/health" && return 0; sleep 0.05
  done
  echo "!! $name did not come up"; tail -5 "$ROOT/$name.log"; return 1
}
stop() { # stop NAME  (SIGTERM, wait)
  local pid; pid=$(pid_of "$1"); [ -z "$pid" ] && return 0
  kill "$pid" 2>/dev/null; for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.05; done
  kill -9 "$pid" 2>/dev/null; forget "$1"; sleep 0.2
}
stop_all() { for f in "$ROOT"/*.pid; do [ -f "$f" ] && stop "$(basename "$f" .pid)"; done; }
trap stop_all EXIT

# ---- API helpers (print "STATUS BODY") -------------------------------------
api() { # api METHOD URL [json]
  local m=$1 u=$2 d=${3:-}
  if [ -n "$d" ]; then curl -s --max-time 10 -o "$ROOT/body" -w '%{http_code}' -X "$m" -H 'content-type: application/json' -d "$d" "$u"
  else curl -s --max-time 10 -o "$ROOT/body" -w '%{http_code}' -X "$m" "$u"; fi
  printf ' %s' "$(tr -d '\n' < "$ROOT/body" | cut -c1-100)"
}
ns_create() { local d=${2:-"{}"}; api POST "http://127.0.0.1:${3:-$P_ADMIN}/v1/namespaces/$1/create" "$d"; }
ns_delete() { api DELETE "http://127.0.0.1:${2:-$P_ADMIN}/v1/namespaces/$1"; }
ns_fork()   { api POST "http://127.0.0.1:${3:-$P_ADMIN}/v1/namespaces/$1/fork/$2"; }
ns_ckpt()   { api POST "http://127.0.0.1:${2:-$P_ADMIN}/v1/namespaces/$1/checkpoint"; }
ns_config() { api GET  "http://127.0.0.1:${2:-$P_ADMIN}/v1/namespaces/$1/config"; }
ns_stats()  { api GET  "http://127.0.0.1:${2:-$P_ADMIN}/v1/namespaces/$1/stats"; }
q() { # q NS SQL [http port]  -> "STATUS firstvalue-or-error"
  local ns=$1 sql=$2 port=${3:-$P_HTTP}
  local body; body=$(python3 -c 'import json,sys; print(json.dumps({"requests":[{"type":"execute","stmt":{"sql":sys.argv[1]}},{"type":"close"}]}))' "$sql")
  local code; code=$(curl -s --max-time 10 -o "$ROOT/body" -w '%{http_code}' -X POST -H 'content-type: application/json' -H "x-namespace: $ns" -d "$body" "http://127.0.0.1:$port/v2/pipeline")
  local v; v=$(python3 -c '
import json,sys
try:
    r=json.load(open(sys.argv[1]))
    if "results" in r:
        x=r["results"][0]
        if x.get("type")=="ok":
            rows=x["response"].get("result",{}).get("rows",[])
            print(rows[0][0]["value"] if rows and rows[0] else "ok")
        else: print("err:"+x.get("error",{}).get("message","?")[:60])
    else: print(r.get("error","?")[:60])
except Exception as e: print("?")' "$ROOT/body")
  printf '%s %s' "$code" "$v"
}
q_code() { q "$@" | cut -d' ' -f1; }
seed() { q "$1" "create table t(x)" "${2:-$P_HTTP}" >/dev/null; q "$1" "insert into t select value from generate_series(1,${3:-2000})" "${2:-$P_HTTP}" >/dev/null; }
count() { q "$1" "select count(*) from t" "${2:-$P_HTTP}" | cut -d' ' -f2; }
wait_count() { # wait_count NS PORT EXPECTED -> prints final count
  for _ in $(seq 1 40); do c=$(count "$1" "$2"); [ "$c" = "$3" ] && break; sleep 0.2; done; echo "$c"
}
load() { python3 $LOAD --quiet --port "$@"; }

echo "##### $LABEL: regression matrix"

# ===========================================================================
# S1 lifecycle and real 404s
start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S1 "create ns1" "$(ns_create ns1)"
rec S1 "create ns1 again" "$(ns_create ns1)"
seed ns1
rec S1 "query ns1 count" "$(q ns1 'select count(*) from t')"
rec S1 "config ns1" "$(ns_config ns1 | cut -c1-40)"
rec S1 "stats ns1" "$(ns_stats ns1 | cut -c1-40)"
rec S1 "query unknown" "$(q nope 'select 1')"
rec S1 "config unknown" "$(ns_config nope)"
rec S1 "stats unknown" "$(ns_stats nope)"
rec S1 "delete ns1" "$(ns_delete ns1)"
rec S1 "query deleted" "$(q ns1 'select 1')"
rec S1 "config deleted" "$(ns_config ns1)"
rec S1 "dir deleted" "$([ -d "$ROOT/p/dbs/ns1" ] && echo present || echo gone)"
rec S1 "delete unknown" "$(ns_delete nope)"

# S2 checkpoint: loaded, unloaded (after restart), unknown
ns_create ns2 >/dev/null; seed ns2
rec S2 "checkpoint loaded" "$(ns_ckpt ns2)"
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S2 "checkpoint unloaded (after restart)" "$(ns_ckpt ns2)"
rec S2 "query after unloaded checkpoint" "$(q ns2 'select count(*) from t')"
rec S2 "checkpoint unknown" "$(ns_ckpt nope)"
rec S2 "query unknown after its checkpoint" "$(q nope 'select 1')"

# S3 fork: hot source, cold source, unknown source, existing destination
ns_create src >/dev/null; seed src
rec S3 "fork hot src->dst" "$(ns_fork src dst)"
rec S3 "dst count" "$(q dst 'select count(*) from t')"
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S3 "fork cold src->dst2" "$(ns_fork src dst2)"
rec S3 "dst2 count" "$(q dst2 'select count(*) from t')"
rec S3 "fork unknown->x" "$(ns_fork nope x)"
rec S3 "fork src->dst2 (dst2 loaded)" "$(ns_fork src dst2)"
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S3 "fork src->dst (dst exists, unloaded) [pre-existing check]" "$(ns_fork src dst)"
rec S3 "dst after that: query" "$(q dst 'select count(*) from t')"
rec S3 "dst after that: config" "$(ns_config dst | cut -c1-40)"
rec S3 "dst after that: dir" "$([ -d "$ROOT/p/dbs/dst" ] && echo present || echo gone)"

# S4 dump restore via create
printf 'CREATE TABLE d(x);\nINSERT INTO d VALUES (1),(2),(3);\n' > "$ROOT/dump.sql"
rec S4 "create from dump" "$(ns_create nsd "{\"dump_url\":\"file://$ROOT/dump.sql\"}")"
rec S4 "dump rows" "$(q nsd 'select count(*) from d')"

# S5 shared schema (create goes through fork)
rec S5 "create schema" "$(ns_create schema '{"shared_schema":true}')"
rec S5 "schema ddl" "$(q schema 'create table s(x)')"
rec S5 "create linked1 (hot schema)" "$(ns_create linked1 '{"shared_schema_name":"schema"}')"
rec S5 "linked1 query" "$(q linked1 'select count(*) from s')"
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S5 "create linked2 (cold schema)" "$(ns_create linked2 '{"shared_schema_name":"schema"}')"
rec S5 "linked2 query" "$(q linked2 'select count(*) from s')"
rec S5 "delete schema with linked dbs" "$(ns_delete schema)"

# S6 delete under load: must be 404 after, never 503, no resurrection
# the load tool names namespaces ns0..; create ns0 for it instead
ns_create ns0 >/dev/null; seed ns0
rec S6 "load tally (ns0)" "$(load $P_HTTP --namespaces 1 --threads 8 --duration 4 --at 1.5 --run "curl -s -o /dev/null -w '%{http_code}' -X DELETE http://127.0.0.1:$P_ADMIN/v1/namespaces/ns0")"
sleep 0.5
rec S6 "config after delete-under-load" "$(ns_config ns0)"
rec S6 "query after delete-under-load" "$(q ns0 'select 1')"
rec S6 "dir after delete-under-load" "$([ -d "$ROOT/p/dbs/ns0" ] && echo present || echo gone)"

# S7 shutdown persistence (plain, and with --snapshot-at-shutdown)
for i in 1 2 3; do ns_create pers$i >/dev/null; seed pers$i "$P_HTTP" 1500; done
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 --snapshot-at-shutdown || exit 1
rec S7 "counts after restart" "$(count pers1) $(count pers2) $(count pers3)"
q pers1 "insert into t values (0)" >/dev/null
stop p; start p "$BIN" "$ROOT/p" $P_HTTP $P_ADMIN --enable-namespaces --max-active-namespaces 100 || exit 1
rec S7 "counts after snapshot-at-shutdown restart" "$(count pers1) $(count pers2) $(count pers3)"
rec S7 "shutdown errors in log" "$(grep -c -E 'ERROR.*(shutdown|shutting)' "$ROOT/p.log")"
stop p

# S8 namespaces disabled: SIGTERM under load on the default namespace
start d "$BIN" "$ROOT/d" $P_HTTP $P_ADMIN --max-active-namespaces 100 || exit 1
q default "create table t(x)" >/dev/null
rec S8 "default ns sigterm tally" "$(python3 $LOAD --quiet --port $P_HTTP --namespaces 1 --threads 16 --duration 6 --sigterm-after 2 --pid $(pid_of d) | sed 's/ns0/default/')"
forget d
rec S8 "false 404 in log" "$(grep -c '404 Not Found' "$ROOT/d.log")"

# ===========================================================================
# S9 primary + replica
start p "$BIN" "$ROOT/p9" $P_HTTP $P_ADMIN --enable-namespaces --grpc-listen-addr 127.0.0.1:$P_GRPC || exit 1
start r "$BIN" "$ROOT/r9" $R_HTTP $R_ADMIN --enable-namespaces --primary-grpc-url http://127.0.0.1:$P_GRPC || exit 1
ns_create rep >/dev/null; seed rep "$P_HTTP" 2000
rec S9 "replica catches up" "$(wait_count rep $R_HTTP 2000)"
rec S9 "proxied write via replica" "$(q rep 'insert into t values (0)' $R_HTTP)"
rec S9 "primary sees proxied write" "$(wait_count rep $P_HTTP 2001)"
rec S9 "replica sees it" "$(wait_count rep $R_HTTP 2001)"
rec S9 "replica unknown ns" "$(q nope 'select 1' $R_HTTP)"
# replica shutdown under read load
ns_create ns0 >/dev/null; seed ns0 "$P_HTTP" 100; wait_count ns0 $R_HTTP 100 >/dev/null
rec S9 "replica SIGTERM under read load" "$(python3 $LOAD --quiet --port $R_HTTP --namespaces 1 --threads 16 --duration 5 --sigterm-after 1.5 --pid $(pid_of r))"
forget r
start r "$BIN" "$ROOT/r9" $R_HTTP $R_ADMIN --enable-namespaces --primary-grpc-url http://127.0.0.1:$P_GRPC || exit 1
rec S9 "replica after restart" "$(wait_count rep $R_HTTP 2001)"
# primary shutdown under proxied-write load through the replica
rec S9 "primary SIGTERM under proxied writes (replica statuses)" "$(python3 $LOAD --quiet --port $R_HTTP --namespaces 1 --ns rep --sql "insert into t values (9)" --threads 8 --duration 8 --sigterm-after 2 --pid $(pid_of p))"
forget p
start p "$BIN" "$ROOT/p9" $P_HTTP $P_ADMIN --enable-namespaces --grpc-listen-addr 127.0.0.1:$P_GRPC || exit 1
pc=$(count rep $P_HTTP)
rec S9 "primary count after restart" "$pc"
q rep "insert into t values (1)" >/dev/null
rec S9 "replication resumes after primary restart" "$(wait_count rep $R_HTTP $((pc+1)))"
rec S9 "proxied write after primary restart" "$(q rep 'insert into t values (2)' $R_HTTP)"
rec S9 "replica count after that" "$(wait_count rep $R_HTTP $((pc+2)))"
# destroy on primary while replica replicates: the replica must still recognise the message
ns_delete rep >/dev/null; sleep 2
rec S9 "replica log after primary destroy" "$(grep -c "doesn't exist, trying to replicate again" "$ROOT/r.log")"
rec S9 "replica log: non-fatal/unavailable lines" "$(grep -c -i -E 'unavailable|non-fatal' "$ROOT/r.log")"
stop r; stop p

# S10 mixed versions: this binary as primary, the other as replica
if [ -n "$BIN_OTHER" ]; then
start p "$BIN" "$ROOT/p10" $P_HTTP $P_ADMIN --enable-namespaces --grpc-listen-addr 127.0.0.1:$P_GRPC || exit 1
start r "$BIN_OTHER" "$ROOT/r10" $R_HTTP $R_ADMIN --enable-namespaces --primary-grpc-url http://127.0.0.1:$P_GRPC || exit 1
ns_create mix >/dev/null; seed mix "$P_HTTP" 500
rec S10 "($OTHER replica) catches up" "$(wait_count mix $R_HTTP 500)"
rec S10 "($OTHER replica) primary SIGTERM under proxied writes" "$(python3 $LOAD --quiet --port $R_HTTP --namespaces 1 --ns mix --sql "insert into t values (9)" --threads 8 --duration 8 --sigterm-after 2 --pid $(pid_of p))"
forget p
start p "$BIN" "$ROOT/p10" $P_HTTP $P_ADMIN --enable-namespaces --grpc-listen-addr 127.0.0.1:$P_GRPC || exit 1
pc=$(count mix $P_HTTP); q mix "insert into t values (1)" >/dev/null
rec S10 "($OTHER replica) replication resumes" "$(wait_count mix $R_HTTP $((pc+1)))"
rec S10 "($OTHER replica) proxied write after restart" "$(q mix 'insert into t values (2)' $R_HTTP)"
rec S10 "($OTHER replica) log unavailable/non-fatal/doesnt-exist" "$(grep -c -i -E 'unavailable|non-fatal' "$ROOT/r.log")/$(grep -c "doesn't exist" "$ROOT/r.log")"
stop r; stop p
fi

echo "##### done: $RESULTS"
