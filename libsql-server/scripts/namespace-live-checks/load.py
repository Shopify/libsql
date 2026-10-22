#!/usr/bin/env python3
"""Drive a running sqld over Hrana HTTP from several keep-alive clients and
tally the status codes it answers.

Each thread loops over `POST /v2/pipeline` with one statement, selecting the
namespace with the `x-namespace` header (`ns0`..`nsN-1`, or a fixed `--ns`).
An optional action splits the tally into a "before" and an "after" phase:
`--sigterm-after S --pid PID` sends SIGTERM to a server, `--at S --run CMD`
runs a shell command. The report lists, per phase, how many responses had
each status, when each status was first seen after the action, and a few
distinct bodies for non-200 answers.

Examples:
  load.py --port 18080 --namespaces 6 --threads 24 --duration 20
  load.py --port 18080 --namespaces 20 --threads 32 --duration 12 \
          --sigterm-after 3 --pid $(pgrep -n sqld)
  load.py --port 18080 --ns ns0 --sql "insert into t values (1)" \
          --threads 8 --duration 4 --at 1.5 --run "curl -X DELETE ..."
"""
import argparse
import collections
import http.client
import json
import os
import signal
import subprocess
import threading
import time

p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
p.add_argument("--port", type=int, required=True, help="sqld user HTTP port on 127.0.0.1")
p.add_argument("--namespaces", type=int, default=1, help="cycle over ns0..nsN-1")
p.add_argument("--ns", type=str, default=None, help="fixed namespace instead of ns0..nsN-1")
p.add_argument("--sql", type=str, default="select 1")
p.add_argument("--threads", type=int, default=16)
p.add_argument("--duration", type=float, default=10)
p.add_argument("--sigterm-after", type=float, default=None, help="seconds after start to SIGTERM --pid")
p.add_argument("--pid", type=int, default=None)
p.add_argument("--at", type=float, default=None, help="seconds after start to run --run")
p.add_argument("--run", type=str, default=None, help="shell command to run at --at")
p.add_argument("--quiet", action="store_true", help="one-line summary only")
args = p.parse_args()

BODY = json.dumps({"requests": [{"type": "execute", "stmt": {"sql": args.sql}}, {"type": "close"}]})
HEADERS = {"content-type": "application/json"}

lock = threading.Lock()
tally = collections.defaultdict(collections.Counter)  # phase -> status -> count
bodies = collections.defaultdict(set)  # status -> distinct bodies (truncated)
first_seen = {}  # (phase, status) -> seconds after the action
action_at = [None]
stop = threading.Event()
t0 = time.monotonic()


def phase():
    return "after" if action_at[0] is not None and time.monotonic() >= action_at[0] else "before"


def since_action():
    return None if action_at[0] is None else round(time.monotonic() - action_at[0], 3)


def record(status, body=None):
    ph = phase()
    with lock:
        tally[ph][status] += 1
        first_seen.setdefault((ph, status), since_action())
        if body is not None and len(bodies[status]) < 3:
            bodies[status].add(body[:160])


def worker(i):
    conn = None
    consecutive_conn_errors = 0
    n = 0
    while not stop.is_set():
        ns = args.ns or f"ns{(i + n) % args.namespaces}"
        n += 1
        try:
            if conn is None:
                conn = http.client.HTTPConnection("127.0.0.1", args.port, timeout=5)
            conn.request("POST", "/v2/pipeline", body=BODY, headers=dict(HEADERS, **{"x-namespace": ns}))
            resp = conn.getresponse()
            data = resp.read()
            consecutive_conn_errors = 0
            if resp.status == 200:
                record(200)
            else:
                record(resp.status, data.decode("utf-8", "replace"))
            if resp.getheader("connection", "").lower() == "close":
                conn.close()
                conn = None
        except Exception as e:  # connection refused, reset, timeout
            record("conn_error", type(e).__name__)
            consecutive_conn_errors += 1
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            conn = None
            # once the server is gone after the action, stop instead of spinning
            if phase() == "after" and consecutive_conn_errors >= 20:
                return
            time.sleep(0.01)


threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(args.threads)]
for t in threads:
    t.start()

if args.sigterm_after is not None:
    time.sleep(args.sigterm_after)
    action_at[0] = time.monotonic()
    os.kill(args.pid, signal.SIGTERM)
    if not args.quiet:
        print(f"sent SIGTERM to {args.pid} at t={round(action_at[0] - t0, 3)}s", flush=True)
elif args.at is not None:
    time.sleep(args.at)
    action_at[0] = time.monotonic()
    r = subprocess.run(args.run, shell=True, capture_output=True, text=True)
    if not args.quiet:
        print(f"ran action at t={round(action_at[0] - t0, 3)}s -> {r.stdout.strip()[:120]}", flush=True)

deadline = t0 + args.duration
while time.monotonic() < deadline and any(t.is_alive() for t in threads):
    time.sleep(0.05)
stop.set()
for t in threads:
    t.join(timeout=2)


def fmt(counter):
    return ", ".join(f"{k}:{v}" for k, v in sorted(counter.items(), key=lambda kv: str(kv[0])))


if args.quiet:
    print(" ".join(f"{ph}{{{fmt(tally[ph])}}}" for ph in ("before", "after") if tally[ph]))
    raise SystemExit(0)

print("\n=== tally (phase -> status: count) ===")
for ph in ("before", "after"):
    if tally[ph]:
        print(f"{ph:7s} {fmt(tally[ph])}")
if any(v is not None for v in first_seen.values()):
    print("\n=== first seen (seconds after the action) ===")
    for (ph, st), t in sorted(first_seen.items(), key=lambda kv: (kv[1] is None, kv[1] or 0)):
        if ph == "after":
            print(f"  {st}: +{t}s")
print("\n=== distinct bodies for non-200 ===")
for st, bs in bodies.items():
    for b in bs:
        print(f"  {st}: {b}")
