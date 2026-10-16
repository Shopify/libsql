#!/usr/bin/env python3
"""Print two regress.sh result files side by side and mark the lines that differ.

Usage: compare.py <a/results.tsv> <b/results.tsv> [label-a] [label-b]
"""
import csv
import sys


def load(path):
    out = {}
    for row in csv.reader(open(path), delimiter="\t"):
        if len(row) == 3:
            out[(row[0], row[1])] = row[2]
    return out


def short(v, n):
    v = v.replace('{"error":', "").replace('"}', "").replace('"', "")
    return v[: n - 1] + "…" if len(v) > n else v


a, b = load(sys.argv[1]), load(sys.argv[2])
la = sys.argv[3] if len(sys.argv) > 3 else sys.argv[1]
lb = sys.argv[4] if len(sys.argv) > 4 else sys.argv[2]
keys = list(dict.fromkeys(list(a.keys()) + list(b.keys())))
w = 60
print(f"{'scenario / check':52s} | {la:{w}s} | {lb:{w}s} |")
print("-" * 52 + "-+-" + "-" * w + "-+-" + "-" * w + "-+")
differ = 0
for k in keys:
    va, vb = a.get(k, "-"), b.get(k, "-")
    mark = "" if va == vb else " *"
    differ += bool(mark)
    print(f"{(k[0] + ' ' + k[1])[:52]:52s} | {short(va, w):{w}s} | {short(vb, w):{w}s} |{mark}")
print(f"\n{differ} of {len(keys)} checks differ (marked *). Values with ids or counters are expected to differ.")
