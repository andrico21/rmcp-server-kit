#!/usr/bin/env bash
# check-bench-threshold.sh — assert a Criterion bench's mean is below max_ns.
#
# Usage: check-bench-threshold.sh <bench_name> <max_ns>
#
# Reads target/criterion/<bench_name>/base/estimates.json (the file
# Criterion writes after `cargo bench`) and parses the
# `mean.point_estimate` field. Exits 0 if mean <= max_ns, 1 otherwise.
#
# This script intentionally avoids `jq` so CI runners don't need extra
# tooling. The estimates.json schema is stable in Criterion 0.5.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <bench_name> <max_ns>" >&2
  exit 2
fi

bench_name="$1"
max_ns="$2"
estimates="target/criterion/${bench_name}/base/estimates.json"

if [[ ! -f "$estimates" ]]; then
  echo "ERROR: $estimates not found. Did 'cargo bench --bench ${bench_name%%/*}' run?" >&2
  exit 1
fi

# Extract mean.point_estimate (a JSON number).
mean_ns=$(python3 -c "import json,sys; d=json.load(open('${estimates}')); print(d['mean']['point_estimate'])")

# Compare as floats; bash can't, so use awk.
ok=$(awk -v m="$mean_ns" -v t="$max_ns" 'BEGIN { print (m <= t) ? "1" : "0" }')

if [[ "$ok" == "1" ]]; then
  printf "PASS: %s mean=%.1f ns <= threshold=%s ns\n" "$bench_name" "$mean_ns" "$max_ns"
  exit 0
else
  printf "FAIL: %s mean=%.1f ns > threshold=%s ns\n" "$bench_name" "$mean_ns" "$max_ns" >&2
  exit 1
fi
