#!/usr/bin/env bash
set -euo pipefail

for x in {1..6}; do
  n=$((2**x))
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running test with x=$x (n=$n)…"
  bash ./run_cts_test.zsh 2 "$n"
  echo "    ✅ Finished x=$x (n=$n)"
done

echo "All tests completed successfully."
