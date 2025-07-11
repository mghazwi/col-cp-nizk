#!/usr/bin/env bash
set -euo pipefail

for x in {2..10}; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running test with x=$x"
  bash ./run_mpc_ipp_test.zsh  "$x"
  echo "    ✅ Finished x=$x"
done

echo "All tests completed successfully."
