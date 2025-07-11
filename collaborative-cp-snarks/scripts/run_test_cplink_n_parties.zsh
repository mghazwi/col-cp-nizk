#!/bin/bash
set -e

N_PARTIES=${1:-2}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="bp-test"

# Build Docker image
docker build -t "$IMAGE_NAME" "$REPO_ROOT/docker"

pids=()
for PARTY in $(seq 0 $((N_PARTIES-1))); do
    docker run --rm --network host --cap-add NET_ADMIN \
        -v "$REPO_ROOT":/workspace \
        -w /workspace/collaborative-cp-snarks \
        "$IMAGE_NAME" /workspace/docker/with_netlim.sh \
        cargo test --package collaborative-cp-snarks --lib \
        -- snark::legogroth16::link::test::test_same_value_different_bases_n_time_on_shares \
        --exact --nocapture "$PARTY" "$N_PARTIES" "$N_PARTIES"  &
    pids+=("$!")
done

for pid in "${pids[@]}"; do
    wait "$pid"
done