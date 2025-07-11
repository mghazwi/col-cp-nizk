#!/bin/bash
set -e

N_PARTIES=${1:-2}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="lego_party"

# Build Docker image
docker build -t "$IMAGE_NAME" "$REPO_ROOT/docker"

pids=()
for PARTY in $(seq 0 $((N_PARTIES-1))); do
    docker run --rm --network host --cap-add NET_ADMIN \
        -v "$REPO_ROOT":/workspace \
        -w /workspace/collaborative-cp-snarks \
        "$IMAGE_NAME" /workspace/docker/with_netlim.sh \
        cargo test --package collaborative-cp-snarks --lib \
        -- snark::legogroth16::tests::test_legogroth16::legogroth16 \
        --exact --nocapture "$PARTY" 13 4 "$N_PARTIES" &
    pids+=("$!")
done

for pid in "${pids[@]}"; do
    wait "$pid"
done