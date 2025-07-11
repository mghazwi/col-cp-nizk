#!/bin/bash
set -e

N_PARTIES=${1:-2}
N_CONST=${2:-4}

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
        -- bp::r1cs_mpc::test_mpc_prover_with_link::test_mpc_bp_r1cs_n_const_with_link \
        --exact --nocapture "$PARTY" "$N_PARTIES" "$N_CONST"  &
    pids+=("$!")
done

for pid in "${pids[@]}"; do
    wait "$pid"
done