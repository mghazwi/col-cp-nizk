#!/bin/bash
set -e

# Number of constraints (default: 2)
N_CONST=${1:-2}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="groth16-test"

# Build Docker image
docker build -t "$IMAGE_NAME" "$REPO_ROOT/docker"

# Run single-party Groth16 test
docker run --rm --network host --cap-add NET_ADMIN \
    -v "$REPO_ROOT":/workspace \
    -w /workspace/collaborative-cp-snarks \
    "$IMAGE_NAME" /workspace/docker/with_netlim.sh \
    cargo test --package collaborative-cp-snarks --lib \
      -- snark::groth16::tests::test_groth16::single_party_groth16 \
      --exact --nocapture "$N_CONST"