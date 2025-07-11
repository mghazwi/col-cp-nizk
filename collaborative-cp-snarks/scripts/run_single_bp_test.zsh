#!/bin/bash
set -e

# Number of constraints (default: 2)
N_CONST=${1:-2}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="single_bp-test"

# Build Docker image
docker build -t "$IMAGE_NAME" "$REPO_ROOT/docker"

# Run single-party bp test
docker run --rm --network host --cap-add NET_ADMIN \
    -v "$REPO_ROOT":/workspace \
    -w /workspace/collaborative-cp-snarks \
    "$IMAGE_NAME" /workspace/docker/with_netlim.sh \
    cargo test --package collaborative-cp-snarks --lib \
      -- bp::r1cs::test::test_bp_r1cs_n_const \
      --exact --nocapture "$N_CONST"