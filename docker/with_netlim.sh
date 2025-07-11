#!/bin/bash
set -e

RATE="${NET_LIMIT:-200mbit}"

tc qdisc replace dev lo root tbf rate "$RATE" burst 32kbit latency 400ms
trap 'tc qdisc del dev lo root || true' EXIT

exec "$@"