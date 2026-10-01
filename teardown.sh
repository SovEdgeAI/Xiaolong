#!/usr/bin/env bash
# teardown.sh — stop RA3 and the testbed containers.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> stopping RA3"
( cd "$HERE/ra3-respond" && docker compose down ) 2>/dev/null || true

echo "==> stopping testbed containers"
docker rm -f testbed-agent ue-good victim 2>/dev/null || true
# Core/RAN/SDN containers brought up by the testbed scripts:
docker rm -f cp-2 up-2 gnb-2 ue-2 onos stratum-bmv2 mongo-container a2-host 2>/dev/null || true

echo "Done."
