#!/bin/bash
# run_attack.sh - stage the harness into the UE and fire one bounded attack.
#
#   ./run_attack.sh <TYPE> [--duration S] [--pps N] [--detached]
#
# Reads the victim address from ../victim/victim.env. Copies attack.sh +
# slowrate.py into ue-2 and runs them there so the traffic originates from the
# compromised UE and crosses the P4 switch. All bounds pass through to attack.sh.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UE="${UE:-ue-2}"
ENVF="$DIR/../victim/victim.env"
[[ -f "$ENVF" ]] || { echo "no $ENVF; run victim/start_victim.sh first" >&2; exit 1; }
# shellcheck disable=SC1090
. "$ENVF"
: "${VICTIM_IP:?victim.env has no VICTIM_IP}"

TYPE="${1:?usage: run_attack.sh TYPE [opts]}"; shift || true
DETACHED=0
PASS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --detached) DETACHED=1; shift ;;
    *) PASS+=("$1"); shift ;;
  esac
done

# The UE image ships none of these; a fresh (redeployed) UE needs them.
docker exec "$UE" sh -c 'command -v hping3 >/dev/null && command -v nmap >/dev/null && command -v curl >/dev/null && command -v iptables >/dev/null' || {
  echo "[run] installing attack tools in $UE (one-time)..."
  docker exec "$UE" sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq hping3 nmap python3 curl iptables iproute2 iputils-ping >/dev/null 2>&1'
}
docker exec "$UE" mkdir -p /opt/attack
docker cp "$DIR/attack.sh"   "$UE:/opt/attack/attack.sh"
docker cp "$DIR/slowrate.py" "$UE:/opt/attack/slowrate.py"
docker exec "$UE" chmod +x /opt/attack/attack.sh

CMD="/opt/attack/attack.sh $TYPE $VICTIM_IP ${PASS[*]:-}"
if [[ "$DETACHED" == 1 ]]; then
  docker exec -d "$UE" sh -c "$CMD >/tmp/attack.log 2>&1"
  echo "[run] $TYPE started detached against $VICTIM_IP (log: ue-2:/tmp/attack.log)"
else
  docker exec "$UE" sh -c "$CMD"
fi
