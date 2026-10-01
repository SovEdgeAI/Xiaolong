#!/bin/bash
# testbed_autonomy.sh - turn the testbed's OWN decision-making off or on.
#
#   off     stop the built-in detector so RA3 is the sole decider
#   on      restart it (the upstream behaviour)
#   status  show what is running
#
# The autonomous chain is:
#   getDBData.py  -> ML-scores each flow, flags source IPs in the flow API
#   DetectionModule (ONOS) -> polls /flaggedIps/top, POSTs them to /blocked-ips
#   MitigationModule (ONOS) -> installs the switch drop rules for /blocked-ips
#
# Stopping getDBData.py removes the ML flagging, so nothing gets auto-flagged
# and DetectionModule never auto-blocks. MitigationModule keeps reconciling
# /blocked-ips against the switch, which is exactly the path RA3 drives through
# the testbed-agent: RA3 stays the only thing that decides to block, and the
# testbed is left as a pure network + enforcement substrate.
set -euo pipefail

HOST="${A2_HOST_CONTAINER:-a2-host}"
FLOW_API="${FLOW_API:-http://127.0.0.1:23500}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVCDIR="$DIR/../approach2/docker_scripts"

running() { docker exec "$HOST" sh -c "pgrep -f '[g]etDBData.py' >/dev/null && echo yes || echo no"; }

case "${1:-status}" in
  off)
    echo "[autonomy] stopping the built-in detector (getDBData.py)..."
    docker exec "$HOST" sh -c 'pkill -f '[g]etDBData.py' 2>/dev/null || true'
    # clear anything it flagged/blocked so RA3 starts from a clean slate
    docker exec "$HOST" sh -c "curl -s -X DELETE $FLOW_API/blocked-ips >/dev/null 2>&1 || true"
    for ip in $(docker exec "$HOST" sh -c "curl -s $FLOW_API/flaggedIps 2>/dev/null" \
                | grep -oE '10\.45\.[0-9]+\.[0-9]+' | sort -u); do
      docker exec "$HOST" sh -c "curl -s -X DELETE $FLOW_API/flagged-ips/$ip >/dev/null 2>&1 || true"
    done
    echo "[autonomy] detector stopped; RA3 is now the sole decider (running=$(running))"
    ;;
  on)
    echo "[autonomy] restarting the built-in detector..."
    docker exec -e PY="${PY:-python3}" "$HOST" sh -c \
      "cd $SVCDIR/../.. ; cd approach2/ML ; \
       PYTHONUNBUFFERED=1 FLOW_API=$FLOW_API setsid nohup python3 getDBData.py \
       >$SVCDIR/run/logs/getdbdata.log 2>&1 </dev/null &"
    sleep 2
    echo "[autonomy] detector running=$(running)"
    ;;
  status)
    echo "built-in detector (getDBData.py) running: $(running)"
    docker exec "$HOST" sh -c "echo -n '  flagged: '; curl -s $FLOW_API/flaggedIps 2>/dev/null; echo; echo -n '  blocked: '; curl -s $FLOW_API/blocked-ips 2>/dev/null; echo"
    ;;
  *) echo "usage: $0 {off|on|status}" >&2; exit 2 ;;
esac
