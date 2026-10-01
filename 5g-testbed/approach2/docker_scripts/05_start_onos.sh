#!/bin/bash
# 05_start_onos.sh
#
# Docker-based replacement for bash_scripts/start_onos.sh, which builds ONOS
# from source with `bazel run onos-local`. The released 2.2.2 image matches the
# onos.version this app's pom.xml compiles against, so it is used directly.
#
# --network=host is required: bash_scripts/netcfg.json points the device at
# grpc://localhost:50001, which is where 04_start_stratum.sh bound stratum_bmv2.
set -euo pipefail

ONOS_IMAGE="${ONOS_IMAGE:-onosproject/onos:2.2.2}"

# The apps README step 7 activates over the Karaf console, pre-loaded at boot.
ONOS_APPS="${ONOS_APPS:-drivers,drivers.bmv2,drivers.stratum,hostprovider,netcfghostprovider,proxyarp,gui2}"

echo "[05] Starting ONOS ($ONOS_IMAGE)..."
docker rm -f onos >/dev/null 2>&1 || true

docker run -d --name onos --network=host \
  --restart=unless-stopped \
  -e ONOS_APPS="$ONOS_APPS" \
  "$ONOS_IMAGE" >/dev/null

echo "[05] Waiting for ONOS and the stratum driver (this takes a minute)..."
# The REST API answers well before the driver apps from ONOS_APPS are active.
# Deploying the pipeconf into that window loses the app/netcfg silently, so wait
# until drivers.stratum reports ACTIVE, not merely until :8181 responds.
for i in $(seq 1 180); do
  if curl -sf -u onos:rocks --noproxy localhost \
       http://localhost:8181/onos/v1/applications/org.onosproject.drivers.stratum 2>/dev/null \
       | grep -q '"state":"ACTIVE"'; then
    echo "[05] ONOS is up (drivers.stratum ACTIVE) after ${i}s."
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' onos 2>/dev/null)" != "true" ]]; then
    echo "[05] ONOS container exited:" >&2
    docker logs onos 2>&1 | tail -25 >&2
    exit 1
  fi
  sleep 1
  [[ $i -eq 180 ]] && { echo "[05] timed out waiting for ONOS" >&2; exit 1; }
done

echo "[05] Active apps:"
curl -sf -u onos:rocks --noproxy localhost http://localhost:8181/onos/v1/applications \
  | tr ',' '\n' | grep -oE '"name":"org\.onosproject\.[a-z0-9.]+"' | sed 's/.*://;s/"//g' | sort | head -20
echo "[05] GUI: http://localhost:8181/onos/ui  (onos/rocks)"
