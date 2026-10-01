#!/bin/bash
# 04_start_stratum.sh
#
# Docker-based replacement for bash_scripts/run_stratum.sh.
#
# Runs stratum_bmv2 with --network=host so it binds the veth0/2/4/6/8/10 side of
# the fabric that 01_create_network.sh left in the host namespace, exactly as the
# chassis config names them. The P4Runtime endpoint is published on
# localhost:50001, which is the managementAddress in bash_scripts/netcfg.json.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPROACH2="$(cd "$DIR/.." && pwd)"
NET_IMAGE="${NET_IMAGE:-opennetworking/mn-stratum:latest}"
P4_PROGRAM="${1:-onos-p4-gtp}"

STRATUM_FILES="$APPROACH2/stratum_files"
P4_DIR="$APPROACH2/p4-code"
RUNDIR="$DIR/run/stratum"
mkdir -p "$RUNDIR"

if [[ ! -f "$P4_DIR/$P4_PROGRAM.json" ]]; then
  echo "Error: $P4_DIR/$P4_PROGRAM.json not found (compile the P4 program first)." >&2
  exit 1
fi

echo "[04] Starting stratum_bmv2 for $P4_PROGRAM..."
docker rm -f stratum-bmv2 >/dev/null 2>&1 || true

docker run -d --name stratum-bmv2 --privileged --network=host \
  --restart=unless-stopped \
  -v "$STRATUM_FILES":/stratum-files:ro \
  -v "$P4_DIR":/p4:ro \
  -v "$RUNDIR":/var/stratum \
  --entrypoint stratum_bmv2 \
  "$NET_IMAGE" \
    -device_id=1 \
    -chassis_config_file=/stratum-files/chassis-config.txt \
    -forwarding_pipeline_configs_file=/var/stratum/pipe.txt \
    -persistent_config_dir=/var/stratum \
    -initial_pipeline="/p4/$P4_PROGRAM.json" \
    -cpu_port=255 \
    -external_stratum_urls=0.0.0.0:50001 \
    -local_stratum_url=localhost:44400 \
    -max_num_controllers_per_node=10 \
    -write_req_log_file=/var/stratum/write-reqs.txt \
    -logtosyslog=false \
    -bmv2_log_level=info \
    -logtostderr=true >/dev/null

sleep 4
if [[ "$(docker inspect -f '{{.State.Running}}' stratum-bmv2 2>/dev/null)" != "true" ]]; then
  echo "[04] stratum_bmv2 failed to start:" >&2
  docker logs stratum-bmv2 2>&1 | tail -25 >&2
  exit 1
fi

echo "[04] stratum_bmv2 running. Ports bound:"
docker logs stratum-bmv2 2>&1 | grep -iE 'veth|listening|external' | tail -12 || true
echo "[04] P4Runtime on localhost:50001 (device_id=1)"
