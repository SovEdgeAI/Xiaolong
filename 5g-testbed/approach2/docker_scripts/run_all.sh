#!/bin/bash
# run_all.sh - bring up the whole approach2 stack, in dependency order.
#
# Ordering matters and is not arbitrary:
#   01 before 03  the veth pairs must exist before they can be moved into the
#                 container namespaces (and removing a container destroys the
#                 pair whose peer it holds, so 01 always re-creates them).
#   03 before 04  stratum_bmv2 binds veth0/2/4/6/8/10 at startup; re-running 01
#                 underneath it would leave the switch with dead interfaces.
#   05 before 06  the app and netcfg are pushed over the ONOS REST API.
#   06 before 07  GTP-U is only forwarded once the app installs gtp_flows
#                 entries in response to packet-ins, so the core needs ONOS up.
#
# Re-running this script from scratch is safe; each step is idempotent.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

step() {
  echo
  echo "============================================================"
  echo " $1"
  echo "============================================================"
}

step "00  prerequisites: SCTP module, mongo-container, UERANSIM build"
./00_prereqs.sh

step "01  veth fabric + br-p4-onos + static ARP (host namespace)"
./01_create_network.sh

step "02  generate Open5GS configs"
./02_gen_configs.sh

step "03  containers cp-2 / up-2 / gnb-2 / ue-2, wired to the fabric"
./03_start_containers.sh

step "04  stratum_bmv2 P4 switch"
./04_start_stratum.sh

step "05  ONOS controller"
./05_start_onos.sh

step "06  build + deploy the approach2 pipeconf/app"
./06_deploy_app.sh

step "07  Open5GS control plane + UPF"
./07_start_core.sh

step "08  UERANSIM gNB + UE"
./08_start_ran.sh

step "09  log server, flow REST API, ML detection"
./09_start_services.sh

step "DONE"
cat <<'EOF'
Validate the data path (README step 14):
  docker exec ue-2 ping -I uesimtun0 -c 4 8.8.8.8

Run the DDoS test (README step 16):
  docker exec ue-2 ping -I uesimtun0 -c 10000 -i 0.000001 -q 8.8.8.8

Watch detection and mitigation:
  tail -f run/logs/getdbdata.log                     # LR/NB predictions
  curl -s --noproxy '*' http://127.0.0.1:23500/blocked-ips
  curl -s -u onos:rocks --noproxy localhost \
       http://localhost:8181/onos/v1/flows/device:s1

ONOS GUI: http://localhost:8181/onos/ui  (onos/rocks)

Clear a mitigation (drop the block and let the flow re-learn):
  curl -s -X DELETE --noproxy '*' http://127.0.0.1:23500/blocked-ip/10.45.0.3
  ./06_deploy_app.sh      # reinstalls a clean pipeline
EOF
