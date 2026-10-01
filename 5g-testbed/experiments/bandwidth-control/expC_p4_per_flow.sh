#!/bin/bash
# expC_p4_per_flow.sh - Experiment C: PER-FLOW bandwidth control in the P4 pipeline.
#
# This is the capability neither expA nor expB provides:
#   expA (OVS meter)  polices the whole gNB<->UPF tunnel - OVS has no GTP parser,
#                     so it cannot tell one UE or one flow from another.
#   expB (core AMBR)  polices a whole PDU session, per subscriber.
#   expC (this)       polices ONE GTP inner-IP flow, identified by
#                     (inner src, inner dst, protocol).
#
# onos-p4-gtp.p4 attaches an indirect meter to gtp_flows and track_gtp_flows
# carries an `index` selecting that flow's cell. CreateGTPFlows allocates a cell
# per direction per flow and logs the mapping; QoSMeterModule writes the rate.
#
# The control surface is two files in the ONOS container:
#   /tmp/qos_meter_index   cell to act on (or "all")
#   /tmp/qos_rate_kbps     rate in kbps; 0 = unlimited
#
# Note the DN address is 192.168.230.1 (a host address) rather than 172.17.0.1:
# ue-2 has a direct route for 172.17.0.0/16 on eth0, so that destination would
# bypass the tunnel entirely and never reach the P4 switch.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$DIR/results"
mkdir -p "$RESULTS"

UE="${UE:-ue-2}"
DN="${DN:-192.168.230.1}"
DURATION="${DURATION:-8}"

UE_ADDR=$(docker exec "$UE" sh -c \
  "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1")
[[ -n "$UE_ADDR" ]] || { echo "Error: no uesimtun0 on $UE" >&2; exit 1; }
echo "[C] UE=$UE tunnel=$UE_ADDR DN=$DN"

set_rate() { docker exec onos sh -c "echo $2 > /tmp/qos_meter_index; echo $1 > /tmp/qos_rate_kbps"; sleep 3; }

# ue-2 lacks UERANSIM's 0.0.0.0/1 tunnel routes, so pin the DN to the tunnel.
docker exec "$UE" ip route replace "$DN/32" dev uesimtun0 src "$UE_ADDR"

measure_tcp() {
  docker exec "$UE" iperf3 -c "$DN" -B "$UE_ADDR" -t "$DURATION" --json 2>/dev/null \
    | python3 -c "
import json,sys
try: print(round(json.load(sys.stdin)['end']['sum_sent']['bits_per_second']/1e6,2))
except Exception: print('nan')"
}

echo "[C] Clearing limits and warming the flow so its cell is allocated..."
set_rate 0 all
docker exec "$UE" iperf3 -c "$DN" -B "$UE_ADDR" -t 3 >/dev/null 2>&1 || true
docker exec "$UE" ping -I uesimtun0 -c 2 -W 3 "$DN" >/dev/null 2>&1 || true

# Cell allocation is announced in the ONOS log as "QoS: flow <s>-<d>-<proto> -> meter cell N".
cell_for() {  # protocol number
  docker logs onos 2>&1 | grep "QoS: flow ${UE_ADDR}-${DN}-$1 " \
    | tail -1 | grep -oE 'meter cell [0-9]+' | grep -oE '[0-9]+'
}
TCP_CELL=$(cell_for 6)
ICMP_CELL=$(cell_for 1)
echo "[C] TCP flow  ${UE_ADDR}->${DN} proto 6 -> meter cell ${TCP_CELL:-?}"
echo "[C] ICMP flow ${UE_ADDR}->${DN} proto 1 -> meter cell ${ICMP_CELL:-?}"
[[ -n "$TCP_CELL" ]] || { echo "Error: TCP flow cell not found in ONOS log" >&2; exit 1; }

echo "[C] Baseline (no limit):"
set_rate 0 all
BASE=$(measure_tcp)
echo "[C]   $BASE Mbit/s"
echo "setpoint_kbps,achieved_mbps" > "$RESULTS/expC_sweep.csv"
echo "0,$BASE" >> "$RESULTS/expC_sweep.csv"

echo "[C] Sweeping the setpoint on cell $TCP_CELL only:"
for rate in 20000 10000 5000 2000; do
  set_rate "$rate" "$TCP_CELL"
  mbps=$(measure_tcp)
  printf '  setpoint %6s kbps -> achieved %8s Mbit/s\n' "$rate" "$mbps"
  echo "$rate,$mbps" >> "$RESULTS/expC_sweep.csv"
done

# The decisive check: a different flow between the SAME pair of addresses must
# be unaffected, which is what proves the policing is per-flow and not per-tunnel.
echo "[C] Selectivity check - ICMP (cell ${ICMP_CELL:-?}) while TCP is capped at 2 Mbit/s:"
docker exec "$UE" ping -I uesimtun0 -c 4 -W 3 "$DN" 2>&1 | tail -2

echo "[C] Clearing limits."
set_rate 0 all
echo "[C] done. Results in $RESULTS/expC_sweep.csv"
