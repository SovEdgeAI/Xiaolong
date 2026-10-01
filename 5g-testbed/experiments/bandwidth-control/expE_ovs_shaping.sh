#!/bin/bash
# expE_ovs_shaping.sh - Experiment E: does OVS track the setpoint better when it
# SHAPES instead of POLICES?
#
# expA's 0.47x came from an OpenFlow meter with a DROP band: excess is discarded,
# TCP treats the loss as congestion and backs off. OVS offers two other knobs:
#
#   E1  Interface.ingress_policing_rate  - a tc ingress policer on the port the
#       gNB traffic ENTERS. Also a policer (drops), so the hypothesis is that it
#       behaves like the meter. Included to separate "OVS" from "policer".
#   E2  QoS(linux-htb) + Queue.max-rate    - an HTB shaper on the port the traffic
#       LEAVES towards the UPF, with an OpenFlow rule steering GTP-U into the
#       queue via set_queue. Queues rather than drops, so TCP should sit on the
#       setpoint the way the UPF's AMBR shaper did in expB.
#
# Both are still SDN-controllable: the queue is selected by an OpenFlow action,
# and both OVSDB knobs can be written by Ryu's OVSDB library. Here the rule and
# the queue config are written directly so the mechanism is measured in isolation.
#
# Granularity is unchanged from expA: OVS cannot see inside GTP, so this shapes
# the whole tunnel.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$DIR/results"; mkdir -p "$RESULTS"

UE="${UE:-ue-1}"; DN="${DN:-172.17.0.1}"; DURATION="${DURATION:-8}"
BR=br-ovs-ryu
# Host-side OVS port names for the approach1 containers (from eth1 iflink).
PORT_GNB="${PORT_GNB:-81b0369754eb4_l}"   # traffic from gNB enters here
PORT_UPF="${PORT_UPF:-33705c3868f34_l}"   # traffic to UPF leaves here
RATES_KBPS=(5000 10000 20000 50000 100000)

# One long-lived privileged helper with the OVS CLI, so we don't apt-get per call.
ovs() {
  if [[ "$(docker inspect -f '{{.State.Running}}' ovs-tools 2>/dev/null)" != "true" ]]; then
    docker rm -f ovs-tools >/dev/null 2>&1 || true
    docker run -dit --name ovs-tools --privileged --network=host \
      -v /var/run/openvswitch:/var/run/openvswitch ubuntu:24.04 bash >/dev/null
    docker exec ovs-tools sh -c 'apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openvswitch-switch iproute2 >/dev/null 2>&1'
  fi
  docker exec ovs-tools "$@"
}

ue_addr() { docker exec "$UE" sh -c "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1"; }
measure_tcp() {
  local addr; addr=$(ue_addr); [[ -n "$addr" ]] || { echo nan; return; }
  docker exec "$UE" iperf3 -c "$DN" -B "$addr" -t "$DURATION" --json 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin); s=d['end']['sum_sent']; print(round(s['bits_per_second']/1e6,2), s.get('retransmits','-'))
except Exception: print('nan -')"
}

cleanup() {
  echo "[E] cleanup: removing queue rule, QoS records, ingress policing; restoring GTP punt"
  ovs ovs-ofctl -O OpenFlow13 del-flows "$BR" "cookie=0xE0/-1" 2>/dev/null || true
  ovs ovs-vsctl -- clear port "$PORT_UPF" qos 2>/dev/null || true
  ovs ovs-vsctl -- --all destroy qos -- --all destroy queue 2>/dev/null || true
  ovs ovs-vsctl set interface "$PORT_GNB" ingress_policing_rate=0 ingress_policing_burst=0 2>/dev/null || true
  # Restore approach1's detection punt exactly as found.
  ovs ovs-ofctl -O OpenFlow13 add-flow "$BR" "table=0,cookie=0x1,priority=1000,udp,tp_dst=2152,actions=controller,normal" 2>/dev/null || true
}
trap cleanup EXIT

echo "[E] UE=$UE addr=$(ue_addr) DN=$DN  gnb-port=$PORT_GNB upf-port=$PORT_UPF"
ovs ovs-vsctl set-fail-mode "$BR" secure
# The CONTROLLER punt copies every GTP packet to Ryu and corrupts baselines (see expA).
ovs ovs-ofctl -O OpenFlow13 del-flows "$BR" "cookie=0x1/-1" 2>/dev/null || true
ovs ovs-vsctl set interface "$PORT_GNB" ingress_policing_rate=0 ingress_policing_burst=0
ovs ovs-vsctl -- clear port "$PORT_UPF" qos 2>/dev/null || true
sleep 2

CSV="$RESULTS/expE_sweep.csv"
echo "mechanism,setpoint_kbps,achieved_mbps,retransmits" > "$CSV"

read -r base retr <<<"$(measure_tcp)"
echo "[E] baseline (no shaping): $base Mbit/s"
echo "baseline,0,$base,$retr" >> "$CSV"

echo "[E1] ingress_policing_rate on $PORT_GNB (tc policer, drops)"
[[ "${ONLY_E2:-0}" == "1" ]] && RATES_E1=() || RATES_E1=("${RATES_KBPS[@]}")
for r in "${RATES_E1[@]}"; do
  ovs ovs-vsctl set interface "$PORT_GNB" ingress_policing_rate="$r" ingress_policing_burst="$(( r / 10 ))"
  sleep 2
  read -r mbps retr <<<"$(measure_tcp)"
  printf '  setpoint %6s kbps -> %8s Mbit/s  (%.2fx, retr %s)\n' "$r" "$mbps" "$(python3 -c "print(float('$mbps')/($r/1000))" 2>/dev/null || echo 0)" "$retr"
  echo "ingress_policing,$r,$mbps,$retr" >> "$CSV"
done
ovs ovs-vsctl set interface "$PORT_GNB" ingress_policing_rate=0 ingress_policing_burst=0

echo "[E2] linux-htb queue on $PORT_UPF + OpenFlow set_queue (shaper, queues)"
# GTP-U towards the UPF goes into queue 1; everything else stays on the default queue.
ovs ovs-ofctl -O OpenFlow13 add-flow "$BR" \
  "table=0,cookie=0xE0,priority=500,udp,tp_dst=2152,actions=set_queue:1,normal"
for r in "${RATES_KBPS[@]}"; do
  bps=$(( r * 1000 ))
  ovs ovs-vsctl -- clear port "$PORT_UPF" qos -- --all destroy qos -- --all destroy queue >/dev/null 2>&1 || true
  ovs ovs-vsctl -- set port "$PORT_UPF" qos=@q \
    -- --id=@q  create qos type=linux-htb other-config:max-rate=2000000000 queues:0=@q0 queues:1=@q1 \
    -- --id=@q0 create queue other-config:max-rate=2000000000 \
    -- --id=@q1 create queue other-config:min-rate="$bps" other-config:max-rate="$bps" >/dev/null
  sleep 2
  read -r mbps retr <<<"$(measure_tcp)"
  printf '  setpoint %6s kbps -> %8s Mbit/s  (%.2fx, retr %s)\n' "$r" "$mbps" "$(python3 -c "print(float('$mbps')/($r/1000))" 2>/dev/null || echo 0)" "$retr"
  echo "htb_queue,$r,$mbps,$retr" >> "$CSV"
done

echo "[E] done -> $CSV"
