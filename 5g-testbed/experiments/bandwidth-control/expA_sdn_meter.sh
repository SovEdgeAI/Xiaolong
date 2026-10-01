#!/bin/bash
# expA_sdn_meter.sh - Experiment A: bandwidth control from the SDN controller.
#
# Installs an OpenFlow 1.3 meter (DROP band, kbps) from the Ryu application
# mid-run and records the effect on UE->DN throughput measured with iperf3.
#
# Path under test:
#   ue-1 (10.45.0.6) --uesimtun0--> gnb-1 --GTP-U--> [br-ovs-ryu] --> up-1 (UPF)
#   --decap--> 172.17.0.1 (iperf3 server in the host netns)
#
# The meter sits on br-ovs-ryu and matches UDP/2152 in both directions, so it
# polices the ENTIRE gNB<->UPF tunnel. OVS has no GTP parser (no gtp_teid match
# field, inner IP is opaque), so per-UE or per-PDU-session policing is NOT
# possible here - see expC for the P4 per-flow version.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$DIR/results"
mkdir -p "$RESULTS"

UE="${UE:-ue-1}"
# The UE gets a fresh address every time it re-registers, so never hardcode it.
UE_ADDR="${UE_ADDR:-$(docker exec "$UE" sh -c \
  "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null)}"
DN="${DN:-172.17.0.1}"
QOS_API="${QOS_API:-http://127.0.0.1:8080}"
RATE_KBPS="${RATE_KBPS:-20000}"
DURATION="${DURATION:-30}"
ON_AT="${ON_AT:-10}"
OFF_AT="${OFF_AT:-20}"

CURL=(curl -s --max-time 10 --noproxy '*')

meter_on()  { "${CURL[@]}" -X PUT "$QOS_API/qos/meter/$1" >/dev/null; }
meter_off() { "${CURL[@]}" -X DELETE "$QOS_API/qos/meter" >/dev/null; }

# Never leave a rate limit installed if this script dies partway through.
trap 'meter_off >/dev/null 2>&1 || true' EXIT

echo "[A] UE=$UE tunnel address=$UE_ADDR  DN=$DN"
[[ -n "$UE_ADDR" ]] || { echo "Error: no uesimtun0 address on $UE (is nr-ue running?)" >&2; exit 1; }

echo "[A] Clearing any existing rate limit..."
meter_off || true
sleep 2

# Pre-flight: a blackholed path or a dead iperf3 server produces empty JSON and
# silently poisons every measurement below, so fail loudly here instead.
echo "[A] Pre-flight check against the DN..."
if ! docker exec "$UE" iperf3 -c "$DN" -B "$UE_ADDR" -t 2 >/dev/null 2>&1; then
  echo "Error: cannot reach iperf3 server at $DN from $UE." >&2
  echo "       Check: docker ps | grep dn-iperf, and the br-ovs-ryu flow table." >&2
  exit 1
fi
echo "[A]   reachable."

# --- Part 1: TCP, meter toggled mid-run -------------------------------------
echo "[A] TCP run: ${DURATION}s, meter ${RATE_KBPS} kbps ON at t=${ON_AT}s, OFF at t=${OFF_AT}s"
(
  sleep "$ON_AT";  meter_on "$RATE_KBPS"; echo "    -> meter ON  (${RATE_KBPS} kbps)" >&2
  sleep $((OFF_AT - ON_AT)); meter_off;   echo "    -> meter OFF" >&2
) &
TOGGLE=$!

docker exec "$UE" iperf3 -c "$DN" -B "$UE_ADDR" -t "$DURATION" -i 1 --json \
  > "$RESULTS/expA_tcp.json" 2>/dev/null || true
wait $TOGGLE 2>/dev/null || true
meter_off || true

python3 - "$RESULTS/expA_tcp.json" "$RESULTS/expA_tcp.csv" "$ON_AT" "$OFF_AT" <<'PY'
import json, sys
src, dst, on, off = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
d = json.load(open(src))
rows = []
for iv in d.get('intervals', []):
    s = iv['sum']
    t = s['start']
    phase = 'metered' if on <= t < off else 'unmetered'
    rows.append((round(t, 1), round(s['bits_per_second'] / 1e6, 2), phase))
with open(dst, 'w') as f:
    f.write('time_s,throughput_mbps,phase\n')
    for r in rows:
        f.write('%s,%s,%s\n' % r)
print('    wrote %s (%d samples)' % (dst, len(rows)))
for label in ('unmetered', 'metered'):
    v = [r[1] for r in rows if r[2] == label]
    if v:
        print('    %-10s mean %7.2f Mbit/s  min %7.2f  max %7.2f'
              % (label, sum(v) / len(v), min(v), max(v)))
PY

# --- Part 2: setpoint sweep -------------------------------------------------
# Sweeps the meter setpoint to show throughput tracks the control input.
#
# Note on interpretation: an OpenFlow meter with a DROP band is a *policer*, not
# a shaper - it discards anything over the rate instead of queueing it. TCP
# responds to that loss with congestion backoff plus retransmits, so achieved
# throughput sits well BELOW the setpoint and the gap widens as the setpoint
# falls. That is expected policer behaviour, not a measurement error. A shaper
# (OVS QoS/HTB queue) would track the setpoint far more closely; the meter is
# used here because it is the control surface reachable from the SDN controller.
#
# iperf3's UDP mode (which would show the raw policed rate) fails over this path
# with "unable to read from stream socket" even at 2 Mbit/s, while raw UDP via
# netcat traverses the tunnel fine - an iperf3/UERANSIM interaction, not a
# network fault. TCP is used throughout instead.
echo "[A] Setpoint sweep (TCP, ${SWEEP_SECS:-8}s per point)"
echo "setpoint_kbps,achieved_mbps,retransmits" > "$RESULTS/expA_sweep.csv"
for rate in 5000 10000 20000 50000 100000; do
  meter_on "$rate"; sleep 2
  out=$(docker exec "$UE" iperf3 -c "$DN" -B "$UE_ADDR" -t "${SWEEP_SECS:-8}" --json 2>/dev/null || echo '{}')
  read -r mbps retr <<<"$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    s=d['end']['sum_sent']
    print(round(s['bits_per_second']/1e6,2), s.get('retransmits','na'))
except Exception:
    print('nan na')
" <<<"$out")"
  printf '  setpoint %6s kbps -> achieved %8s Mbit/s (retr %s)\n' "$rate" "$mbps" "$retr"
  echo "$rate,$mbps,$retr" >> "$RESULTS/expA_sweep.csv"
  meter_off; sleep 1
done

meter_off || true
echo "[A] done. Results in $RESULTS/"
