#!/bin/bash
# expB_core_ambr.sh - Experiment B: bandwidth control from the 5G core.
#
# This is the AMF/SMF-side counterpart to expA. No SDN controller involvement:
# the only thing changed is Session-AMBR in the subscriber record, which the UDM
# hands to the SMF at PDU session establishment, and which the SMF pushes to the
# UPF as a PFCP QER. If throughput follows the setting, bandwidth control is a
# native 5G core function here and does not need an SDN program at all.
#
# The UE must re-register for a new Session-AMBR to take effect: AMBR is applied
# when the PDU session is established, not renegotiated mid-session.
#
# Open5GS AMBR units: 0=bps 1=Kbps 2=Mbps 3=Gbps 4=Tbps
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$DIR/results"
mkdir -p "$RESULTS"

UE="${UE:-ue-1}"
DN="${DN:-172.17.0.1}"
IMSI="${IMSI:-001010000000001}"
MONGO_DB="${MONGO_DB:-open5gs}"
DURATION="${DURATION:-8}"

set_ambr() {  # value, unit
  docker exec mongo-container mongosh --quiet "mongodb://127.0.0.1:27017/$MONGO_DB" --eval "
    db.subscribers.updateOne({imsi:'$IMSI'}, {\$set:{
      'ambr.downlink':{value:$1,unit:$2}, 'ambr.uplink':{value:$1,unit:$2},
      'slice.0.session.0.ambr.downlink':{value:$1,unit:$2},
      'slice.0.session.0.ambr.uplink':{value:$1,unit:$2}}})" >/dev/null
}

reregister() {
  # Re-establish the PDU session so the new AMBR is applied.
  docker exec "$UE" sh -c '
    pkill -x nr-ue 2>/dev/null; sleep 3
    cd /ueransim && nohup ./nr-ue -c config/open5gs-ue1.yaml >/var/log/nr-ue.log 2>&1 &
    sleep 12' >/dev/null 2>&1 || true
}

ue_addr() {
  docker exec "$UE" sh -c \
    "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1"
}

measure() {
  local addr; addr=$(ue_addr)
  [[ -n "$addr" ]] || { echo "nan"; return; }
  docker exec "$UE" iperf3 -c "$DN" -B "$addr" -t "$DURATION" --json 2>/dev/null \
    | python3 -c "
import json,sys
try: print(round(json.load(sys.stdin)['end']['sum_sent']['bits_per_second']/1e6,2))
except Exception: print('nan')"
}

echo "setting,ambr_mbps,achieved_mbps" > "$RESULTS/expB_ambr.csv"

# value unit label
for spec in "1 3 1000" "100 2 100" "20 2 20" "1 3 1000"; do
  read -r val unit label <<<"$spec"
  echo "[B] Setting Session-AMBR to ${label} Mbit/s (value=$val unit=$unit)..."
  set_ambr "$val" "$unit"
  reregister
  addr=$(ue_addr)
  mbps=$(measure)
  printf '[B]   UE=%s  achieved %s Mbit/s\n' "${addr:-none}" "$mbps"
  echo "${label},${label},${mbps}" >> "$RESULTS/expB_ambr.csv"
done

echo "[B] done. Subscriber restored to 1 Gbit/s. Results in $RESULTS/expB_ambr.csv"
