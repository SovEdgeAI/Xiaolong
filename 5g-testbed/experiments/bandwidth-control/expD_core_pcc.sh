#!/bin/bash
# expD_core_pcc.sh - Experiment D: PER-FLOW control from the 5G core via PCC rules.
#
# expB showed the core enforces Session-AMBR (whole PDU session). This asks the
# sharper question: can the core act on ONE service data flow (SDF), which is the
# 3GPP-native answer to "control a specific flow" - and if so, can it both
# rate-limit it (MBR) and block it (flow_status = DISABLED, i.e. gate closed)?
#
# Path: subscriber record (MongoDB) -> PCF reads pcc_rule -> Npcf_SMPolicyControl
#       -> SMF creates a dedicated QoS flow -> PFCP PDR (SDF filter) + QER/FAR on UPF.
#
# The SDF filter is protocol-specific (proto 6 = TCP) so ICMP between the SAME
# UE and DN is the selectivity control, exactly as in expC.
#
# Open5GS DB conventions (fields libogsdbi parses):
#   flow.direction   1 = downlink, 2 = uplink, 3 = bidirectional
#   flow.description IPFilterRule; Open5GS emits "permit out <proto> from <DN> to assigned"
#   qos.index        5QI. A GBR 5QI (1-4) is used so MBR is applied per flow.
#   flow_status      0 EN-UL, 1 EN-DL, 2 ENABLED, 3 DISABLED (gate closed), 4 REMOVED
#   *.unit           0 bps, 1 Kbps, 2 Mbps, 3 Gbps
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$DIR/results"
mkdir -p "$RESULTS"

UE="${UE:-ue-1}"
DN="${DN:-172.17.0.1}"
IMSI="${IMSI:-001010000000001}"
MONGO_DB="${MONGO_DB:-open5gs}"
DURATION="${DURATION:-8}"
BACKUP="$RESULTS/subscriber_backup.json"
[[ -s "$BACKUP" ]] || { echo "Error: $BACKUP missing - refuse to modify the subscriber without a backup" >&2; exit 1; }

MONGO() { docker exec -i mongo-container mongosh --quiet "mongodb://127.0.0.1:27017/$MONGO_DB" "$@"; }

set_pcc() {   # $1 = JSON array for pcc_rule (or [] to clear)
  MONGO --eval "db.subscribers.updateOne({imsi:'$IMSI'},{\$set:{'slice.0.session.0.pcc_rule':$1}})" >/dev/null
}

restore_subscriber() {
  # Restore the exact pre-experiment document.
  python3 - "$BACKUP" <<'PY' | MONGO >/dev/null
import json,sys
d=json.load(open(sys.argv[1])); d.pop('_id',None)
print("db.subscribers.replaceOne({imsi:%r}, %s)" % (d['imsi'], json.dumps(d)))
PY
}

reregister() {
  docker exec "$UE" sh -c '
    pkill -x nr-ue 2>/dev/null; sleep 3
    cd /ueransim && nohup ./nr-ue -c config/open5gs-ue1.yaml >/var/log/nr-ue.log 2>&1 &
    sleep 12' >/dev/null 2>&1 || true
}
ue_addr() { docker exec "$UE" sh -c "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1"; }

measure_tcp() {  # prints Mbit/s, or "blocked" if the connection never opens
  local addr; addr=$(ue_addr); [[ -n "$addr" ]] || { echo nan; return; }
  local out; out=$(docker exec "$UE" iperf3 -c "$DN" -B "$addr" -t "$DURATION" --connect-timeout 6000 --json 2>&1 || true)
  python3 -c "
import json,sys
raw=sys.stdin.read()
try:
    d=json.loads(raw)
    if 'error' in d: print('blocked' if ('timed out' in d['error'] or 'refused' in d['error'] or 'unable to connect' in d['error']) else 'error')
    else: print(round(d['end']['sum_sent']['bits_per_second']/1e6,2))
except Exception: print('blocked' if 'unable to connect' in raw else 'nan')" <<<"$out"
}
measure_icmp() {  # prints "<loss>%/<avg ms>"
  docker exec "$UE" ping -I uesimtun0 -c 5 -W 2 -i 0.3 "$DN" 2>&1 | python3 -c "
import re,sys; t=sys.stdin.read()
l=re.search(r'(\d+)% packet loss',t); a=re.search(r'= [\d.]+/([\d.]+)/',t)
print((l.group(1) if l else '?')+'%/'+(a.group(1)+'ms' if a else 'n/a'))"
}
smf_mark()  { docker exec cp-1 sh -c 'wc -l < /var/log/open5gs/smf.out'; }
smf_since() { docker exec cp-1 sh -c "tail -n +$(( $1 + 1 )) /var/log/open5gs/smf.out | grep -iE 'qfi|qer|pcc|gate|mbr|flow' | head -8"; }

# One PCC rule matching TCP (proto 6) between the DN and this UE, both directions.
pcc_json() {  # $1 = MBR Mbit/s, $2 = flow_status
  cat <<EOF
[{
  "flow": [
    {"direction": 1, "description": "permit out 6 from $DN to assigned"},
    {"direction": 2, "description": "permit out 6 from $DN to assigned"}
  ],
  "qos": {
    "index": 2,
    "arp": {"priority_level": 1, "pre_emption_capability": 1, "pre_emption_vulnerability": 1},
    "mbr": {"downlink": {"value": $1, "unit": 2}, "uplink": {"value": $1, "unit": 2}},
    "gbr": {"downlink": {"value": 1,  "unit": 2}, "uplink": {"value": 1,  "unit": 2}}
  },
  "flow_status": $2,
  "precedence": 1
}]
EOF
}

trap 'echo "[D] restoring subscriber"; restore_subscriber; reregister' EXIT

CSV="$RESULTS/expD_pcc.csv"
echo "phase,mbr_mbps,flow_status,tcp_mbps,icmp_loss_rtt,ue_addr" > "$CSV"

run_phase() {  # label mbr status
  local mark; mark=$(smf_mark)
  reregister
  local addr tcp icmp; addr=$(ue_addr); tcp=$(measure_tcp); icmp=$(measure_icmp)
  printf '[D]   %-22s TCP %-9s ICMP %-12s (UE %s)\n' "$1" "$tcp" "$icmp" "${addr:-none}"
  echo "$1,$2,$3,$tcp,$icmp,${addr:-none}" >> "$CSV"
  echo "      SMF:"; smf_since "$mark" | sed 's/^/        /' || true
}

echo "[D] Baseline - no PCC rule"
set_pcc "[]"
run_phase baseline 0 -

echo "[D] Per-flow MBR on TCP only (ICMP is the control)"
for mbr in 100 20 5; do
  set_pcc "$(pcc_json $mbr 2)"
  run_phase "MBR ${mbr} Mbit/s" "$mbr" 2
done

echo "[D] Block TCP only: flow_status=3 (DISABLED / gate closed)"
set_pcc "$(pcc_json 100 3)"
run_phase "gate closed" 100 3

echo "[D] done -> $CSV"
