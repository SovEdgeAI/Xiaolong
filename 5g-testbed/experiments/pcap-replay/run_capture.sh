#!/bin/bash
# run_capture.sh CAPTURE MODE   - evaluate the approach-2 defense against one real
#                                 DDoS capture: replay it, measure whether the pipeline
#                                 detects the attacker, blocks it, and stops the traffic.
#
# This is a defensive evaluation harness. It drives captured attack traffic through the
# detection/mitigation pipeline and records how well the defense responds.
#
#   MODE ue     malicious-UE threat model (the paper's): every packet leaves from the
#               UE's own tunnel address, so the capture is one flow per protocol.
#   MODE spoof  stress test: each original source becomes its own 10.45.x.y, keeping
#               the capture's multi-source structure.
#
# Alongside the attack a benign control source (10.45.200.1, ICMP at ~3 pps) runs, to
# catch false positives. On-wire counts use the switch ports: veth6 is the gNB side
# (traffic entering the switch), veth4 the UPF side (traffic that got through). The
# inner source sits at byte 70 of the frame (GTP-U carries the PDU Session Container
# extension). Result: one CSV row appended to results/replay.csv.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RES="$DIR/results"; mkdir -p "$RES"
CSV="$RES/replay.csv"
CAP="${1:?usage: run_capture.sh CAPTURE MODE}"; MODE="${2:?usage: run_capture.sh CAPTURE MODE}"
PPS="${PPS:-2000}"; WATCH_S="${WATCH_S:-100}"
API=http://127.0.0.1:23500; ONOSAPI=http://localhost:8181/onos/v1
BENIGN=10.45.200.1; DN=192.168.230.1; UE=ue-2
PCAP="$ROOT/datasets/stopddos/$CAP"
[[ -f "$PCAP" ]] || { echo "missing $PCAP - run tools/fetch_stopddos.sh" >&2; exit 1; }
C=(curl -s --max-time 8 --noproxy '*')
O=(curl -s --max-time 8 --noproxy localhost -u onos:rocks)

onos_ok()   { "${O[@]}" "$ONOSAPI/devices/device:s1" 2>/dev/null | grep -q '"available":true'; }
detector_ok() { pgrep -f 'ryu-env/bin/python getDBDat[a].py' >/dev/null; }
gtp_count() { "${O[@]}" "$ONOSAPI/flows/device:s1" | python3 -c "import sys,json;print(sum(1 for f in json.load(sys.stdin)['flows'] if 'gtp_flows' in f.get('tableId','')))" 2>/dev/null || echo -1; }
drop_count(){ "${O[@]}" "$ONOSAPI/flows/device:s1" | python3 -c "import sys,json;print(sum(1 for f in json.load(sys.stdin)['flows'] if 'dropped' in f.get('tableId','')))" 2>/dev/null || echo -1; }
# `|| true` matters: under `set -e -o pipefail`, an empty list makes grep exit 1, and an
# assignment like `bl=$(blocked)` takes that status and aborts the whole script.
blocked()   { "${C[@]}" "$API/blocked-ips" | grep -oE '"ueip":"[^"]+"' | cut -d'"' -f4 || true; }

echo "== evaluate: $CAP  mode=$MODE  pps=$PPS  watch=${WATCH_S}s"

# --- clean slate: no leftover blocks/flows from a previous run bias this one -------
for ip in $(blocked); do python3 "$ROOT/tools/enforce.py" clear --ue "$ip" --approach 2 >/dev/null 2>&1 || true; done
"${C[@]}" -X DELETE "$API/blocked-ips" >/dev/null || true
docker exec mongo-container mongosh --quiet mongodb://127.0.0.1:27017/onos-p4-flows \
  --eval 'for (const c of ["flows","unidirectionalflows","flaggedips"]) db[c].deleteMany({})' >/dev/null 2>&1 || true
# 06 rebuilds the pipeline, clearing every gtp_flows entry so counts start at zero.
( cd "$ROOT/approach2/docker_scripts" && ./06_deploy_app.sh >/dev/null 2>&1 ) || true
docker exec "$UE" sh -c 'pkill -x nr-ue 2>/dev/null; sleep 3; cd /ueransim && nohup ./nr-ue -c config/open5gs-ue1.yaml >/var/log/nr-ue.log 2>&1 & sleep 12' || true
docker exec "$UE" ip route replace "$DN/32" dev uesimtun0 2>/dev/null || true
UE_IP=$(docker exec "$UE" sh -c "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1")
echo "   UE tunnel address: ${UE_IP:-NONE}"

# Preflight: prove the GTP data path carries traffic BEFORE replaying. Without this a
# wedged tunnel produces a full run of zeros (gtp_flows=0, blocked=0) that looks like
# "the defense missed the attack" when in fact nothing ever reached the switch. That
# silently invalidated 10 of 12 rows in an earlier suite.
if [[ -z "$UE_IP" ]]; then
  echo "   ABORT: no uesimtun0 on $UE (UE not attached)" >&2; exit 2
fi
pre_flows=$(gtp_count)
timeout 15 docker exec "$UE" ping -I uesimtun0 -c 4 -i 0.3 -W 2 "$DN" >/dev/null 2>&1 || true
sleep 3
if [[ "$(gtp_count)" -le "$pre_flows" && "$pre_flows" -eq 0 ]]; then
  echo "   ABORT: no GTP flow formed for a test ping - data path is down." >&2
  echo "          Recover with: cd approach2/docker_scripts && ./07_start_core.sh && ./08_start_ran.sh" >&2
  exit 2
fi
echo "   data path OK (gtp_flows=$(gtp_count))"

# --- benign control: a steady low-rate source that should NOT be flagged ----------
docker exec -d "$UE" sh -c "while true; do python3 - <<'PY'
from scapy.all import IP, ICMP, send
send(IP(src='$BENIGN', dst='$DN')/ICMP(), iface='uesimtun0', verbose=False)
PY
sleep 0.3; done"

# --- baseline switch counters for on-wire mitigation proof ------------------------
t0=$(date +%s)
in6_start=$(gtp_count)

# --- replay the attack in the background ------------------------------------------
loops=$(( WATCH_S * PPS / 3000 + 4 ))   # keep the attack running through the watch window
( "$ROOT/tools/replay_pcap.sh" "$PCAP" --pps "$PPS" --loop "$loops" --src-mode "$MODE" \
    > "$RES/${CAP%.pcap*}.$MODE.replay.log" 2>&1 ) &
replay_pid=$!

# --- watch for detection and blocking ---------------------------------------------
block_s=""; benign_flagged=no
while (( $(date +%s) - t0 < WATCH_S )); do
  sleep 5
  now=$(( $(date +%s) - t0 ))
  bl=$(blocked)
  attackers=$(echo "$bl" | grep -vx "$BENIGN" | grep -c . || true)
  if [[ -z "$block_s" && "$attackers" -gt 0 ]]; then block_s=$now; fi
  if echo "$bl" | grep -qx "$BENIGN"; then benign_flagged=yes; fi
  printf '   t+%3ds  gtp_flows=%s  drop_rules=%s  blocked_attackers=%s\n' \
    "$now" "$(gtp_count)" "$(drop_count)" "$attackers"
  # UE mode: one block is the whole result. (if/break, not `&& break`, which would
  # return 1 when block_s is empty and abort the script under set -e.)
  if [[ -n "$block_s" && "$MODE" == "ue" ]]; then break; fi
done

# --- mitigation proof: for a blocked source, packets in (gNB) vs out (UPF) ---------
leak="n/a"
first_block=$(blocked | grep -vx "$BENIGN" | head -1 || true)
if [[ -n "$first_block" ]]; then
  # The reconciler installs the drop rule up to 5 s after the IP hits /blocked-ips,
  # and we broke the watch loop the instant it appeared - so wait for the rule to
  # actually be in the data plane, otherwise the measurement races the install and
  # reports a false leak.
  for _ in $(seq 1 6); do
    [[ "$(drop_count)" -ge 1 ]] && break
    sleep 3
  done
  sleep 5
  hx=$(printf '0x%02x%02x%02x%02x' ${first_block//./ })
  docker exec ovs-tools sh -c "rm -f /tmp/i /tmp/o; (timeout 8 tcpdump -i veth6 -nn -l 'udp port 2152 and ether[70:4]=$hx' 2>/dev/null | wc -l >/tmp/i) & (timeout 8 tcpdump -i veth4 -nn -l 'udp port 2152 and ether[70:4]=$hx' 2>/dev/null | wc -l >/tmp/o) &" || true
  sleep 1
  docker exec "$UE" sh -c "timeout 6 tcpreplay -i uesimtun0 --pps $PPS --loop 3 /tmp/replay/out.pcap >/dev/null 2>&1" || true
  sleep 6
  gin=$(docker exec ovs-tools cat /tmp/i 2>/dev/null || echo 0)
  gout=$(docker exec ovs-tools cat /tmp/o 2>/dev/null || echo 0)
  leak="${gout}/${gin}"   # out/in: 0/N = fully mitigated
  echo "   mitigation for $first_block: entered switch=$gin  reached UPF=$gout"
fi

kill "$replay_pid" 2>/dev/null || true
docker exec "$UE" sh -c 'pkill -f "while true" 2>/dev/null; pkill -x tcpreplay 2>/dev/null' || true

# --- one CSV row ------------------------------------------------------------------
n_blocked=$(blocked | grep -vx "$BENIGN" | grep -c . || true)
n_srcs=$(grep -oE 'distinct sources mapped' "$RES/${CAP%.pcap*}.$MODE.replay.log" >/dev/null 2>&1 && \
         grep -oE '[0-9]+ distinct sources' "$RES/${CAP%.pcap*}.$MODE.replay.log" | grep -oE '^[0-9]+' || echo "1")
[[ -s "$CSV" ]] || echo "capture,mode,ue_ip,sources,first_block_s,blocked_attackers,gtp_flows_peak,leak_out_in,benign_flagged,onos_ok,detector_ok" > "$CSV"
echo "$CAP,$MODE,${UE_IP:-none},$n_srcs,${block_s:-none},$n_blocked,$(gtp_count),$leak,$benign_flagged,$(onos_ok && echo yes || echo no),$(detector_ok && echo yes || echo no)" >> "$CSV"
tail -1 "$CSV" | sed 's/^/   ROW: /'
