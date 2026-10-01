#!/bin/bash
# start_good_ue.sh - a second, legitimate UE that sends normal traffic.
#
# The evaluation uses this to check that RA3's mitigation stops the BAD UE
# (ue-2, 10.45.0.3) without harming a normal user. The good UE registers as a
# second subscriber (IMSI ...002 -> 10.45.0.4) and runs a steady, low-rate HTTP
# client against the victim. The harness reads its success rate before/during/
# after mitigation.
#
#   ./start_good_ue.sh            # provision subscriber, start nr-ue, pin route
#   ./start_good_ue.sh traffic    # (re)start the normal-traffic client
#   ./start_good_ue.sh probe      # one success-rate sample (JSON)
#   ./start_good_ue.sh ip         # print the good UE address
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
GOOD_UE="${GOOD_UE:-ue-good}"
SRC_UE="${SRC_UE:-ue-2}"           # donor: same image + a built UERANSIM
IMSI="${GOOD_IMSI:-001010000000002}"
UE_ADDR="${GOOD_UE_ADDR:-10.45.0.4}"
GNB_IP=192.168.235.5
MONGO="mongodb://192.168.235.1:27017"
VENVF="$DIR/victim.env"

victim_ip() { grep -E '^VICTIM_IP=' "$VENVF" | cut -d= -f2; }

provision_subscriber() {
  # second subscriber in open5gs_a2, same key/opc, address 10.45.0.4
  docker exec -i mongo-container mongosh --quiet "$MONGO/open5gs_a2" <<EOF >/dev/null
db.subscribers.deleteMany({ imsi: '$IMSI' });
db.subscribers.insertOne({
  imsi: '$IMSI', msisdn: [], imeisv: '4301816125816152',
  mme_host: [], mme_realm: [], purge_flag: [],
  security: { k: '465B5CE8 B199B49F AA5F0A2E E238A6BC', op: null,
              opc: 'E8ED289D EBA952E4 283B54E8 8E6183CA', amf: '8000', sqn: NumberLong("0") },
  ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
  slice: [{ sst: 1, default_indicator: true,
    session: [{ name: 'internet', type: 3,
      qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
      ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
      ue: { addr: '$UE_ADDR' }, pcc_rule: [] }] }],
  access_restriction_data: 32, subscriber_status: 0,
  network_access_mode: 0, subscribed_rau_tau_timer: 12, __v: 0
});
EOF
  echo "  provisioned subscriber $IMSI -> $UE_ADDR"
}

ensure_container() {
  if [[ "$(docker inspect -f '{{.State.Running}}' "$GOOD_UE" 2>/dev/null)" == "true" ]]; then return; fi
  docker rm -f "$GOOD_UE" >/dev/null 2>&1 || true
  local image; image=$(docker inspect -f '{{.Config.Image}}' "$SRC_UE")
  docker run -dit --privileged --name "$GOOD_UE" --hostname "$GOOD_UE" \
    --cap-add=NET_ADMIN --cap-add=SYS_ADMIN "$image" bash >/dev/null
  # tools + UERANSIM: copy from the host build (container-to-container cp is
  # not supported, so stage via the host).
  docker exec "$GOOD_UE" sh -c 'command -v curl >/dev/null || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl libsctp1 iproute2 iputils-ping >/dev/null 2>&1)'
  local uedir="$DIR/../approach2/docker_scripts/run/ueransim"
  if [[ -x "$uedir/nr-ue" ]]; then
    docker cp "$uedir" "$GOOD_UE:/ueransim" >/dev/null
  else
    local stage="/tmp/good-ue-ueransim.$$"; rm -rf "$stage"
    docker cp "$SRC_UE:/ueransim" "$stage" >/dev/null
    docker cp "$stage" "$GOOD_UE:/ueransim" >/dev/null; rm -rf "$stage"
  fi
  echo "  started $GOOD_UE ($image)"
}

write_ue_cfg() {
  # take the working UE config from the bad UE (via host), re-IMSI it
  local stage="/tmp/good-ue-cfg.$$"
  docker cp "$SRC_UE:/ueransim/config/open5gs-ue1.yaml" "$stage" >/dev/null
  sed -i "s|^supi:.*|supi: 'imsi-$IMSI'|" "$stage"
  docker exec "$GOOD_UE" mkdir -p /ueransim/config
  docker cp "$stage" "$GOOD_UE:/ueransim/config/good-ue.yaml" >/dev/null
  rm -f "$stage"
}

start_nr_ue() {
  docker exec "$GOOD_UE" sh -c '
    pkill -x nr-ue 2>/dev/null || true; sleep 1
    cd /ueransim && nohup ./nr-ue -c config/good-ue.yaml >/var/log/nr-ue.log 2>&1 &
    sleep 6'
  docker exec "$GOOD_UE" sh -c 'ip -br addr show uesimtun0 2>/dev/null' \
    || { echo "  good UE tunnel not up; see docker logs" >&2; return 1; }
}

pin_route() {
  local vip="$1" tun
  tun=$(docker exec "$GOOD_UE" sh -c "ip -o -4 addr show | awk '/10\\.45\\./{print \$2; exit}'")
  [[ -n "$tun" ]] || { echo "  good UE has no tunnel" >&2; return 1; }
  docker exec "$GOOD_UE" ip route replace "$vip/32" dev "$tun"
  echo "  routed $GOOD_UE -> $vip via $tun"
}

# A steady legitimate HTTP client: one request/second, logging success/fail to
# a counter file the harness reads. Low rate so it is pure "legit user" signal.
start_traffic() {
  local vip="$1"
  docker exec "$GOOD_UE" sh -c 'pkill -f "[g]ood_traffic" 2>/dev/null || true'
  docker exec -d "$GOOD_UE" sh -c "cat >/tmp/good_traffic.sh <<'EOS'
ok=0; fail=0
tun=\$(ip -o -4 addr show | awk '/10\\.45\\./{print \$2; exit}')
while true; do
  if curl -s -m 3 --interface \"\$tun\" -o /dev/null http://$vip/ 2>/dev/null; then ok=\$((ok+1)); else fail=\$((fail+1)); fi
  printf '{\"ok\": %d, \"fail\": %d}\n' \"\$ok\" \"\$fail\" > /tmp/good_traffic.json
  sleep 1
done
EOS
sh /tmp/good_traffic.sh"
  echo "  good UE normal HTTP traffic started -> $vip"
}

case "${1:-up}" in
  ip)      docker exec "$GOOD_UE" sh -c "ip -o -4 addr show | awk '/10\\.45\\./{print \$4}' | cut -d/ -f1" 2>/dev/null; exit 0 ;;
  probe)   docker exec "$GOOD_UE" cat /tmp/good_traffic.json 2>/dev/null || echo '{"ok":0,"fail":0}'; exit 0 ;;
  traffic) start_traffic "$(victim_ip)"; exit 0 ;;
  route)   pin_route "$(victim_ip)"; exit 0 ;;
esac

VIP="$(victim_ip)"; [[ -n "$VIP" ]] || { echo "no victim.env; run start_victim.sh first" >&2; exit 1; }
echo "[good-ue] provisioning + starting legitimate UE..."
provision_subscriber
ensure_container
write_ue_cfg
start_nr_ue
pin_route "$VIP"
start_traffic "$VIP"
sleep 3
echo "[good-ue] good UE at $(docker exec "$GOOD_UE" sh -c "ip -o -4 addr show | awk '/10\\.45\\./{print \$4}' | cut -d/ -f1"), probe: $(docker exec "$GOOD_UE" cat /tmp/good_traffic.json 2>/dev/null)"
