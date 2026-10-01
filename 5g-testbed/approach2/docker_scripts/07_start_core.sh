#!/bin/bash
# 07_start_core.sh
#
# Docker-based replacement for README steps 11-12 (Open5GS control plane + UPF).
#
# The subscriber lives in the open5gs_a2 database, separate from approach1's
# open5gs database, so the two deployments never contend over the same record.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$DIR/configs"
ETC=/opt/open5gs/etc/open5gs
BIN=/opt/open5gs/bin
LOGS=/var/log/open5gs

IMSI="${IMSI:-001010000000001}"
UE_ADDR="${UE_ADDR:-10.45.0.3}"
MONGO="mongodb://192.168.235.1:27017"
# The openverso image ships DB_URI=mongodb://mongo/open5gs in the container env,
# and Open5GS gives that env var precedence over db_uri in the YAML, so it has
# to be overridden per exec or udr/pcf/bsf silently fall back to the wrong host.
DB_URI="$MONGO/open5gs_a2"

# NRF must be up before the others register with it.
CP_NFS=(nrf amf smf ausf udm udr pcf nssf bsf)

# `pkill -f open5gs-` would match the `sh -c` command string carrying these same
# names and kill its own shell, so match on the exact process name instead.
STOP_NFS='for d in nrfd amfd smfd ausfd udmd udrd pcfd nssfd bsfd upfd scpd; do
            pkill -x "open5gs-$d" 2>/dev/null || true
          done'

echo "[07] Provisioning subscriber $IMSI in open5gs_a2..."
docker exec -i mongo-container mongosh --quiet "$MONGO/open5gs_a2" <<EOF >/dev/null
db.subscribers.deleteMany({ imsi: '$IMSI' });
db.subscribers.insertOne({
  imsi: '$IMSI', msisdn: [], imeisv: '4301816125816151',
  mme_host: [], mme_realm: [], purge_flag: [],
  security: {
    k: '465B5CE8 B199B49F AA5F0A2E E238A6BC', op: null,
    opc: 'E8ED289D EBA952E4 283B54E8 8E6183CA', amf: '8000',
    sqn: NumberLong("513")
  },
  ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
  slice: [{
    sst: 1, default_indicator: true,
    session: [{
      name: 'internet', type: 3,
      qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
      ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
      ue: { addr: '$UE_ADDR' }, pcc_rule: []
    }]
  }],
  access_restriction_data: 32, subscriber_status: 0,
  network_access_mode: 0, subscribed_rau_tau_timer: 12, __v: 0
});
EOF
echo "[07] Subscriber count: $(docker exec -i mongo-container mongosh --quiet "$MONGO/open5gs_a2" --eval 'db.subscribers.countDocuments()')"

echo "[07] Installing configs..."
for nf in "${CP_NFS[@]}"; do
  docker cp "$CFG/cp/$nf.yaml" "cp-2:$ETC/$nf.yaml"
done
docker cp "$CFG/up/upf.yaml" "up-2:$ETC/upf.yaml"
echo "[07]   cp-2: ${CP_NFS[*]}"
echo "[07]   up-2: upf"

echo "[07] Starting UPF on up-2..."
docker exec up-2 sh -c "
  set -e
  mkdir -p $LOGS
  $STOP_NFS
  sleep 1
  # ogstun carries the UE data network; it is recreated on each run.
  ip link del ogstun 2>/dev/null || true
  ip tuntap add name ogstun mode tun
  ip addr add 10.45.0.1/16 dev ogstun
  ip addr add 2001:db8:cafe::1/48 dev ogstun
  ip link set ogstun up
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  # Decapsulated UE traffic leaves via the container's own default route.
  iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
  $BIN/open5gs-upfd -D >>$LOGS/upf.out 2>&1
" >/dev/null
sleep 2

echo "[07] Starting control plane on cp-2..."
docker exec cp-2 sh -c "mkdir -p $LOGS; $STOP_NFS; sleep 1"
for nf in "${CP_NFS[@]}"; do
  # Redirect inside the container: -D daemonizes but keeps stdout, so if that
  # stdout is a pipe back to this script the daemon takes SIGPIPE and dies the
  # moment the reader goes away. A file keeps it alive and keeps the log.
  docker exec -e DB_URI="$DB_URI" cp-2 \
    sh -c "$BIN/open5gs-${nf}d -D >>$LOGS/${nf}.out 2>&1"
  # NRF has to be registered before the rest come up.
  [[ "$nf" == "nrf" ]] && sleep 4 || sleep 1
done

sleep 5
echo "[07] Running network functions:"
printf '  cp-2: %s\n' "$(docker exec cp-2 sh -c "ps -eo comm | grep -o 'open5gs-[a-z]*d' | sort -u | tr '\n' ' '")"
printf '  up-2: %s\n' "$(docker exec up-2 sh -c "ps -eo comm | grep -o 'open5gs-[a-z]*d' | sort -u | tr '\n' ' '")"

echo "[07] PFCP association (UPF <-> SMF):"
docker exec cp-2 sh -c "grep -ih 'pfcp\|associat' $LOGS/smf.log 2>/dev/null | tail -3" || true
