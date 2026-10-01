#!/bin/bash
# fix_5g_env.sh - Fix and restart the 5G Docker environment
#
# This script fixes all configuration issues and restarts the 5G environment.
# It assumes containers (mongo-container, cp-1, up-1, gnb-1, ue-1) already exist
# on the 5g-network (192.168.230.0/24).
#
# Root causes fixed:
#   1. NF configs used hostname "nrf" which doesn't resolve in Docker → use IPs
#   2. Missing db_uri in UDR/PCF/BSF configs → added
#   3. openverso image sets DB_URI=mongodb://mongo/open5gs env var → override
#   4. All NFs tried to bind SBI on port 80 → assign unique ports
#   5. Subscriber data used wrong schema → use correct Open5GS v2.4.0 format
#   6. UPF missing subnet config → added
#   7. UE container missing iproute2 → installed
#
# Usage: bash fix_5g_env.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/configs"

echo "============================================"
echo " 5G Environment Fix Script"
echo "============================================"

# ========== Step 1: Kill all old processes ==========
echo ""
echo "[Step 1] Killing all old processes..."
docker exec cp-1 pkill -f open5gs 2>/dev/null || true
docker exec up-1 pkill -f open5gs 2>/dev/null || true
docker exec gnb-1 pkill -f nr-gnb 2>/dev/null || true
docker exec ue-1 pkill -f nr-ue 2>/dev/null || true
sleep 2
echo "  Done."

# ========== Step 2: Deploy configs ==========
echo ""
echo "[Step 2] Deploying corrected configs..."
for f in nrf amf smf ausf udm udr pcf nssf bsf; do
  docker cp "${CONFIGS_DIR}/cp/${f}.yaml" cp-1:/opt/open5gs/etc/open5gs/${f}.yaml
  echo "  ✓ cp-1: ${f}.yaml"
done
docker cp "${CONFIGS_DIR}/up/upf.yaml" up-1:/opt/open5gs/etc/open5gs/upf.yaml
echo "  ✓ up-1: upf.yaml"

# ========== Step 3: Setup UPF tunnel ==========
echo ""
echo "[Step 3] Setting up ogstun in UP-1..."
docker exec up-1 bash -c '
  ip tuntap add name ogstun mode tun 2>/dev/null || true
  ip addr flush dev ogstun 2>/dev/null || true
  ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
  ip addr add 2001:db8:cafe::1/48 dev ogstun 2>/dev/null || true
  ip link set ogstun up
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  iptables -t nat -C POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
'
echo "  ✓ ogstun configured"

# ========== Step 4: Fix subscriber data ==========
echo ""
echo "[Step 4] Fixing subscriber data in MongoDB..."
docker exec mongo-container mongosh mongodb://localhost:27017/open5gs --quiet --eval '
  db.subscribers.deleteMany({});
  db.subscribers.insertOne({
    imsi: "001010000000001",
    msisdn: [],
    imeisv: "4301816125816151",
    mme_host: [],
    mme_realm: [],
    purge_flag: [],
    security: {
      k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
      op: null,
      opc: "E8ED289DEBA952E4283B54E88E6183CA",
      amf: "8000",
      sqn: NumberLong("513")
    },
    ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
    slice: [{
      sst: 1,
      default_indicator: true,
      session: [{
        name: "internet",
        type: 3,
        qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
        ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
        pcc_rule: []
      }]
    }],
    access_restriction_data: 32,
    subscriber_status: 0,
    network_access_mode: 0,
    subscribed_rau_tau_timer: 12,
    __v: 0
  });
  print("Subscriber count: " + db.subscribers.countDocuments({}));
'
echo "  ✓ Subscriber data fixed"

# ========== Step 5: Start services in dependency order ==========
echo ""
echo "[Step 5] Starting 5G Core services..."
DB_OVERRIDE="-e DB_URI=mongodb://192.168.230.2:27017/open5gs"

echo "  Starting NRF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-nrfd
sleep 3

echo "  Starting UDR..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-udrd
sleep 2

echo "  Starting UDM..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-udmd
sleep 1

echo "  Starting AUSF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-ausfd
sleep 1

echo "  Starting PCF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-pcfd
sleep 1

echo "  Starting NSSF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-nssfd
sleep 1

echo "  Starting BSF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-bsfd
sleep 1

echo "  Starting AMF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-amfd
sleep 2

echo "  Starting UPF..."
docker exec -d up-1 /opt/open5gs/bin/open5gs-upfd
sleep 2

echo "  Starting SMF..."
docker exec -d $DB_OVERRIDE cp-1 /opt/open5gs/bin/open5gs-smfd
sleep 3

# ========== Step 6: Verify ==========
echo ""
echo "[Step 6] Verifying services..."
CP_COUNT=$(docker exec cp-1 ps aux | grep open5gs | grep -v grep | wc -l)
UP_COUNT=$(docker exec up-1 ps aux | grep open5gs | grep -v grep | wc -l)
echo "  CP NFs running: $CP_COUNT/9 (NRF, AMF, SMF, AUSF, UDM, UDR, PCF, NSSF, BSF)"
echo "  UP NFs running: $UP_COUNT/1 (UPF)"

if [ "$CP_COUNT" -lt 9 ] || [ "$UP_COUNT" -lt 1 ]; then
    echo "  ⚠️  WARNING: Not all NFs started. Run NFs interactively to debug:"
    echo "     docker exec cp-1 /opt/open5gs/bin/open5gs-<nf>d"
fi

# ========== Step 7: Start RAN ==========
echo ""
echo "[Step 7] Starting gNB and UE..."

echo "  Starting gNB..."
docker exec -d gnb-1 /ueransim/nr-gnb -c /ueransim/config/open5gs-gnb1.yaml
sleep 3

echo "  Starting UE..."
docker exec -d ue-1 /ueransim/nr-ue -c /ueransim/config/open5gs-ue1.yaml
sleep 5

echo ""
echo "============================================"
echo " Setup Complete!"
echo "============================================"
echo ""
echo " Port Assignments:"
echo "   NRF:  7777    AMF:  7778 (NGAP: 38412)"
echo "   SMF:  7779    UDR:  7780"
echo "   AUSF: 7781    UDM:  7782"
echo "   PCF:  7783    NSSF: 7784"
echo "   BSF:  7785"
echo ""
echo " Network: 192.168.230.0/24"
echo "   mongo: .2  |  cp-1: .3  |  up-1: .4  |  gnb-1: .5  |  ue-1: .6"
echo ""
echo " To test UE registration interactively:"
echo "   docker exec ue-1 /ueransim/nr-ue -c /ueransim/config/open5gs-ue1.yaml"
echo ""
echo " To check UE TUN interface:"
echo "   docker exec ue-1 ip addr show uesimtun0"
echo ""
