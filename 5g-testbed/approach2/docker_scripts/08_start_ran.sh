#!/bin/bash
# 08_start_ran.sh
#
# Docker-based replacement for README step 13 (UERANSIM gNB + UE).
#
# The UERANSIM tree is taken from the approach1 containers when they exist
# (same ubuntu:24.04 base, so the binaries match this glibc) and the approach1
# configs are re-addressed onto the 192.168.235.0/24 fabric. Without approach1,
# the build from 00_prereqs.sh is used and the configs are generated here.
#
# The gNB's N3/GTP-U endpoint (192.168.235.5) and the UPF's (192.168.235.4) sit
# on opposite sides of the P4 switch, so every GTP-U packet between them is
# parsed by onos-p4-gtp.p4 - that is what the detector consumes.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${TMPDIR:-/tmp}/a2-ueransim.$$"
SRC_GNB="${SRC_GNB:-gnb-1}"   # donor container holding a built UERANSIM

GNB_IP=192.168.235.5
UE_IP=192.168.235.6
AMF_IP=192.168.235.2

cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

GNB_CFG="$STAGE/ueransim/config/open5gs-gnb1.yaml"
UE_CFG="$STAGE/ueransim/config/open5gs-ue1.yaml"
mkdir -p "$STAGE"

if docker inspect "$SRC_GNB" >/dev/null 2>&1; then
  echo "[08] Staging UERANSIM from $SRC_GNB..."
  docker cp "$SRC_GNB:/ueransim" "$STAGE/ueransim" >/dev/null
  [[ -x "$STAGE/ueransim/nr-gnb" ]] || { echo "Error: nr-gnb not found in donor." >&2; exit 1; }

  # Re-address the known-good approach1 configs onto the approach2 subnet.
  docker cp "ue-1:/ueransim/config/open5gs-ue1.yaml" "$UE_CFG" >/dev/null
  sed -i -e "s/192\.168\.230\.5/$GNB_IP/g" -e "s/192\.168\.230\.3/$AMF_IP/g" "$GNB_CFG"
  sed -i -e "s/192\.168\.230\.5/$GNB_IP/g" "$UE_CFG"
else
  # No approach1 on this host: use the build from 00_prereqs.sh and write the
  # configs from scratch. PLMN 001/01, TAC 1, SST 1 and DNN "internet" match
  # configs/cp/amf.yaml and smf.yaml; IMSI and K/OPc match 07's subscriber.
  UERANSIM_DIR="${UERANSIM_DIR:-$DIR/run/ueransim}"
  [[ -x "$UERANSIM_DIR/nr-gnb" ]] || { echo "Error: no $SRC_GNB and no build in $UERANSIM_DIR; run ./00_prereqs.sh" >&2; exit 1; }
  echo "[08] Staging UERANSIM from $UERANSIM_DIR (no $SRC_GNB on this host)..."
  cp -r "$UERANSIM_DIR" "$STAGE/ueransim"
  IMSI="${IMSI:-001010000000001}"
  cat >"$GNB_CFG" <<EOF
mcc: '001'
mnc: '01'
nci: '0x000000010'
idLength: 32
tac: 1
linkIp: $GNB_IP
ngapIp: $GNB_IP
gtpIp: $GNB_IP
amfConfigs:
  - address: $AMF_IP
    port: 38412
slices:
  - sst: 1
ignoreStreamIds: true
EOF
  cat >"$UE_CFG" <<EOF
supi: 'imsi-$IMSI'
mcc: '001'
mnc: '01'
protectionScheme: 0
homeNetworkPublicKey: '5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650'
homeNetworkPublicKeyId: 1
routingIndicator: '0000'
key: '465B5CE8B199B49FAA5F0A2EE238A6BC'
op: 'E8ED289DEBA952E4283B54E88E6183CA'
opType: 'OPC'
amf: '8000'
imei: '356938035643803'
imeiSv: '4370816125816151'
gnbSearchList:
  - $GNB_IP
uacAic: {mps: false, mcs: false}
uacAcc: {normalClass: 0, class11: false, class12: false, class13: false, class14: false, class15: false}
sessions:
  - type: 'IPv4'
    apn: 'internet'
    slice:
      sst: 1
configured-nssai:
  - sst: 1
default-nssai:
  - sst: 1
    sd: 1
integrity: {IA1: true, IA2: true, IA3: true}
ciphering: {EA1: true, EA2: true, EA3: true}
integrityMaxRate: {uplink: 'full', downlink: 'full'}
EOF
fi
echo "[08]   gNB link/ngap/gtp -> $GNB_IP, AMF -> $AMF_IP"
echo "[08]   UE gnbSearchList  -> $GNB_IP"

for c in gnb-2 ue-2; do
  docker exec "$c" rm -rf /ueransim 2>/dev/null || true
  docker cp "$STAGE/ueransim" "$c:/ueransim" >/dev/null
  # nr-gnb links against libsctp for the N2/NGAP SCTP association.
  if ! docker exec "$c" sh -c 'ldconfig -p | grep -q libsctp.so.1'; then
    echo "[08]   installing libsctp1 in $c..."
    docker exec "$c" sh -c \
      'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libsctp1 >/dev/null'
  fi
  echo "[08]   installed /ueransim in $c"
done

echo "[08] Starting nr-gnb on gnb-2..."
docker exec gnb-2 sh -c '
  pkill -x nr-gnb 2>/dev/null || true
  sleep 1
  cd /ueransim
  # Detach fully and log to a file: a pipe back to the host would take the
  # process down with SIGPIPE once the reader exits.
  nohup ./nr-gnb -c config/open5gs-gnb1.yaml >/var/log/nr-gnb.log 2>&1 &
  sleep 3
'
docker exec gnb-2 sh -c 'grep -iE "NG Setup|SCTP|error" /var/log/nr-gnb.log | tail -4' || true

echo "[08] Starting nr-ue on ue-2..."
docker exec ue-2 sh -c '
  pkill -x nr-ue 2>/dev/null || true
  sleep 1
  cd /ueransim
  nohup ./nr-ue -c config/open5gs-ue1.yaml >/var/log/nr-ue.log 2>&1 &
  sleep 6
'
docker exec ue-2 sh -c 'grep -iE "PDU Session|registration|connection|error" /var/log/nr-ue.log | tail -6' || true

echo "[08] UE tunnel interface:"
docker exec ue-2 ip -br addr show uesimtun0 2>/dev/null \
  || { echo "  uesimtun0 not up yet; see 'docker exec ue-2 cat /var/log/nr-ue.log'" >&2; exit 1; }
