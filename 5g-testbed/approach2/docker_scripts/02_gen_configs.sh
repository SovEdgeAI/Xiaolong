#!/bin/bash
# 02_gen_configs.sh
#
# Generates the Open5GS configs for approach2 under docker_scripts/configs/.
#
# Addressing (approach2 uses 192.168.235.0/24; approach1 keeps 192.168.230.0/24):
#   192.168.235.2  cp-2 veth1  all SBI + NRF, AMF NGAP   (s1 port 0)
#   192.168.235.3  cp-2 veth3  SMF PFCP / GTP-C / GTP-U  (s1 port 1)
#   192.168.235.4  up-2 veth5  UPF PFCP / GTP-U          (s1 port 2)
#   192.168.235.5  gnb-2 veth7                           (s1 port 3)
#   192.168.235.6  ue-2  veth9                           (s1 port 4)
#   192.168.235.1  br-p4-onos (host) gateway             (s1 port 5)
#
# GTP-U between gnb-2 (.5) and up-2 (.4) is the traffic the P4 pipeline parses,
# so it must cross the switch rather than a Docker bridge.
#
# The subscriber DB is open5gs_a2, deliberately separate from approach1's
# open5gs DB, so the two deployments cannot disturb each other's subscribers.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP="$DIR/configs/cp"
UP="$DIR/configs/up"
mkdir -p "$CP" "$UP"

SBI=192.168.235.2       # cp-2 veth1 - SBI plane + NRF
SMF_U=192.168.235.3     # cp-2 veth3 - SMF user/PFCP plane
UPF=192.168.235.4       # up-2 veth5
DB="mongodb://192.168.235.1:27017/open5gs_a2"

# A plain SBI-only NF: name, port, and whether it needs the subscriber DB.
gen_simple_nf() {
  local nf="$1" port="$2" with_db="${3:-no}"
  {
    [[ "$with_db" == "db" ]] && echo "db_uri: $DB"
    cat <<EOF
$nf:
  sbi:
    - dev: veth1
      advertise: $SBI
      port: $port
nrf:
  sbi:
    - addr: $SBI
      port: 7777
parameter:
max:
pool:
time:
EOF
  } > "$CP/$nf.yaml"
  echo "  wrote cp/$nf.yaml"
}

cat > "$CP/nrf.yaml" <<EOF
nrf:
  sbi:
    - dev: veth1
      advertise: $SBI
      port: 7777
parameter:
max:
pool:
time:
EOF
echo "  wrote cp/nrf.yaml"

cat > "$CP/amf.yaml" <<EOF
amf:
  sbi:
    - dev: veth1
      advertise: $SBI
      port: 7778
  ngap:
    - dev: veth1
  guami:
    - plmn_id:
        mcc: 001
        mnc: 01
      amf_id:
        region: 2
        set: 1
  tai:
    - plmn_id:
        mcc: 001
        mnc: 01
      tac: 1
  plmn_support:
    - plmn_id:
        mcc: 001
        mnc: 01
      s_nssai:
        - sst: 1
  security:
    integrity_order : [ NIA2, NIA1, NIA0 ]
    ciphering_order : [ NEA0, NEA1, NEA2 ]
  network_name:
    full: Open5GS
  amf_name: open5gs-amf0
nrf:
  sbi:
    - addr: $SBI
      port: 7777
parameter:
max:
pool:
time:
EOF
echo "  wrote cp/amf.yaml"

# SMF keeps SBI on veth1 but puts PFCP/GTP on veth3 (.3), which is the address
# the UPF is told to reach for PFCP.
cat > "$CP/smf.yaml" <<EOF
smf:
  sbi:
    - dev: veth1
      advertise: $SBI
      port: 7779
  pfcp:
    - dev: veth3
  gtpc:
    - dev: veth3
  gtpu:
    - dev: veth3
  subnet:
    - addr: 10.45.0.1/16
      dnn: internet
  dns:
    - 8.8.8.8
    - 8.8.4.4
  mtu: 1400
nrf:
  sbi:
    - addr: $SBI
      port: 7777
upf:
  pfcp:
    - addr: $UPF
parameter:
max:
pool:
time:
EOF
echo "  wrote cp/smf.yaml"

cat > "$CP/nssf.yaml" <<EOF
nssf:
  sbi:
    - dev: veth1
      advertise: $SBI
      port: 7784
  nsi:
    - addr: $SBI
      port: 7777
      s_nssai:
        sst: 1
nrf:
  sbi:
    - addr: $SBI
      port: 7777
parameter:
max:
pool:
time:
EOF
echo "  wrote cp/nssf.yaml"

gen_simple_nf ausf 7781
gen_simple_nf udm  7782
gen_simple_nf udr  7780 db
gen_simple_nf pcf  7783 db
gen_simple_nf bsf  7785 db

# UPF lives in up-2 on veth5 and talks PFCP back to the SMF's veth3 address.
cat > "$UP/upf.yaml" <<EOF
upf:
  pfcp:
    - dev: veth5
  gtpu:
    - dev: veth5
  subnet:
    - addr: 10.45.0.1/16
      dnn: internet
smf:
  pfcp:
    - addr: $SMF_U
parameter:
max:
pool:
time:
EOF
echo "  wrote up/upf.yaml"

echo "[02] configs generated under $DIR/configs"
