#!/bin/bash
# replay_pcap.sh - replay any pcap from a UERANSIM UE through the approach2 5G path.
#
#   ./tools/replay_pcap.sh PCAP [--pps N | --mbps N | --multiplier X | --topspeed]
#                               [--loop N] [--src-mode spoof|ue] [--proto tcp|udp|icmp]
#                               [--max-packets N] [--dst IP] [--ue CONTAINER]
#
# What happens:
#   1. The pcap is copied into the UE container and adapted by tools/pcap_adapt.py
#      (raw-IP link type, sources mapped into 10.45.0.0/16, destination pinned to a
#      tunnelled DN, oversized packets trimmed to the 1400-byte tunnel MTU,
#      checksums recomputed).
#   2. tcpreplay injects it into uesimtun0. UERANSIM encapsulates it as GTP-U, so it
#      reaches the P4 switch exactly like traffic a real UE generated: gtp_flows
#      entries are created per inner source, the detector scores them, and a flagged
#      source is blocked by dropped_inner_ipv4.
#
# Rate: default is the capture's own timing. For a detector test the attack must
# last longer than the detection window (5 consecutive predictions x 5 s polling,
# ~40 s end to end), so short captures usually want --loop or a --pps rate.
set -euo pipefail

usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
[[ $# -ge 1 ]] || usage 1
[[ "$1" == "-h" || "$1" == "--help" ]] && usage 0

PCAP="$1"; shift
[[ -f "$PCAP" ]] || { echo "Error: no such pcap: $PCAP" >&2; exit 1; }

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UE=ue-2; DST=192.168.230.1; SRC_MODE=spoof; LOOP=1
RATE=(); ADAPT_EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pps)         RATE=(--pps "$2"); shift 2 ;;
    --mbps)        RATE=(--mbps "$2"); shift 2 ;;
    --multiplier)  RATE=(--multiplier "$2"); shift 2 ;;
    --topspeed)    RATE=(--topspeed); shift ;;
    --loop)        LOOP="$2"; shift 2 ;;
    --src-mode)    SRC_MODE="$2"; shift 2 ;;
    --proto)       ADAPT_EXTRA+=(--proto "$2"); shift 2 ;;
    --max-packets) ADAPT_EXTRA+=(--max-packets "$2"); shift 2 ;;
    --dst)         DST="$2"; shift 2 ;;
    --ue)          UE="$2"; shift 2 ;;
    -h|--help)     usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

UE_IP=$(docker exec "$UE" sh -c "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1")
[[ -n "$UE_IP" ]] || { echo "Error: $UE has no uesimtun0 - is nr-ue registered?" >&2; exit 1; }
echo "[replay] UE=$UE tunnel=$UE_IP  DN=$DST  src-mode=$SRC_MODE"

# Tooling is not in the UE image; install once (idempotent).
if ! docker exec "$UE" sh -c 'command -v tcpreplay >/dev/null && python3 -c "import scapy" 2>/dev/null'; then
  echo "[replay] installing tcpreplay + scapy in $UE..."
  docker exec "$UE" sh -c 'apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tcpreplay tcpdump python3-scapy >/dev/null 2>&1'
fi

# ue-2 has no UERANSIM 0.0.0.0/1 routes, so pin the DN to the tunnel or the
# traffic leaves via Docker's eth0 and never touches the switch.
docker exec "$UE" ip route replace "$DST/32" dev uesimtun0

docker exec "$UE" mkdir -p /tmp/replay
docker cp "$PCAP" "$UE:/tmp/replay/in.pcap" >/dev/null
docker cp "$DIR/pcap_adapt.py" "$UE:/tmp/replay/pcap_adapt.py" >/dev/null

echo "[replay] adapting $(basename "$PCAP")..."
docker exec "$UE" python3 /tmp/replay/pcap_adapt.py /tmp/replay/in.pcap /tmp/replay/out.pcap \
  --dst "$DST" --src-mode "$SRC_MODE" --ue-ip "$UE_IP" "${ADAPT_EXTRA[@]}" 2>&1 | grep -v 'Incompatible L3' | sed 's/^/[adapt] /'

echo "[replay] injecting into uesimtun0 (${RATE[*]:-original timing}, loop $LOOP)..."
docker exec "$UE" tcpreplay -i uesimtun0 "${RATE[@]}" --loop "$LOOP" /tmp/replay/out.pcap 2>&1 \
  | grep -E 'Actual|Rated|Successful|Failed|Truncated' | sed 's/^\s*/[tcpreplay] /'
echo "[replay] done. Watch: tail -f approach2/docker_scripts/run/logs/getdbdata.log ; curl -s --noproxy '*' http://127.0.0.1:23500/blocked-ips"
