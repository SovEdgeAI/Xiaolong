#!/bin/bash
# run_remaining.sh - the runs still needed to complete results/replay.csv.
#
# Appends to the existing CSV (which already holds the synflood ue/spoof rows and the
# ICMP ue row). Two deliberate choices:
#
#   * UE mode for every capture - this is the threat model the system is designed for
#     and the only one where a per-source detector can act.
#   * spoof mode ONLY for the low-cardinality captures (11, 41, 79 sources). The
#     high-cardinality spoof runs (37k, 9.9k, 2k sources) are already characterised by
#     the synflood row, and repeating them destabilised the 5G data path last time -
#     they wedge UERANSIM's user plane, not the defense.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run() {  # capture mode watch
  echo "############ $1 [$2]"
  WATCH_S="$3" "$DIR/run_capture.sh" "$1" "$2" 2>&1 \
    | grep -vE 'WARNING|Inconsistent|reflective' || echo "   (run failed - see above)"
}

run pkt.UDP.rdm.fixedlength.pcapng    ue    90
run amp.UDP.DNSANY.pcap               ue    90
run amp.UDP.memcached.ntp.cldap.pcap  ue    90
run pkt.UDP.fragmented.pcap           ue    90
run pkt.UDP.rdm.fixedlength.pcapng    spoof 110
run pkt.UDP.fragmented.pcap           spoof 110
run amp.UDP.DNSANY.pcap               spoof 110

echo
echo "== results/replay.csv =="
column -t -s, "$DIR/results/replay.csv"
