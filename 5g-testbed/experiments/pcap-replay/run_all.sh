#!/bin/bash
# run_all.sh - evaluate the approach-2 defense against the six representative StopDDoS
# captures, in both threat models. Produces results/replay.csv (one row per run).
#
# Each run is self-contained: run_capture.sh clears blocks, rebuilds the pipeline,
# re-registers the UE, replays, measures, and appends a row. Fresh CSV each time.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURES=(
  pkt.TCP.synflood.spoofed.pcap
  pkt.ICMP.largeempty.pcap
  pkt.UDP.rdm.fixedlength.pcapng
  amp.UDP.DNSANY.pcap
  amp.UDP.memcached.ntp.cldap.pcap
  pkt.UDP.fragmented.pcap
)
MODES=(ue spoof)

rm -f "$DIR/results/replay.csv"
for cap in "${CAPTURES[@]}"; do
  for mode in "${MODES[@]}"; do
    echo "############################################################"
    echo "## $cap  [$mode]"
    echo "############################################################"
    # spoof mode never converges to a single block, so give it the full window.
    ws=90; [[ "$mode" == spoof ]] && ws=110
    WATCH_S=$ws "$DIR/run_capture.sh" "$cap" "$mode" 2>&1 \
      | grep -vE 'WARNING|Inconsistent|reflective' || true
  done
done

echo
echo "== results/replay.csv =="
column -t -s, "$DIR/results/replay.csv"
