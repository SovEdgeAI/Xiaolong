#!/bin/bash
# fetch_stopddos.sh - download captures from the StopDDoS packet-capture collection.
#
#   ./tools/fetch_stopddos.sh            # the 6 representative captures used by
#                                        # experiments/pcap-replay
#   ./tools/fetch_stopddos.sh --all      # all 18 (~230 MB)
#   ./tools/fetch_stopddos.sh FILE...    # specific files by name
#
# Files land in datasets/stopddos/, which is git-ignored: the collection's license
# allows free use for building DDoS protection but does not grant redistribution,
# so the repo keeps this script instead of the captures.
#
# Cite as: L.F. Haaijer, DDoS Packet Capture Collection (2022).
#          https://github.com/StopDDoS/packet-captures
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/datasets/stopddos"
BASE="https://raw.githubusercontent.com/StopDDoS/packet-captures/main"
REPRESENTATIVE=(
  pkt.TCP.synflood.spoofed.pcap
  pkt.ICMP.largeempty.pcap
  pkt.UDP.rdm.fixedlength.pcapng
  amp.UDP.DNSANY.pcap
  amp.UDP.memcached.ntp.cldap.pcap
  pkt.UDP.fragmented.pcap
)

if [[ "${1:-}" == "--all" ]]; then
  mapfile -t FILES < <(curl -sf --max-time 30 \
    "https://api.github.com/repos/StopDDoS/packet-captures/git/trees/main?recursive=1" \
    | python3 -c "import sys,json; [print(t['path']) for t in json.load(sys.stdin)['tree'] if t['path'].endswith(('.pcap','.pcapng'))]")
elif [[ $# -gt 0 ]]; then
  FILES=("$@")
else
  FILES=("${REPRESENTATIVE[@]}")
fi

mkdir -p "$DIR"
for f in "${FILES[@]}"; do
  out="$DIR/$f"
  if [[ -s "$out" ]]; then
    echo "  have  $f ($(du -h "$out" | cut -f1))"
    continue
  fi
  curl -sfL --max-time 600 -o "$out.part" "$BASE/$f" || { echo "  FAIL  $f" >&2; rm -f "$out.part"; continue; }
  # GitHub disabled LFS for this repo; a pointer file instead of a capture means the
  # raw endpoint stopped serving content - fall back to the mirror in the README.
  if head -c 40 "$out.part" | grep -q 'git-lfs'; then
    echo "  FAIL  $f is an LFS pointer; use the zip mirror: https://wqrld.net/captures.zip" >&2
    rm -f "$out.part"; continue
  fi
  mv "$out.part" "$out"
  echo "  got   $f ($(du -h "$out" | cut -f1))"
done
echo "-> $DIR"
echo "Cite: L.F. Haaijer, DDoS Packet Capture Collection (2022). https://github.com/StopDDoS/packet-captures"
