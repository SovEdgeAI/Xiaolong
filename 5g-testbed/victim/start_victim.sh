#!/bin/bash
# start_victim.sh - the victim the compromised UE aims at, on the approach2 path.
#
#   ./start_victim.sh          # (re)build, run, and route the UE to it
#   ./start_victim.sh route    # just (re)pin the UE route (after a UE restart)
#   ./start_victim.sh ip       # print the victim IP the harness should target
#
# Placement and why:
#   - victim runs on the docker default bridge (172.17.0.0/16), which is where
#     up-2 (the UPF) egresses UE traffic after decapsulation + NAT.
#   - ue-2 has a *direct* 172.17.0.0/16 route on eth0, which would bypass the P4
#     switch entirely. So we pin ONLY the victim's /32 to uesimtun0: traffic to
#     it goes UE -> gNB -> (GTP-U across the P4 switch) -> UPF -> NAT -> victim.
#     That is the path the detector parses and RA3's block_ip acts on.
#   - the victim therefore sees the UPF's NAT address as the source, not the UE
#     address; RA3 blocks the UE upstream at the switch, so that is fine.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME=victim
IMAGE=victim:local
UE="${UE:-ue-2}"
STATE="$DIR/victim.env"

victim_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME"; }

pin_route() {
  local ip="$1"
  # tunnel dev name can change across UE restarts; read it live
  local tun
  tun=$(docker exec "$UE" sh -c "ip -o -4 addr show | awk '/10\\.45\\./{print \$2; exit}'")
  [[ -n "$tun" ]] || { echo "Error: $UE has no 10.45.x tunnel address; is nr-ue up?" >&2; exit 1; }
  docker exec "$UE" ip route replace "$ip/32" dev "$tun"
  echo "  routed $UE -> $ip/32 via $tun (through the P4 switch)"
}

case "${1:-up}" in
  ip)    victim_ip; exit 0 ;;
  route) ip=$(victim_ip); [[ -n "$ip" ]] || { echo "victim not running" >&2; exit 1; }
         pin_route "$ip"; exit 0 ;;
esac

echo "[victim] building image..."
docker build -q -t "$IMAGE" "$DIR" >/dev/null

echo "[victim] (re)starting container..."
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname "$NAME" --restart unless-stopped \
  --privileged \
  --sysctl net.ipv4.tcp_syncookies=0 \
  -e METRICS_PORT=9100 -e WATCH_PORTS=80,53,23,3306 \
  "$IMAGE" >/dev/null

for i in $(seq 1 20); do
  ip=$(victim_ip); [[ -n "$ip" ]] && break; sleep 0.5
done
[[ -n "$ip" ]] || { echo "Error: victim got no IP" >&2; exit 1; }
echo "  victim at $ip (web :80, metrics :9100, listeners 53/23/3306)"

pin_route "$ip"

printf 'VICTIM_IP=%s\nVICTIM_METRICS=http://%s:9100\n' "$ip" "$ip" > "$STATE"
echo "  wrote $STATE"

echo "[victim] checks:"
docker exec "$NAME" python3 -c \
  'import urllib.request; urllib.request.urlopen("http://127.0.0.1:9100/health", timeout=3)' \
  && echo "  metrics :9100 OK"
tun=$(docker exec "$UE" sh -c "ip -o -4 addr show | awk '/10\\.45\\./{print \$2; exit}'")
docker exec "$UE" ping -I "$tun" -c 2 -W 3 "$ip" >/dev/null 2>&1 \
  && echo "  UE -> victim OK through the tunnel ($tun)" \
  || echo "  WARNING: UE cannot reach victim; check nr-ue and the route" >&2
