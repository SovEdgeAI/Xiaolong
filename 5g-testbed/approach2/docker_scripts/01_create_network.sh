#!/bin/bash
# 01_create_network.sh
#
# Docker-based replacement for bash_scripts/createveth.sh + get_arp.sh.
#
# The upstream scripts assume libvirt VMs reached over macvtap and run everything
# with host sudo. This host has no libvirt and no passwordless sudo, so the veth
# fabric is built from a privileged --network=host container instead: it shares
# the host network namespace and carries CAP_NET_ADMIN, so the links it creates
# are real host links, visible to stratum_bmv2 and to the 5G containers.
#
# Topology (matches approach2/stratum_files/chassis-config.txt):
#   s1 port 0  veth0 <-> veth1   cp-2   192.168.235.2  (AMF)
#   s1 port 1  veth2 <-> veth3   cp-2   192.168.235.3  (SMF)
#   s1 port 2  veth4 <-> veth5   up-2   192.168.235.4  (UPF)
#   s1 port 3  veth6 <-> veth7   gnb-2  192.168.235.5
#   s1 port 4  veth8 <-> veth9   ue-2   192.168.235.6
#   s1 port 5  veth10 <-> veth11 br-p4-onos 192.168.235.1 (uplink/gateway)
set -euo pipefail

NET_IMAGE="${NET_IMAGE:-opennetworking/mn-stratum:latest}"
NAT_IMAGE="${NAT_IMAGE:-openverso/open5gs:latest}"   # only image on hand with iptables

echo "[01] Building veth fabric + br-p4-onos in the host network namespace..."

# --entrypoint sh: the image's default entrypoint is mininet's `mn`.
docker run --rm -i --privileged --network=host --entrypoint sh "$NET_IMAGE" -s <<'EOSCRIPT'
set -e

MTU=8500

create_pair() {
  a="$1"; b="$2"; mac_a="$3"; mac_b="$4"

  # Recreate idempotently; deleting one side removes the peer too.
  ip link del "$a" 2>/dev/null || true
  ip link del "$b" 2>/dev/null || true

  ip link add name "$a" type veth peer name "$b"
  ip link set dev "$a" address "$mac_a"
  ip link set dev "$b" address "$mac_b"
  ip link set dev "$a" mtu "$MTU"
  ip link set dev "$b" mtu "$MTU"
  ip link set dev "$a" up
  ip link set dev "$b" up

  # bmv2 sees raw frames; offloads would hand it coalesced/unchecksummed packets.
  for i in "$a" "$b"; do
    for f in rx tx sg tso ufo gso gro lro rxvlan txvlan ntuple rxhash; do
      ethtool -K "$i" "$f" off >/dev/null 2>&1 || true
    done
    ethtool --set-eee "$i" eee off >/dev/null 2>&1 || true
  done
  echo "  created $a <-> $b"
}

create_pair veth0  veth1  02:42:ac:11:00:01 02:42:ac:11:00:02
create_pair veth2  veth3  02:42:ac:11:00:03 02:42:ac:11:00:04
create_pair veth4  veth5  02:42:ac:11:00:05 02:42:ac:11:00:06
create_pair veth6  veth7  02:42:ac:11:00:07 02:42:ac:11:00:08
create_pair veth8  veth9  02:42:ac:11:00:09 02:42:ac:11:00:0A
create_pair veth10 veth11 02:42:ac:11:00:0B 02:42:ac:11:00:0C

# Uplink bridge: veth11 is the far side of switch port 5, and carries the
# 192.168.235.1 gateway address the UE/gNB/CP/UP default-route to.
ip link del br-p4-onos 2>/dev/null || true
ip link add name br-p4-onos type bridge
ip link set dev br-p4-onos address 02:42:ac:11:00:0C
ip link set veth11 master br-p4-onos
ip addr add 192.168.235.1/24 dev br-p4-onos
ip link set dev br-p4-onos up
ip link set dev br-p4-onos mtu "$MTU"
echo "  bridge br-p4-onos up with 192.168.235.1/24 (veth11 enslaved)"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "  ip_forward enabled"

# The switch drops ARP (onos-p4-gtp.p4 only acts on valid IPv4 headers), so the
# host cannot resolve the containers either. Pin the peer MACs that this script
# just assigned - the container side of the same table is done in 03.
for e in "192.168.235.2 02:42:ac:11:00:02" \
         "192.168.235.3 02:42:ac:11:00:04" \
         "192.168.235.4 02:42:ac:11:00:06" \
         "192.168.235.5 02:42:ac:11:00:08" \
         "192.168.235.6 02:42:ac:11:00:0A"; do
  set -- $e
  ip neigh replace "$1" lladdr "$2" dev br-p4-onos nud permanent
done
echo "  static ARP entries pinned on br-p4-onos"
EOSCRIPT

# The stratum image ships no iptables, so the NAT rules go on in a second pass
# using an image that has it. --network=host means these land in the host tables.
echo "[01] Installing NAT rules..."
docker run --rm -i --privileged --network=host --entrypoint sh "$NAT_IMAGE" -s <<'EOSCRIPT'
set -e
# NAT so the 235 subnet and the UE pool can reach the internet.
for src in 192.168.235.0/24 10.45.0.0/16; do
  iptables -t nat -C POSTROUTING -s "$src" ! -o br-p4-onos -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$src" ! -o br-p4-onos -j MASQUERADE
  echo "  MASQUERADE $src"
done
EOSCRIPT

echo "[01] Host-side view:"
ip -br addr show br-p4-onos 2>/dev/null || true
ip -o link show | grep -oE 'veth([0-9]|1[01])\b' | sort -u -V | tr '\n' ' '
echo
echo "[01] done."
