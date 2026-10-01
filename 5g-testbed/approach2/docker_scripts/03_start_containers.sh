#!/bin/bash
# 03_start_containers.sh
#
# Docker-based replacement for bash_scripts/start_approach2_vms.sh (virsh) and
# bash_scripts/arp.sh. Creates cp-2 / up-2 / gnb-2 / ue-2, moves the veth peers
# built by 01_create_network.sh into their network namespaces, and installs the
# static ARP entries the pipeline requires.
#
# Why static ARP: onos-p4-gtp.p4 only ever applies tables when hdr.ipv4 is
# valid, so ARP frames are never assigned an egress port and are dropped by the
# switch. The upstream design worked around this the same way (bash_scripts/
# arp.sh); here the MACs are the deterministic ones 01_create_network.sh set on
# each veth peer, so no discovery step is needed.
#
# Each container also keeps its default Docker bridge eth0. That is only for
# management/apt and for the UPF's post-decapsulation egress; all 192.168.235.0/24
# traffic - including the gNB<->UPF GTP-U the detector inspects - is routed out
# the veth and therefore across the P4 switch.
set -euo pipefail

CORE_IMAGE="${CORE_IMAGE:-openverso/open5gs:latest}"
RAN_IMAGE="${RAN_IMAGE:-ubuntu:24.04}"   # matches the host toolchain UERANSIM was built with
NET_IMAGE="${NET_IMAGE:-opennetworking/mn-stratum:latest}"

# name:image
CONTAINERS=(
  "cp-2:$CORE_IMAGE"
  "up-2:$CORE_IMAGE"
  "gnb-2:$RAN_IMAGE"
  "ue-2:$RAN_IMAGE"
)

# container:iface:cidr
LINKS=(
  "cp-2:veth1:192.168.235.2/24"
  "cp-2:veth3:192.168.235.3/24"
  "up-2:veth5:192.168.235.4/24"
  "gnb-2:veth7:192.168.235.5/24"
  "ue-2:veth9:192.168.235.6/24"
)

# ip mac  (peer-side MACs assigned in 01_create_network.sh; .1 is br-p4-onos)
ARP_ENTRIES=(
  "192.168.235.1 02:42:ac:11:00:0C"
  "192.168.235.2 02:42:ac:11:00:02"
  "192.168.235.3 02:42:ac:11:00:04"
  "192.168.235.4 02:42:ac:11:00:06"
  "192.168.235.5 02:42:ac:11:00:08"
  "192.168.235.6 02:42:ac:11:00:0A"
)

echo "[03] (Re)creating containers..."
for entry in "${CONTAINERS[@]}"; do
  name="${entry%%:*}"; image="${entry#*:}"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -dit --privileged --name "$name" --hostname "$name" \
    --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
    "$image" bash >/dev/null
  echo "  started $name ($image)"
done

echo "[03] Ensuring network tooling is present..."
for entry in "${CONTAINERS[@]}"; do
  cname="${entry%%:*}"
  # The RAN image is minimal: no iproute2, no ping. Needed before any link work.
  if docker exec "$cname" sh -c 'command -v ip >/dev/null 2>&1'; then
    echo "  $cname already has iproute2"
  else
    echo "  installing iproute2/iputils-ping in $cname (may take a moment)..."
    docker exec "$cname" sh -c \
      'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iputils-ping >/dev/null'
    echo "  $cname tooling installed"
  fi
done

echo "[03] Moving veth peers into container namespaces..."
for entry in "${LINKS[@]}"; do
  IFS=: read -r cname iface cidr <<<"$entry"
  pid=$(docker inspect -f '{{.State.Pid}}' "$cname")

  # The move must happen from the host netns, which this helper shares.
  docker run --rm --privileged --network=host --pid=host \
    --entrypoint ip "$NET_IMAGE" link set "$iface" netns "$pid"

  docker exec "$cname" ip link set "$iface" up
  docker exec "$cname" ip addr add "$cidr" dev "$iface"
  docker exec "$cname" ip link set "$iface" mtu 8500
  echo "  $cname <- $iface ($cidr)"
done

echo "[03] Installing static ARP entries..."
for entry in "${CONTAINERS[@]}"; do
  cname="${entry%%:*}"

  # Addresses this container owns, and the veth it reaches the subnet through.
  own_ips=$(docker exec "$cname" ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1)
  dev=$(docker exec "$cname" sh -c \
        "ip -o -4 route show scope link | awk '/192.168.235.0\/24/{print \$3; exit}'")
  if [[ -z "$dev" ]]; then
    echo "  WARNING: $cname has no route to 192.168.235.0/24; skipping ARP" >&2
    continue
  fi

  for arp in "${ARP_ENTRIES[@]}"; do
    read -r aip amac <<<"$arp"
    grep -qx "$aip" <<<"$own_ips" && continue   # never ARP for yourself
    docker exec "$cname" ip neigh replace "$aip" lladdr "$amac" dev "$dev" nud permanent
  done

  # Reach the rest of the world through the uplink bridge on switch port 5.
  docker exec "$cname" ip route replace 192.168.235.0/24 dev "$dev" >/dev/null 2>&1 || true
  echo "  $cname ARP table primed via $dev"
done

echo "[03] done. Interfaces:"
for entry in "${CONTAINERS[@]}"; do
  cname="${entry%%:*}"
  printf '  %-6s %s\n' "$cname" "$(docker exec "$cname" ip -br -4 addr show | tr '\n' ' ')"
done
