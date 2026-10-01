#!/bin/bash
# setup_ovs_network.sh - Migrate Docker containers to OVS bridge
# Run with: sudo bash setup_ovs_network.sh
set -e

echo "============================================"
echo " Step 1: OVS Bridge & Network Migration"
echo "============================================"

# Kill all 5G processes first
echo "[1a] Killing all running processes..."
docker exec cp-1 pkill -f open5gs 2>/dev/null || true
docker exec up-1 pkill -f open5gs 2>/dev/null || true
docker exec gnb-1 pkill -f nr-gnb 2>/dev/null || true
docker exec ue-1 pkill -f nr-ue 2>/dev/null || true
sleep 2
echo "  ✓ All processes killed"

# Create OVS bridge
echo "[1b] Creating OVS bridge br-ovs-ryu..."
ovs-vsctl --if-exists del-br br-ovs-ryu
ovs-vsctl add-br br-ovs-ryu
ip addr add 192.168.230.1/24 dev br-ovs-ryu
ip link set br-ovs-ryu up
echo "  ✓ OVS bridge created at 192.168.230.1/24"

# Set up NAT for internet access
echo "[1c] Setting up NAT..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo "  Default interface: $INTERFACE"
iptables -t nat -C POSTROUTING -s 192.168.230.0/24 -o "$INTERFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 192.168.230.0/24 -o "$INTERFACE" -j MASQUERADE
echo "  ✓ NAT configured"

# Disconnect containers from Docker 5g-network
echo "[1d] Disconnecting containers from Docker 5g-network..."
for c in mongo-container cp-1 up-1 gnb-1 ue-1; do
    docker network disconnect 5g-network "$c" 2>/dev/null || echo "  $c: already disconnected or not on 5g-network"
done
echo "  ✓ Containers disconnected from Docker bridge"

# Connect containers to OVS bridge using ovs-docker
echo "[1e] Connecting containers to OVS bridge..."
ovs-docker add-port br-ovs-ryu eth1 mongo-container --ipaddress=192.168.230.2/24 --gateway=192.168.230.1
echo "  ✓ mongo-container: 192.168.230.2"

ovs-docker add-port br-ovs-ryu eth1 cp-1 --ipaddress=192.168.230.3/24 --gateway=192.168.230.1
echo "  ✓ cp-1: 192.168.230.3"

ovs-docker add-port br-ovs-ryu eth1 up-1 --ipaddress=192.168.230.4/24 --gateway=192.168.230.1
echo "  ✓ up-1: 192.168.230.4"

ovs-docker add-port br-ovs-ryu eth1 gnb-1 --ipaddress=192.168.230.5/24 --gateway=192.168.230.1
echo "  ✓ gnb-1: 192.168.230.5"

ovs-docker add-port br-ovs-ryu eth1 ue-1 --ipaddress=192.168.230.6/24 --gateway=192.168.230.1
echo "  ✓ ue-1: 192.168.230.6"

# Set up default routes in containers (ovs-docker sets gateway but let's make sure)
echo "[1f] Verifying routes in containers..."
for c in mongo-container cp-1 up-1 gnb-1 ue-1; do
    docker exec "$c" ip route replace default via 192.168.230.1 dev eth1 2>/dev/null || true
    echo "  ✓ $c: default route via 192.168.230.1"
done

# Configure OVS OpenFlow protocol
echo "[1g] Configuring OVS bridge for OpenFlow13..."
ovs-vsctl set bridge br-ovs-ryu protocols=OpenFlow13

echo ""
echo "  ✓ OVS bridge verification:"
ovs-vsctl show
echo ""

# Test connectivity
echo "[1h] Testing connectivity..."
for c in cp-1 up-1 gnb-1 ue-1; do
    IP=$(docker exec "$c" ip -4 addr show eth1 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1)
    echo "  $c: $IP"
done

echo ""
echo "============================================"
echo " OVS Network Migration Complete!"
echo "============================================"
echo ""
echo " Next: Update Open5GS configs to use eth1,"
echo " restart 5G services, and set up DDoS detection."
