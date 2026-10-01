#!/bin/bash

# Function to create a veth pair, set MTU, and configure a static MAC address
create_veth_pair() {
  local veth_name1="$1"
  local veth_name2="$2"
  local mtu_value="$3"
  local mac1="$4"
  local mac2="$5"

  # Create veth pair
  sudo ip link add name "$veth_name1" type veth peer name "$veth_name2"

  # Set static MAC addresses
  sudo ip link set dev "$veth_name1" address "$mac1"
  sudo ip link set dev "$veth_name2" address "$mac2"

  # Bring up veth interfaces
  sudo ip link set dev "$veth_name1" up
  sudo ip link set dev "$veth_name2" up

  # Set MTU value
  sudo ip link set "$veth_name1" mtu "$mtu_value"
  sudo ip link set "$veth_name2" mtu "$mtu_value"

  # Configure ethtool settings for both interfaces in the pair
  for iface in "$veth_name1" "$veth_name2"; do
    ethtool -K "$iface" rx off          # RX checksumming
    ethtool -K "$iface" tx off          # TX checksumming
    ethtool -K "$iface" sg off          # Scatter gather
    ethtool -K "$iface" tso off         # TCP segmentation offload
    ethtool -K "$iface" ufo off         # UDP fragmentation offload
    ethtool -K "$iface" gso off         # Generic segmentation offload
    ethtool -K "$iface" gro off         # Generic receive offload
    ethtool -K "$iface" lro off         # Large receive offload
    ethtool -K "$iface" rxvlan off      # RX VLAN acceleration
    ethtool -K "$iface" txvlan off      # TX VLAN acceleration
    ethtool -K "$iface" ntuple off      # RX ntuple filters and actions
    ethtool -K "$iface" rxhash off      # RX hashing offload
    ethtool --set-eee "$iface" eee off  # Energy Efficient Ethernet
  done
}

# Define consistent MAC addresses for each veth interface pair
create_veth_pair "veth0" "veth1" 8500 "02:42:ac:11:00:01" "02:42:ac:11:00:02"
create_veth_pair "veth2" "veth3" 8500 "02:42:ac:11:00:03" "02:42:ac:11:00:04"
create_veth_pair "veth4" "veth5" 8500 "02:42:ac:11:00:05" "02:42:ac:11:00:06"
create_veth_pair "veth6" "veth7" 8500 "02:42:ac:11:00:07" "02:42:ac:11:00:08"
create_veth_pair "veth8" "veth9" 8500 "02:42:ac:11:00:09" "02:42:ac:11:00:0A"
create_veth_pair "veth10" "veth11" 8500 "02:42:ac:11:00:0B" "02:42:ac:11:00:0C"
