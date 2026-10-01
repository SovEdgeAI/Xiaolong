#!/bin/bash

# Get the Host IP address
IP=$(hostname -I | awk '{print $1}')
echo "Host IP address: $IP"

#Find the interface that has this IP address
interface=$(ip -o -4 route show to default | awk '{print $5}')
echo "Interface: $interface"

sudo ovs-vsctl add-br br-ovs-ryu
sudo apt install net-tools -y 
sudo ifconfig br-ovs-ryu 192.168.230.1/24 
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.230.0/24 -o $interface -j MASQUERADE