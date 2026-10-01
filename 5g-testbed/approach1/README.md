# Baseline Approach: OpenFlow-based SDN DDoS Detection and Mitigation

## Overview
This repository contains the **baseline implementation** for DDoS detection and mitigation in 5G networks using **Open vSwitch (OVS) and the RYU SDN controller**. Unlike the **P4-ONOS** approach, this solution relies on **OpenFlow-based traffic redirection**, where **all GTP-U traffic is forwarded to the SDN controller** for inspection. This baseline approach highlights the **performance limitations** of traditional SDN-based DDoS mitigation strategies, which include **higher detection latency and lower throughput**.

## Key Features
- **GTP-U Traffic Inspection via OpenFlow**: Redirects encapsulated **5G User Plane traffic** to the controller.
- **Centralized DDoS Detection**: Uses **RYU SDN controller** to inspect and classify traffic.
- **Machine Learning-based Attack Detection**: Utilizes ML classifiers to detect **ICMP, UDP, and TCP SYN flooding attacks**.
- **Flow-based Mitigation**: Blocks malicious UE IP addresses at the **Open vSwitch** level.

---

## Setup Instructions

### 1. Environment Setup

Navigate to the `bash_scripts` directory and grant execution permissions:

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts
sudo chmod +x *.sh
```

### 2. Start Virtual Machines (VMs)

Start the required virtual machines (VMs):

```bash
./start_approach1_vms.sh
```

Generate SSH keys for remote access:

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts
./generate_ssh.sh
```

---

## Open vSwitch (OVS) Configuration

### Network Setup

Configure the network environment:

```bash
bash setup_network.sh
```

Add OVS ports:

```bash
bash add_ovs_ports.sh
```

---

## RYU Controller Setup

### Configure the OVS Bridge

```bash
sudo ovs-vsctl set bridge br-ovs-ryu protocols=OpenFlow13
sudo ovs-vsctl set-controller br-ovs-ryu tcp:10.102.196.198:6633
```

### Install Dependencies for RYU-based Application

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/mongodb-app
sudo npm install express mongoose cors
```

### Start the RYU-based Application

```bash
sudo node ovs-ryu-app.js
```

### Start RYU Controller

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/ryu_app
ryu-manager ovs-ryu-app.py
```

#### **Expected Output**

```
loading app ovs-ryu-app.py
loading app ryu.controller.ofp_handler
instantiating app ovs-ryu-app.py of L2Switch
instantiating app ryu.controller.ofp_handler of OFPHandler
```

---

## Deploy the 5G Core Network (Open5GS)

### 1. Start the Core Network Functions

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts/
bash ssh_scripts/cp-1.sh
```

Start individual Open5GS components:

```bash
~/open5gs
./install/bin/open5gs-nrfd &
./install/bin/open5gs-scpd &
./install/bin/open5gs-amfd &
./install/bin/open5gs-smfd &
./install/bin/open5gs-ausfd &
./install/bin/open5gs-udmd &
./install/bin/open5gs-pcfd &
./install/bin/open5gs-nssfd &
./install/bin/open5gs-bsfd &
./install/bin/open5gs-udrd &
```

### 2. Configure the UPF Network Interfaces

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts/
bash ssh_scripts/up-1.sh
```

Manually configure network interfaces:

```bash
sudo ip tuntap add name ogstun mode tun
sudo ip addr add 10.45.0.1/16 dev ogstun
sudo ip addr add 2001:db8:cafe::1/48 dev ogstun
sudo ip link set ogstun up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
```

Start the UPF service:

```bash
~/open5gs
sudo ./install/bin/open5gs-upfd &
```

---

## Start the 5G Radio Access Network (gNB & UE)

### 1. Launch the gNB

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts/
bash ssh_scripts/gnb-1.sh
```

```bash
cd ~/UERANSIM
sudo pkill -f nr-gnb
sudo ./build/nr-gnb -c config/open5gs-gnb1.yaml &
```

### 2. Launch the UE

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/bash_scripts/
bash ssh_scripts/ssh_ue-1.sh
```

```bash
cd ~/UERANSIM
sudo pkill -f nr-ue
sudo ./build/nr-ue -c config/open5gs-ue1.yaml &
```

---

## Validate Network Functionality

Run this command on the `ue-1` VM to verify connectivity:

```bash
ping -I uesimtun0 -c 2 8.8.8.8
```

#### **Expected Output:**

```
PING 8.8.8.8 (8.8.8.8) from 10.45.0.3 uesimtun0: 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=17.8 ms
--- 8.8.8.8 ping statistics ---
2 packets transmitted, 1 received, 50% packet loss, time 1014ms
rtt min/avg/max/mdev = 17.753/17.753/17.753/0.000 ms
```

---

## Machine Learning (ML) Components

### 1. Start the Statistics Module

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/ML
python3 stats.py
```

### 2. Start the ML Model

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/ML
python3 MLmodule.py
```

### 3. Start the Detection Module

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach1/ML
python3 detection.py
```

---

This structured README provides a step-by-step guide for setting up and running the **OpenFlow-based SDN DDoS Detection and Mitigation** system.

