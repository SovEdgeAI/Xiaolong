# P4-ONOS: 5G DDoS Detection and Mitigation

## Overview
This repository contains the implementation of **Approach 2** for detecting and mitigating DDoS attacks in 5G networks using **P4, ONOS, and SDN**. This approach leverages **programmable P4 switches** and the **ONOS SDN controller** to analyze **GTP-U traffic** in real-time, enabling **flow-based intrusion detection** without the need for deep packet inspection (DPI). The system utilizes **machine learning (ML)** for anomaly detection and reduces **detection latency** compared to traditional SDN-based solutions.

## Key Features
- **GTP Traffic Analysis**: Extracts inner IP headers from **GTP-U encapsulated packets** to detect DDoS attacks.
- **Programmable Packet Processing**: Uses **P4 switches** for real-time packet analysis.
- **ONOS Controller Integration**: Implements **flow-based rules** for **attack mitigation**.
- **Machine Learning-based Detection**: Uses ML classifiers to identify **DDoS attack patterns**.


## Setup Instructions

### 1. Set Up the Environment
Navigate to the `bash_scripts` directory and grant execution permissions to all scripts:
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
sudo chmod +x *.sh
```

### 2. Create Virtual Ethernet (veth) Pairs
```bash
sudo bash createveth.sh
```

### 3. Start Virtual Machines (VMs)
```bash
sudo bash start_approach2_vms.sh
```

### 4. Generate ARP Script
```bash
sudo bash get_arp.sh
```

### 5. Compile and Deploy P4 Program
```bash
./compile_p4.sh onos-p4-gtp
```

```bash
./generate_pipe.sh onos-p4-gtp
```

```bash
./run_stratum.sh onos-p4-gtp
```

### 6. Configure SSH Access for VMs
Open a new terminal

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
./generate_ssh.sh
```
**Run the following for all VMs:**
```bash
sudo bash arp.sh
```

* Use SSH to be able to access the vms 

```bash
./ssh_scripts/cp-2.sh
sudo bash arp.sh
exit
```

* Do the same for the following vms 
  * up-2
  * ue-2
  * gnb-2 


* For the last VM, test connectivity 

```bash
for i in {1..6}; do ping -c 1 192.168.235.$i; done
```

```
ue-2@ue-2:~$ ping -c 1 192.168.235.1 ; ping -c 1 192.168.235.2 ;
PING 192.168.235.1 (192.168.235.1) 56(84) bytes of data.
64 bytes from 192.168.235.1: icmp_seq=1 ttl=64 time=6.23 ms

--- 192.168.235.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 6.232/6.232/6.232/0.000 ms
PING 192.168.235.2 (192.168.235.2) 56(84) bytes of data.
64 bytes from 192.168.235.2: icmp_seq=1 ttl=64 time=4.25 ms

--- 192.168.235.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.246/4.246/4.246/0.000 ms
ue-2@ue-2:~$ for i in {1..6}; do ping -c 1 192.168.235.$i; done
PING 192.168.235.1 (192.168.235.1) 56(84) bytes of data.
64 bytes from 192.168.235.1: icmp_seq=1 ttl=64 time=5.92 ms

--- 192.168.235.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 5.923/5.923/5.923/0.000 ms
PING 192.168.235.2 (192.168.235.2) 56(84) bytes of data.
64 bytes from 192.168.235.2: icmp_seq=1 ttl=64 time=4.71 ms

--- 192.168.235.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.713/4.713/4.713/0.000 ms
PING 192.168.235.3 (192.168.235.3) 56(84) bytes of data.
64 bytes from 192.168.235.3: icmp_seq=1 ttl=64 time=5.19 ms

--- 192.168.235.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 5.194/5.194/5.194/0.000 ms
PING 192.168.235.4 (192.168.235.4) 56(84) bytes of data.
64 bytes from 192.168.235.4: icmp_seq=1 ttl=64 time=5.59 ms

--- 192.168.235.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 5.590/5.590/5.590/0.000 ms
PING 192.168.235.5 (192.168.235.5) 56(84) bytes of data.
64 bytes from 192.168.235.5: icmp_seq=1 ttl=64 time=4.92 ms

--- 192.168.235.5 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.921/4.921/4.921/0.000 ms
PING 192.168.235.6 (192.168.235.6) 56(84) bytes of data.
64 bytes from 192.168.235.6: icmp_seq=1 ttl=64 time=0.048 ms

--- 192.168.235.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.048/0.048/0.048/0.000 ms
```

### 7. Start ONOS SDN Controller
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
./start_onos.sh
```

* Open a new terminal


Activate necessary ONOS applications:
```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -o "HostKeyAlgorithms=+ssh-rsa" -o LogLevel=ERROR -p 8101 onos@localhost
```

`Password`: rocks

```bash
app activate org.onosproject.drivers.stratum
app activate org.onosproject.drivers.bmv2
app activate org.onosproject.hostprovider
app activate org.onosproject.netconf
exit
```

### 8. Generate and Upload ONOS Configuration
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
./generate_netcfg.sh onos-p4-gtp
```
```bash
./upload_onos.sh onos-p4-gtp
```

**Expected output:**

```
Pipeconf: us.fiu.adwise.approach2
ArtifactID: approach2-1.0-SNAPSHOT
Deleting existing ONOS app: http://10.102.196.198:8181/onos/v1/applications/us.fiu.adwise.approach2
Data Binary Path: /home/ubuntu/5G-SDN-DDoS-Detection-Mitigation/approach2/onos_app/approach2/target/approach2-1.0-SNAPSHOT.oar
{"name":"us.fiu.adwise.approach2","id":175,"version":"1.0.SNAPSHOT","category":"Network","description":"Shows different functionalities of P4 Switches","readme":"Shows different functionalities of P4 Switches","origin":"https://approach2.adwise.fiu.us","url":"https://approach2.adwise.fiu.us","featuresRepo":"mvn:org.onosproject/approach2/1.0-SNAPSHOT/xml/features","state":"ACTIVE","features":["approach2"],"permissions":[],"requiredApps":[]}Uploading network configuration...
ONOS app uploaded and activated successfully.
```

### 9. Start Controller ONOS Logging Server
```bash
cd ../python_scripts
python3 logserver.py
```

### 10. Start MongoDB (For ML-based IDS)
Open a new terminal 

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/mongodb-app/
sudo npm install express mongoose cors
```

```bash
sudo node onos-p4-gtp-app.js
```

### 11. Deploy the 5G Core Network (Open5GS)
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
bash ssh_scripts/cp-2.sh
```
```bash
cd open5gs
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

### 12. Configure UPF Network Interfaces
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
bash ssh_scripts/up-2.sh
```

```bash
sudo ip tuntap add name ogstun mode tun
sudo ip addr add 10.45.0.1/16 dev ogstun
sudo ip addr add 2001:db8:cafe::1/48 dev ogstun
sudo ip link set ogstun up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
```

```bash
cd open5gs
./install/bin/open5gs-upfd &
```

### 13. Start 5G Radio Access Network (gNB & UE)
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
bash ssh_scripts/gnb-2.sh
```

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/UERANSIM/
sudo pkill -f nr-gnb
sudo ./build/nr-gnb -c config/open5gs-gnb1.yaml &
```
```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts
bash ssh_scripts/ssh_ue-2.sh
```

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/UERANSIM/
sudo pkill -f nr-ue
sudo ./build/nr-ue -c config/open5gs-ue1.yaml &
```

### 14. Validate Network Functionality

* Run this on the ue-2 vm

```bash
ping -I uesimtun0 -c 2 8.8.8.8
```
Expected output:
```
ue-2@ue-2:~/5G-SDN-DDoS-Detection-Mitigation/UERANSIM$ ping -I uesimtun0 -c 2 8.8.8.8
PING 8.8.8.8 (8.8.8.8) from 10.45.0.3 uesimtun0: 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=2 ttl=116 time=17.8 ms

--- 8.8.8.8 ping statistics ---
2 packets transmitted, 1 received, 50% packet loss, time 1014ms
rtt min/avg/max/mdev = 17.753/17.753/17.753/0.000 ms
ue-2@ue-2:~/5G-SDN-DDoS-Detection-Mitigation/UERANSIM$
```


### 15. Start Machine Learning-Based Detection

* Open a new terminal 

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/ML
python3 GetPredictionModule.py
```

* Open a new terminal 

```bash
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/ML
python3 getDBData.py
```

> **Note:**
> The `getDBData.py` script pulls network traffic data, checks if it's normal or suspicious using machine learning, and updates the database. It sends the results to a REST API, which confirms the update. This helps the system track and respond to potential threats in real-time.

### 16. Test the mitigation 

Using the UE, run the following for an ICMP flooding 

```bash
sudo ping -I uesimtun0 -c 10000 -i 0.000001 8.8.8.8
```



## References
This project is based on the findings from the research paper **"DDoS Attack Detection and Mitigation in 5G Networks using P4 and SDN"**, which explores using **P4-programmable switches and SDN for real-time attack detection**.

