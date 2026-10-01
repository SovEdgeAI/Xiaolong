
## MongoDB

* MongoDB

```shell
docker run -d -p 27017:27017 --network=bridge --name=mongo-container mongo:latest
```

IP is 172.17.0.4

```shell
cd ~/5G-env/open5gs/install/etc/open5gs
```

```
grep -rl "mongodb://localhost/open5gs" /root/5G-env/open5gs/install/etc/open5gs/ | xargs sed -i 's|mongodb://localhost/open5gs|mongodb://172.17.0.4:27017/open5gs|g'
```
## CP

### Setup

```shell
sudo ovs-vsctl del-port br-ovs-ryu cp-1.1
sudo ovs-vsctl del-port br-ovs-ryu cp-1.2
sudo ovs-vsctl add-port br-ovs-ryu cp-1.1 -- set Interface cp-1.1 type=internal
sudo ovs-vsctl add-port br-ovs-ryu cp-1.2 -- set Interface cp-1.2 type=internal
```

```shell
docker stop cp; docker rm cp-1
docker run -dit --privileged --name cp-1 --network=bridge ubuntu-5g:1.2 bash
```


```shell
CP_PID=$(docker inspect -f '{{.State.Pid}}' cp-1)
sudo ip link set cp-1.1 netns $CP_PID
sudo ip link set cp-1.2 netns $CP_PID
```


```shell
docker exec -it cp-1 bash
```

```shell
ip link set cp-1.1 up
ip link set cp-1.2 up
```


```shell
ip addr add 192.168.230.2/24 dev cp-1.1
ip addr add 192.168.230.3/24 dev cp-1.2
```

```shell
ip route add default via 192.168.230.1 dev cp-1.1
ip route add default via 192.168.230.1 dev cp-1.2
```

```shell
ping -c 2 -I gnb-1 192.168.230.1
```

```shell
~/5G-env/open5gs
```

### Open5GS - config
#### AMF config

```
sed -i -e 's|999|001|g' -e 's|70|01|g' install/etc/open5gs/amf.yaml
```

```shell
sed -i '345s|.*|       - addr: 192.168.230.2|' install/etc/open5gs/amf.yaml
```


#### SMF config


```shell
sed -i '511s|.*|       - addr: 192.168.230.3|' install/etc/open5gs/smf.yaml
sed -i '512s|.*|#     - addr: ::1|' install/etc/open5gs/smf.yaml
```

```shell
sed -i '515s|.*|#     - addr: ::1|' install/etc/open5gs/smf.yaml
sed -i '518s|.*|#     - addr: ::1|' install/etc/open5gs/smf.yaml
```

```shell
sed -i '698s|.*|       - addr: 192.168.230.4|' install/etc/open5gs/smf.yaml
```


#### Run Open5GS - CP

```shell
cd ~/5G-env/open5gs
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

## UP

### Setup

```shell
sudo ovs-vsctl del-port br-ovs-ryu up-1
sudo ovs-vsctl add-port br-ovs-ryu up-1 -- set Interface up-1 type=internal
```

```shell
docker stop up-1; docker rm up-1
docker run -dit --privileged --name up-1 --network=bridge ubuntu-5g:1.2 bash
```

```shell
UP_PID=$(docker inspect -f '{{.State.Pid}}' up-1)
sudo ip link set up-1 netns $UP_PID
```

```shell
docker exec -it up-1 bash
```

```shell
ip link set up-1 up
```

```shell
ip addr add 192.168.230.4/24 dev up-1
```

```shell
ip route add default via 192.168.230.1 dev up-1
```

```shell
ping -c 2 -I gnb-1 192.168.230.1
```

### Open5GS - config 

#### UPF config

```shell
sed -i '176s|.*|       - addr: 192.168.230.4|' install/etc/open5gs/upf.yaml
sed -i '178s|.*|       - addr: 192.168.230.4|' install/etc/open5gs/upf.yaml
```

#### Run Open5GS - UP

```shell
ip tuntap add name ogstun mode tun
ip addr add 10.45.0.1/16 dev ogstun
ip addr add 2001:db8:cafe::1/48 dev ogstun
ip link set ogstun up
```


```shell
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE
```

```shell
cd ~/5G-env/open5gs
./install/bin/open5gs-upfd &
```


```shell
cd ~/5G-env/open5gs
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






###  Delete mongoDB from host

```shell
sudo systemctl stop mongod
```

```shell
sudo apt-get purge mongodb-org* -y
sudo apt-get autoremove
```

```shell
sudo rm -r /var/log/mongodb
sudo rm -r /var/lib/mongodb
```

```shell
mongod --version
```


### Mongosh

```shell
sudo apt update
```

```shell
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-mongosh
```

* connect to mongodb


```shell
mongosh mongodb://172.17.0.4:27017
```


## gNB

### Setup

```shell
sudo ovs-vsctl del-port br-ovs-ryu gnb-1
sudo ovs-vsctl add-port br-ovs-ryu gnb-1 -- set Interface gnb-1 type=internal
```

```shell
docker stop gnb-1; docker rm gnb-1
docker run -dit --privileged --name gnb-1 --network=bridge ubuntu-5g:1.2 bash
```

```shell
gNB_PID=$(docker inspect -f '{{.State.Pid}}' gnb-1)
sudo ip link set gnb-1 netns $gNB_PID
```

```shell
docker exec -it gnb-1 bash
```

```shell
ip link set gnb-1 up
```

```shell
ip addr add 192.168.230.5/24 dev gnb-1
```

```shell
ip route add default via 192.168.230.1 dev gnb-1
```

```shell
ping -c 2 -I gnb-1 192.168.230.1
```



### UERANSIM - gNB

```shell
cd ~/5G-env/UERANSIM
cd config
cp open5gs-gnb.yaml open5gs-gnb1.yaml
nano open5gs-gnb1.yaml
```

```
sed -i -e 's|999|001|g' -e 's|70|01|g' open5gs-gnb1.yaml
```


```shell
sed -i '8s|.*|linkIp: 192.168.230.5|' open5gs-gnb1.yaml
sed -i '9s|.*|ngapIp: 192.168.230.5|' open5gs-gnb1.yaml
sed -i '10s|.*|gtpIp: 192.168.230.5|' open5gs-gnb1.yaml
sed -i '14s|.*|  - address: 192.168.230.2|' open5gs-gnb1.yaml  
```


### Run UERANSIM - gNB

```shell
./build/nr-gnb -c config/open5gs-gnb1.yaml &
```




## UE 

### Setup

```shell
sudo ovs-vsctl del-port br-ovs-ryu ue-1
sudo ovs-vsctl add-port br-ovs-ryu ue-1 -- set Interface ue-1 type=internal
```

```shell
docker stop ue-1; docker rm ue-1
docker run -dit --privileged --name ue-1 --network=bridge ubuntu-5g:1.2 bash
```

```shell
UE_PID=$(docker inspect -f '{{.State.Pid}}' ue-1)
sudo ip link set ue-1 netns $UE_PID
```

```shell
docker exec -it ue-1 bash
```

```shell
ip link set ue-1 up
```

```shell
ip addr add 192.168.230.6/24 dev ue-1
```

```shell
ip route add default via 192.168.230.1 dev ue-1
```

```shell
ping -c 2 -I ue-1 192.168.230.1
```




### UERANSIM - UE

```shell
cd ~/5G-env/UERANSIM
cd config
cp open5gs-ue.yaml open5gs-ue1.yaml
nano open5gs-ue1.yaml
```

```
sed -i -e 's|999|001|g' -e 's|70|01|g' open5gs-ue1.yaml
```


```shell
sed -i '31s|.*|  - 192.168.230.5|' open5gs-ue1.yaml  
```


### Run UERANSIM - gNB

```shell
./build/nr-ue -c config/open5gs-ue1.yaml 
```


### Add Subscriber

```shell
mongosh mongodb://172.17.0.4:27017/open5gs
show dbs
use open5gs
```


```shell
db.subscribers.insertOne({
  imsi: '001010000000001',
  msisdn: [],
  imeisv: '4301816125816151',
  mme_host: [],
  mme_realm: [],
  purge_flag: [],
  security: {
    k: '465B5CE8 B199B49F AA5F0A2E E238A6BC',
    op: null,
    opc: 'E8ED289D EBA952E4 283B54E8 8E6183CA',
    amf: '8000',
    sqn: NumberLong("513")
  },
  ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
  slice: [
    {
      sst: 1,
      default_indicator: true,
      session: [
        {
          name: 'internet',
          type: 3,
          qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
          ambr: { downlink: { value: 1, unit: 3 }, uplink: { value: 1, unit: 3 } },
          ue: { addr: '10.45.0.3' },
          _id: ObjectId("6473fd45a07e473e0b5334ce"),
          pcc_rule: []
        }
      ],
      _id: ObjectId("6473fd45a07e473e0b5334cd")
    }
  ],
  access_restriction_data: 32,
  subscriber_status: 0,
  network_access_mode: 0,
  subscribed_rau_tau_timer: 12,
  __v: 0
})
```


