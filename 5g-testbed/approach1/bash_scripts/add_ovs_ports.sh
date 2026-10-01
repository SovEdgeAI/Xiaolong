#!/bin/bash

sudo ovs-vsctl add-port br-ovs-ryu cp-1 -- set Interface cp-1 type=internal
sudo ovs-vsctl add-port br-ovs-ryu up-1 -- set Interface up-1 type=internal
sudo ovs-vsctl add-port br-ovs-ryu ue-1 -- set Interface ue-1 type=internal
sudo ovs-vsctl add-port br-ovs-ryu gnb-1 -- set Interface gnb-1 type=internal

sudo ovs-vsctl show