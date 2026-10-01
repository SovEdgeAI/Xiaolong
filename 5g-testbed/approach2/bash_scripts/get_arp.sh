#!/bin/bash

#check if br-p4-onos exists
if [[ $(ip a | grep br-p4-onos) ]]; then
    echo "br-p4-onos exists"
else
    echo "br-p4-onos does not exist"
    sudo brctl addbr br-p4-onos
    sudo brctl addif br-p4-onos veth11
    sudo ip addr add 192.168.235.1/24 dev br-p4-onos

fi


sudo ip link set dev br-p4-onos up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.235.0/24 ! -o enp0s25 -j MASQUERADE

# Get the output from ip a
ip_output=$(ip a)

#MACVTAP
# Search for lines containing "macvtap" and "brd" using awk
filtered_output_macvtap=$(echo "$ip_output" | awk '/macvtap/,/brd/')

# Initialize counter
counter=0

# Iterate over the filtered output
while read -r line; do
    if [[ $line =~ macvtap ]]; then
        # Extract interface name
        interface=$(echo "$line" | awk '{print $2}')
        # Increment counter
        ((counter++))
    elif [[ $line =~ "link/ether" ]]; then
        # Extract MAC address
        mac_address=$(echo "$line" | awk '{print $2}')
        # Create variables dynamically
        declare "interfacename$counter=$interface"
        declare "macaddress$counter=$mac_address"
    fi
done <<< "$filtered_output_macvtap"

# Print the variables
for ((i = 1; i <= counter; i++)); do
    interface_var="interfacename$i"
    mac_var="macaddress$i"
    echo "${!interface_var}: ${!mac_var}"
done

# Create arp.sh file
echo "#!/bin/bash" > arp.sh

# Create ARP entries for each interface
for ((i = 1; i <= counter; i++)); do
    interface_var="interfacename$i"
    mac_var="macaddress$i"
    # If interface contains veth1 then assign
    if [[ ${!interface_var} == *"veth1"* ]]; then
        echo "sudo arp -s 192.168.235.2 ${!mac_var}" >> arp.sh
    elif [[ ${!interface_var} == *"veth3"* ]]; then
        echo "sudo arp -s 192.168.235.3 ${!mac_var}" >> arp.sh
    elif [[ ${!interface_var} == *"veth5"* ]]; then
        echo "sudo arp -s 192.168.235.4 ${!mac_var}" >> arp.sh
    elif [[ ${!interface_var} == *"veth7"* ]]; then
        echo "sudo arp -s 192.168.235.5 ${!mac_var}" >> arp.sh
    elif [[ ${!interface_var} == *"veth9"* ]]; then
        echo "sudo arp -s 192.168.235.6 ${!mac_var}" >> arp.sh
    fi
done

#br-p4-onos BRIDGE 
# Search for lines containing "br-p4-onos:" and "brd" using awk
filtered_output_br=$(echo "$ip_output" | awk '/br-p4-onos:/,/brd/')

# Extract interface name and MAC address for br-p4-onos
while read -r line; do
    if [[ $line =~ "br-p4-onos" ]]; then
        # Extract interface name
        interface_br=$(echo "$line" | awk '{print $2}')
    elif [[ $line =~ "link/ether" ]]; then
        # Extract MAC address
        mac_address_br=$(echo "$line" | awk '{print $2}')
    fi
done <<< "$filtered_output_br"

# echo "br-p4-onos interface: $interface_br"
echo "br-p4-onos MAC address: $mac_address_br"

echo "sudo arp -s 192.168.235.1 $mac_address_br" >> arp.sh

echo "Number of MACVTAP interfaces found: $counter"


# Command to get DHCP leases from the 'default' network
leases=$(sudo virsh net-dhcp-leases default)

# Extract IP addresses and hostnames of VMs whose hostname ends with '-2'
echo "$leases" | awk '/-2/ {print $5, $6}' | while read ip hostname; do
  # Remove the subnet mask from the IP address
  ip_clean=$(echo $ip | cut -d '/' -f1)
  echo "VM Name: $hostname, IP Address: $ip_clean"
  sudo scp arp.sh $hostname@$ip_clean:~/
done
