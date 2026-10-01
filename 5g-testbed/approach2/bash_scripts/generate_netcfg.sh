#!/bin/bash

# Get the Host IP address
IP=$(hostname -I | awk '{print $1}')
echo "Host IP address: $IP"

# Check if P4 program name is provided as an argument
if [[ -z "$1" ]]; then
    echo "Error: P4 program name not provided. Usage: $0 <p4_program>"
    exit 1
fi

p4_program="$1"

# Find the P4 program file and get its directory
p4_file_path=$(find ~/5G-SDN-DDoS-Detection-Mitigation -type f -name "${p4_program}.p4" 2>/dev/null)

if [[ -z "$p4_file_path" ]]; then
    echo "Error: P4 file not found for program $p4_program."
    exit 1
fi

# Extract the directory of the P4 program
p4_program_path=$(dirname "$p4_file_path")
echo "P4 program found at: $p4_program_path"

# Convert hyphens to underscores for ONOS app path
p4_program_underscore=$(echo "$p4_program" | sed 's/-/_/g')

# Explicitly set ONOS app path (Check if approach2 is part of the directory structure)
onos_app_path=~/5G-SDN-DDoS-Detection-Mitigation/approach2/onos_app/approach2

# Check if the ONOS app directory exists
if [[ ! -d "$onos_app_path" ]]; then
    echo "Error: ONOS app directory not found at '$onos_app_path'."
    exit 1
fi

# Find MainComponent.java in the correct path
main_path=$(find "$onos_app_path/src/main/java/us/fiu/adwise/approach2/" -type f -name "MainComponent.java" 2>/dev/null)

if [[ -z "$main_path" ]]; then
    echo "Error: MainComponent.java not found in ONOS app directory."
    exit 1
fi

# Extract the package path inside ONOS
Pipeconf="us.fiu.adwise.approach2"

echo "Pipeconf: $Pipeconf"

# Move to ONOS app directory and copy netcfg.json
cd "$onos_app_path" || exit
echo "Working in directory: $(pwd)"

# Navigate to bash script directory
cd ~/5G-SDN-DDoS-Detection-Mitigation/approach2/bash_scripts

# Copy netcfg.json to the ONOS app directory
cp netcfg.json "$onos_app_path/"

# Replace placeholder with actual Pipeconf value in netcfg.json
sed -i "s|<REPLACE_WITH_PIPECONF>|\"$Pipeconf\"|g" "$onos_app_path/netcfg.json"

echo "netcfg.json updated successfully."
