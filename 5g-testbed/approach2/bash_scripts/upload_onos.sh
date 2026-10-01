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

# Find the P4 program path
p4_program_path=$(find ~/5G-SDN-DDoS-Detection-Mitigation -type f -name "${p4_program}.p4" 2>/dev/null)

if [[ -z "$p4_program_path" ]]; then
    echo "Error: P4 directory not found for program $p4_program."
    exit 1
fi

echo "P4 program path: $p4_program_path"

# Convert hyphens to underscores
p4_program_underscore=$(echo "$p4_program" | sed 's/-/_/g')

# Set ONOS app path correctly
onos_app_path=~/5G-SDN-DDoS-Detection-Mitigation/approach2/onos_app/approach2

# Check if the ONOS app directory exists
echo "Checking ONOS app directory: $onos_app_path"
if [[ ! -d "$onos_app_path" ]]; then
    echo "Error: ONOS app directory not found at '$onos_app_path'."
    exit 1
fi

echo "ONOS app path: $onos_app_path"

# Locate MainComponent.java
main_path=$(find "$onos_app_path/src/main/java/us/fiu/adwise/approach2" -name "MainComponent.java" -type f 2>/dev/null)

if [[ -z "$main_path" ]]; then
    echo "Error: MainComponent.java not found in ONOS app directory."
    exit 1
fi

cd "$onos_app_path/" || exit
echo "Working in directory: $(pwd)"

# Copy JSON and P4 info files to the ONOS app directory
p4_program_dir=$(dirname "$p4_program_path")

cp "$p4_program_dir/$p4_program.json" "$onos_app_path/src/main/resources/"
cp "$p4_program_dir/$p4_program.p4info.txt" "$onos_app_path/src/main/resources/"

# Run Maven package build
mvn clean package

# Extract package path for ONOS app
extracted_path=$(echo "$main_path" | awk -F'/java/' '{print $2}' | awk -F'/MainComponent.java' '{print $1}')
Pipeconf=$(echo "$extracted_path" | sed 's/\//./g')
# Pipeconf=us.fiu.adwise.approach2

echo "Pipeconf: $Pipeconf"

ArtifactID="approach2-1.0-SNAPSHOT"
echo "ArtifactID: $ArtifactID"

# Delete existing ONOS app instance
delete_url="http://$IP:8181/onos/v1/applications/$Pipeconf"
echo "Deleting existing ONOS app: $delete_url"
curl --fail -sSL --user onos:rocks --noproxy localhost -X DELETE "http://$IP:8181/onos/v1/applications/$Pipeconf"

sleep 10




# Find the ONOS application .oar file
data_binary_path=$(find "$onos_app_path/target" -name "*.oar" -type f 2>/dev/null)

if [[ -z "$data_binary_path" ]]; then
    echo "Error: ONOS .oar file not found."
    exit 1
fi

echo "Data Binary Path: $data_binary_path"

# Upload and activate the ONOS application
curl --fail -sSL --user onos:rocks --noproxy localhost -X POST -H "Content-Type: application/octet-stream" \
     --data-binary "@./target/$ArtifactID.oar" \
     "http://$IP:8181/onos/v1/applications?activate=true"

# Upload the network configuration file
config_url="http://$IP:8181/onos/v1/network/configuration"
echo "Uploading network configuration..."
curl --fail -sSL --user onos:rocks --noproxy localhost -X POST -H 'Content-Type:application/json' \
     -d @./netcfg.json "$config_url"

sleep 1

echo "ONOS app uploaded and activated successfully."


