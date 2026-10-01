#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Get the username using whoami
username=$(whoami)

echo "Running stratum for user: $username"

# Function to find file paths with error checking
find_file_path() {
    local file_name="$1"
    local file_path
    file_path=$(find ~/5G-SDN-DDoS-Detection-Mitigation -type f -name "$file_name" 2>/dev/null)

    if [[ -z "$file_path" ]]; then
        echo "Error: $file_name not found."
        exit 1
    fi

    echo "$file_path"
}

# Find required file paths
chassis_path=$(find_file_path "chassis-config.txt")
echo "Chassis path: $chassis_path"

pipe_path=$(find_file_path "pipe.txt")
echo "Pipe path: $pipe_path"

write_reqs_path=$(find_file_path "write-reqs.txt")
echo "Write reqs path: $write_reqs_path"

# Check if P4 program name is provided as an argument
if [[ -z "$1" ]]; then
    echo "Error: P4 program name not provided. Usage: $0 <p4_program>"
    exit 1
fi

p4_program="$1"
echo "P4 program name: $p4_program"

# Find the P4 program file (.p4) and extract its directory
p4_file=$(find ~/5G-SDN-DDoS-Detection-Mitigation/approach2 -type f -name "${p4_program}.p4" 2>/dev/null)

if [[ -z "$p4_file" ]]; then
    echo "Error: P4 file not found for program $p4_program."
    exit 1
fi

# Extract the directory where the P4 file is located
p4_path=$(dirname "$p4_file")
echo "P4 directory path: $p4_path"

# Define Stratum command with parameters
stratum_cmd="sudo stratum_bmv2 \
    -device_id=1 \
    -chassis_config_file=$chassis_path \
    -forwarding_pipeline_configs_file=$pipe_path \
    -persistent_config_dir=/home/$username \
    -initial_pipeline=${p4_path}/${p4_program}.json \
    -cpu_port=255 \
    -external_stratum_urls=0.0.0.0:50001 \
    -local_stratum_url=localhost:44400 \
    -max_num_controllers_per_node=10 \
    -write_req_log_file=$write_reqs_path \
    -logtosyslog=false \
    -bmv2_log_level=trace \
    -logtostderr=true"

# Run Stratum command and filter output
echo "Running Stratum command..."
eval "$stratum_cmd 2>&1 | grep -v 'StratumErrorSpace::ERR_UNIMPLEMENTED: DataRequest field loopback_status is not supported yet!'"
