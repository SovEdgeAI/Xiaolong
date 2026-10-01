#!/bin/bash

# Check if P4 program name is provided as an argument
if [[ -z "$1" ]]; then
    echo "Error: P4 program name not provided. Usage: $0 <p4_program>"
    exit 1
fi

p4_program="$1"

# Find the P4 program file (.p4) within the specified directory
p4_file=$(find ~/5G-SDN-DDoS-Detection-Mitigation/approach2 -type f -name "${p4_program}.p4" 2>/dev/null)

if [[ -z "$p4_file" ]]; then
    echo "Error: P4 file not found for program $p4_program."
    exit 1
fi

# Extract the directory where the P4 file is located
p4_path=$(dirname "$p4_file")

# Set paths for compiled files
json_output="${p4_path}/${p4_program}.json"
p4info_output="${p4_path}/${p4_program}.p4info.txt"

# Generate pipeline
generate_cmd="sudo python3 generatepipe2.py ${json_output} ${p4info_output}"

echo "Generating pipeline for P4 program: $p4_program"

eval $generate_cmd

# Ensure pipe.txt exists before moving
if [[ -f "pipe.txt" ]]; then
    mv pipe.txt ../stratum_files
    echo "Pipeline file moved to ../stratum_files"
else
    echo "Error: pipe.txt not found. Pipeline generation may have failed."
    exit 1
fi
