#!/bin/bash

# Check if P4 program name is provided as an argument
if [[ -z "$1" ]]; then
    echo "Error: P4 program name not provided. Usage: $0 <p4_program>"
    exit 1
fi

p4_program="$1"

# Find the P4 program file within the specified directory
p4_file=$(find ~/5G-SDN-DDoS-Detection-Mitigation/approach2 -type f -name "${p4_program}.p4" 2>/dev/null)

if [[ -z "$p4_file" ]]; then
    echo "Error: P4 file not found for program $p4_program."
    exit 1
fi

# Extract the directory where the P4 file is located
p4_path=$(dirname "$p4_file")

# Set output paths for compiled files within the same directory as the P4 file
json_output="${p4_path}/${p4_program}.json"
p4info_output="${p4_path}/${p4_program}.p4info.txt"

# Compile the P4 program, specifying the output directory
compile_cmd="p4c -b bmv2 --p4runtime-files ${p4info_output} -o ${p4_path} ${p4_file}"

echo "Compiling P4 program: $p4_program"

# Execute the compile command
eval $compile_cmd

echo "Compilation finished. Compiled files are in: $p4_path"
