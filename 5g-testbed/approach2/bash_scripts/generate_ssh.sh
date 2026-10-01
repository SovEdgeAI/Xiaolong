#!/bin/bash

# Define the output directory
SCRIPT_DIR="./ssh_scripts"

# Create the directory if it doesn't exist
mkdir -p "$SCRIPT_DIR"

# Get the DHCP leases from the 'default' network
leases=$(sudo virsh net-dhcp-leases default)

# Extract IP addresses and hostnames of VMs whose hostname ends with '-2'
vm_list=$(echo "$leases" | awk '$6 ~ /-2$/ {print $5, $6}')

# Generate SSH scripts for each VM
echo "$vm_list" | while read ip hostname; do
  ip_clean=$(echo $ip | cut -d '/' -f1) # Remove subnet mask

  if [[ -z "$ip_clean" || -z "$hostname" ]]; then
    continue  # Skip empty lines
  fi

  script_path="${SCRIPT_DIR}/${hostname}.sh"

  echo "Generating SSH script for: $hostname ($ip_clean)..."

  # Create the SSH script
  cat <<EOF > "$script_path"
#!/bin/bash
echo "Connecting to VM: $hostname ($ip_clean)..."
sudo ssh -t $hostname@$ip_clean
EOF

  # Make the script executable
  chmod +x "$script_path"
done

echo "All SSH scripts have been generated in: $SCRIPT_DIR"
