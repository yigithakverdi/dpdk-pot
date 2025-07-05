#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
IMAGE_NAME="yigithak/dpdk-pot:0.0.1"  # Your DPDK image
NUM_TRANSIT_NODES=${1:-5}  # Default to 5 transit nodes, take from first argument
NODE_PREFIX="pot-node"     # Common prefix for all nodes
INGRESS_NODE="${NODE_PREFIX}-ingress"  # Ingress node name
EGRESS_NODE="${NODE_PREFIX}-egress"    # Egress node name
TRANSIT_NODE_PREFIX="${NODE_PREFIX}-transit"  # Prefix for transit nodes
VETH_PREFIX="veth"  # Prefix for veth interfaces
NET_PREFIX="10.10.20"  # Network prefix for IP addresses
IPV6_PREFIX="2001:db8:1::"  # IPv6 prefix for addresses
KEYS_FILE="${2:-$(pwd)/keys.txt}"  # Path to input keys file, if available
GEN_KEYS_FILE="$(pwd)/container_keys.txt"  # Path to generated keys file
SEGMENT_LIST_FILE="$(pwd)/segment_list.txt"  # Path to generated segment list file
SOCKET_MEM="128"  # Socket memory for DPDK
START_LCORE=1  # Starting CPU core number
# Common DPDK args - we use ethX where X is the node index
DPDK_BASE_ARGS="-n 4 --no-pci --iova-mode=va --socket-mem ${SOCKET_MEM}"

# Validate input
if [[ ! "$NUM_TRANSIT_NODES" =~ ^[0-9]+$ ]] || [ "$NUM_TRANSIT_NODES" -lt 1 ] || [ "$NUM_TRANSIT_NODES" -gt 100 ]; then
    echo "Error: Number of transit nodes must be a positive integer (1-100)"
    echo "Usage: $0 [number_of_transit_nodes] [optional_keys_file] [use_keys(yes/no)]"
    exit 1
fi

echo "[INFO] Setting up $NUM_TRANSIT_NODES transit nodes in a chain topology"
if [[ "$USE_KEYS" == "no" ]]; then
    echo "[INFO] Key generation disabled - will rely on application's hardcoded keys"
fi

# --- Helper Functions ---
info() {
    echo "[INFO] $1" >&2
}

error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}

# --- Cleanup Function ---
cleanup() {
    info "--- Starting Cleanup ---"
    
    # Stop and remove all containers with our prefix
    local containers=$(sudo docker ps -a --format '{{.Names}}' | grep "^${NODE_PREFIX}")
    if [ -n "$containers" ]; then
        echo "$containers" | xargs -r sudo docker stop >/dev/null 2>&1 || true
        echo "$containers" | xargs -r sudo docker rm >/dev/null 2>&1 || true
        info "Removed all POT node containers"
    fi
    
    # Remove all veth interfaces with our prefix
    local veths=$(ip link show | grep "${VETH_PREFIX}" | awk -F': ' '{print $2}' | cut -d'@' -f1)
    if [ -n "$veths" ]; then
        for veth in $veths; do
            sudo ip link del "$veth" >/dev/null 2>&1 || true
        done
        info "Removed all veth interfaces"
    fi
    
    info "--- Cleanup Complete ---"
}

# --- Key Management Function ---
generate_keys_file() {
    info "Generating keys file at $GEN_KEYS_FILE"
    > "$GEN_KEYS_FILE"  # Clear file
    
    # If we have an input keys file, try to use those keys first
    declare -A key_map
    if [ -f "$KEYS_FILE" ]; then
        info "Reading keys from $KEYS_FILE"
        while read -r line || [ -n "$line" ]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue
            
            read -r ipv6 key <<< "$line"
            if [ -n "$ipv6" ] && [ -n "$key" ]; then
                key_map["$ipv6"]="$key"
            fi
        done < "$KEYS_FILE"
    fi
    
    # Generate keys for each container
    for i in $(seq 0 $NUM_TRANSIT_NODES); do
        local ipv6="${IPV6_PREFIX}${i}"
        local key
        
        # Check if we already have a key for this IP in our map
        if [ -n "${key_map[$ipv6]}" ]; then
            key="${key_map[$ipv6]}"
        else
            # Generate a new random key
            key="$(openssl rand -hex 16)"
        fi
        
        echo "$ipv6 $key" >> "$GEN_KEYS_FILE"
    done
    
    info "Keys file generated with $((NUM_TRANSIT_NODES + 1)) entries"
}

# --- Segment List Generation Function ---
generate_segment_list() {
    info "Generating segment list file at $SEGMENT_LIST_FILE"
    > "$SEGMENT_LIST_FILE"  # Clear file
    
    # Add transit nodes to the segment list
    # This creates a path that will be traversed in order: ingress → transit-1 → ... → transit-N → egress
    
    # First add all transit nodes in reverse order
    for i in $(seq $NUM_TRANSIT_NODES -1 1); do
        # Format the IPv6 address for this transit node
        local ipv6="${IPV6_PREFIX}${i}"
        echo "$ipv6" >> "$SEGMENT_LIST_FILE"
    done
    
    # Add the egress node last
    local egress_ipv6="${IPV6_PREFIX}$((NUM_TRANSIT_NODES + 1))"
    echo "$egress_ipv6" >> "$SEGMENT_LIST_FILE"
    
    info "Segment list file generated with $((NUM_TRANSIT_NODES + 1)) entries"
    
    # Display the path
    local path="ingress (${IPV6_PREFIX}0)"
    for i in $(seq 1 $NUM_TRANSIT_NODES); do
        path="$path → transit-$i (${IPV6_PREFIX}${i})"
    done
    path="$path → egress (${IPV6_PREFIX}$((NUM_TRANSIT_NODES + 1)))"
    info "Path: $path"
}

# --- Launch Container Function ---
# Args: $1=container_name, $2=container_index
launch_container() {
    local name="$1"
    local index="$2"
    local lcore=$((START_LCORE + index % $(nproc)))
    
    info "Launching container: $name (using core $lcore)" >&2
    sudo docker run -d \
        --name="$name" \
        --hostname="$name" \
        --privileged \
        --cpuset-cpus="$lcore" \
        --network=none \
        --entrypoint sleep \
        -v /dev/hugepages:/dev/hugepages \
        -v /dev/vfio:/dev/vfio \
        -v /sys/bus/pci/devices:/sys/bus/pci/devices \
        -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
        -v /sys/devices/system/node:/sys/devices/system/node \
        -v "$GEN_KEYS_FILE":/etc/dpdk-pot/keys.txt \
        -v "$SEGMENT_LIST_FILE":/etc/dpdk-pot/segment_list.txt \
        "$IMAGE_NAME" \
        infinity >/dev/null

    sleep 1
    
    local pid
    pid=$(sudo docker inspect -f '{{.State.Pid}}' "$name")
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        error_exit "Failed to get PID for container $name"
    fi
    
    echo "$pid"
}

# --- Verification Function ---
verify_connections() {
    info "--- Verifying Network Connections ---"
    
    # Check if all expected containers are running
    for name in "${container_names[@]}"; do
        if ! sudo docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
            error_exit "Container ${name} is not running!"
        fi
        info "✓ Container ${name} is running"
    done
    
    # Check all interfaces are present in containers
    for i in $(seq 0 $((total_nodes - 1))); do
        local name="${container_names[$i]}"
        local pid="${container_pids[$i]}"
        local expected_interfaces=()
        
        # Ingress and egress nodes should have eth0, transit nodes should have eth0 and eth1
        if [[ "$i" -eq 0 ]] || [[ "$i" -eq $((total_nodes - 1)) ]]; then
            expected_interfaces+=("eth0")
        else
            expected_interfaces+=("eth0" "eth1")
        fi
        
        for iface in "${expected_interfaces[@]}"; do
            if ! sudo nsenter -t "$pid" -n ip link show "$iface" &>/dev/null; then
                error_exit "Interface ${iface} not found in container ${name}!"
            fi
            info "✓ Container ${name} has interface ${iface}"
        done
        
        # Check IPv6 addresses
        # Check IPv6 addresses
        local expected_addr="${IPV6_PREFIX}${i}/64"
        
        # The 'ip' command may shorten '::0/64' to '::/64'. We must check for both forms for the ingress node.
        # We capture the output to avoid running the command twice.
        local actual_addr_output
        actual_addr_output=$(sudo nsenter -t "$pid" -n ip -6 addr)
        
        local found=false
        if [[ "$i" -eq 0 ]]; then
            # For the ingress node, check for both "...::0/64" and the canonical form "...::/64"
            local canonical_addr="${IPV6_PREFIX}/64"
            if echo "$actual_addr_output" | grep -q -F -e "$expected_addr" -e "$canonical_addr"; then
                found=true
            fi
        else
            # For all other nodes, the address is not at the zero boundary, so a direct check is fine.
            if echo "$actual_addr_output" | grep -q -F "$expected_addr"; then
                found=true
            fi
        fi
        
        if ! $found; then
            error_exit "IPv6 address ${expected_addr} not found in container ${name}!"
        fi
        info "✓ Container ${name} has correct IPv6 address ${expected_addr}"
    done
    
    # Test connectivity between adjacent nodes
    for i in $(seq 0 $((total_nodes - 2))); do
        local left_name="${container_names[$i]}"
        local left_pid="${container_pids[$i]}"
        local right_idx=$((i + 1))
        local right_ipv6="${IPV6_PREFIX}${right_idx}"
        
        # For nodes with multiple interfaces, we must specify the source interface for the ping.
        # The 'left' node in the pair always connects to the 'right' node via its eth1 interface,
        # unless it's the ingress node (which only has eth0).
        local source_interface="eth1"
        if [[ "$i" -eq 0 ]]; then
            source_interface="eth0"
        fi
        
        info "Testing connectivity from ${left_name} (via ${source_interface}) to ${right_ipv6}..."
        # Use ping -I to specify the outgoing interface to resolve routing ambiguity.
        if ! sudo nsenter -t "$left_pid" -n ping -6 -I "$source_interface" -c 2 "$right_ipv6" &>/dev/null; then
            info "⚠️ Ping from ${left_name} to ${right_ipv6} failed"
        else
            info "✓ ${left_name} can ping ${right_ipv6}"
        fi
    done
    
    info "--- Verification Complete ---"
}

# --- Create and Assign Veth Function ---
# Args: $1=left_name, $2=right_name, $3=left_container_pid, $4=right_container_pid, $5=left_ip, $6=right_ip, $7=left_idx, $8=right_idx
# --- Create and Assign Veth Function ---
# Args: $1=left_name, $2=right_name, $3=left_container_pid, $4=right_container_pid, $5=left_ip, $6=right_ip, $7=left_idx, $8=right_idx
create_and_assign_veth() {
    local left_veth="$1"
    local right_veth="$2"
    local left_pid="$3"
    local right_pid="$4"
    local left_ip="$5"
    local right_ip="$6"
    local left_idx="$7"
    local right_idx="$8"
    
    info "Creating veth pair: $left_veth <-> $right_veth"
    sudo ip link add "$left_veth" type veth peer name "$right_veth"
    sudo ip link set "$left_veth" up
    sudo ip link set "$right_veth" up
    
    # --- CORRECTED LOGIC ---
    # Ingress/Egress nodes get 'eth0'. Transit nodes get 'eth0' (towards ingress) and 'eth1' (towards egress).
    local left_if_name
    if [ "$left_idx" -eq 0 ]; then
        left_if_name="eth0"  # Ingress node's only interface
    else
        left_if_name="eth1"  # "Right-hand" interface for a transit node
    fi
    
    # The "left-hand" interface for any node is always eth0.
    local right_if_name="eth0"
    
    # Move left veth to left container
    info "Moving $left_veth to container PID $left_pid as ${left_if_name}"
    sudo ip link set "$left_veth" netns "$left_pid"
    sudo nsenter -t "$left_pid" -n ip link set "$left_veth" name "$left_if_name"
    sudo nsenter -t "$left_pid" -n ip link set "$left_if_name" up
    if [ -n "$left_ip" ]; then
        sudo nsenter -t "$left_pid" -n ip addr add "$left_ip" dev "$left_if_name" 2>/dev/null || true
    fi
    
    # Add IPv6 address to left container
    left_ipv6="${IPV6_PREFIX}${left_idx}/64"
    info "Adding IPv6 address $left_ipv6 to ${NODE_PREFIX}-${left_idx} on ${left_if_name}"
    sudo nsenter -t "$left_pid" -n sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$left_pid" -n sysctl -w net.ipv6.conf."$left_if_name".disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$left_pid" -n ip -6 addr add "$left_ipv6" dev "$left_if_name" 2>/dev/null || true
    
    # Move right veth to right container
    info "Moving $right_veth to container PID $right_pid as ${right_if_name}"
    sudo ip link set "$right_veth" netns "$right_pid"
    sudo nsenter -t "$right_pid" -n ip link set "$right_veth" name "$right_if_name"
    sudo nsenter -t "$right_pid" -n ip link set "$right_if_name" up
    if [ -n "$right_ip" ]; then
        sudo nsenter -t "$right_pid" -n ip addr add "$right_ip" dev "$right_if_name" 2>/dev/null || true
    fi
    
    # Add IPv6 address to right container
    right_ipv6="${IPV6_PREFIX}${right_idx}/64"
    info "Adding IPv6 address $right_ipv6 to ${NODE_PREFIX}-${right_idx} on ${right_if_name}"
    sudo nsenter -t "$right_pid" -n sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$right_pid" -n sysctl -w net.ipv6.conf."$right_if_name".disable_ipv6=0 >/dev/null 2>&1 || true
    sudo nsenter -t "$right_pid" -n ip -6 addr add "$right_ipv6" dev "$right_if_name" 2>/dev/null || true
}

# --- Main Execution ---
cleanup

# Generate keys and segment list files first
if [[ "$USE_KEYS" == "yes" ]]; then
    generate_keys_file
else
    info "Skipping key generation as requested"
    touch "$GEN_KEYS_FILE"  # Create empty file
fi
generate_segment_list

info "--- Creating POT Network with Ingress, $NUM_TRANSIT_NODES Transit Nodes, and Egress ---"

# Launch all containers first
declare -a container_pids
declare -a container_names
declare -a container_roles  # Store container roles: "ingress", "transit-X", or "egress"

# 1. Launch ingress node (index 0 for container array)
ingress_name="${INGRESS_NODE}"
container_names+=("$ingress_name")
container_roles+=("ingress")
pid=$(launch_container "$ingress_name" 0)
container_pids+=("$pid")
info "Launched ingress container $ingress_name with PID $pid"

# 2. Launch transit nodes (indices 1 to N for container array)
for i in $(seq 1 $NUM_TRANSIT_NODES); do
    name="${TRANSIT_NODE_PREFIX}-${i}"
    container_names+=("$name")
    container_roles+=("transit-${i}")
    pid=$(launch_container "$name" "$i")
    container_pids+=("$pid")
    info "Launched transit container $name with PID $pid"
done

# 3. Launch egress node (index N+1 for container array)
egress_name="${EGRESS_NODE}"
container_names+=("$egress_name")
container_roles+=("egress")
pid=$(launch_container "$egress_name" $((NUM_TRANSIT_NODES + 1)))
container_pids+=("$pid")
info "Launched egress container $egress_name with PID $pid"

# Now create veth pairs to connect the containers in a chain:
# ingress → transit-1 → transit-2 → ... → transit-N → egress

# Total number of nodes (including ingress and egress)
total_nodes=$((NUM_TRANSIT_NODES + 2))

# Now connect all nodes with veth pairs
for i in $(seq 0 $((total_nodes - 2))); do
    left_idx=$i
    right_idx=$((i + 1))
    
    left_name="${container_names[$left_idx]}"
    right_name="${container_names[$right_idx]}"
    left_pid="${container_pids[$left_idx]}"
    right_pid="${container_pids[$right_idx]}"
    
    left_veth="${VETH_PREFIX}_${left_idx}_${right_idx}_l"
    right_veth="${VETH_PREFIX}_${left_idx}_${right_idx}_r"
    
    left_ip="${NET_PREFIX}.${left_idx}/24"
    right_ip="${NET_PREFIX}.${right_idx}/24"
    
    # Adjust IPv6 indices to match container roles
    left_ipv6_idx=$left_idx
    right_ipv6_idx=$right_idx
    
    create_and_assign_veth "$left_veth" "$right_veth" "$left_pid" "$right_pid" "$left_ip" "$right_ip" "$left_ipv6_idx" "$right_ipv6_idx"
done

info "--- Setup Complete! ---"
echo
info "POT chain created with: 1 ingress node, $NUM_TRANSIT_NODES transit nodes, and 1 egress node"
info "Container keys file generated at $GEN_KEYS_FILE"
info "Segment list file generated at $SEGMENT_LIST_FILE"
echo

# Run the verification function
verify_connections

# Print instructions for running the DPDK-POT application
info "--- Running DPDK-POT Application Instructions ---"
echo
info "1. Access the Ingress Node:"
echo "  sudo docker exec -it --user root ${INGRESS_NODE} bash"
echo
echo "  # Inside the ingress container, run:"
echo "  ./build/dpdk-pot -l 0-1 ${DPDK_BASE_ARGS} --vdev=net_af_packet0,iface=eth0 -- \\
    --role ingress \\
    --node-id 0 \\
    --keys-file /etc/dpdk-pot/keys.txt \\
    --segment-list /etc/dpdk-pot/segment_list.txt \\
    --log-level debug"
echo
info "2. Access Each Transit Node:"
for i in $(seq 1 $NUM_TRANSIT_NODES); do
echo "  sudo docker exec -it --user root ${TRANSIT_NODE_PREFIX}-${i} bash"
echo
echo "  # Inside transit-${i} container, run:"
echo "  # Note: A transit node requires two vdevs for its two interfaces (eth0 and eth1)."
echo "  ./build/dpdk-pot -l 0-1 ${DPDK_BASE_ARGS} --vdev=net_af_packet0,iface=eth0 --vdev=net_af_packet1,iface=eth1 -- \\
    --role transit \\
    --node-id ${i} \\
    --keys-file /etc/dpdk-pot/keys.txt \\
    --log-level debug"
echo
done
info "3. Access the Egress Node:"
echo "  sudo docker exec -it --user root ${EGRESS_NODE} bash"
echo
echo "  # Inside the egress container, run:"
echo "  ./build/dpdk-pot -l 0-1 ${DPDK_BASE_ARGS} --vdev=net_af_packet0,iface=eth0 -- \\
    --role egress \\
    --node-id $((NUM_TRANSIT_NODES + 1)) \\
    --keys-file /etc/dpdk-pot/keys.txt \\
    --log-level debug"
echo
info "For running DPDK testpmd (alternative for testing):"
echo "  # Inside any container:"
echo "  PMDS_DIR=\$(ls -d /usr/local/lib/x86_64-linux-gnu/dpdk/pmds-*/ | head -n 1) && \\"
echo "  dpdk-testpmd \\"
echo "    -l 0-1 \\"
echo "    --iova-mode=va \\"
echo "    --socket-mem ${SOCKET_MEM} \\"
echo "    --file-prefix \"pot_node\" \\"
echo "    --single-file-segments \\"
echo "    --no-pci \\"
echo "    --vdev=\"net_af_packet0,iface=eth\${NODE_ID:-0}\" \\"
echo "    -d \"\${PMDS_DIR%/}\" \\"
echo "    -- \\"
echo "    --interactive --portmask=0x1"
echo
info "To clean up all containers and interfaces:"
echo "  $0 0  # (passing 0 will just clean up)"
echo
info "--- Network Information ---"
info "IPv6 Addressing:"
info "Each container has been assigned an IPv6 address in the format:"
info "  ${IPV6_PREFIX}[node_index]"
info "  - Ingress: ${IPV6_PREFIX}0"
for i in $(seq 1 $NUM_TRANSIT_NODES); do
info "  - Transit-${i}: ${IPV6_PREFIX}${i}"
done
info "  - Egress: ${IPV6_PREFIX}$((NUM_TRANSIT_NODES + 1))"
echo
info "Network Topology:"
echo "  ingress → transit-1 → transit-2 → ... → transit-${NUM_TRANSIT_NODES} → egress"
echo
info "Segment List for SRv6 routing:"
cat "$SEGMENT_LIST_FILE" | while read line; do
    echo "  - $line"
done
echo

