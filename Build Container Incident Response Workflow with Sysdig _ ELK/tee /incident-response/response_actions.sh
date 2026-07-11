#!/bin/bash

# Function to isolate suspicious container
isolate_container() {
    local container_name="$1"
    echo "Isolating container: $container_name"
    
    # Remove container from networks (except default)
    docker network ls --format "{{.Name}}" | grep -v bridge | while read network; do
        docker network disconnect "$network" "$container_name" 2>/dev/null || true
    done
    
    # Log isolation action
    logger "INCIDENT_RESPONSE: Container $container_name isolated from networks"
}

# Function to collect forensic data
collect_forensics() {
    local container_name="$1"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local forensics_dir="/tmp/forensics_${container_name}_${timestamp}"
    
    mkdir -p "$forensics_dir"
    
    # Collect container information
    docker inspect "$container_name" > "$forensics_dir/container_inspect.json"
    docker logs "$container_name" > "$forensics_dir/container_logs.txt"
    docker exec "$container_name" ps aux > "$forensics_dir/processes.txt" 2>/dev/null || true
    docker exec "$container_name" netstat -tulpn > "$forensics_dir/network.txt" 2>/dev/null || true
    
    echo "Forensic data collected in: $forensics_dir"
    logger "INCIDENT_RESPONSE: Forensic data collected for container $container_name"
}

# Function to stop malicious container
stop_container() {
    local container_name="$1"
    echo "Stopping malicious container: $container_name"
    docker stop "$container_name"
    logger "INCIDENT_RESPONSE: Container $container_name stopped due to security incident"
}

# Main response function
respond_to_incident() {
    local incident_type="$1"
    local container_name="$2"
    
    case "$incident_type" in
        "privilege_escalation")
            collect_forensics "$container_name"
            isolate_container "$container_name"
            ;;
        "suspicious_network")
            collect_forensics "$container_name"
            isolate_container "$container_name"
            ;;
        "file_modification")
            collect_forensics "$container_name"
            ;;
        "critical")
            collect_forensics "$container_name"
            stop_container "$container_name"
            ;;
        *)
            echo "Unknown incident type: $incident_type"
            ;;
    esac
}

# Example usage
if [ "$#" -eq 2 ]; then
    respond_to_incident "$1" "$2"
else
    echo "Usage: $0 <incident_type> <container_name>"
    echo "Incident types: privilege_escalation, suspicious_network, file_modification, critical"
fi
