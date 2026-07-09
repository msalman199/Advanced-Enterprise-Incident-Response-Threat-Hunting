#!/bin/bash

HUNT_DIR="$HOME/sigma-hunt"
LOG_FILE="$HUNT_DIR/hunt_results.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting proactive hunt..." | tee -a $LOG_FILE

# Function to run OSQuery and check results
run_hunt_query() {
    local query_file=$1
    local rule_name=$2
    
    echo "[$TIMESTAMP] Executing hunt: $rule_name" | tee -a $LOG_FILE
    
    # Run the query and capture results
    result=$(sudo osqueryi --json "$query_file" 2>/dev/null)
    
    if [ ! -z "$result" ] && [ "$result" != "[]" ]; then
        echo "[$TIMESTAMP] ALERT: $rule_name - Suspicious activity detected!" | tee -a $LOG_FILE
        echo "$result" | tee -a $LOG_FILE
        echo "----------------------------------------" | tee -a $LOG_FILE
    else
        echo "[$TIMESTAMP] $rule_name - No threats detected" | tee -a $LOG_FILE
    fi
}

# Create manual queries since sigma conversion might need adjustment
echo "SELECT pid, name, path, cmdline FROM processes WHERE name IN ('nc', 'netcat', 'ncat', 'socat', 'wget', 'curl') AND (cmdline LIKE '%/tmp/%' OR cmdline LIKE '%/dev/shm/%' OR cmdline LIKE '%bash -i%' OR cmdline LIKE '%sh -i%');" > $HUNT_DIR/process_hunt.sql

echo "SELECT pid, name, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE remote_port IN (4444, 5555, 6666, 7777, 8888, 9999) AND state = 'ESTABLISHED';" > $HUNT_DIR/network_hunt.sql

# Run hunt queries
run_hunt_query "$HUNT_DIR/process_hunt.sql" "Suspicious Process Hunt"
run_hunt_query "$HUNT_DIR/network_hunt.sql" "Suspicious Network Hunt"

echo "[$TIMESTAMP] Hunt completed. Results logged to $LOG_FILE" | tee -a $LOG_FILE
