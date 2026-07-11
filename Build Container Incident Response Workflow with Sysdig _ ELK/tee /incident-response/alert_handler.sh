#!/bin/bash

ALERT_THRESHOLD=5
LOG_FILE="/var/log/falco/events.log"
ALERT_LOG="/var/log/incident-alerts.log"

# Function to send alert
send_alert() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] SECURITY ALERT: $message" | tee -a "$ALERT_LOG"
    
    # In production, this could send to Slack, email, or SIEM
    logger "CONTAINER_SECURITY_ALERT: $message"
}

# Function to analyze recent events
analyze_events() {
    local recent_events=$(tail -100 "$LOG_FILE" | grep -c "WARNING\|ERROR")
    
    if [ "$recent_events" -gt "$ALERT_THRESHOLD" ]; then
        send_alert "High number of security events detected: $recent_events events in last 100 log entries"
    fi
}

# Function to check for specific threats
check_threats() {
    local privilege_escalation=$(tail -50 "$LOG_FILE" | grep -c "privilege escalation")
    local suspicious_network=$(tail -50 "$LOG_FILE" | grep -c "Suspicious network")
    local file_modification=$(tail -50 "$LOG_FILE" | grep -c "file modification")
    
    if [ "$privilege_escalation" -gt 0 ]; then
        send_alert "Privilege escalation detected in containers"
    fi
    
    if [ "$suspicious_network" -gt 0 ]; then
        send_alert "Suspicious network activity detected in containers"
    fi
    
    if [ "$file_modification" -gt 0 ]; then
        send_alert "Unauthorized file modifications detected in containers"
    fi
}

# Main execution
main() {
    if [ -f "$LOG_FILE" ]; then
        analyze_events
        check_threats
    else
        echo "Falco log file not found: $LOG_FILE"
        exit 1
    fi
}

main "$@"
