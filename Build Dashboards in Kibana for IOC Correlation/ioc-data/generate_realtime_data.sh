#!/bin/bash

while true; do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    IOC_TYPES=("hash" "ip" "domain" "url")
    SEVERITIES=("low" "medium" "high" "critical")
    ACTIONS=("blocked" "monitored" "quarantined" "allowed")
    
    IOC_TYPE=${IOC_TYPES[$RANDOM % ${#IOC_TYPES[@]}]}
    SEVERITY=${SEVERITIES[$RANDOM % ${#SEVERITIES[@]}]}
    ACTION=${ACTIONS[$RANDOM % ${#ACTIONS[@]}]}
    SOURCE_IP="192.168.1.$((RANDOM % 254 + 1))"
    DEST_IP="10.0.0.$((RANDOM % 254 + 1))"
    
    case $IOC_TYPE in
        "hash")
            IOC_VALUE=$(echo -n "sample_file_$RANDOM" | md5sum | cut -d' ' -f1)
            EVENT_TYPE="malware_detection"
            ;;
        "ip")
            IOC_VALUE="203.0.113.$((RANDOM % 254 + 1))"
            EVENT_TYPE="ip_reputation"
            ;;
        "domain")
            IOC_VALUE="suspicious-domain-$RANDOM.com"
            EVENT_TYPE="suspicious_domain"
            ;;
        "url")
            IOC_VALUE="http://malicious-site-$RANDOM.net/payload"
            EVENT_TYPE="url_analysis"
            ;;
    esac
    
    echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"$EVENT_TYPE\",\"ioc_type\":\"$IOC_TYPE\",\"ioc_value\":\"$IOC_VALUE\",\"severity\":\"$SEVERITY\",\"source_ip\":\"$SOURCE_IP\",\"destination_ip\":\"$DEST_IP\",\"action\":\"$ACTION\"}" >> ~/ioc-data/realtime_ioc_events.json
    
    sleep 30
done
