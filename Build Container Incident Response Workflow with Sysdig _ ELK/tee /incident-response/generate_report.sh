#!/bin/bash

REPORT_FILE="/tmp/incident_report_$(date +%Y%m%d_%H%M%S).txt"

echo "Container Security Incident Report" > "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"
echo "=================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Security events summary
echo "SECURITY EVENTS SUMMARY:" >> "$REPORT_FILE"
echo "------------------------" >> "$REPORT_FILE"
if [ -f "/var/log/falco/events.log" ]; then
    echo "Total events: $(wc -l < /var/log/falco/events.log)" >> "$REPORT_FILE"
    echo "Warning events: $(grep -c 'WARNING' /var/log/falco/events.log 2>/dev/null || echo 0)" >> "$REPORT_FILE"
    echo "Error events: $(grep -c 'ERROR' /var/log/falco/events.log 2>/dev/null || echo 0)" >> "$REPORT_FILE"
else
    echo "No Falco events log found" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Container status
echo "CONTAINER STATUS:" >> "$REPORT_FILE"
echo "-----------------" >> "$REPORT_FILE"
docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Recent alerts
echo "RECENT ALERTS:" >> "$REPORT_FILE"
echo "--------------" >> "$REPORT_FILE"
if [ -f "/var/log/incident-alerts.log" ]; then
    tail -10 /var/log/incident-alerts.log >> "$REPORT_FILE"
else
    echo "No alerts generated" >> "$REPORT_FILE"
fi
echo "" >> "$REPORT_FILE"

# Forensic data
echo "FORENSIC DATA COLLECTED:" >> "$REPORT_FILE"
echo "------------------------" >> "$REPORT_FILE"
ls -la /tmp/forensics_* 2>/dev/null >> "$REPORT_FILE" || echo "No forensic data collected" >> "$REPORT_FILE"

echo "Report generated: $REPORT_FILE"
cat "$REPORT_FILE"
