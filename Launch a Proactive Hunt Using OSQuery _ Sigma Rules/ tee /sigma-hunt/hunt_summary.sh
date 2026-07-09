#!/bin/bash

HUNT_DIR="$HOME/sigma-hunt"
REPORT_FILE="$HUNT_DIR/hunt_report.txt"

echo "=== PROACTIVE THREAT HUNT REPORT ===" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== SYSTEM OVERVIEW ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT hostname, cpu_brand, physical_memory FROM system_info;" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== ACTIVE PROCESSES SUMMARY ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT COUNT(*) as total_processes FROM processes;" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== NETWORK CONNECTIONS SUMMARY ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT COUNT(*) as active_connections FROM process_open_sockets WHERE state = 'ESTABLISHED';" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== HUNT RESULTS ===" >> $REPORT_FILE
if [ -f "$HUNT_DIR/hunt_results.log" ]; then
    cat "$HUNT_DIR/hunt_results.log" >> $REPORT_FILE
else
    echo "No hunt results available" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== RECOMMENDATIONS ===" >> $REPORT_FILE
echo "1. Review any ALERT entries in the hunt results" >> $REPORT_FILE
echo "2. Investigate suspicious processes or network connections" >> $REPORT_FILE
echo "3. Consider implementing additional Sigma rules for your environment" >> $REPORT_FILE
echo "4. Schedule regular proactive hunts using the provided scripts" >> $REPORT_FILE

echo "Report generated: $REPORT_FILE"
