#!/bin/bash

echo "=== Linux Forensic Triage Kit ==="
echo "Starting automated analysis..."

# Create analysis directory
mkdir -p /tmp/triage_$(date +%Y%m%d_%H%M%S)
cd /tmp/triage_$(date +%Y%m%d_%H%M%S)

# Collect system information
echo "Collecting system information..."
uname -a > system_info.txt
ps aux > running_processes.txt
netstat -tulpn > network_connections.txt
last -n 50 > recent_logins.txt

# Export recent audit events
echo "Exporting audit events..."
sudo ausearch --start today > audit_today.txt
sudo ausearch -k exec --start today > exec_events.txt
sudo ausearch -k network --start today > network_events.txt

# Create quick timeline
echo "Creating timeline..."
sudo log2timeline.py --storage-file quick_timeline.plaso /var/log/auth.log /var/log/syslog 2>/dev/null
psort.py -o l2tcsv -w quick_timeline.csv quick_timeline.plaso 2>/dev/null

echo "Triage complete. Results in: $(pwd)"
ls -la
