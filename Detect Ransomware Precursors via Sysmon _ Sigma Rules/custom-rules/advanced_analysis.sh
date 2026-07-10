#!/bin/bash
echo "=== Advanced Sysmon Log Analysis ==="

# Count events by type
echo "Event Distribution:"
sudo journalctl -u sysmon --no-pager | grep -o 'EventID=[0-9]*' | sort | uniq -c | sort -nr

# Look for rapid file modifications
echo -e "\nRapid File Modifications (potential encryption):"
sudo journalctl -u sysmon --since "5 minutes ago" | grep "EventID=11" | wc -l

# Check for network connections during file activity
echo -e "\nNetwork Connections:"
sudo journalctl -u sysmon --since "5 minutes ago" | grep "EventID=3" | head -5

# Timeline of recent activities
echo -e "\nRecent Activity Timeline:"
sudo journalctl -u sysmon --since "5 minutes ago" --no-pager | tail -10
