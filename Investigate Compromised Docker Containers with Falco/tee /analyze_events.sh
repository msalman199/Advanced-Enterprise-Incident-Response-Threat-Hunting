#!/bin/bash

echo "Container Security Event Analysis"
echo "================================="

# Check if Falco events log exists
if [ ! -f /var/log/falco_events.log ]; then
    echo "Falco events log not found. Creating sample events..."
    sudo touch /var/log/falco_events.log
fi

# Analyze recent events
echo "Recent Security Events (Last 50 lines):"
echo "----------------------------------------"
sudo tail -50 /var/log/falco_events.log | grep -E "(WARNING|CRITICAL|ERROR)" || echo "No critical events found in recent logs"

echo ""
echo "Container-specific Events:"
echo "-------------------------"
sudo grep -i "container" /var/log/falco_events.log | tail -20 || echo "No container events found"

echo ""
echo "Privilege Escalation Events:"
echo "----------------------------"
sudo grep -i "privilege" /var/log/falco_events.log | tail -10 || echo "No privilege escalation events found"

echo ""
echo "Network Activity Events:"
echo "------------------------"
sudo grep -i "network\|connection" /var/log/falco_events.log | tail -10 || echo "No network events found"

echo ""
echo "File Access Events:"
echo "------------------"
sudo grep -i "file.*access\|sensitive" /var/log/falco_events.log | tail -10 || echo "No file access events found"

# Container runtime analysis
echo ""
echo "Current Container Status:"
echo "------------------------"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"

echo ""
echo "Container Resource Usage:"
echo "------------------------"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
