#!/bin/bash
echo "=== ATTACK TIMELINE ANALYSIS ==="

# Get current date for filtering
TODAY=$(date +"%b %d")

echo "Timeline of security events for $TODAY:"
{
    sudo grep "$TODAY" /var/log/auth.log | grep -E "(Failed|sudo|su):"
    sudo grep "$TODAY" /var/log/syslog | grep -E "(usermod|useradd|sudo)"
} | sort -k3 -M -k4 -n | tail -10
