#!/bin/bash
echo "Starting real-time privilege escalation monitoring..."
echo "Press Ctrl+C to stop"

tail -f /var/log/auth.log | while read line; do
    if echo "$line" | grep -q -E "(sudo|Failed|usermod)"; then
        echo "[ALERT] $(date): $line"
    fi
done
