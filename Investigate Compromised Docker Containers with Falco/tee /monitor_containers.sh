#!/bin/bash

echo "Starting container monitoring..."
echo "Falco Events Log:"
echo "=================="

# Monitor Falco events in real-time
tail -f /var/log/falco_events.log | while read line; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $line"
done &

MONITOR_PID=$!

# Function to stop monitoring
cleanup() {
    echo "Stopping monitoring..."
    kill $MONITOR_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "Monitoring active. Press Ctrl+C to stop."
wait $MONITOR_PID
