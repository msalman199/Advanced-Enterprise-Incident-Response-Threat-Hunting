#!/usr/bin/env python3
import json
import requests
import datetime

def create_high_severity_event():
    event = {
        "@timestamp": datetime.datetime.now().isoformat(),
        "source_ip": "192.168.1.100",
        "destination_ip": "192.168.1.10",
        "source_port": 12345,
        "destination_port": 80,
        "protocol": "TCP",
        "action": "blocked",
        "severity": "high",
        "event_type": "web_attack",
        "user_agent": "sqlmap/1.0",
        "url": "/admin/login.php",
        "status_code": 403,
        "threat_score": 95
    }
    
    url = "http://localhost:9200/security-logs-2024/_doc"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=event, headers=headers)
    return response.status_code == 201

# Create multiple high-severity events
for i in range(5):
    if create_high_severity_event():
        print(f"High-severity event {i+1} created")
    else:
        print(f"Failed to create event {i+1}")

print("Test events generated. Check alerts.log for notifications.")
