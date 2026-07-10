#!/usr/bin/env python3
import json
import random
import datetime
import requests
from time import sleep

# Malicious IPs and patterns for realistic threat simulation
malicious_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10"]
suspicious_user_agents = [
    "sqlmap/1.0",
    "Nikto/2.1.6",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.25.1"
]
attack_urls = [
    "/admin/login.php",
    "/wp-admin/admin-ajax.php",
    "/etc/passwd",
    "/../../../etc/shadow",
    "/phpMyAdmin/",
    "/shell.php"
]

def generate_security_event():
    event_types = ["web_attack", "port_scan", "brute_force", "malware_download", "normal_traffic"]
    event_type = random.choice(event_types)
    
    base_event = {
        "@timestamp": datetime.datetime.now().isoformat(),
        "source_ip": random.choice(malicious_ips) if event_type != "normal_traffic" else f"192.168.1.{random.randint(1,254)}",
        "destination_ip": "192.168.1.10",
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 22, 21, 3389]),
        "protocol": random.choice(["TCP", "UDP"]),
        "event_type": event_type
    }
    
    if event_type == "web_attack":
        base_event.update({
            "action": "blocked",
            "severity": "high",
            "user_agent": random.choice(suspicious_user_agents),
            "url": random.choice(attack_urls),
            "status_code": random.choice([403, 404, 500]),
            "threat_score": random.randint(80, 100)
        })
    elif event_type == "port_scan":
        base_event.update({
            "action": "detected",
            "severity": "medium",
            "threat_score": random.randint(60, 80)
        })
    elif event_type == "brute_force":
        base_event.update({
            "action": "blocked",
            "severity": "high",
            "url": "/login",
            "status_code": 401,
            "threat_score": random.randint(70, 90)
        })
    else:
        base_event.update({
            "action": "allowed",
            "severity": "low",
            "status_code": 200,
            "threat_score": random.randint(1, 30)
        })
    
    return base_event

def send_to_elasticsearch(event):
    url = "http://localhost:9200/security-logs-2024/_doc"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=event, headers=headers)
    return response.status_code == 201

# Generate and send events
for i in range(100):
    event = generate_security_event()
    if send_to_elasticsearch(event):
        print(f"Event {i+1} sent successfully")
    else:
        print(f"Failed to send event {i+1}")
    sleep(0.1)

print("Sample data generation completed!")
