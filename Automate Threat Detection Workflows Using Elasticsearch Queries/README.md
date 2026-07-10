<div align="center">

# 🚨 Automate Threat Detection Workflows Using Elasticsearch Queries

### Advanced Query Automation & Real-Time Alerting Lab

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=for-the-badge&logo=kibana&logoColor=white)
![ElastAlert2](https://img.shields.io/badge/ElastAlert2-Automated_Alerts-FF6F00?style=for-the-badge&logo=elastic&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![REST API](https://img.shields.io/badge/REST_API-005571?style=for-the-badge&logo=fastapi&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)
![Threat Detection](https://img.shields.io/badge/Threat-Detection-DC143C?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![SOC](https://img.shields.io/badge/SOC-Automation-32CD32?style=for-the-badge&logo=elastic&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📚 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Install and Configure Elasticsearch Stack](#️-task-1-install-and-configure-elasticsearch-stack)
- [🧪 Task 2: Create Sample Security Data and Indices](#-task-2-create-sample-security-data-and-indices)
- [🔎 Task 3: Create Advanced Threat Detection Queries](#-task-3-create-advanced-threat-detection-queries)
- [🔔 Task 4: Set Up Automated Alerts and Workflows](#-task-4-set-up-automated-alerts-and-workflows)
- [🧫 Task 5: Test and Refine Detection Workflows](#-task-5-test-and-refine-detection-workflows)
- [🗺️ Task 6: Create Advanced Detection Queries](#️-task-6-create-advanced-detection-queries)
- [✅ Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧩 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | 🔍 Create and automate advanced Elasticsearch queries for threat detection |
| 2 | 🔔 Configure automated alerts for security threats |
| 3 | 🧪 Build and test complete threat detection workflows |
| 4 | 📡 Implement real-time monitoring using Elasticsearch and Kibana |

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic understanding of Linux command line |
| 🧾 JSON Format | Familiarity with JSON format |
| 🛡️ Security Concepts | Basic knowledge of logs, threats, and indicators |
| 🌐 REST APIs | Understanding of HTTP requests and REST APIs |

---

## 🖥️ Lab Environment

> ☁️ **Al Nafi** provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated Linux machine. The provided machine is bare metal with no pre-installed tools — all required components are installed during the lab.

---

## ⚙️ Task 1: Install and Configure Elasticsearch Stack

### ☕ Subtask 1.1: Install Java and Elasticsearch

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# ☕ Install Java 11 (required for Elasticsearch)
sudo apt install openjdk-11-jdk -y

# ✅ Verify Java installation
java -version

# 📥 Download and install Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-amd64.deb
sudo dpkg -i elasticsearch-8.11.0-amd64.deb

# ⚙️ Configure Elasticsearch for single-node setup
sudo nano /etc/elasticsearch/elasticsearch.yml
```

📝 Add these configurations to `elasticsearch.yml`:
```yaml
cluster.name: threat-detection-cluster
node.name: node-1
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
```

```bash
# TODO: Re-enable xpack.security for any non-isolated lab or production deployment
```

### 📊 Subtask 1.2: Install Kibana

```bash
# 📥 Download and install Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-amd64.deb
sudo dpkg -i kibana-8.11.0-amd64.deb

# ⚙️ Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

📝 Add these configurations to `kibana.yml`:
```yaml
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# TODO: Confirm Kibana version 8.11.0 matches installed Elasticsearch version exactly
```

### ▶️ Subtask 1.3: Start Services

```bash
# 🟢 Enable and start Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# 🟢 Enable and start Kibana
sudo systemctl enable kibana
sudo systemctl start kibana

# 🩺 Verify services are running
sudo systemctl status elasticsearch
sudo systemctl status kibana

# ✅ Test Elasticsearch connection
curl -X GET "localhost:9200/"

# TODO: Add a startup delay/retry loop before the first curl check
```

---

## 🧪 Task 2: Create Sample Security Data and Indices

### 🗂️ Subtask 2.1: Create Security Log Index

```bash
# 📐 Create index template for security logs
curl -X PUT "localhost:9200/_index_template/security-logs" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["security-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "source_ip": {"type": "ip"},
        "destination_ip": {"type": "ip"},
        "source_port": {"type": "integer"},
        "destination_port": {"type": "integer"},
        "protocol": {"type": "keyword"},
        "action": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "event_type": {"type": "keyword"},
        "user_agent": {"type": "text"},
        "url": {"type": "keyword"},
        "status_code": {"type": "integer"},
        "bytes_transferred": {"type": "long"},
        "country": {"type": "keyword"},
        "threat_score": {"type": "integer"}
      }
    }
  }
}'

# TODO: Add an ILM policy to roll over security-logs-* indices after 30 days
```

### 🎲 Subtask 2.2: Generate Sample Threat Data

> 💡 Create a script to generate sample security events:

```python
#!/usr/bin/env python3
# 🧬 generate_security_data.py — Synthetic Security Event Generator
import json
import random
import datetime
import requests
from time import sleep

# 🚩 Malicious IPs and patterns for realistic threat simulation
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

# 🚀 Generate and send events
for i in range(100):
    event = generate_security_event()
    if send_to_elasticsearch(event):
        print(f"Event {i+1} sent successfully")
    else:
        print(f"Failed to send event {i+1}")
    sleep(0.1)

print("Sample data generation completed!")

# TODO: Add a --count CLI argument instead of hardcoding 100 events
```

```bash
# 🐍 Install Python requests library
sudo apt install python3-pip -y
pip3 install requests

# ▶️ Run the data generation script
python3 generate_security_data.py
```

---

## 🔎 Task 3: Create Advanced Threat Detection Queries

### 🚨 Subtask 3.1: Create High-Severity Threat Detection Query

```bash
# 🔴 Create query for high-severity threats
curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"severity": "high"}},
        {"range": {"threat_score": {"gte": 70}}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}],
  "size": 10
}'

# TODO: Parameterize the threat_score threshold for tuning per environment
```

### 🔑 Subtask 3.2: Create Brute Force Attack Detection Query

```bash
# 🔓 Query to detect brute force attacks
curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-5m"}}},
        {"term": {"event_type": "brute_force"}},
        {"term": {"status_code": 401}}
      ]
    }
  },
  "aggs": {
    "attacks_by_ip": {
      "terms": {
        "field": "source_ip",
        "size": 10
      },
      "aggs": {
        "attack_count": {
          "value_count": {
            "field": "source_ip"
          }
        }
      }
    }
  }
}'
```

### 🕵️ Subtask 3.3: Create Suspicious User Agent Detection Query

```bash
# 🎭 Query to detect suspicious user agents
curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "should": [
        {"wildcard": {"user_agent": "*sqlmap*"}},
        {"wildcard": {"user_agent": "*Nikto*"}},
        {"wildcard": {"user_agent": "*Nmap*"}},
        {"wildcard": {"user_agent": "*python-requests*"}}
      ],
      "minimum_should_match": 1,
      "filter": [
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}]
}'

# TODO: Extend wildcard list with additional known scanner/tool user agents
```

---

## 🔔 Task 4: Set Up Automated Alerts and Workflows

### 🧰 Subtask 4.1: Install and Configure Elastalert

```bash
# 📥 Install Elastalert2 (modern version)
pip3 install elastalert2

# 📁 Create Elastalert configuration directory
mkdir -p /home/$USER/elastalert
cd /home/$USER/elastalert

# ⚙️ Create main configuration file
cat > config.yaml << 'EOF'
rules_folder: rules
run_every:
  minutes: 1
buffer_time:
  minutes: 15
es_host: localhost
es_port: 9200
writeback_index: elastalert_status
writeback_alias: elastalert_alerts
alert_time_limit:
  days: 2
EOF

# TODO: Move es_host/es_port into environment variables for portability
```

### 📏 Subtask 4.2: Create Threat Detection Rules

```bash
# 📁 Create directory for rules
mkdir -p rules
```

📝 Create high-severity threat alert rule:
```yaml
# rules/high_severity_threats.yaml
name: High Severity Threat Detection
type: frequency
index: security-logs-*
num_events: 1
timeframe:
  minutes: 5

filter:
- bool:
    must:
    - term:
        severity: "high"
    - range:
        threat_score:
          gte: 80

alert:
- "email"
- "debug"

email:
- "security@company.com"

alert_text: |
  High severity threat detected!

  Event Type: {0}
  Source IP: {1}
  Threat Score: {2}
  Timestamp: {3}

alert_text_args:
  - event_type
  - source_ip
  - threat_score
  - "@timestamp"

include:
  - source_ip
  - destination_ip
  - event_type
  - severity
  - threat_score
  - action
```

📝 Create brute force detection rule:
```yaml
# rules/brute_force_detection.yaml
name: Brute Force Attack Detection
type: frequency
index: security-logs-*
num_events: 3
timeframe:
  minutes: 5

filter:
- bool:
    must:
    - term:
        event_type: "brute_force"
    - term:
        status_code: 401

query_key: source_ip

alert:
- "debug"

alert_text: |
  Brute force attack detected!

  Source IP: {0}
  Number of attempts: {1}
  Time window: 5 minutes

alert_text_args:
  - source_ip
  - num_matches

include:
  - source_ip
  - destination_ip
  - url
  - status_code
  - "@timestamp"
```

```bash
# TODO: Replace the placeholder security@company.com with the lab tenant's real alerting address
```

### 🧾 Subtask 4.3: Create Custom Alert Script

```python
#!/usr/bin/env python3
# 📣 custom_alert.py — Custom Alert Handler
import json
import sys
import datetime
import subprocess

def send_alert(alert_data):
    """Process and send custom alerts"""

    rule_name = alert_data.get('rule_name', 'Unknown Rule')
    num_matches = alert_data.get('num_matches', 0)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert_message = f"""
    SECURITY ALERT - {timestamp}
    ================================
    Rule: {rule_name}
    Matches: {num_matches}

    Event Details:
    """

    for match in alert_data.get('matches', []):
        alert_message += f"""
    - Source IP: {match.get('source_ip', 'N/A')}
    - Event Type: {match.get('event_type', 'N/A')}
    - Severity: {match.get('severity', 'N/A')}
    - Threat Score: {match.get('threat_score', 'N/A')}
    - Timestamp: {match.get('@timestamp', 'N/A')}
    """

    with open('/home/' + subprocess.getoutput('whoami') + '/elastalert/alerts.log', 'a') as f:
        f.write(alert_message + "\n" + "="*50 + "\n")

    print(f"Alert processed: {rule_name}")
    return True

if __name__ == "__main__":
    alert_data = json.loads(sys.stdin.read())
    send_alert(alert_data)

# TODO: Add structured JSON logging in addition to the plain-text alerts.log
```

```bash
chmod +x custom_alert.py
```

---

## 🧫 Task 5: Test and Refine Detection Workflows

### ⚡ Subtask 5.1: Initialize Elastalert

```bash
# 🏗️ Create Elastalert index
elastalert-create-index

# 🧪 Test configuration
elastalert-test-rule rules/high_severity_threats.yaml

# TODO: Add a second `elastalert-test-rule` pass for brute_force_detection.yaml
```

### 🔁 Subtask 5.2: Run Elastalert in Background

```bash
# ▶️ Start Elastalert
nohup elastalert --config config.yaml --verbose > elastalert.log 2>&1 &

# 🔍 Check if Elastalert is running
ps aux | grep elastalert

# TODO: Wrap this in a systemd service for automatic restart on failure
```

### 🎯 Subtask 5.3: Generate Test Threats and Verify Alerts

```python
#!/usr/bin/env python3
# 🧨 trigger_alerts.py — High-Severity Event Trigger
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

# 🚀 Create multiple high-severity events
for i in range(5):
    if create_high_severity_event():
        print(f"High-severity event {i+1} created")
    else:
        print(f"Failed to create event {i+1}")

print("Test events generated. Check alerts.log for notifications.")

# TODO: Add a brute-force burst trigger (3+ events within timeframe) to test that rule too
```

```bash
python3 trigger_alerts.py
```

### 📡 Subtask 5.4: Monitor and Verify Alerts

```bash
# 📄 Check alert logs
tail -f alerts.log

# 🩺 Check Elastalert status
curl -X GET "localhost:9200/elastalert_status/_search?pretty"

# 🔍 View recent security events
curl -X GET "localhost:9200/security-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-10m"
      }
    }
  },
  "sort": [{"@timestamp": {"order": "desc"}}],
  "size": 5
}'
```

### 📊 Subtask 5.5: Access Kibana Dashboard

```bash
# 🌐 Check if Kibana is accessible
curl -I http://localhost:5601

echo "Access Kibana at: http://localhost:5601"
echo "Create index pattern: security-logs-*"
echo "Time field: @timestamp"

# TODO: Save the security-logs-* index pattern via API like in the Kibana dashboard lab
```

---

## 🗺️ Task 6: Create Advanced Detection Queries

### 🌍 Subtask 6.1: Geographic Anomaly Detection

```bash
# 🗺️ Query for geographic anomalies (multiple countries from same IP)
curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "ips_with_multiple_countries": {
      "terms": {
        "field": "source_ip",
        "size": 100
      },
      "aggs": {
        "countries": {
          "terms": {
            "field": "country",
            "size": 10
          }
        },
        "country_count": {
          "cardinality": {
            "field": "country"
          }
        },
        "multiple_countries": {
          "bucket_selector": {
            "buckets_path": {
              "country_count": "country_count"
            },
            "script": "params.country_count > 1"
          }
        }
      }
    }
  }
}'

# TODO: Populate the "country" field via GeoIP enrichment for realistic results
```

### 🕒 Subtask 6.2: Time-Based Anomaly Detection

```bash
# ⏰ Query for unusual activity patterns (high activity during off-hours)
curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "activity_by_hour": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "hour"
      },
      "aggs": {
        "event_count": {
          "value_count": {
            "field": "@timestamp"
          }
        },
        "high_severity_events": {
          "filter": {
            "term": {
              "severity": "high"
            }
          }
        }
      }
    }
  }
}'

# TODO: Add a bucket_selector to flag hours exceeding a baseline event-count threshold
```

---

## ✅ Verification and Testing

```bash
# 1️⃣ Verify Elasticsearch is running and has data
curl -X GET "localhost:9200/security-logs-*/_count"

# 2️⃣ Check Elastalert is processing rules
ps aux | grep elastalert

# 3️⃣ Verify alerts are being generated
ls -la alerts.log
tail -5 alerts.log

# 4️⃣ Test query performance
time curl -X GET "localhost:9200/security-logs-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"term": {"severity": "high"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}'

echo "Threat detection workflow verification completed!"

# TODO: Capture query latency in a log file to track performance regressions over time
```

**✔️ Expected Result:** The `security-logs-*` index shows a nonzero document count, the Elastalert process appears in `ps aux`, `alerts.log` contains recent entries, and the high-severity search returns matching results with low query latency.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Artifact |
|---|---|---|---|
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance | Suspicious user agent (Nikto/Nmap) detection query |
| T1190 | Exploit Public-Facing Application | Initial Access | `web_attack` events targeting `/admin`, `/wp-admin`, `/phpMyAdmin` |
| T1110 | Brute Force | Credential Access | `brute_force` event type / status code 401 frequency rule |
| T1595.001 | Active Scanning: IP Blocks | Reconnaissance | Port scan (`port_scan`) event detection |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Malicious source IP correlation across HTTP(S) ports |
| T1036 | Masquerading | Defense Evasion | Suspicious user agent spoofing (e.g. `python-requests`) |

---

## 🧩 Troubleshooting

<details>
<summary>❗ Elasticsearch package fails to install with dpkg</summary>

- Confirm the `.deb` package downloaded fully: `ls -lh elasticsearch-8.11.0-amd64.deb`
- Retry with `sudo dpkg -i elasticsearch-8.11.0-amd64.deb` and resolve dependencies via `sudo apt -f install`
- Verify Java 11 is installed before attempting install

</details>

<details>
<summary>❗ generate_security_data.py fails to connect</summary>

- Confirm Elasticsearch is running: `curl -X GET "localhost:9200/"`
- Verify `python3-pip` and `requests` are installed: `pip3 show requests`
- Check the index template was created successfully in Subtask 2.1

</details>

<details>
<summary>❗ Elastalert fails to start or exits immediately</summary>

- Confirm `elastalert-create-index` was run before starting the service
- Check `elastalert.log` for configuration or connection errors
- Verify `config.yaml` `es_host`/`es_port` values match your Elasticsearch instance

</details>

<details>
<summary>❗ No alerts appear in alerts.log</summary>

- Confirm Elastalert is actually running: `ps aux | grep elastalert`
- Verify rule filters match your generated data's field values exactly (e.g. `severity: "high"`)
- Re-run `trigger_alerts.py` to generate fresh matching events within the rule's timeframe

</details>

<details>
<summary>❗ Kibana index pattern shows no data</summary>

- Confirm `security-logs-*` documents exist: `curl -X GET "localhost:9200/security-logs-*/_count"`
- Ensure the time field is set to `@timestamp` when creating the index pattern
- Check the Kibana time range picker isn't excluding your generated event timestamps

</details>

---

## 🏁 Conclusion

You have successfully created an automated threat detection system using Elasticsearch. This lab covered:

**🎯 Key Accomplishments**
- 🛠️ **Stack Deployment** — Installed and configured the Elasticsearch stack for security monitoring
- 🔎 **Advanced Queries** — Created queries for detecting brute force, web attacks, port scans, and suspicious user agents
- 🔔 **Automated Alerting** — Implemented real-time alerting using Elastalert2 for immediate threat response
- 🧪 **Workflow Testing** — Tested and refined detection workflows with realistic, generated security data

**🌍 Real-World Applications**
- 🕵️ **SOC Operations** — Real-time monitoring capabilities essential for modern Security Operations Centers
- 🚨 **Threat Hunting** — Query patterns directly applicable to proactive threat hunting activities
- 📈 **Enterprise Security** — Robust foundation for scalable, automated incident response workflows
- 🔗 **Query + Alerting Synergy** — Combining Elasticsearch's search power with automated alerting for proactive detection

---

<div align="center">

### 🏢 Al Nafi Cloud Security Training Platform

**Blue Team / Threat Intelligence & Digital Forensics Track**

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1E90FF?style=for-the-badge)

</div>
