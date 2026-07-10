<div align="center">

# 📊 Build Dashboards in Kibana for IOC Correlation

### ELK Stack Deployment & Real-Time Threat Visualization Lab

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Logstash](https://img.shields.io/badge/Logstash-005571?style=for-the-badge&logo=logstash&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-005571?style=for-the-badge&logo=kibana&logoColor=white)
![ELK Stack](https://img.shields.io/badge/ELK_Stack-Deployed-F04E98?style=for-the-badge&logo=elastic&logoColor=white)
![Java](https://img.shields.io/badge/Java_11-007396?style=for-the-badge&logo=openjdk&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-000000?style=for-the-badge&logo=json&logoColor=white)
![IOC Correlation](https://img.shields.io/badge/IOC-Correlation-FF4500?style=for-the-badge&logo=elastic&logoColor=white)
![Threat Detection](https://img.shields.io/badge/Threat-Detection-DC143C?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📚 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Install and Configure ELK Stack](#️-task-1-install-and-configure-elk-stack)
- [🧪 Task 2: Create Sample IOC Data](#-task-2-create-sample-ioc-data)
- [📈 Task 3: Create Custom Kibana Dashboards](#-task-3-create-custom-kibana-dashboards)
- [🔎 Task 4: Configure IOC Correlation Queries](#-task-4-configure-ioc-correlation-queries)
- [⏱️ Task 5: Real-Time Monitoring Setup](#️-task-5-real-time-monitoring-setup)
- [✅ Task 6: Verify Dashboard Functionality](#-task-6-verify-dashboard-functionality)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧩 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | 🛠️ Install and configure the ELK stack (Elasticsearch, Logstash, Kibana) on a single Linux machine |
| 2 | 📊 Create custom Kibana dashboards for IOC (Indicators of Compromise) visualization |
| 3 | 🔗 Configure queries to correlate security events and IOCs |
| 4 | 📡 Build real-time monitoring visualizations for threat detection |

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command-line knowledge |
| 📜 Log Analysis | Understanding of log analysis concepts |
| 🧾 JSON Format | Familiarity with JSON data format |
| 🛡️ Cybersecurity Basics | Basic concepts of IOCs and threat indicators |

---

## 🖥️ Lab Environment

> ☁️ **Al Nafi** provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — all required components are installed during the lab.

---

## ⚙️ Task 1: Install and Configure ELK Stack

### ☕ Subtask 1.1: Install Java and System Dependencies

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# ☕ Install Java 11 (required for Elasticsearch)
sudo apt install openjdk-11-jdk curl wget gnupg2 -y

# ✅ Verify Java installation
java -version

# TODO: Pin Java version in CI to avoid future Elasticsearch compatibility breaks
```

### 🔍 Subtask 1.2: Install Elasticsearch

```bash
# 🌐 Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# 📥 Install Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# ⚙️ Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

📝 Add these configurations to the file:
```yaml
network.host: localhost
http.port: 9200
discovery.type: single-node
```

```bash
# ▶️ Start and enable Elasticsearch
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

# ✅ Verify Elasticsearch is running
curl -X GET "localhost:9200/"

# TODO: Enable authentication/TLS before using outside an isolated lab network
```

### 📊 Subtask 1.3: Install Kibana

```bash
# 📥 Install Kibana
sudo apt install kibana -y

# ⚙️ Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

📝 Add these configurations:
```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# ▶️ Start and enable Kibana
sudo systemctl start kibana
sudo systemctl enable kibana

# ⏳ Wait for Kibana to start (takes 2-3 minutes)
sleep 180

# TODO: Restrict server.host binding once lab moves beyond localhost testing
```

### 🔄 Subtask 1.4: Install Logstash

```bash
# 📥 Install Logstash
sudo apt install logstash -y

# ▶️ Start and enable Logstash
sudo systemctl start logstash
sudo systemctl enable logstash

# TODO: Verify logstash service status with `systemctl status logstash`
```

---

## 🧪 Task 2: Create Sample IOC Data

### 🗃️ Subtask 2.1: Generate IOC Sample Data

```bash
# 📁 Create directory for sample data
mkdir ~/ioc-data
cd ~/ioc-data

# 📝 Create sample IOC data file
cat > ioc_events.json << 'EOF'
{"timestamp":"2024-01-15T10:30:00Z","event_type":"malware_detection","ioc_type":"hash","ioc_value":"d41d8cd98f00b204e9800998ecf8427e","severity":"high","source_ip":"192.168.1.100","destination_ip":"10.0.0.50","action":"blocked"}
{"timestamp":"2024-01-15T10:35:00Z","event_type":"suspicious_domain","ioc_type":"domain","ioc_value":"malicious-site.com","severity":"medium","source_ip":"192.168.1.101","destination_ip":"8.8.8.8","action":"monitored"}
{"timestamp":"2024-01-15T10:40:00Z","event_type":"ip_reputation","ioc_type":"ip","ioc_value":"203.0.113.5","severity":"high","source_ip":"192.168.1.102","destination_ip":"203.0.113.5","action":"blocked"}
{"timestamp":"2024-01-15T10:45:00Z","event_type":"file_hash","ioc_type":"hash","ioc_value":"5d41402abc4b2a76b9719d911017c592","severity":"critical","source_ip":"192.168.1.103","destination_ip":"10.0.0.51","action":"quarantined"}
{"timestamp":"2024-01-15T10:50:00Z","event_type":"url_analysis","ioc_type":"url","ioc_value":"http://suspicious-url.net/payload","severity":"medium","source_ip":"192.168.1.104","destination_ip":"198.51.100.10","action":"monitored"}
{"timestamp":"2024-01-15T11:00:00Z","event_type":"malware_detection","ioc_type":"hash","ioc_value":"098f6bcd4621d373cade4e832627b4f6","severity":"high","source_ip":"192.168.1.105","destination_ip":"10.0.0.52","action":"blocked"}
{"timestamp":"2024-01-15T11:05:00Z","event_type":"suspicious_domain","ioc_type":"domain","ioc_value":"phishing-example.org","severity":"critical","source_ip":"192.168.1.106","destination_ip":"8.8.4.4","action":"blocked"}
{"timestamp":"2024-01-15T11:10:00Z","event_type":"ip_reputation","ioc_type":"ip","ioc_value":"198.51.100.25","severity":"medium","source_ip":"192.168.1.107","destination_ip":"198.51.100.25","action":"monitored"}
EOF

# TODO: Expand sample dataset with additional IOC types (email, registry, mutex)
```

### 🔧 Subtask 2.2: Configure Logstash Pipeline

```bash
# ⚙️ Create Logstash configuration
sudo nano /etc/logstash/conf.d/ioc-pipeline.conf
```

📝 Add this configuration:
```ruby
input {
  file {
    path => "/home/*/ioc-data/ioc_events.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "json"
  }
}

filter {
  date {
    match => [ "timestamp", "ISO8601" ]
  }

  mutate {
    add_field => { "correlation_id" => "%{ioc_type}_%{ioc_value}" }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "ioc-events-%{+YYYY.MM.dd}"
  }
}
```

```bash
# 🔄 Restart Logstash to apply configuration
sudo systemctl restart logstash

# ⏳ Wait for data ingestion
sleep 60

# TODO: Add a dead_letter_queue for malformed IOC event handling
```

---

## 📈 Task 3: Create Custom Kibana Dashboards

### 🗂️ Subtask 3.1: Access Kibana and Create Index Pattern

```bash
# 🌐 Check if Kibana is accessible
curl -I http://localhost:5601

echo "Access Kibana at: http://localhost:5601"
echo "Creating index pattern via API..."

# 📌 Create index pattern via API
curl -X POST "localhost:5601/api/saved_objects/index-pattern/ioc-events-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "ioc-events-*",
      "timeFieldName": "timestamp"
    }
  }'

# TODO: Confirm index pattern appears under Stack Management > Index Patterns
```

### 🥧 Subtask 3.2: Create IOC Correlation Visualizations

```bash
# 🥧 Create IOC Type Distribution visualization
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "IOC Type Distribution",
      "visState": "{\"title\":\"IOC Type Distribution\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"ioc_type.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }'

# 📉 Create Severity Timeline visualization
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "IOC Severity Timeline",
      "visState": "{\"title\":\"IOC Severity Timeline\",\"type\":\"histogram\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":\"true\",\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"timestamp\",\"interval\":\"auto\",\"customInterval\":\"2h\",\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"severity.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }'

# TODO: Add a "Top Targeted Destination IPs" bar chart visualization
```

### 🖇️ Subtask 3.3: Create IOC Correlation Dashboard

```bash
# 🖇️ Create the main IOC Correlation Dashboard
curl -X POST "localhost:5601/api/saved_objects/dashboard" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "IOC Correlation Dashboard",
      "hits": 0,
      "description": "Dashboard for correlating and visualizing Indicators of Compromise",
      "panelsJSON": "[{\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15,\"i\":\"1\"},\"panelIndex\":\"1\",\"version\":\"7.17.0\",\"panelRefName\":\"panel_1\"},{\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":15,\"i\":\"2\"},\"panelIndex\":\"2\",\"version\":\"7.17.0\",\"panelRefName\":\"panel_2\"}]",
      "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
      "version": 1,
      "timeRestore": false,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
      }
    },
    "references": [
      {
        "name": "panel_1",
        "type": "visualization",
        "id": "ioc-type-distribution"
      },
      {
        "name": "panel_2",
        "type": "visualization",
        "id": "ioc-severity-timeline"
      }
    ]
  }'

# TODO: Add timeRestore:true with a default 24h window for analyst convenience
```

---

## 🔎 Task 4: Configure IOC Correlation Queries

### 🔍 Subtask 4.1: Create Saved Searches for IOC Correlation

```bash
# 🚨 Create High Severity IOCs search
curl -X POST "localhost:5601/api/saved_objects/search" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "High Severity IOCs",
      "description": "Search for high and critical severity IOCs",
      "hits": 0,
      "columns": ["timestamp", "ioc_type", "ioc_value", "severity", "source_ip", "action"],
      "sort": [["timestamp", "desc"]],
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"highlightAll\":true,\"version\":true,\"query\":{\"query\":\"severity:(high OR critical)\",\"language\":\"kuery\"},\"filter\":[]}"
      }
    }
  }'

# 🌐 Create IOC Correlation by Source IP search
curl -X POST "localhost:5601/api/saved_objects/search" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "IOC Correlation by Source IP",
      "description": "Correlate IOCs by source IP address",
      "hits": 0,
      "columns": ["timestamp", "source_ip", "ioc_type", "ioc_value", "event_type", "action"],
      "sort": [["source_ip.keyword", "asc"], ["timestamp", "desc"]],
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"highlightAll\":true,\"version\":true,\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }'

# TODO: Save a third search scoped to `action:"quarantined"` for containment review
```

### 🌡️ Subtask 4.2: Create Advanced Correlation Visualizations

```bash
# 🌡️ Create Source IP vs IOC Type heatmap
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Source IP vs IOC Type Correlation",
      "visState": "{\"title\":\"Source IP vs IOC Type Correlation\",\"type\":\"heatmap\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"enableHover\":false,\"legendPosition\":\"right\",\"times\":[],\"colorsNumber\":4,\"colorSchema\":\"Yellow to Red\",\"setColorRange\":false,\"colorsRange\":[],\"invertColors\":false,\"percentageMode\":false,\"valueAxes\":[{\"show\":false,\"id\":\"ValueAxis-1\",\"type\":\"value\",\"scale\":{\"type\":\"linear\",\"defaultYExtents\":false},\"labels\":{\"show\":false,\"rotate\":0,\"color\":\"#555\"}}]},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"source_ip.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"ioc_type.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{\"vis\":{\"defaultColors\":{\"0 - 1\":\"rgb(255,245,240)\",\"1 - 2\":\"rgb(254,224,210)\",\"2 - 3\":\"rgb(252,187,161)\",\"3 - 4\":\"rgb(252,146,114)\"}}}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }'

# 🍩 Create Action Response Distribution
curl -X POST "localhost:5601/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "IOC Response Actions",
      "visState": "{\"title\":\"IOC Response Actions\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"action.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\"}}]}",
      "uiStateJSON": "{}",
      "description": "",
      "version": 1,
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"index\":\"ioc-events-*\",\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }'

# TODO: Add drilldown from heatmap cells to the "IOC Correlation by Source IP" search
```

---

## ⏱️ Task 5: Real-Time Monitoring Setup

### 🔁 Subtask 5.1: Configure Auto-Refresh and Alerts

```bash
# 🎲 Create a script to continuously add new IOC data
cat > ~/ioc-data/generate_realtime_data.sh << 'EOF'
#!/bin/bash

while true; do
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    IOC_TYPES=("hash" "ip" "domain" "url")
    SEVERITIES=("low" "medium" "high" "critical")
    ACTIONS=("blocked" "monitored" "quarantined" "allowed")

    IOC_TYPE=${IOC_TYPES[$RANDOM % ${#IOC_TYPES[@]}]}
    SEVERITY=${SEVERITIES[$RANDOM % ${#SEVERITIES[@]}]}
    ACTION=${ACTIONS[$RANDOM % ${#ACTIONS[@]}]}
    SOURCE_IP="192.168.1.$((RANDOM % 254 + 1))"
    DEST_IP="10.0.0.$((RANDOM % 254 + 1))"

    case $IOC_TYPE in
        "hash")
            IOC_VALUE=$(echo -n "sample_file_$RANDOM" | md5sum | cut -d' ' -f1)
            EVENT_TYPE="malware_detection"
            ;;
        "ip")
            IOC_VALUE="203.0.113.$((RANDOM % 254 + 1))"
            EVENT_TYPE="ip_reputation"
            ;;
        "domain")
            IOC_VALUE="suspicious-domain-$RANDOM.com"
            EVENT_TYPE="suspicious_domain"
            ;;
        "url")
            IOC_VALUE="http://malicious-site-$RANDOM.net/payload"
            EVENT_TYPE="url_analysis"
            ;;
    esac

    echo "{\"timestamp\":\"$TIMESTAMP\",\"event_type\":\"$EVENT_TYPE\",\"ioc_type\":\"$IOC_TYPE\",\"ioc_value\":\"$IOC_VALUE\",\"severity\":\"$SEVERITY\",\"source_ip\":\"$SOURCE_IP\",\"destination_ip\":\"$DEST_IP\",\"action\":\"$ACTION\"}" >> ~/ioc-data/realtime_ioc_events.json

    sleep 30
done
EOF

chmod +x ~/ioc-data/generate_realtime_data.sh

# TODO: Parameterize sleep interval via an environment variable
```

### 🔌 Subtask 5.2: Configure Real-Time Data Pipeline

```bash
# ⚙️ Create additional Logstash configuration for real-time data
sudo nano /etc/logstash/conf.d/realtime-ioc-pipeline.conf
```

📝 Add this configuration:
```ruby
input {
  file {
    path => "/home/*/ioc-data/realtime_ioc_events.json"
    start_position => "end"
    codec => "json"
  }
}

filter {
  date {
    match => [ "timestamp", "ISO8601" ]
  }

  mutate {
    add_field => {
      "correlation_id" => "%{ioc_type}_%{ioc_value}"
      "data_source" => "realtime"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "ioc-events-%{+YYYY.MM.dd}"
  }
}
```

```bash
# 🔄 Restart Logstash
sudo systemctl restart logstash

# 🚀 Start real-time data generation in background
nohup ~/ioc-data/generate_realtime_data.sh > /dev/null 2>&1 &

echo "Real-time IOC data generation started"
echo "Data will be continuously added to your dashboard"

# TODO: Wrap the background generator in a systemd unit for restart resilience
```

---

## ✅ Task 6: Verify Dashboard Functionality

### 🧾 Subtask 6.1: Test Dashboard Access and Functionality

```bash
# 🔍 Verify Elasticsearch has data
curl -X GET "localhost:9200/ioc-events-*/_search?size=5&pretty"

# 📋 Check Kibana dashboard access
echo "=== Lab Verification ==="
echo "1. Kibana URL: http://localhost:5601"
echo "2. Navigate to Dashboard section"
echo "3. Open 'IOC Correlation Dashboard'"
echo "4. Verify visualizations are displaying data"
echo "5. Test time range filters and auto-refresh"

# 🩺 Display service status
echo "=== Service Status ==="
sudo systemctl status elasticsearch --no-pager -l
sudo systemctl status kibana --no-pager -l
sudo systemctl status logstash --no-pager -l

# TODO: Add a healthcheck script that curls all three services and reports pass/fail
```

### 🔑 Subtask 6.2: Create Sample Correlation Queries

```bash
# 📝 Create a script with sample correlation queries
cat > ~/correlation_queries.txt << 'EOF'
Sample Kibana Query Language (KQL) queries for IOC correlation:

1. High severity events from specific IP:
   source_ip:"192.168.1.100" AND severity:(high OR critical)

2. Multiple IOC types from same source:
   source_ip:"192.168.1.101" AND ioc_type:(hash OR domain)

3. Blocked actions in last hour:
   action:"blocked" AND timestamp:[now-1h TO now]

4. Correlation by IOC value:
   ioc_value:"d41d8cd98f00b204e9800998ecf8427e"

5. Event type correlation:
   event_type:"malware_detection" AND severity:"critical"
EOF

echo "Sample correlation queries saved to ~/correlation_queries.txt"
cat ~/correlation_queries.txt

# TODO: Add a query for correlating IOCs across both source_ip and destination_ip fields
```

**✔️ Expected Result:** The `IOC Correlation Dashboard` loads at `http://localhost:5601`, both visualizations render populated data from the `ioc-events-*` index, and saved searches return matching KQL results.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Artifact |
|---|---|---|---|
| T1071 | Application Layer Protocol | Command and Control | `url_analysis` / suspicious URL IOC events |
| T1583.001 | Acquire Infrastructure: Domains | Resource Development | `suspicious_domain` IOC correlation |
| T1595 | Active Scanning | Reconnaissance | `ip_reputation` source/destination IP tracking |
| T1204 | User Execution | Execution | `malware_detection` file hash events |
| T1105 | Ingress Tool Transfer | Command and Control | `file_hash` quarantine/blocked action events |
| T1046 | Network Service Discovery | Discovery | Source IP vs IOC Type heatmap correlation |

---

## 🧩 Troubleshooting

<details>
<summary>❗ Elasticsearch fails to start</summary>

- Confirm Java 11 is installed: `java -version`
- Check logs: `sudo journalctl -u elasticsearch -n 50`
- Verify `discovery.type: single-node` is set in `elasticsearch.yml`

</details>

<details>
<summary>❗ Kibana shows "Kibana server is not ready yet"</summary>

- Wait the full 2–3 minutes after starting the service
- Confirm Elasticsearch is reachable: `curl -X GET "localhost:9200/"`
- Check `elasticsearch.hosts` matches `http://localhost:9200` in `kibana.yml`

</details>

<details>
<summary>❗ No data appears in the dashboard</summary>

- Confirm the Logstash pipeline config path matches your actual home directory (`/home/*/ioc-data/...`)
- Check Logstash logs: `sudo journalctl -u logstash -n 50`
- Re-run `curl -X GET "localhost:9200/ioc-events-*/_search?size=5&pretty"` to confirm ingestion

</details>

<details>
<summary>❗ Index pattern creation via API returns an error</summary>

- Ensure the `kbn-xsrf: true` header is included in every Kibana API call
- Confirm Kibana is fully started before calling `/api/saved_objects/...`
- Delete and recreate the index pattern if a conflicting one already exists

</details>

<details>
<summary>❗ Real-time data generator script not producing events</summary>

- Confirm the script is executable: `chmod +x ~/ioc-data/generate_realtime_data.sh`
- Check it's running in the background: `ps aux | grep generate_realtime_data`
- Verify the Logstash `realtime-ioc-pipeline.conf` `start_position => "end"` setting is correct

</details>

---

## 🏁 Conclusion

You have successfully completed **Lab 9: Build Dashboards in Kibana for IOC Correlation**. In this lab, you:

**🎯 Key Accomplishments**
- 🛠️ **ELK Stack Deployment** — Installed and configured a complete ELK stack on a single Linux machine
- 📊 **Custom Dashboards** — Created Kibana dashboards with multiple visualizations for IOC analysis
- 🔗 **Correlation Queries** — Configured KQL queries to identify relationships between security events
- ⏱️ **Real-Time Monitoring** — Set up continuous data ingestion and live visualization
- 🌐 **Practical IOC Correlation** — Built severity analysis, source IP tracking, and response action monitoring capabilities

**🌍 Real-World Applications**
- 🕵️ **Security Analysis** — Rapid visualization and correlation of threat intelligence data for SOC operators
- 🚨 **Threat Detection** — Real-time visibility into IOCs for faster detection and response
- 📈 **Enterprise Monitoring** — Scalable techniques extendable to larger datasets and production environments
- 🧯 **Incident Response** — Correlation methods directly applicable to live incident triage and threat hunting

---

<div align="center">

### 🏢 Al Nafi Cloud Security Training Platform

**Blue Team / Threat Intelligence & Digital Forensics Track**

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1E90FF?style=for-the-badge)

</div>
