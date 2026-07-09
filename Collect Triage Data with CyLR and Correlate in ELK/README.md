<div align="center">

# 🛡️ Collect Triage Data with CyLR and Correlate in ELK

### Al Nafi Cloud Labs — Blue Team / Digital Forensics & Triage Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![CyLR](https://img.shields.io/badge/CyLR-Rapid%20Triage%20Collection-B22222?style=for-the-badge)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Logstash](https://img.shields.io/badge/Logstash-Data%20Pipeline-005571?style=for-the-badge&logo=logstash&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Visualization-005571?style=for-the-badge&logo=kibana&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through building a rapid triage-and-correlation pipeline using **CyLR** for lightweight forensic artifact collection and the **ELK stack** (Elasticsearch, Logstash, Kibana) for parsing, indexing, and analyzing that data. You'll collect authentication logs, bash history, and system configuration files, pipe them through a custom Logstash parser, and query the results for indicators of compromise.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Install and configure CyLR for rapid endpoint data collection
- ✅ Set up the ELK stack (Elasticsearch, Logstash, Kibana) for data analysis
- ✅ Configure Logstash to parse and ingest CyLR output
- ✅ Create Kibana visualizations for triage data analysis
- ✅ Perform correlation analysis on collected forensic artifacts

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![CyLR](https://img.shields.io/badge/-CyLR-B22222?style=flat-square) | Rapid, targeted collection of forensic triage artifacts |
| ![Elasticsearch](https://img.shields.io/badge/-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white) | Indexing & search backend for triage data |
| ![Logstash](https://img.shields.io/badge/-Logstash-005571?style=flat-square&logo=logstash&logoColor=white) | Parsing, enrichment & ingestion pipeline |
| ![Kibana](https://img.shields.io/badge/-Kibana-005571?style=flat-square&logo=kibana&logoColor=white) | Visualization & index pattern management |
| ![Java](https://img.shields.io/badge/-Java%2011-007396?style=flat-square&logo=openjdk&logoColor=white) | Runtime dependency for the ELK stack |
| ![jq](https://img.shields.io/badge/-jq-000000?style=flat-square) | JSON parsing for CLI-based analysis scripts |
| ![Bash](https://img.shields.io/badge/-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white) | Triage analysis & report generation scripting |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of log analysis concepts
- Familiarity with JSON data structures
- Basic knowledge of digital forensics principles

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your environment. The machine is bare metal with no pre-installed tools — you'll install all required software during the lab.

---

## 🚀 Task 1: Install and Configure Required Tools

### 1.1 — Install Java and Dependencies

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# ☕ Install Java 11 (required for ELK stack)
sudo apt install openjdk-11-jdk wget curl unzip -y

# 🔍 Verify Java installation
java -version
```

### 1.2 — Install Elasticsearch

```bash
# 🔑 Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# 📦 Install Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# ✏️ Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

```yaml
cluster.name: cylr-analysis
node.name: node-1
network.host: localhost
http.port: 9200
discovery.type: single-node
```

### 1.3 — Install Logstash and Kibana

```bash
# 📦 Install Logstash and Kibana
sudo apt install logstash kibana -y

# ✏️ Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

### 1.4 — Start ELK Services

```bash
# ▶️ Enable and start services
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch

# ⏳ Wait for Elasticsearch to start
sleep 30

# ▶️ Start remaining services
sudo systemctl start logstash kibana

# 🔍 Verify services are running
sudo systemctl status elasticsearch logstash kibana
# TODO: Confirm all three services report "active (running)" before proceeding
```

---

## 🧰 Task 2: Install and Configure CyLR

### 2.1 — Download and Install CyLR

```bash
# 📁 Create working directory
mkdir ~/cylr-lab && cd ~/cylr-lab

# ⬇️ Download CyLR (Linux version)
wget https://github.com/orlikoski/CyLR/releases/latest/download/CyLR_linux-x64.zip

# 📦 Extract CyLR
unzip CyLR_linux-x64.zip
chmod +x CyLR

# 🔍 Verify installation
./CyLR --help
```

### 2.2 — Create CyLR Collection Configuration

```bash
# 📝 Create custom collection configuration
nano cylr-config.txt
```

```
# CyLR Collection Configuration
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
/home/*/.bash_history
/etc/passwd
/etc/shadow
/etc/hosts
/proc/*/cmdline
/proc/*/environ
```

> ⚠️ **Note:** This configuration collects sensitive files (`/etc/shadow`, process environment variables). Restrict output file permissions and access to authorized triage personnel only.

### 2.3 — Run CyLR Data Collection

```bash
# ▶️ Run CyLR with custom configuration
sudo ./CyLR -c cylr-config.txt -o cylr-output.zip

# 📦 Extract collected data
unzip cylr-output.zip -d cylr-data/

# 🔍 Examine collected data structure
ls -la cylr-data/
find cylr-data/ -type f | head -20
```

---

## 🔧 Task 3: Configure Logstash for CyLR Data Processing

### 3.1 — Create Logstash Configuration

```bash
# 📝 Create Logstash pipeline configuration
sudo nano /etc/logstash/conf.d/cylr-pipeline.conf
```

```ruby
input {
  file {
    path => "/home/*/cylr-lab/cylr-data/**/*"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "plain"
    add_field => { "source_type" => "cylr_artifact" }
  }
}

filter {
  # Add timestamp
  mutate {
    add_field => { "collection_timestamp" => "%{@timestamp}" }
  }

  # Parse file paths
  grok {
    match => { "path" => "/home/.*/cylr-lab/cylr-data/(?<artifact_category>[^/]+)/(?<artifact_name>.*)" }
  }

  # Process auth.log entries
  if [path] =~ /auth\.log/ {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
    }
    mutate {
      add_field => { "log_type" => "authentication" }
    }
  }

  # Process bash history
  if [path] =~ /bash_history/ {
    mutate {
      add_field => { "log_type" => "command_history" }
      add_field => { "command" => "%{message}" }
    }
  }

  # Process system files
  if [path] =~ /(passwd|shadow|hosts)/ {
    mutate {
      add_field => { "log_type" => "system_config" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "cylr-triage-%{+YYYY.MM.dd}"
  }

  stdout {
    codec => rubydebug
  }
}
```

### 3.2 — Test and Start Logstash Pipeline

```bash
# 🧪 Test Logstash configuration
sudo /usr/share/logstash/bin/logstash --config.test_and_exit --path.settings /etc/logstash -f /etc/logstash/conf.d/cylr-pipeline.conf

# ▶️ Restart Logstash with new configuration
sudo systemctl restart logstash

# 📋 Monitor Logstash logs
sudo tail -f /var/log/logstash/logstash-plain.log
# TODO: Watch for grok parse failures (_grokparsefailure tag) and adjust patterns as needed
```

---

## 📊 Task 4: Analyze and Visualize Data in Kibana

### 4.1 — Access Kibana and Create Index Pattern

```bash
# 🔍 Check if Kibana is accessible
curl -I http://localhost:5601

# 🌐 Open browser to Kibana (if GUI available) or use curl for API calls
echo "Access Kibana at: http://localhost:5601"
```

```bash
# ⏳ Wait for data to be indexed
sleep 60

# 📌 Create index pattern
curl -X POST "localhost:5601/api/saved_objects/index-pattern/cylr-triage-*" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "cylr-triage-*",
      "timeFieldName": "@timestamp"
    }
  }'
```

### 4.2 — Query and Analyze Triage Data

```bash
# 🔍 Search for authentication events
curl -X GET "localhost:9200/cylr-triage-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match": {
        "log_type": "authentication"
      }
    },
    "size": 10
  }'

# 🔍 Search for command history
curl -X GET "localhost:9200/cylr-triage-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "match": {
        "log_type": "command_history"
      }
    },
    "size": 10
  }'

# 📊 Get aggregation of artifact types
curl -X GET "localhost:9200/cylr-triage-*/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "artifact_types": {
        "terms": {
          "field": "log_type.keyword"
        }
      }
    }
  }'
```

### 4.3 — Create Analysis Queries

```bash
# 📝 Create script for common triage queries
nano triage-analysis.sh
```

```bash
#!/bin/bash

echo "=== CyLR Triage Data Analysis ==="

echo "1. Authentication Events:"
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match": {"log_type": "authentication"}},
    "size": 5
  }' | jq '.hits.hits[]._source | select(.program) | {timestamp: .timestamp, program: .program, message: .log_message}'

echo -e "\n2. Suspicious Commands:"
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"match": {"log_type": "command_history"}},
          {"regexp": {"command.keyword": ".*(sudo|su|wget|curl|nc|netcat|chmod|rm).*"}}
        ]
      }
    },
    "size": 10
  }' | jq '.hits.hits[]._source.command'

echo -e "\n3. System Configuration Changes:"
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match": {"log_type": "system_config"}},
    "size": 5
  }' | jq '.hits.hits[]._source | {file: .path, content: .message}'

echo -e "\n4. Data Collection Summary:"
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "by_type": {"terms": {"field": "log_type.keyword"}},
      "by_category": {"terms": {"field": "artifact_category.keyword"}}
    }
  }' | jq '.aggregations'
```

```bash
# 🔐 Make script executable and run
chmod +x triage-analysis.sh
./triage-analysis.sh
```

### 4.4 — Generate Triage Report

```bash
# 📝 Create comprehensive triage report
nano generate-report.sh
```

```bash
#!/bin/bash

REPORT_FILE="cylr-triage-report-$(date +%Y%m%d-%H%M%S).txt"

echo "CyLR Triage Analysis Report" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "=================================" >> $REPORT_FILE

# Get total document count
TOTAL_DOCS=$(curl -s -X GET "localhost:9200/cylr-triage-*/_count" | jq '.count')
echo -e "\nTotal Artifacts Collected: $TOTAL_DOCS" >> $REPORT_FILE

# Get breakdown by type
echo -e "\nArtifact Breakdown:" >> $REPORT_FILE
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "aggs": {
      "types": {"terms": {"field": "log_type.keyword", "size": 20}}
    }
  }' | jq -r '.aggregations.types.buckets[] | "- \(.key): \(.doc_count) items"' >> $REPORT_FILE

# Get recent authentication events
echo -e "\nRecent Authentication Events:" >> $REPORT_FILE
curl -s -X GET "localhost:9200/cylr-triage-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": {"match": {"log_type": "authentication"}},
    "sort": [{"@timestamp": {"order": "desc"}}],
    "size": 10
  }' | jq -r '.hits.hits[]._source | select(.timestamp and .program) | "- \(.timestamp) \(.program): \(.log_message)"' >> $REPORT_FILE

echo -e "\nReport saved to: $REPORT_FILE"
cat $REPORT_FILE
```

```bash
# ▶️ Generate the report
chmod +x generate-report.sh
./generate-report.sh
```

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Name | Tactic | Correlated Artifact in This Lab |
|---|---|---|---|
| T1078 | Valid Accounts | Defense Evasion / Persistence | `auth.log` authentication events |
| T1552.003 | Bash History | Credential Access | `.bash_history` command_history entries |
| T1005 | Data from Local System | Collection | `/etc/passwd`, `/etc/shadow`, `/etc/hosts` system_config entries |
| T1059 | Command and Scripting Interpreter | Execution | Suspicious command regex (`sudo`, `wget`, `nc`, `chmod`, `rm`) |

---

## 🧪 Verification and Testing

### Verify Data Collection and Processing

```bash
# ✅ Check Elasticsearch indices
curl -X GET "localhost:9200/_cat/indices/cylr-*?v"

# ✅ Verify data ingestion
curl -X GET "localhost:9200/cylr-triage-*/_search?size=0" | jq '.hits.total.value'

# ✅ Test search functionality
curl -X GET "localhost:9200/cylr-triage-*/_search?q=log_type:authentication&size=1" | jq '.hits.hits[0]._source'

# ✅ Check Logstash processing
sudo systemctl status logstash
```

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Elasticsearch won't start</strong></summary>

- Check Java installation: `java -version`
- Check memory settings in `/etc/elasticsearch/jvm.options`
- Review logs: `sudo journalctl -u elasticsearch -f`

</details>

<details>
<summary><strong>❌ Issue: Logstash parsing errors</strong></summary>

- Verify file paths and permissions in `/etc/logstash/conf.d/cylr-pipeline.conf`
- Test the config directly: `sudo /usr/share/logstash/bin/logstash --config.test_and_exit -f /etc/logstash/conf.d/cylr-pipeline.conf`
- Review logs: `sudo journalctl -u logstash -f`

</details>

<details>
<summary><strong>❌ Issue: No data in Kibana</strong></summary>

- Ensure Logstash pipeline is processing files correctly (check `stdout` output in Logstash logs)
- Confirm the index pattern `cylr-triage-*` was created successfully
- Verify documents exist: `curl -X GET "localhost:9200/cylr-triage-*/_search?size=0"`

</details>

<details>
<summary><strong>❌ Issue: Permission denied during collection</strong></summary>

- Run CyLR with `sudo` for system file access
- Verify file permissions: `ls -la cylr-data/`
- Adjust if needed: `sudo chmod -R 644 cylr-data/`

</details>

**Debug Commands:**

```bash
# Check service logs
sudo journalctl -u elasticsearch -f
sudo journalctl -u logstash -f

# Verify file permissions
ls -la cylr-data/
sudo chmod -R 644 cylr-data/

# Test Elasticsearch connectivity
curl -X GET "localhost:9200/_cluster/health?pretty"
```

---

## 🏁 Conclusion

You have successfully completed a comprehensive digital forensics triage workflow using CyLR for rapid data collection and the ELK stack for analysis and correlation. This lab demonstrated how to:

- 📥 Collect forensic artifacts efficiently using CyLR
- 🔧 Process and index triage data with Logstash
- 🔍 Perform correlation analysis using Elasticsearch queries
- 📊 Generate actionable intelligence from collected artifacts

This workflow is essential for incident response and digital forensics professionals who need to quickly assess system compromise and identify indicators of malicious activity. The combination of automated collection and powerful analysis capabilities enables rapid triage decisions in time-critical investigations.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Digital Forensics & Rapid Triage**

*Empowering the next generation of cybersecurity defenders*

</div>
