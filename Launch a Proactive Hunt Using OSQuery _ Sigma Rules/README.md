<div align="center">

# 🛡️ Launch a Proactive Hunt Using OSQuery + Sigma Rules

### Al Nafi Cloud Labs — Blue Team / Threat Hunting Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![OSQuery](https://img.shields.io/badge/OSQuery-Endpoint%20Monitoring-1560A5?style=for-the-badge&logo=osquery&logoColor=white)
![Sigma](https://img.shields.io/badge/Sigma-Detection%20Rules-00A98F?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Sigma%20CLI-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Automation-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **OSQuery** for endpoint visibility and pairing it with **Sigma rules** for standardized, portable threat detection. You'll configure scheduled queries, author custom Sigma detections for suspicious processes and network connections, convert them to OSQuery syntax, and run automated hunt scripts against live test activity.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Deploy and configure OSQuery for endpoint monitoring and data collection
- ✅ Implement Sigma rules for automated threat detection and anomaly identification
- ✅ Analyze endpoint data to identify potential security threats and suspicious activities
- ✅ Execute proactive threat hunting techniques using open-source tools

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![OSQuery](https://img.shields.io/badge/-OSQuery-1560A5?style=flat-square&logo=osquery&logoColor=white) | SQL-based endpoint telemetry & scheduled monitoring |
| ![Sigma](https://img.shields.io/badge/-Sigma-00A98F?style=flat-square) | Vendor-agnostic detection rule format |
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | `sigma-cli` and OSQuery backend conversion |
| ![Git](https://img.shields.io/badge/-Git-F05032?style=flat-square&logo=git&logoColor=white) | Cloning the SigmaHQ rules repository |
| ![Bash](https://img.shields.io/badge/-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white) | Hunt automation & scheduled reporting scripts |
| ![Cron](https://img.shields.io/badge/-Cron-000000?style=flat-square&logo=gnu-bash&logoColor=white) | Continuous hunt scheduling |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of system processes and network connections
- Familiarity with JSON data structures
- Basic knowledge of security concepts and threat indicators

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided machine is bare metal with no pre-installed tools — you will install all required components during the lab exercises.

---

## 🚀 Task 1: Deploy OSQuery for Endpoint Monitoring

### 1.1 — Install OSQuery

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 📦 Install required dependencies
sudo apt install -y curl gnupg software-properties-common

# 🔑 Add OSQuery repository
curl -L https://pkg.osquery.io/deb/pubkey.gpg | sudo apt-key add -
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'

# 🐧 Install OSQuery
sudo apt update
sudo apt install -y osquery
```

### 1.2 — Configure OSQuery

```bash
# 📁 Create OSQuery configuration directory
sudo mkdir -p /etc/osquery

# 📝 Create configuration file
sudo tee /etc/osquery/osquery.conf << 'EOF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "network_connections": {
      "query": "SELECT pid, name, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE state != 'LISTEN';",
      "interval": 300
    },
    "running_processes": {
      "query": "SELECT pid, name, path, cmdline, uid, gid FROM processes;",
      "interval": 600
    },
    "file_changes": {
      "query": "SELECT target_path, category, time, action FROM file_events WHERE category != 'UNKNOWN';",
      "interval": 180
    }
  },
  "file_paths": {
    "system_binaries": [
      "/usr/bin/%%",
      "/usr/sbin/%%",
      "/bin/%%",
      "/sbin/%%"
    ],
    "tmp": [
      "/tmp/%%"
    ]
  }
}
EOF
# TODO: Tune schedule intervals to balance telemetry fidelity against endpoint load
```

### 1.3 — Start OSQuery Service

```bash
# 📁 Create necessary directories
sudo mkdir -p /var/log/osquery /var/osquery

# 🔐 Set proper permissions
sudo chown -R osquery:osquery /var/log/osquery /var/osquery

# ▶️ Enable and start OSQuery service
sudo systemctl enable osqueryd
sudo systemctl start osqueryd

# 🔍 Verify service status
sudo systemctl status osqueryd
```

### 1.4 — Test OSQuery Installation

```bash
# 🧪 Test OSQuery interactive mode
sudo osqueryi --config_path /etc/osquery/osquery.conf

# Run basic queries (execute these in osqueryi shell):
# SELECT * FROM system_info;
# SELECT pid, name, path FROM processes LIMIT 10;
# .quit
```

---

## 🎯 Task 2: Apply Sigma Rules for Anomaly Detection

### 2.1 — Install Sigma and Dependencies

```bash
# 📦 Install Python and pip
sudo apt install -y python3 python3-pip git

# 📦 Install Sigma
pip3 install sigma-cli pysigma-backend-osquery

# 📥 Clone Sigma rules repository
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma-rules
```

### 2.2 — Create Custom Sigma Rules

```bash
# 📁 Create Sigma rules directory
mkdir -p ~/sigma-hunt/rules ~/sigma-hunt/queries

# 📝 Create a custom Sigma rule for suspicious process execution
tee ~/sigma-hunt/rules/suspicious_process.yml << 'EOF'
title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789012
description: Detects execution of potentially suspicious processes
author: Security Analyst
date: 2024/01/01
references:
    - https://attack.mitre.org/techniques/T1059/
logsource:
    product: linux
    service: osquery
    definition: 'Requirements: OSQuery running with process monitoring'
detection:
    selection:
        name:
            - 'nc'
            - 'netcat'
            - 'ncat'
            - 'socat'
            - 'wget'
            - 'curl'
        cmdline|contains:
            - '/tmp/'
            - '/dev/shm/'
            - 'bash -i'
            - 'sh -i'
    condition: selection
falsepositives:
    - Legitimate administrative activities
level: medium
tags:
    - attack.execution
    - attack.t1059
EOF

# 📝 Create rule for network connections
tee ~/sigma-hunt/rules/suspicious_network.yml << 'EOF'
title: Suspicious Network Connections
id: 87654321-4321-4321-4321-210987654321
description: Detects suspicious outbound network connections
author: Security Analyst
date: 2024/01/01
logsource:
    product: linux
    service: osquery
detection:
    selection:
        remote_port:
            - 4444
            - 5555
            - 6666
            - 7777
            - 8888
            - 9999
        state: 'ESTABLISHED'
    condition: selection
falsepositives:
    - Legitimate applications using these ports
level: high
tags:
    - attack.command_and_control
    - attack.t1071
EOF
```

### 2.3 — Convert Sigma Rules to OSQuery

```bash
# 📦 Install additional dependencies
pip3 install pysigma-backend-osquery

# 🔄 Convert Sigma rules to OSQuery queries
sigma convert -t osquery ~/sigma-hunt/rules/suspicious_process.yml > ~/sigma-hunt/queries/suspicious_process.sql

sigma convert -t osquery ~/sigma-hunt/rules/suspicious_network.yml > ~/sigma-hunt/queries/suspicious_network.sql

# 👀 View converted queries
echo "=== Suspicious Process Query ==="
cat ~/sigma-hunt/queries/suspicious_process.sql

echo "=== Suspicious Network Query ==="
cat ~/sigma-hunt/queries/suspicious_network.sql
# TODO: Manually validate converted SQL syntax before relying on it in production
```

### 2.4 — Create Hunt Script

```bash
# 📝 Create an automated hunting script
tee ~/sigma-hunt/hunt.sh << 'EOF'
#!/bin/bash

HUNT_DIR="$HOME/sigma-hunt"
LOG_FILE="$HUNT_DIR/hunt_results.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$TIMESTAMP] Starting proactive hunt..." | tee -a $LOG_FILE

# Function to run OSQuery and check results
run_hunt_query() {
    local query_file=$1
    local rule_name=$2

    echo "[$TIMESTAMP] Executing hunt: $rule_name" | tee -a $LOG_FILE

    # Run the query and capture results
    result=$(sudo osqueryi --json "$query_file" 2>/dev/null)

    if [ ! -z "$result" ] && [ "$result" != "[]" ]; then
        echo "[$TIMESTAMP] ALERT: $rule_name - Suspicious activity detected!" | tee -a $LOG_FILE
        echo "$result" | tee -a $LOG_FILE
        echo "----------------------------------------" | tee -a $LOG_FILE
    else
        echo "[$TIMESTAMP] $rule_name - No threats detected" | tee -a $LOG_FILE
    fi
}

# Create manual queries since sigma conversion might need adjustment
echo "SELECT pid, name, path, cmdline FROM processes WHERE name IN ('nc', 'netcat', 'ncat', 'socat', 'wget', 'curl') AND (cmdline LIKE '%/tmp/%' OR cmdline LIKE '%/dev/shm/%' OR cmdline LIKE '%bash -i%' OR cmdline LIKE '%sh -i%');" > $HUNT_DIR/process_hunt.sql

echo "SELECT pid, name, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE remote_port IN (4444, 5555, 6666, 7777, 8888, 9999) AND state = 'ESTABLISHED';" > $HUNT_DIR/network_hunt.sql

# Run hunt queries
run_hunt_query "$HUNT_DIR/process_hunt.sql" "Suspicious Process Hunt"
run_hunt_query "$HUNT_DIR/network_hunt.sql" "Suspicious Network Hunt"

echo "[$TIMESTAMP] Hunt completed. Results logged to $LOG_FILE" | tee -a $LOG_FILE
EOF

chmod +x ~/sigma-hunt/hunt.sh
```

---

## 🔍 Task 3: Analyze Data from Endpoints to Detect Threats

### 3.1 — Generate Test Activity

```bash
# 📁 Create test directory
mkdir -p /tmp/test-activity

# 🌐 Generate some network activity (safe, local-only examples)
echo "Testing network connections..."
timeout 5 nc -l 1234 &
sleep 2
echo "test" | nc localhost 1234

# 📝 Create a test script in /tmp
tee /tmp/test-activity/test_script.sh << 'EOF'
#!/bin/bash
echo "This is a test script in /tmp directory"
ps aux | head -5
EOF

chmod +x /tmp/test-activity/test_script.sh
/tmp/test-activity/test_script.sh
```

> ℹ️ These activities are intentionally benign and local-only — they exist purely to trigger the detection rules created above so you can observe the hunt pipeline end-to-end.

### 3.2 — Execute Proactive Hunt

```bash
# ▶️ Execute the hunt
~/sigma-hunt/hunt.sh

# 📄 View hunt results
echo "=== Hunt Results ==="
cat ~/sigma-hunt/hunt_results.log

# 📋 Check OSQuery logs for additional data
echo "=== Recent OSQuery Logs ==="
sudo tail -20 /var/log/osquery/osqueryd.results.log
```

### 3.3 — Manual Threat Analysis

```bash
# 🧪 Launch OSQuery interactive mode
sudo osqueryi --config_path /etc/osquery/osquery.conf

# Execute analysis queries (run these in osqueryi shell):
# Check for processes with suspicious characteristics
# SELECT pid, name, path, cmdline, uid FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%';

# Look for unusual network connections
# SELECT pid, name, local_port, remote_address, remote_port FROM process_open_sockets WHERE remote_port > 1024 AND state = 'ESTABLISHED';

# Check for recently modified files in sensitive directories
# SELECT path, mtime, size FROM file WHERE path LIKE '/tmp/%' AND mtime > (strftime('%s', 'now') - 3600);

# Exit OSQuery
# .quit
```

### 3.4 — Create Continuous Monitoring

```bash
# 📝 Create a monitoring script
tee ~/sigma-hunt/continuous_hunt.sh << 'EOF'
#!/bin/bash
cd $HOME/sigma-hunt
./hunt.sh

# Check if any alerts were generated
if grep -q "ALERT" hunt_results.log; then
    echo "SECURITY ALERT: Suspicious activity detected at $(date)" >> alerts.log
    tail -10 hunt_results.log >> alerts.log
fi
EOF

chmod +x ~/sigma-hunt/continuous_hunt.sh

# ⏰ Add to crontab for every 10 minutes (optional)
echo "# Uncomment the line below to enable continuous hunting every 10 minutes"
echo "# */10 * * * * $HOME/sigma-hunt/continuous_hunt.sh"
# TODO: Add log rotation for alerts.log before enabling this in a long-running environment
```

### 3.5 — Analyze and Report Findings

```bash
# 📝 Generate hunt summary
tee ~/sigma-hunt/hunt_summary.sh << 'EOF'
#!/bin/bash

HUNT_DIR="$HOME/sigma-hunt"
REPORT_FILE="$HUNT_DIR/hunt_report.txt"

echo "=== PROACTIVE THREAT HUNT REPORT ===" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== SYSTEM OVERVIEW ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT hostname, cpu_brand, physical_memory FROM system_info;" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== ACTIVE PROCESSES SUMMARY ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT COUNT(*) as total_processes FROM processes;" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== NETWORK CONNECTIONS SUMMARY ===" >> $REPORT_FILE
sudo osqueryi --json "SELECT COUNT(*) as active_connections FROM process_open_sockets WHERE state = 'ESTABLISHED';" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== HUNT RESULTS ===" >> $REPORT_FILE
if [ -f "$HUNT_DIR/hunt_results.log" ]; then
    cat "$HUNT_DIR/hunt_results.log" >> $REPORT_FILE
else
    echo "No hunt results available" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "=== RECOMMENDATIONS ===" >> $REPORT_FILE
echo "1. Review any ALERT entries in the hunt results" >> $REPORT_FILE
echo "2. Investigate suspicious processes or network connections" >> $REPORT_FILE
echo "3. Consider implementing additional Sigma rules for your environment" >> $REPORT_FILE
echo "4. Schedule regular proactive hunts using the provided scripts" >> $REPORT_FILE

echo "Report generated: $REPORT_FILE"
EOF

chmod +x ~/sigma-hunt/hunt_summary.sh

# ▶️ Generate the report
~/sigma-hunt/hunt_summary.sh

# 📄 Display the report
echo "=== FINAL HUNT REPORT ==="
cat ~/sigma-hunt/hunt_report.txt
```

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Name | Tactic | Detection Method in This Lab |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution | `suspicious_process.yml` — nc/netcat/wget/curl with reverse-shell patterns |
| T1071 | Application Layer Protocol | Command and Control | `suspicious_network.yml` — established connections on common C2 ports |
| T1036 | Masquerading | Defense Evasion | File path monitoring in `/tmp` and `/dev/shm` |

---

## 🧪 Verification and Testing

```bash
# ✅ Check OSQuery service status
sudo systemctl status osqueryd

# ✅ Verify log files are being created
ls -la /var/log/osquery/

# ✅ Test hunt script execution
~/sigma-hunt/hunt.sh

# ✅ Verify Sigma rules are properly formatted
ls -la ~/sigma-hunt/rules/

# ✅ Check that queries are executable
ls -la ~/sigma-hunt/queries/
```

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: <code>osqueryd</code> service fails to start</strong></summary>

```bash
sudo journalctl -u osqueryd -n 50
```

- Confirm `/etc/osquery/osquery.conf` is valid JSON: `python3 -m json.tool /etc/osquery/osquery.conf`
- Confirm `/var/log/osquery` and `/var/osquery` ownership matches the `osquery` user

</details>

<details>
<summary><strong>❌ Issue: <code>sigma convert</code> fails or produces empty output</strong></summary>

- Confirm `pysigma-backend-osquery` installed correctly: `pip3 show pysigma-backend-osquery`
- Validate the rule YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('rule.yml'))"`
- As a fallback, the `hunt.sh` script includes hand-written equivalents of both queries

</details>

<details>
<summary><strong>❌ Issue: Hunt script reports no results even after generating test activity</strong></summary>

- Confirm `osqueryd` has been running long enough to capture the scheduled query interval
- Re-run `/tmp/test-activity/test_script.sh` and immediately re-run `~/sigma-hunt/hunt.sh`
- Check `sudo tail -20 /var/log/osquery/osqueryd.results.log` for raw event data

</details>

---

## 🏁 Conclusion

You have successfully completed a comprehensive proactive threat hunting lab using OSQuery and Sigma rules. You accomplished:

- ⚙️ Deployed OSQuery for continuous endpoint monitoring and data collection
- 🎯 Implemented Sigma rules for automated threat detection and anomaly identification
- 🔍 Created custom hunting queries to identify suspicious processes and network connections
- 🤖 Developed automated hunting scripts for continuous security monitoring
- 📊 Analyzed endpoint data to detect potential security threats and indicators of compromise

This lab demonstrates how open-source tools can provide enterprise-level threat hunting capabilities. The combination of OSQuery's powerful endpoint visibility and Sigma's standardized detection rules creates a robust foundation for proactive security monitoring. These skills are essential for security analysts, incident responders, and threat hunters working to identify and mitigate advanced persistent threats before they cause significant damage.

The techniques learned here can be scaled and customized for production environments, making this knowledge directly applicable to real-world cybersecurity operations.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Proactive Threat Hunting**

*Empowering the next generation of cybersecurity defenders*

</div>
