<div align="center">

# 🔐 Detect Ransomware Precursors via Sysmon + Sigma Rules

### Behavioral Detection & Early-Warning Analysis Lab

![Sysmon](https://img.shields.io/badge/Sysmon-Linux-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Sigma Rules](https://img.shields.io/badge/Sigma-Detection_Rules-8A2BE2?style=for-the-badge&logo=yaml&logoColor=white)
![Ransomware Detection](https://img.shields.io/badge/Ransomware-Detection-DC143C?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![YAML](https://img.shields.io/badge/YAML-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1486-FF6F00?style=for-the-badge&logo=mitre&logoColor=white)
![Log Analysis](https://img.shields.io/badge/Log-Analysis-32CD32?style=for-the-badge&logo=elastic&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📚 Table of Contents

- [🎯 Objectives](#-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🛰️ Task 1: Deploy Sysmon for System Activity Logging](#️-task-1-deploy-sysmon-for-system-activity-logging)
- [📏 Task 2: Apply Sigma Rules for Ransomware Detection](#-task-2-apply-sigma-rules-for-ransomware-detection)
- [🔍 Task 3: Analyze Sysmon Logs for Ransomware Activity](#-task-3-analyze-sysmon-logs-for-ransomware-activity)
- [✅ Verification and Testing](#-verification-and-testing)
- [🧹 Cleanup](#-cleanup)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧩 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Objectives

| # | Objective |
|---|-----------|
| 1 | 🛰️ Deploy Sysmon on Linux to capture detailed system activity logs |
| 2 | 📏 Implement Sigma rules for detecting ransomware precursor behaviors |
| 3 | 🔍 Analyze Sysmon logs to identify potential ransomware indicators |
| 4 | 🧠 Understand common ransomware attack patterns and detection techniques |

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command-line knowledge |
| 📜 Log Analysis | Understanding of log analysis concepts |
| 🧾 YAML Format | Familiarity with YAML file format |
| 🦠 Ransomware Knowledge | Knowledge of common ransomware attack vectors |

---

## 🖥️ Lab Environment

> ☁️ **Al Nafi** provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — all required components are installed during the lab.

---

## 🛰️ Task 1: Deploy Sysmon for System Activity Logging

### 🔧 1.1 Install Dependencies

```bash
# 📦 Update the system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y git build-essential cmake libxml2-dev libssl-dev wget curl unzip

# TODO: Pin package versions for reproducible lab builds
```

### 📥 1.2 Install Sysmon for Linux

```bash
# 🌐 Download and install Sysmon for Linux
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install -y sysmonforlinux

# TODO: Verify Ubuntu version compatibility if using a distro other than 20.04
```

### ⚙️ 1.3 Configure Sysmon

> 📝 Create a comprehensive Sysmon configuration file:

```xml
<!-- sysmon-config.xml -->
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- 🧩 Process Creation -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">/usr/bin/whoami</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- 📁 File Creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">.encrypted</TargetFilename>
        <TargetFilename condition="contains">.locked</TargetFilename>
        <TargetFilename condition="contains">README</TargetFilename>
        <TargetFilename condition="endswith">.txt</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- 🌐 Network Connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <DestinationPort condition="is">443</DestinationPort>
        <DestinationPort condition="is">80</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

```bash
# TODO: Expand FileCreate filters with additional known ransomware extensions (.crypz, .cerber, etc.)
```

### ▶️ 1.4 Start Sysmon Service

```bash
# 🚀 Install and start Sysmon with the configuration
sudo sysmon -accepteula -i sysmon-config.xml
sudo systemctl enable sysmon
sudo systemctl start sysmon

# ✅ Verify Sysmon is running
sudo systemctl status sysmon
sudo sysmon -c

# TODO: Confirm the active config hash matches sysmon-config.xml after any edits
```

---

## 📏 Task 2: Apply Sigma Rules for Ransomware Detection

### 📦 2.1 Install Sigma Framework

```bash
# 📥 Clone and install Sigma
git clone https://github.com/SigmaHQ/sigma.git
cd sigma
pip3 install -r requirements.txt
sudo pip3 install pysigma

# TODO: Pin the Sigma repo to a specific release tag for reproducibility
```

### 📝 2.2 Create Ransomware Detection Rules

> 🔒 Create a custom Sigma rule for ransomware file encryption patterns:

```bash
mkdir -p custom-rules
```

```yaml
# custom-rules/ransomware_file_encryption.yml
title: Ransomware File Encryption Activity
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects potential ransomware file encryption based on file extension changes
author: Security Lab
date: 2024/01/01
references:
    - https://attack.mitre.org/techniques/T1486/
logsource:
    product: sysmon
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains:
            - '.encrypted'
            - '.locked'
            - '.crypto'
            - '.crypt'
    condition: selection
falsepositives:
    - Legitimate encryption software
level: high
tags:
    - attack.impact
    - attack.t1486
```

> ⚙️ Create a rule for suspicious process execution:

```yaml
# custom-rules/ransomware_process_execution.yml
title: Suspicious Ransomware Process Execution
id: 87654321-4321-4321-4321-210987654321
status: experimental
description: Detects execution of processes commonly associated with ransomware
author: Security Lab
date: 2024/01/01
logsource:
    product: sysmon
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wbadmin delete catalog'
            - 'bcdedit /set'
            - 'cipher /w'
    condition: selection
falsepositives:
    - System administration activities
level: high
tags:
    - attack.impact
    - attack.defense_evasion
```

```bash
# TODO: Add a third rule targeting mass file rename/move bursts within a short timeframe
```

### 🧰 2.3 Install Log Analysis Tools

```bash
# 🛠️ Install tools for log processing
sudo apt install -y jq rsyslog
pip3 install sigmac

# TODO: Confirm sigmac output format matches the SIEM backend used in production
```

---

## 🔍 Task 3: Analyze Sysmon Logs for Ransomware Activity

### 🧪 3.1 Generate Test Activity

> 💡 Create a script to simulate ransomware-like behavior:

```bash
#!/bin/bash
# 🎭 simulate_ransomware.sh — Safe Ransomware Behavior Simulation
echo "Simulating ransomware-like activity..."

# 📁 Create test files
mkdir -p /tmp/test_files
for i in {1..5}; do
    echo "Important document $i" > /tmp/test_files/document$i.txt
done

# 🔒 Simulate file encryption (rename files)
for file in /tmp/test_files/*.txt; do
    mv "$file" "$file.encrypted"
done

# 📄 Create ransom note
echo "Your files have been encrypted! Contact us for decryption key." > /tmp/test_files/README_DECRYPT.txt

# 🗑️ Simulate shadow copy deletion attempt (safe simulation)
echo "vssadmin delete shadows /all /quiet" > /tmp/fake_command.log

echo "Simulation complete. Check Sysmon logs for detection."

# TODO: Add a variant simulating slow, staggered encryption to test timing-based rules
```

```bash
chmod +x simulate_ransomware.sh
```

### ▶️ 3.2 Execute Simulation

```bash
# 🚦 Run the simulation to generate log entries
./simulate_ransomware.sh
sleep 5
```

### 📜 3.3 Analyze Sysmon Logs

```bash
# 📖 View recent Sysmon logs
sudo journalctl -u sysmon -n 50 --no-pager

# 📁 Search for file creation events
sudo journalctl -u sysmon | grep -i "EventID.*11" | tail -10

# ⚙️ Search for process creation events
sudo journalctl -u sysmon | grep -i "EventID.*1" | tail -10

# TODO: Pipe journalctl output through `jq` once Sysmon logs are exported as JSON
```

### 🕵️ 3.4 Apply Sigma Rules for Detection

```python
#!/usr/bin/env python3
# 🚨 detect_ransomware.py — Sysmon Log Ransomware Indicator Scanner
import re
import subprocess
import json

def check_file_encryption_indicators():
    """Check for file encryption indicators in Sysmon logs"""
    print("=== Checking for File Encryption Indicators ===")

    result = subprocess.run(['sudo', 'journalctl', '-u', 'sysmon', '-n', '100', '--no-pager'],
                          capture_output=True, text=True)

    logs = result.stdout

    encrypted_patterns = ['.encrypted', '.locked', '.crypto', '.crypt']
    ransom_notes = ['README', 'DECRYPT', 'RANSOM']

    findings = []

    for line in logs.split('\n'):
        for pattern in encrypted_patterns:
            if pattern in line and 'EventID=11' in line:
                findings.append(f"ALERT: Encrypted file detected - {line.strip()}")

        for note in ransom_notes:
            if note in line and 'EventID=11' in line:
                findings.append(f"ALERT: Potential ransom note - {line.strip()}")

    if findings:
        for finding in findings:
            print(finding)
    else:
        print("No file encryption indicators found.")

    return len(findings)

def check_process_indicators():
    """Check for suspicious process execution"""
    print("\n=== Checking for Suspicious Process Indicators ===")

    result = subprocess.run(['sudo', 'journalctl', '-u', 'sysmon', '-n', '100', '--no-pager'],
                          capture_output=True, text=True)

    logs = result.stdout

    suspicious_commands = ['vssadmin delete', 'wbadmin delete', 'bcdedit', 'cipher /w']
    findings = []

    for line in logs.split('\n'):
        for cmd in suspicious_commands:
            if cmd.lower() in line.lower() and 'EventID=1' in line:
                findings.append(f"ALERT: Suspicious command detected - {line.strip()}")

    if findings:
        for finding in findings:
            print(finding)
    else:
        print("No suspicious process indicators found.")

    return len(findings)

def main():
    print("Ransomware Detection Analysis")
    print("=" * 50)

    file_alerts = check_file_encryption_indicators()
    process_alerts = check_process_indicators()

    total_alerts = file_alerts + process_alerts

    print(f"\n=== Summary ===")
    print(f"File encryption alerts: {file_alerts}")
    print(f"Process execution alerts: {process_alerts}")
    print(f"Total alerts: {total_alerts}")

    if total_alerts > 0:
        print("\n⚠️  POTENTIAL RANSOMWARE ACTIVITY DETECTED!")
        print("Recommended actions:")
        print("1. Isolate affected systems")
        print("2. Check backup integrity")
        print("3. Investigate network connections")
        print("4. Review recent user activities")
    else:
        print("\n✅ No ransomware indicators detected in current logs.")

if __name__ == "__main__":
    main()

# TODO: Add a scoring weight system instead of a flat alert count
```

```bash
chmod +x detect_ransomware.py
```

### ▶️ 3.5 Run Detection Analysis

```bash
# 🚦 Execute the detection script
python3 detect_ransomware.py
```

### 📊 3.6 Advanced Log Analysis

```bash
#!/bin/bash
# 📈 advanced_analysis.sh — Comprehensive Sysmon Log Analysis
echo "=== Advanced Sysmon Log Analysis ==="

# 📊 Count events by type
echo "Event Distribution:"
sudo journalctl -u sysmon --no-pager | grep -o 'EventID=[0-9]*' | sort | uniq -c | sort -nr

# ⚡ Look for rapid file modifications
echo -e "\nRapid File Modifications (potential encryption):"
sudo journalctl -u sysmon --since "5 minutes ago" | grep "EventID=11" | wc -l

# 🌐 Check for network connections during file activity
echo -e "\nNetwork Connections:"
sudo journalctl -u sysmon --since "5 minutes ago" | grep "EventID=3" | head -5

# 🕒 Timeline of recent activities
echo -e "\nRecent Activity Timeline:"
sudo journalctl -u sysmon --since "5 minutes ago" --no-pager | tail -10

# TODO: Add a threshold alert if file modification count exceeds a defined baseline
```

```bash
chmod +x advanced_analysis.sh
./advanced_analysis.sh
```

---

## ✅ Verification and Testing

### 🧪 Test Detection Capabilities

```bash
# 🧾 Test 1: Mass file renaming
mkdir -p /tmp/mass_encrypt_test
for i in {1..10}; do
    echo "Test file $i" > /tmp/mass_encrypt_test/file$i.doc
    mv /tmp/mass_encrypt_test/file$i.doc /tmp/mass_encrypt_test/file$i.doc.locked
done

# 📄 Test 2: Ransom note creation
echo "All your files are encrypted!" > /tmp/mass_encrypt_test/HOW_TO_DECRYPT.txt

# ⏳ Wait and analyze
sleep 3
python3 detect_ransomware.py

# TODO: Add a Test 3 covering shadow-copy-deletion command detection specifically
```

**✔️ Expected Result:** `detect_ransomware.py` reports nonzero **File encryption alerts** and **Process execution alerts**, and the summary displays the ⚠️ **POTENTIAL RANSOMWARE ACTIVITY DETECTED!** warning with recommended response actions.

---

## 🧹 Cleanup

```bash
# 🗑️ Remove test files and reset environment
sudo rm -rf /tmp/test_files /tmp/mass_encrypt_test
rm -f simulate_ransomware.sh detect_ransomware.py advanced_analysis.sh

# TODO: Also clear /tmp/fake_command.log and reset Sysmon config if reused for another run
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Artifact |
|---|---|---|---|
| T1486 | Data Encrypted for Impact | Impact | `.encrypted`/`.locked`/`.crypto` file extension detection (Sigma rule) |
| T1490 | Inhibit System Recovery | Impact | `vssadmin delete shadows`, `wbadmin delete catalog` command detection |
| T1561 | Disk Wipe | Impact | `cipher /w` command pattern detection |
| T1112 | Modify Registry | Defense Evasion | `bcdedit /set` command execution detection |
| T1204.002 | User Execution: Malicious File | Execution | Sysmon EventID 1 process creation monitoring |
| T1567 | Exfiltration Over Web Service | Exfiltration | Network connection monitoring on ports 443/80 |

---

## 🧩 Troubleshooting

<details>
<summary>❗ Sysmon fails to install on Ubuntu</summary>

- Confirm the Microsoft package repo was added: `dpkg -l | grep packages-microsoft-prod`
- Match the packages-microsoft-prod.deb URL to your actual Ubuntu version
- Run `sudo apt update` again after adding the repository before installing

</details>

<details>
<summary>❗ Sysmon service won't start</summary>

- Confirm the configuration file loaded without errors: `sudo sysmon -c`
- Check service logs: `sudo journalctl -u sysmon -n 50 --no-pager`
- Re-apply the config with `sudo sysmon -accepteula -i sysmon-config.xml`

</details>

<details>
<summary>❗ No EventID 11 (FileCreate) events appear in logs</summary>

- Confirm the `FileCreate` `RuleGroup` in `sysmon-config.xml` includes the correct `TargetFilename` conditions
- Verify test files are actually being created/renamed under a monitored path
- Restart Sysmon after any configuration changes: `sudo systemctl restart sysmon`

</details>

<details>
<summary>❗ detect_ransomware.py reports no alerts despite simulation</summary>

- Confirm `simulate_ransomware.sh` ran successfully and files were renamed to `.encrypted`
- Increase the `journalctl -n 100` line count if simulation logs have scrolled out of range
- Verify `sudo` permissions allow the script to read `journalctl -u sysmon` output

</details>

<details>
<summary>❗ Sigma rule installation (pysigma/sigmac) errors</summary>

- Confirm `pip3 install -r requirements.txt` completed without dependency conflicts
- Use a virtual environment if system-wide pip installs conflict with existing packages
- Verify Python 3 version compatibility with the installed Sigma/pysigma release

</details>

---

## 🏁 Conclusion

In this lab, you successfully:

**🎯 Key Accomplishments**
- 🛰️ **Sysmon Deployment** — Deployed Sysmon on Linux to capture process creation, file modification, and network connection activity
- 📏 **Sigma Rule Implementation** — Built custom Sigma rules to detect ransomware precursor behaviors such as file encryption patterns and suspicious command execution
- 🔍 **Log Analysis** — Analyzed Sysmon logs using both manual techniques and automated Python scripts to surface ransomware indicators
- 🚨 **Automated Detection** — Created detection scripts that flag suspicious activity based on known ransomware behaviors

**🌍 Real-World Applications**
- 🕵️ **Early Threat Detection** — Proactive monitoring and behavioral analysis are crucial for catching ransomware before encryption completes
- 📏 **Standardized Detection** — Sigma's rule format provides a portable, SIEM-agnostic detection framework
- 🧯 **Incident Response** — Detection scripts and log analysis techniques directly support real-world IR workflows
- 🛡️ **Threat Hunting** — Behavioral indicators learned here extend to hunting for other impact-stage attack techniques

---

<div align="center">

### 🏢 Al Nafi Cloud Security Training Platform

**Blue Team / Threat Intelligence & Digital Forensics Track**

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1E90FF?style=for-the-badge)

</div>
