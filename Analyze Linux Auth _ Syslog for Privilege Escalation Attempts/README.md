<div align="center">

# 🔓 Analyze Linux Auth & Syslog for Privilege Escalation Attempts

### Log Parsing, Correlation & Attack Pattern Detection Lab

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Auth Log](https://img.shields.io/badge/auth.log-Analysis-005571?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Syslog](https://img.shields.io/badge/Syslog-Analysis-32CD32?style=for-the-badge&logo=rsyslog&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Scripting-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Privilege Escalation](https://img.shields.io/badge/Privilege-Escalation-DC143C?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![sudo](https://img.shields.io/badge/sudo-Auditing-FF6F00?style=for-the-badge&logo=linux&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1548-FF4500?style=for-the-badge&logo=mitre&logoColor=white)

</div>

---

## 📚 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🔑 Task 1: Parse Linux Authentication Logs](#-task-1-parse-linux-authentication-logs)
- [📈 Task 2: Analyze Syslog Data for Privilege Escalation](#-task-2-analyze-syslog-data-for-privilege-escalation)
- [🔗 Task 3: Correlate Data to Detect Attack Patterns](#-task-3-correlate-data-to-detect-attack-patterns)
- [✅ Verification and Testing](#-verification-and-testing)
- [🧹 Cleanup](#-cleanup)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧩 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | 🔍 Parse and analyze Linux authentication logs for suspicious activity |
| 2 | 📜 Examine syslog data to identify privilege escalation attempts |
| 3 | 🔗 Correlate log data across multiple sources to detect attack patterns |
| 4 | 🛠️ Use command-line tools to investigate security incidents |

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command-line knowledge |
| 🔑 Permissions & sudo | Understanding of user permissions and sudo functionality |
| 📄 Log Formats | Familiarity with log file formats |
| ⚠️ Privilege Escalation | Knowledge of common privilege escalation techniques |

---

## 🖥️ Lab Environment

> ☁️ **Al Nafi** provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated Linux machine. The provided system is bare metal with no pre-installed security tools — all required tools are installed during the lab exercises.

---

## 🔑 Task 1: Parse Linux Authentication Logs

### 🧰 1.1 Install Required Tools

```bash
# 📦 Update package manager
sudo apt update

# 🛠️ Install log analysis tools
sudo apt install -y rsyslog logrotate grep gawk sed

# TODO: Confirm rsyslog service is active with `systemctl status rsyslog`
```

### 👤 1.2 Generate Sample Authentication Events

```bash
# 🧪 Create test user accounts
sudo useradd -m testuser1
sudo useradd -m testuser2
echo "testuser1:password123" | sudo chpasswd
echo "testuser2:admin456" | sudo chpasswd

# 🔐 Generate authentication events
su - testuser1 -c "whoami"
sudo -u testuser2 whoami
ssh localhost -l testuser1 "exit" 2>/dev/null || true

# TODO: Use randomly generated passwords instead of hardcoded values outside this lab
```

### 📖 1.3 Examine Authentication Log Structure

```bash
# 📜 View recent authentication events
sudo tail -20 /var/log/auth.log

# ✅ Parse successful logins
sudo grep "session opened" /var/log/auth.log | tail -10

# ❌ Parse failed login attempts
sudo grep "authentication failure" /var/log/auth.log | tail -10
```

### 🧾 1.4 Extract Key Authentication Data

```bash
#!/bin/bash
# 📊 parse_auth.sh — Authentication Log Parser
echo "=== AUTHENTICATION ANALYSIS ==="
echo "Recent sudo attempts:"
sudo grep "sudo:" /var/log/auth.log | tail -5

echo -e "\nFailed password attempts:"
sudo grep "Failed password" /var/log/auth.log | tail -5

echo -e "\nSuccessful logins:"
sudo grep "session opened" /var/log/auth.log | tail -5

# TODO: Add a count summary line at the end of each section
```

```bash
chmod +x parse_auth.sh
./parse_auth.sh
```

---

## 📈 Task 2: Analyze Syslog Data for Privilege Escalation

### ⚙️ 2.1 Generate Privilege Escalation Events

```bash
# 🎭 Simulate privilege escalation attempts
sudo -u testuser1 sudo whoami 2>/dev/null || echo "Access denied"
sudo -u testuser2 sudo ls /root 2>/dev/null || echo "Access denied"

# 🚩 Add testuser2 to sudo group (simulating successful escalation)
sudo usermod -aG sudo testuser2
sudo -u testuser2 sudo whoami

# TODO: Add a second escalation path simulating group membership via /etc/group edit
```

### 🔍 2.2 Analyze Syslog for Escalation Indicators

```bash
# 🔑 Check for sudo usage patterns
sudo grep -E "(sudo|su):" /var/log/syslog | tail -10

# 👥 Look for user modifications
sudo grep "usermod\|useradd\|userdel" /var/log/syslog | tail -5

# 🧩 Check for group changes
sudo grep "group" /var/log/syslog | grep -E "(add|mod|del)" | tail -5
```

### 🚨 2.3 Create Privilege Escalation Detection Script

```bash
#!/bin/bash
# 🕵️ detect_escalation.sh — Privilege Escalation Detector
echo "=== PRIVILEGE ESCALATION DETECTION ==="

echo "1. Sudo usage by non-privileged users:"
sudo awk '/sudo:/ && !/root/ {print $1, $2, $3, $5, $6}' /var/log/auth.log | tail -5

echo -e "\n2. User account modifications:"
sudo grep -E "usermod|useradd|groupadd" /var/log/syslog | tail -3

echo -e "\n3. Failed sudo attempts:"
sudo grep "sudo.*FAILED" /var/log/auth.log | tail -3

echo -e "\n4. Successful privilege escalation:"
sudo grep "sudo.*root" /var/log/auth.log | tail -3

# TODO: Add a check for SUID/SGID binary changes as an additional escalation indicator
```

```bash
chmod +x detect_escalation.sh
./detect_escalation.sh
```

---

## 🔗 Task 3: Correlate Data to Detect Attack Patterns

### 🕒 3.1 Create Timeline Analysis

```bash
#!/bin/bash
# 📅 timeline_analysis.sh — Security Event Timeline Builder
echo "=== ATTACK TIMELINE ANALYSIS ==="

# 📆 Get current date for filtering
TODAY=$(date +"%b %d")

echo "Timeline of security events for $TODAY:"
{
    sudo grep "$TODAY" /var/log/auth.log | grep -E "(Failed|sudo|su):"
    sudo grep "$TODAY" /var/log/syslog | grep -E "(usermod|useradd|sudo)"
} | sort -k3 -M -k4 -n | tail -10

# TODO: Parameterize the date range instead of hardcoding "today" only
```

```bash
chmod +x timeline_analysis.sh
./timeline_analysis.sh
```

### 🧩 3.2 Pattern Detection Script

```bash
#!/bin/bash
# 🧬 pattern_detection.sh — Attack Pattern Detector
echo "=== ATTACK PATTERN DETECTION ==="

# ⚡ Check for rapid sudo attempts
echo "1. Rapid sudo attempts (potential brute force):"
sudo awk '/sudo:/ {print $3 " " $4 " " $5}' /var/log/auth.log | sort | uniq -c | sort -nr | head -5

# 🔁 Check for privilege escalation after failed attempts
echo -e "\n2. Users with both failed and successful sudo:"
FAILED_USERS=$(sudo grep "sudo.*FAILED" /var/log/auth.log | awk '{print $5}' | sort -u)
for user in $FAILED_USERS; do
    SUCCESS=$(sudo grep "sudo.*$user" /var/log/auth.log | grep -v "FAILED" | wc -l)
    if [ $SUCCESS -gt 0 ]; then
        echo "User $user: Failed attempts followed by success"
    fi
done

# 🌙 Check for unusual time patterns
echo -e "\n3. Off-hours activity (outside 9-17):"
sudo awk '/sudo:/ {
    hour = substr($3, 1, 2)
    if (hour < 9 || hour > 17) print $0
}' /var/log/auth.log | tail -3

# TODO: Make the off-hours window (9-17) configurable via a script argument
```

```bash
chmod +x pattern_detection.sh
./pattern_detection.sh
```

### 📋 3.3 Comprehensive Security Report

```bash
#!/bin/bash
# 📊 security_report.sh — Comprehensive Security Report Generator
echo "=== COMPREHENSIVE SECURITY REPORT ==="
echo "Generated: $(date)"
echo "=========================================="

echo -e "\n1. AUTHENTICATION SUMMARY:"
echo "Total login attempts: $(sudo grep -c "authentication" /var/log/auth.log)"
echo "Failed logins: $(sudo grep -c "Failed password" /var/log/auth.log)"
echo "Successful logins: $(sudo grep -c "session opened" /var/log/auth.log)"

echo -e "\n2. SUDO ACTIVITY:"
echo "Total sudo commands: $(sudo grep -c "sudo:" /var/log/auth.log)"
echo "Failed sudo attempts: $(sudo grep -c "sudo.*FAILED" /var/log/auth.log)"
echo "Unique users using sudo: $(sudo grep "sudo:" /var/log/auth.log | awk '{print $5}' | sort -u | wc -l)"

echo -e "\n3. PRIVILEGE ESCALATION INDICATORS:"
echo "User modifications: $(sudo grep -c -E "usermod|useradd" /var/log/syslog)"
echo "Group modifications: $(sudo grep -c "groupadd\|groupmod" /var/log/syslog)"

echo -e "\n4. TOP SUSPICIOUS ACTIVITIES:"
sudo grep -E "(Failed|sudo.*FAILED|usermod)" /var/log/auth.log /var/log/syslog | tail -5

echo -e "\n5. RECOMMENDATIONS:"
echo "- Monitor users with failed sudo attempts"
echo "- Review off-hours authentication activity"
echo "- Investigate rapid authentication patterns"
echo "- Verify legitimacy of user/group modifications"

# TODO: Export this report to a dated file under ~/security-reports/ instead of stdout only
```

```bash
chmod +x security_report.sh
./security_report.sh
```

### 📡 3.4 Real-Time Monitoring Setup

```bash
#!/bin/bash
# 🔔 realtime_monitor.sh — Live Privilege Escalation Monitor
echo "Starting real-time privilege escalation monitoring..."
echo "Press Ctrl+C to stop"

tail -f /var/log/auth.log | while read line; do
    if echo "$line" | grep -q -E "(sudo|Failed|usermod)"; then
        echo "[ALERT] $(date): $line"
    fi
done

# TODO: Pipe [ALERT] lines to a webhook or email notifier for real production use
```

```bash
chmod +x realtime_monitor.sh
echo "Real-time monitor created. Run './realtime_monitor.sh' to start monitoring."
```

---

## ✅ Verification and Testing

### 🧪 Test Your Analysis Skills

```bash
# 🎯 Generate test scenario
sudo -u testuser1 sudo ls /root 2>/dev/null || echo "Expected failure"
sudo -u testuser2 sudo ls /root
sudo usermod -aG adm testuser1

# 🚦 Run your analysis
./security_report.sh

# TODO: Add an automated pass/fail check comparing report counts to expected test values
```

**✔️ Expected Result:** `security_report.sh` shows nonzero counts for **Total sudo commands**, **Failed sudo attempts**, and **User modifications**, with `testuser2`'s successful escalation and `testuser1`'s expected failure both reflected in the output.

---

## 🧹 Cleanup

```bash
# 🗑️ Remove test users
sudo userdel -r testuser1 2>/dev/null
sudo userdel -r testuser2 2>/dev/null

# 🧽 Remove scripts (optional)
rm -f parse_auth.sh detect_escalation.sh timeline_analysis.sh pattern_detection.sh security_report.sh realtime_monitor.sh

# TODO: Also revert the sudo group membership changes if the base image will be reused
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Artifact |
|---|---|---|---|
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation | `sudo:` usage and `sudo.*FAILED` log patterns |
| T1136.001 | Create Account: Local Account | Persistence | `useradd`/`usermod` syslog entries |
| T1098 | Account Manipulation | Persistence | `usermod -aG sudo` group membership changes |
| T1078.003 | Valid Accounts: Local Accounts | Defense Evasion / Privilege Escalation | Successful sudo escalation after failed attempts |
| T1110 | Brute Force | Credential Access | Rapid repeated sudo/auth attempts pattern detection |
| T1021.004 | Remote Services: SSH | Lateral Movement | `ssh localhost -l testuser1` authentication event |

---

## 🧩 Troubleshooting

<details>
<summary>❗ /var/log/auth.log or /var/log/syslog not found</summary>

- Confirm `rsyslog` is installed and running: `sudo systemctl status rsyslog`
- Some distributions log to `/var/log/secure` instead — check with `ls /var/log/`
- Restart rsyslog if logs aren't being written: `sudo systemctl restart rsyslog`

</details>

<details>
<summary>❗ useradd or chpasswd commands fail</summary>

- Confirm you have sudo privileges: `sudo -l`
- Check if the username already exists: `id testuser1`
- Verify disk space is available for home directory creation: `df -h /home`

</details>

<details>
<summary>❗ grep commands return no results</summary>

- Confirm the test events were actually generated in Subtask 1.2 / 2.1
- Check log rotation hasn't already archived recent entries: `ls /var/log/auth.log*`
- Some systems buffer syslog writes briefly — wait a few seconds and re-run

</details>

<details>
<summary>❗ pattern_detection.sh shows no rapid sudo attempts</summary>

- Confirm multiple sudo commands were run in quick succession during testing
- Check the `awk` field positions match your system's actual auth.log format (may vary by distro)
- Increase the test scenario's command count to generate a clearer pattern

</details>

<details>
<summary>❗ realtime_monitor.sh shows no alerts</summary>

- Confirm the script is actively tailing the correct log file path
- Trigger a new event (e.g. `sudo whoami`) in a separate terminal while it's running
- Check that `/var/log/auth.log` is the log being written to on your distribution

</details>

---

## 🏁 Conclusion

You have successfully completed a comprehensive analysis of Linux authentication and system logs for privilege escalation detection. You learned to:

**🎯 Key Accomplishments**
- 🔑 **Authentication Log Parsing** — Parsed logs to identify login patterns and failures
- 📜 **Syslog Analysis** — Analyzed syslog data for system-level privilege changes
- 🔗 **Multi-Source Correlation** — Correlated multiple log sources to detect attack patterns
- 🛠️ **Automated Monitoring** — Created automated scripts for ongoing security monitoring

**🌍 Real-World Applications**
- 🕵️ **Security Analysis** — Techniques directly applicable for security analysts investigating Linux hosts
- 🖥️ **System Administration** — Skills essential for sysadmins auditing user/group changes
- 🧯 **Incident Response** — Timeline and pattern detection methods support real-world IR investigations
- 🛡️ **Proactive Defense** — Detecting both successful attacks and attempted breaches enables early intervention

---

<div align="center">

### 🏢 Al Nafi Cloud Security Training Platform

**Blue Team / Threat Intelligence & Digital Forensics Track**

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1E90FF?style=for-the-badge)

</div>
