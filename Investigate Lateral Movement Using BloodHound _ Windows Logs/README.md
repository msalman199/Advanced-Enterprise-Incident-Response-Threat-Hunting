<div align="center">

# 🩸 Investigate Lateral Movement Using BloodHound + Windows Logs

### Active Directory Attack Path Mapping & Log Correlation Lab

![BloodHound](https://img.shields.io/badge/BloodHound-AD_Mapping-DC143C?style=for-the-badge&logo=neo4j&logoColor=white)
![Neo4j](https://img.shields.io/badge/Neo4j-Graph_Database-008CC1?style=for-the-badge&logo=neo4j&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active_Directory-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Lateral Movement](https://img.shields.io/badge/Lateral-Movement-FF4500?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1021-FF6F00?style=for-the-badge&logo=mitre&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📚 Table of Contents

- [🎯 Objectives](#-objectives)
- [📋 Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🐉 Task 1: Set up BloodHound for Active Directory Environment Mapping](#-task-1-set-up-bloodhound-for-active-directory-environment-mapping)
- [📜 Task 2: Analyze Windows Event Logs for Lateral Movement Patterns](#-task-2-analyze-windows-event-logs-for-lateral-movement-patterns)
- [🔗 Task 3: Correlate BloodHound Findings with Event Logs](#-task-3-correlate-bloodhound-findings-with-event-logs)
- [✅ Verification Steps](#-verification-steps)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🧩 Troubleshooting](#-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Objectives

| # | Objective |
|---|-----------|
| 1 | 🐉 Set up BloodHound for Active Directory environment mapping |
| 2 | 📜 Analyze Windows event logs for lateral movement patterns |
| 3 | 🔗 Correlate BloodHound findings with event logs to detect attack paths |
| 4 | 🧠 Identify common lateral movement techniques in enterprise environments |

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| 🏢 Active Directory | Basic understanding of Active Directory concepts |
| 🐧 Linux CLI | Familiarity with Linux command line |
| 📜 Event Log Structure | Knowledge of Windows event logs structure |
| 🌐 Network Security | Understanding of network security fundamentals |

---

## 🖥️ Lab Environment

> ☁️ **Al Nafi** provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — all required software is installed during the lab exercises.

---

## 🐉 Task 1: Set up BloodHound for Active Directory Environment Mapping

### 🔧 Subtask 1.1: Install Required Dependencies

```bash
# 📦 Update system and install Python, Neo4j, and Java
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip openjdk-11-jdk wget curl unzip

# TODO: Confirm Java 11 is the active JDK with `update-alternatives --config java`
```

### 🗄️ Subtask 1.2: Install Neo4j Database

```bash
# 📥 Download and install Neo4j Community Edition
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install neo4j=1:4.4.12

# ⚙️ Configure Neo4j
sudo systemctl enable neo4j
sudo systemctl start neo4j
sudo systemctl status neo4j

# 🔑 Set initial password
sudo neo4j-admin set-initial-password bloodhound123

# TODO: Replace the default bloodhound123 password before using outside an isolated lab
```

### 🩸 Subtask 1.3: Install BloodHound Application

```bash
# 📥 Download and install BloodHound
cd /tmp
wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
sudo mv BloodHound-linux-x64 /opt/bloodhound
sudo chmod +x /opt/bloodhound/BloodHound

# TODO: Verify SHA256 checksum of the downloaded release before extracting
```

### 🐺 Subtask 1.4: Install BloodHound Collectors

```bash
# 📥 Install SharpHound collector
mkdir ~/bloodhound-data
cd ~/bloodhound-data
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1

# 🐍 Install BloodHound Python collector
pip3 install bloodhound

# TODO: Confirm SharpHound.exe version matches the installed BloodHound 4.3.1 release
```

### 🗂️ Subtask 1.5: Create Sample AD Data

> 📝 Generate sample Active Directory data for analysis:

```bash
cd ~/bloodhound-data
cat > sample_ad_data.json << 'EOF'
{
  "computers": [
    {"name": "DC01.corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1000"},
    {"name": "WS01.corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1001"},
    {"name": "WS02.corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1002"}
  ],
  "users": [
    {"name": "admin@corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-500"},
    {"name": "user1@corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1101"},
    {"name": "user2@corp.local", "objectid": "S-1-5-21-1234567890-1234567890-1234567890-1102"}
  ]
}
EOF

# TODO: Add group membership and ACL edges to sample_ad_data.json for richer graph analysis
```

---

## 📜 Task 2: Analyze Windows Event Logs for Lateral Movement Patterns

### 🗒️ Subtask 2.1: Create Sample Windows Event Logs

> 📝 Generate sample Windows event logs containing lateral movement indicators:

```bash
mkdir ~/windows-logs
cd ~/windows-logs

cat > security_events.evtx.csv << 'EOF'
TimeCreated,EventID,Computer,Account,LogonType,SourceIP,TargetComputer
2024-01-15T10:30:00,4624,WS01.corp.local,user1@corp.local,3,192.168.1.100,WS01.corp.local
2024-01-15T10:35:00,4624,WS02.corp.local,user1@corp.local,3,192.168.1.101,WS02.corp.local
2024-01-15T10:40:00,4648,WS01.corp.local,user1@corp.local,2,192.168.1.100,DC01.corp.local
2024-01-15T10:45:00,4624,DC01.corp.local,admin@corp.local,2,192.168.1.101,DC01.corp.local
2024-01-15T10:50:00,5140,DC01.corp.local,admin@corp.local,3,192.168.1.101,\\DC01\ADMIN$
EOF

# TODO: Add EventID 4672 (special privileges assigned) entries to enrich the sample set
```

### 🧰 Subtask 2.2: Install Log Analysis Tools

```bash
# 🛠️ Install tools for log analysis
sudo apt install -y jq csvkit python3-pandas
pip3 install pandas matplotlib seaborn

# TODO: Confirm csvkit and python3-pandas versions don't conflict with pip-installed pandas
```

### 🔍 Subtask 2.3: Analyze Logon Events

```python
#!/usr/bin/env python3
# 🕵️ analyze_logs.py — Lateral Movement Pattern Analyzer
import pandas as pd
import json
from collections import defaultdict

def analyze_lateral_movement(log_file):
    # 📖 Read the CSV file
    df = pd.read_csv(log_file)

    # 🔗 Group by account to track movement
    movement_patterns = defaultdict(list)

    for _, row in df.iterrows():
        account = row['Account']
        computer = row['Computer']
        event_id = row['EventID']
        time = row['TimeCreated']

        movement_patterns[account].append({
            'time': time,
            'computer': computer,
            'event_id': event_id,
            'source_ip': row.get('SourceIP', 'N/A')
        })

    # 🚨 Detect potential lateral movement
    suspicious_accounts = []
    for account, events in movement_patterns.items():
        unique_computers = set([event['computer'] for event in events])
        if len(unique_computers) > 1:
            suspicious_accounts.append({
                'account': account,
                'computers_accessed': list(unique_computers),
                'event_count': len(events)
            })

    return suspicious_accounts

# 🚦 Analyze the logs
results = analyze_lateral_movement('security_events.evtx.csv')
print("Potential Lateral Movement Detected:")
print(json.dumps(results, indent=2))

# TODO: Add a time-window check (e.g. flag only if computers accessed within 15 minutes)
```

```bash
chmod +x analyze_logs.py
python3 analyze_logs.py
```

### 🔑 Subtask 2.4: Extract Key Indicators

```python
#!/usr/bin/env python3
# 📌 extract_indicators.py — Lateral Movement Indicator Extractor
import pandas as pd

def extract_indicators(log_file):
    df = pd.read_csv(log_file)

    # 🔑 Key event IDs for lateral movement
    lateral_movement_events = [4624, 4648, 4672, 5140]

    # 🔍 Filter relevant events
    filtered_df = df[df['EventID'].isin(lateral_movement_events)]

    print("Lateral Movement Indicators:")
    print("=" * 50)

    for _, row in filtered_df.iterrows():
        print(f"Time: {row['TimeCreated']}")
        print(f"Event ID: {row['EventID']}")
        print(f"Account: {row['Account']}")
        print(f"Computer: {row['Computer']}")
        print(f"Source IP: {row.get('SourceIP', 'N/A')}")
        print("-" * 30)

extract_indicators('security_events.evtx.csv')

# TODO: Add EventID 4776 (NTLM authentication) to the lateral_movement_events list
```

```bash
python3 extract_indicators.py
```

---

## 🔗 Task 3: Correlate BloodHound Findings with Event Logs

### 🖥️ Subtask 3.1: Start BloodHound Interface

```bash
# ▶️ Start Neo4j if not running
sudo systemctl start neo4j

# 🚀 Launch BloodHound in background
cd /opt/bloodhound
./BloodHound &

# TODO: Document GUI login steps (bolt://localhost:7687, neo4j / bloodhound123) for lab reviewers
```

> ℹ️ **Note:** BloodHound will open a GUI interface. For this lab, we'll work with the data programmatically.

### 🧬 Subtask 3.2: Create Correlation Script

```python
#!/usr/bin/env python3
# 🔗 correlate_data.py — BloodHound & Windows Log Correlator
import json
import pandas as pd
from datetime import datetime

def load_bloodhound_data(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def correlate_findings(ad_data_file, log_file):
    # 📂 Load BloodHound data
    ad_data = load_bloodhound_data(ad_data_file)

    # 📖 Load Windows logs
    log_df = pd.read_csv(log_file)

    # 🗂️ Extract computer and user lists from AD data
    ad_computers = {comp['name'].lower() for comp in ad_data['computers']}
    ad_users = {user['name'].lower() for user in ad_data['users']}

    print("Correlation Analysis Results:")
    print("=" * 50)

    # 🔍 Check if logged events involve AD assets
    for _, row in log_df.iterrows():
        computer = row['Computer'].lower()
        account = row['Account'].lower()

        if computer in ad_computers and account in ad_users:
            print(f"MATCH FOUND:")
            print(f"  Time: {row['TimeCreated']}")
            print(f"  Event: {row['EventID']}")
            print(f"  Account: {account}")
            print(f"  Computer: {computer}")
            print(f"  Risk Level: HIGH")
            print("-" * 30)

# 🚦 Run correlation
correlate_findings('sample_ad_data.json', 'security_events.evtx.csv')

# TODO: Add a medium-risk tier for events matching only computer OR account, not both
```

```bash
python3 correlate_data.py
```

### 🗺️ Subtask 3.3: Generate Attack Path Analysis

```python
#!/usr/bin/env python3
# 🎯 attack_paths.py — Attack Path Timeline Builder
import json
import pandas as pd
from collections import defaultdict

def analyze_attack_paths(ad_data_file, log_file):
    # 📂 Load data
    with open(ad_data_file, 'r') as f:
        ad_data = json.load(f)

    log_df = pd.read_csv(log_file)

    # 🕒 Build attack timeline
    attack_timeline = []

    for _, row in log_df.iterrows():
        attack_timeline.append({
            'timestamp': row['TimeCreated'],
            'event_id': row['EventID'],
            'account': row['Account'],
            'computer': row['Computer'],
            'source_ip': row.get('SourceIP', 'Unknown')
        })

    # 📅 Sort by timestamp
    attack_timeline.sort(key=lambda x: x['timestamp'])

    print("Potential Attack Path Analysis:")
    print("=" * 50)

    current_account = None
    step = 1

    for event in attack_timeline:
        if event['account'] != current_account:
            print(f"\nStep {step}: Account Compromise")
            print(f"  Account: {event['account']}")
            current_account = event['account']
            step += 1

        print(f"  {event['timestamp']}: Event {event['event_id']} on {event['computer']}")

        if event['event_id'] == 4648:
            print(f"    -> Explicit credential use detected")
        elif event['event_id'] == 5140:
            print(f"    -> Network share access detected")

analyze_attack_paths('sample_ad_data.json', 'security_events.evtx.csv')

# TODO: Add detection annotation for EventID 4672 (special privileges assigned)
```

```bash
python3 attack_paths.py
```

### 📋 Subtask 3.4: Create Investigation Report

```python
#!/usr/bin/env python3
# 📄 generate_report.py — Lateral Movement Investigation Report
import json
import pandas as pd
from datetime import datetime

def generate_investigation_report():
    print("LATERAL MOVEMENT INVESTIGATION REPORT")
    print("=" * 60)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 📖 Load and analyze data
    log_df = pd.read_csv('security_events.evtx.csv')

    print("EXECUTIVE SUMMARY:")
    print("-" * 20)
    print(f"Total Events Analyzed: {len(log_df)}")
    print(f"Unique Accounts: {log_df['Account'].nunique()}")
    print(f"Unique Computers: {log_df['Computer'].nunique()}")
    print()

    print("KEY FINDINGS:")
    print("-" * 20)

    # 🚨 Identify accounts with multiple computer access
    account_computers = log_df.groupby('Account')['Computer'].nunique()
    suspicious_accounts = account_computers[account_computers > 1]

    for account, computer_count in suspicious_accounts.items():
        print(f"• {account}: Accessed {computer_count} different computers")
        computers = log_df[log_df['Account'] == account]['Computer'].unique()
        print(f"  Computers: {', '.join(computers)}")

    print()
    print("RECOMMENDATIONS:")
    print("-" * 20)
    print("• Monitor accounts with cross-system access")
    print("• Implement additional authentication for privileged accounts")
    print("• Review network segmentation policies")
    print("• Enable advanced logging on critical systems")

generate_investigation_report()

# TODO: Export this report to a timestamped file instead of stdout only
```

```bash
python3 generate_report.py
```

---

## ✅ Verification Steps

```bash
# 🩺 Check Neo4j status
sudo systemctl status neo4j

# 📁 Verify BloodHound installation
ls -la /opt/bloodhound/

# 📊 Check analysis results
ls -la ~/windows-logs/
ls -la ~/bloodhound-data/

# ✅ Run final verification
echo "Lab 12 Verification Complete"
echo "BloodHound: $(ls /opt/bloodhound/BloodHound 2>/dev/null && echo 'Installed' || echo 'Not Found')"
echo "Neo4j: $(sudo systemctl is-active neo4j)"
echo "Log Analysis: $(ls ~/windows-logs/*.csv 2>/dev/null | wc -l) files processed"

# TODO: Add a check confirming correlate_data.py produced at least one MATCH FOUND result
```

**✔️ Expected Result:** Neo4j shows `active`, `/opt/bloodhound/BloodHound` exists, `~/windows-logs/*.csv` contains the sample log file, and `correlate_data.py` / `attack_paths.py` output shows detected cross-computer account activity.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Lab Artifact |
|---|---|---|---|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | EventID 5140 `\\DC01\ADMIN$` network share access |
| T1078 | Valid Accounts | Defense Evasion / Persistence | EventID 4624 logons across multiple computers |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Lateral Movement | EventID 4648 explicit credential use |
| T1087 | Account Discovery | Discovery | BloodHound AD user/computer enumeration |
| T1482 | Domain Trust Discovery | Discovery | BloodHound graph-based AD relationship mapping |
| T1078.002 | Valid Accounts: Domain Accounts | Privilege Escalation | Admin account logon to `DC01.corp.local` |

---

## 🧩 Troubleshooting

<details>
<summary>❗ Neo4j fails to start</summary>

- Check status details: `sudo systemctl status neo4j`
- Confirm Java 11 is installed and active: `java -version`
- Review logs: `sudo journalctl -u neo4j -n 50 --no-pager`

</details>

<details>
<summary>❗ BloodHound GUI won't launch</summary>

- Confirm Neo4j is running before launching BloodHound: `sudo systemctl status neo4j`
- Verify the binary has execute permissions: `sudo chmod +x /opt/bloodhound/BloodHound`
- Check for missing GUI/X11 dependencies if running headless — consider a VNC/X11 forwarding setup

</details>

<details>
<summary>❗ neo4j-admin set-initial-password fails</summary>

- Ensure Neo4j service is stopped before setting the initial password, then restart it afterward
- Confirm no password has already been set (initial password can only be set once)
- If already set, reset via `cypher-shell` or by re-initializing the Neo4j data directory

</details>

<details>
<summary>❗ analyze_logs.py or correlate_data.py returns no results</summary>

- Confirm `security_events.evtx.csv` and `sample_ad_data.json` were created exactly as shown
- Check account/computer name casing — the correlation script lowercases both sides for matching
- Verify `pandas` is installed and importable: `python3 -c "import pandas"`

</details>

<details>
<summary>❗ SharpHound.exe / SharpHound.ps1 download fails</summary>

- Confirm outbound internet access to github.com from the lab VM
- Retry the `wget` command; GitHub raw links occasionally rate-limit repeated requests
- Verify the release path still matches the current BloodHound repository structure

</details>

---

## 🏁 Conclusion

You have successfully completed **Lab 12**, where you learned to investigate lateral movement using BloodHound and Windows logs. You accomplished:

**🎯 Key Accomplishments**
- 🐉 **BloodHound Setup** — Installed and configured BloodHound with Neo4j for Active Directory analysis
- 📜 **Log Analysis** — Analyzed Windows event logs to identify lateral movement patterns
- 🔗 **Data Correlation** — Correlated BloodHound findings with event logs to detect attack paths
- 🕵️ **Investigation Skills** — Developed practical skills for detecting and analyzing lateral movement in enterprise environments

**🌍 Real-World Applications**
- 🧯 **Threat Hunting** — Graph-based AD analysis combined with log correlation surfaces attack paths attackers rely on
- 🚨 **Incident Response** — Timeline reconstruction techniques directly support real-world IR investigations
- 🏢 **Security Operations** — Skills transfer directly to SOC analyst and AD security review workflows
- 🛡️ **APT Detection** — Combining graph analysis with traditional logs strengthens detection of advanced persistent threats

---

<div align="center">

### 🏢 Al Nafi Cloud Security Training Platform

**Blue Team / Threat Intelligence & Digital Forensics Track**

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1E90FF?style=for-the-badge)

</div>
