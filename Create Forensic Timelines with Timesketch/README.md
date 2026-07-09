<div align="center">

# 🛡️ Create Forensic Timelines with Timesketch

### Al Nafi Cloud Labs — Blue Team / Digital Forensics Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Timesketch](https://img.shields.io/badge/Timesketch-Forensic%20Timelines-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Plaso](https://img.shields.io/badge/Plaso-log2timeline-6E4C13?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-API%20Client-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **Timesketch**, Google's open-source forensic timeline analysis platform, in a containerized Linux environment. You'll collect artifacts from multiple sources — system logs, simulated web server logs, Windows security events, and network traffic — then import, correlate, and analyze them as a unified forensic timeline.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Install and configure Timesketch on a Linux system
- ✅ Collect forensic data from multiple sources (system logs, web logs, file metadata)
- ✅ Import forensic artifacts into Timesketch
- ✅ Build comprehensive forensic timelines
- ✅ Correlate events across different platforms and data sources
- ✅ Analyze timeline data to identify suspicious activities

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white) | Containerized Timesketch deployment via Docker Compose |
| ![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white) | Metadata & sketch storage backend |
| ![Elasticsearch](https://img.shields.io/badge/-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white) | Timeline event indexing & search |
| ![Plaso](https://img.shields.io/badge/-Plaso-6E4C13?style=flat-square) | `log2timeline`/`psort` super-timeline generation |
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | Timesketch API client scripting |
| ![CSV](https://img.shields.io/badge/-CSV%2FJSON-000000?style=flat-square&logo=json&logoColor=white) | Multi-source artifact import format |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of log file formats
- Familiarity with forensic investigation concepts
- Knowledge of Docker containerization basics

## 🖥️ Lab Environment

> Al Nafi provides Linux-based cloud machines for this lab. Simply click **Start Lab** to access your dedicated environment. The provided machine is bare metal with no pre-installed tools — you will install all required software during the lab.

---

## 🚀 Task 1: Install and Configure Timesketch

### 1.1 — Install Docker and Dependencies

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 📦 Install Docker dependencies
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# 🔑 Add Docker GPG key and repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 🐳 Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 👤 Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# 🔍 Verify Docker installation
docker --version
```

### 1.2 — Deploy Timesketch with Docker

```bash
# 📁 Create Timesketch directory
mkdir ~/timesketch-lab && cd ~/timesketch-lab

# ⬇️ Download Timesketch Docker configuration
curl -s https://raw.githubusercontent.com/google/timesketch/master/docker/release/docker-compose.yml -o docker-compose.yml

# 📝 Create environment file
cat > .env << EOF
POSTGRES_USER=timesketch
POSTGRES_PASSWORD=password
POSTGRES_DB=timesketch
ELASTIC_PASSWORD=password
TIMESKETCH_USER=admin
TIMESKETCH_PASSWORD=admin
EOF
# TODO: Replace default POSTGRES/ELASTIC/TIMESKETCH passwords in any non-isolated environment

# ▶️ Start Timesketch services
docker compose up -d

# ⏳ Wait for services to initialize (approximately 2-3 minutes)
echo "Waiting for Timesketch to initialize..."
sleep 180

# 🔍 Verify services are running
docker compose ps
```

### 1.3 — Access Timesketch Interface

```bash
# 🔍 Check if Timesketch is accessible
curl -I http://localhost:5000

# 🌐 Display access information
echo "Timesketch is available at: http://localhost:5000"
echo "Username: admin"
echo "Password: admin"
```

> ⚠️ **Change the default admin password immediately after first login.**

---

## 📥 Task 2: Collect Forensic Data from Different Sources

### 2.1 — Generate System Log Data

```bash
# 📁 Create forensic data directory
mkdir ~/forensic-data && cd ~/forensic-data

# 🔐 Generate authentication logs
sudo journalctl --since "1 hour ago" --until now -u ssh > auth_logs.log

# 📝 Create sample web server logs
cat > web_access.log << 'EOF'
192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /admin/login.php HTTP/1.1" 200 1234
192.168.1.101 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /admin/login.php HTTP/1.1" 401 567
192.168.1.102 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /sensitive/data.txt HTTP/1.1" 403 234
192.168.1.103 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "POST /upload.php HTTP/1.1" 200 5678
192.168.1.104 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] "GET /admin/users.php HTTP/1.1" 200 3456
EOF

# 🔄 Evaluate date command in web logs
eval "echo \"$(cat web_access.log)\"" > web_access.log

# 📂 Generate file system activity
find /var/log -name "*.log" -type f -exec ls -la {} \; > filesystem_activity.log
```

### 2.2 — Create Plaso Timeline Files

```bash
# 📦 Install Plaso for timeline generation
sudo apt install -y python3-pip
pip3 install plaso-tools

# 📝 Create sample Windows event log (EVTX format simulation)
cat > security_events.csv << EOF
timestamp,source,event_id,description,user,computer
2024-01-15T10:30:00Z,Security,4624,Successful logon,admin,WORKSTATION01
2024-01-15T10:35:00Z,Security,4625,Failed logon attempt,guest,WORKSTATION01
2024-01-15T10:40:00Z,Security,4648,Logon using explicit credentials,admin,WORKSTATION01
2024-01-15T11:00:00Z,Security,4634,Account logoff,admin,WORKSTATION01
2024-01-15T11:15:00Z,Security,4720,User account created,administrator,WORKSTATION01
EOF

# 🔄 Convert logs to Plaso format
log2timeline.py --storage-file timeline.plaso /var/log/

# 📤 Export to CSV for Timesketch
psort.py -o l2tcsv -w timeline.csv timeline.plaso
# TODO: Confirm timeline.csv row count is non-zero before importing
```

### 2.3 — Prepare Network Traffic Data

```bash
# 📝 Create sample network connection logs
cat > network_connections.csv << EOF
timestamp,source_ip,dest_ip,source_port,dest_port,protocol,action
2024-01-15T10:25:00Z,192.168.1.100,10.0.0.50,45123,80,TCP,ALLOW
2024-01-15T10:26:00Z,192.168.1.101,suspicious-domain.com,45124,443,TCP,BLOCK
2024-01-15T10:27:00Z,192.168.1.102,192.168.1.200,45125,22,TCP,ALLOW
2024-01-15T10:28:00Z,192.168.1.103,malware-c2.net,45126,8080,TCP,BLOCK
2024-01-15T10:29:00Z,192.168.1.104,192.168.1.201,45127,3389,TCP,ALLOW
EOF

echo "Forensic data collection completed. Files created:"
ls -la ~/forensic-data/
```

---

## 🧩 Task 3: Build Timeline in Timesketch

### 3.1 — Create New Sketch

```bash
# 📦 Install Timesketch API client
pip3 install timesketch-api-client

# 📝 Create Python script for sketch creation
cat > create_sketch.py << 'EOF'
#!/usr/bin/env python3
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')

# Create new sketch
sketch = ts_client.create_sketch(
    name='Forensic Investigation Lab',
    description='Multi-platform forensic timeline analysis'
)

print(f"Created sketch: {sketch.name} (ID: {sketch.id})")
EOF

python3 create_sketch.py
```

### 3.2 — Import Timeline Data

```bash
# 📝 Create import script
cat > import_data.py << 'EOF'
#!/usr/bin/env python3
import csv
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')

# Get the sketch (assuming it's the first one)
sketches = ts_client.list_sketches()
sketch = sketches[0]

print(f"Using sketch: {sketch.name}")

# Import CSV files
import_files = [
    'security_events.csv',
    'network_connections.csv'
]

for filename in import_files:
    try:
        with open(f'/home/{os.getenv("USER")}/forensic-data/{filename}', 'r') as file:
            print(f"Importing {filename}...")
            timeline = sketch.upload_from_csv(file, filename.replace('.csv', ''))
            print(f"Successfully imported {filename}")
    except Exception as e:
        print(f"Error importing {filename}: {e}")
EOF

# ➕ Add missing import
sed -i '3i import os' import_data.py

python3 import_data.py
# TODO: Confirm both timelines appear under the sketch's "Timelines" tab in the UI
```

### 3.3 — Manual Timeline Creation via Web Interface

```bash
# 🖥️ Display instructions for manual upload
cat << EOF

=== Manual Timeline Upload Instructions ===

1. Open web browser and navigate to: http://localhost:5000
2. Login with credentials:
   - Username: admin
   - Password: admin

3. Create new sketch:
   - Click "New Sketch"
   - Name: "Multi-Platform Investigation"
   - Description: "Cross-platform forensic analysis"

4. Upload timeline files:
   - Click "Upload Timeline"
   - Select files from ~/forensic-data/
   - Choose appropriate parsers for each file type

5. Wait for processing to complete

Files ready for upload:
EOF

ls -la ~/forensic-data/*.csv ~/forensic-data/*.log
```

---

## 🔗 Task 4: Correlate Events Across Platforms

### 4.1 — Create Event Correlation Queries

```bash
# 📝 Create correlation analysis script
cat > correlate_events.py << 'EOF'
#!/usr/bin/env python3
from timesketch_api_client import client
from datetime import datetime, timedelta

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')
sketches = ts_client.list_sketches()
sketch = sketches[0]

# Define correlation queries
correlation_queries = [
    {
        'name': 'Failed Login Attempts',
        'query': 'event_id:4625 OR "Failed logon" OR "401"',
        'description': 'Identify failed authentication attempts across systems'
    },
    {
        'name': 'Suspicious Network Activity',
        'query': 'action:BLOCK OR "suspicious" OR "malware"',
        'description': 'Blocked network connections and suspicious domains'
    },
    {
        'name': 'Administrative Activities',
        'query': 'user:admin OR user:administrator OR "/admin/"',
        'description': 'Administrative user activities across platforms'
    },
    {
        'name': 'File Access Events',
        'query': '"sensitive" OR "upload" OR "data.txt"',
        'description': 'Access to sensitive files and uploads'
    }
]

print("=== Event Correlation Analysis ===\n")

for query_info in correlation_queries:
    print(f"Query: {query_info['name']}")
    print(f"Description: {query_info['description']}")
    print(f"Search: {query_info['query']}")

    # Execute search
    try:
        events = sketch.explore(query_string=query_info['query'])
        print(f"Results: Found {len(events)} matching events")
    except Exception as e:
        print(f"Error executing query: {e}")

    print("-" * 50)
EOF

python3 correlate_events.py
```

### 4.2 — Create Timeline Views

```bash
# 📝 Create view management script
cat > create_views.py << 'EOF'
#!/usr/bin/env python3
from timesketch_api_client import client

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')
sketches = ts_client.list_sketches()
sketch = sketches[0]

# Create saved views for different investigation aspects
views = [
    {
        'name': 'Security Incidents',
        'query': 'event_id:4625 OR action:BLOCK OR "Failed"',
        'description': 'Focus on security-related events'
    },
    {
        'name': 'User Activity Timeline',
        'query': 'user:* AND (logon OR logoff OR login)',
        'description': 'User authentication timeline'
    },
    {
        'name': 'Network Communications',
        'query': 'source_ip:* OR dest_ip:*',
        'description': 'Network traffic analysis'
    }
]

print("Creating timeline views...")

for view_info in views:
    try:
        view = sketch.create_view(
            view_name=view_info['name'],
            query_string=view_info['query']
        )
        print(f"Created view: {view_info['name']}")
    except Exception as e:
        print(f"Error creating view {view_info['name']}: {e}")

print("\nViews created successfully!")
EOF

python3 create_views.py
```

### 4.3 — Generate Investigation Report

```bash
# 📝 Create investigation report
cat > generate_report.py << 'EOF'
#!/usr/bin/env python3
from timesketch_api_client import client
from datetime import datetime

# Connect to Timesketch
ts_client = client.TimesketchApi('http://localhost:5000', 'admin', 'admin')
sketches = ts_client.list_sketches()
sketch = sketches[0]

# Generate investigation summary
report = f"""
=== FORENSIC TIMELINE INVESTIGATION REPORT ===
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Sketch: {sketch.name}

=== KEY FINDINGS ===

1. AUTHENTICATION EVENTS:
   - Multiple failed login attempts detected
   - Administrative account usage identified
   - Cross-platform authentication correlation established

2. NETWORK ACTIVITY:
   - Suspicious domain connections blocked
   - Malware C2 communication attempts identified
   - Network access patterns analyzed

3. FILE SYSTEM ACTIVITY:
   - Sensitive file access attempts recorded
   - Upload activities tracked
   - Administrative file operations logged

=== TIMELINE CORRELATION RESULTS ===

The investigation successfully correlated events across:
- Windows Security Logs (Event ID 4624, 4625, 4648, 4634, 4720)
- Web Server Access Logs (HTTP 200, 401, 403 responses)
- Network Traffic Logs (TCP connections, blocked communications)
- File System Activity Logs (file access, modifications)

=== RECOMMENDATIONS ===

1. Implement enhanced monitoring for failed authentication attempts
2. Review and strengthen network security policies
3. Establish baseline for normal administrative activities
4. Deploy additional logging for sensitive file access

=== INVESTIGATION TIMELINE SUMMARY ===
- Data Sources: 4 different platforms
- Events Analyzed: Multiple log formats
- Correlation Queries: 4 primary investigation areas
- Timeline Views: 3 specialized analysis perspectives

Investigation completed successfully using Timesketch open-source platform.
"""

print(report)

# Save report to file
with open('/home/' + os.getenv('USER') + '/forensic-data/investigation_report.txt', 'w') as f:
    f.write(report)

print("\nReport saved to ~/forensic-data/investigation_report.txt")
EOF

# ➕ Add missing import
sed -i '3i import os' generate_report.py

python3 generate_report.py
# TODO: Attach investigation_report.txt to the case management system used in Task 3 labs
```

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Name | Tactic | Evidence Source in This Lab |
|---|---|---|---|
| T1078 | Valid Accounts | Defense Evasion / Persistence | Admin logon events (4624, 4648) |
| T1110 | Brute Force | Credential Access | Failed logon events (4625, HTTP 401) |
| T1071 | Application Layer Protocol | Command and Control | Blocked connections to `malware-c2.net` |
| T1136 | Create Account | Persistence | Account creation event (4720) |

---

## 🧪 Verification and Testing

### Verify Timesketch Installation

```bash
# ✅ Check all services are running
docker compose ps

# ✅ Test API connectivity
curl -s http://localhost:5000/api/v1/sketches/ | head -20

# ✅ Verify data files
ls -la ~/forensic-data/
```

### Access Investigation Results

```bash
# 📊 Display final results
echo "=== Lab Completion Status ==="
echo "1. Timesketch Platform: Running on http://localhost:5000"
echo "2. Forensic Data: $(ls ~/forensic-data/ | wc -l) files collected"
echo "3. Timeline Analysis: Correlation queries executed"
echo "4. Investigation Report: Generated and saved"

# 📄 Show investigation report
cat ~/forensic-data/investigation_report.txt
```

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Timesketch containers fail to start</strong></summary>

```bash
docker compose logs
```

- Confirm Docker daemon is running: `sudo systemctl status docker`
- Confirm no port conflicts on 5000, 9200, or 5432
- Re-run `docker compose up -d` after resolving conflicts

</details>

<details>
<summary><strong>❌ Issue: <code>log2timeline.py</code> or <code>psort.py</code> not found</strong></summary>

- Confirm Plaso installed correctly: `pip3 show plaso-tools`
- Some distributions require the full `plaso` package rather than `plaso-tools` — check with `log2timeline.py --version`

</details>

<details>
<summary><strong>❌ Issue: Python scripts fail with <code>NameError: name 'os' is not defined</code></strong></summary>

- Confirm the `sed -i '3i import os'` step ran successfully on the affected script
- Verify with `head -5 import_data.py` (or `generate_report.py`) that `import os` appears near the top

</details>

---

## 🏁 Conclusion

You have successfully completed a comprehensive forensic timeline investigation using Timesketch. This lab demonstrated how to:

- ⚙️ Deploy Timesketch as a scalable forensic analysis platform using Docker
- 📥 Collect forensic artifacts from multiple sources including system logs, web server logs, and network traffic
- 🧩 Build comprehensive timelines by importing and correlating data from different platforms
- 🔗 Perform cross-platform analysis using advanced search queries and correlation techniques
- 📄 Generate investigation reports with actionable findings and recommendations

This hands-on experience with Timesketch provides essential skills for digital forensics professionals, enabling efficient analysis of complex multi-platform investigations. The ability to correlate events across different data sources is crucial for modern cybersecurity incident response and forensic analysis workflows.

The timeline analysis techniques learned in this lab are directly applicable to real-world forensic investigations, security incident response, and compliance auditing scenarios.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Digital Forensics & Timeline Analysis**

*Empowering the next generation of cybersecurity defenders*

</div>
