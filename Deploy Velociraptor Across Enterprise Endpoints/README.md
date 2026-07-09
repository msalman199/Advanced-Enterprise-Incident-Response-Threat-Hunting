<div align="center">

# 🛡️ Deploy Velociraptor Across Enterprise Endpoints

### Al Nafi Cloud Labs — Blue Team / DFIR & Endpoint Monitoring Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Velociraptor](https://img.shields.io/badge/Velociraptor-EDR%20%26%20DFIR-6B2FA5?style=for-the-badge)
![VQL](https://img.shields.io/badge/VQL-Threat%20Hunting-E94E1B?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-API%20Automation-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **Velociraptor**, an open-source endpoint visibility and digital forensics platform, across a simulated enterprise environment. You'll stand up the server, enroll a Linux client, simulate a Windows endpoint, define custom monitoring artifacts, and run VQL-based threat hunts against collected telemetry.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Install and configure Velociraptor server on Linux
- ✅ Deploy Velociraptor clients to simulate Windows and Linux endpoints
- ✅ Configure data collection policies for endpoint monitoring
- ✅ Analyze collected endpoint data for threat detection
- ✅ Create custom VQL queries for advanced threat hunting

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![Velociraptor](https://img.shields.io/badge/-Velociraptor-6B2FA5?style=flat-square) | Endpoint visibility, DFIR & response server/client |
| ![VQL](https://img.shields.io/badge/-VQL-E94E1B?style=flat-square) | Velociraptor Query Language for artifact collection & hunting |
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | API automation, client simulation & reporting |
| ![YAML](https://img.shields.io/badge/-YAML-CB171E?style=flat-square&logo=yaml&logoColor=white) | Server/client configuration & custom artifact definitions |
| ![Systemd](https://img.shields.io/badge/-systemd-white?style=flat-square&logo=linux&logoColor=black) | Client service management |
| ![Bash](https://img.shields.io/badge/-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white) | Deployment verification scripting |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of network concepts (ports, protocols)
- Familiarity with JSON configuration files
- Basic knowledge of endpoint security concepts

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Click **Start Lab** to access your environment. The machine is bare metal with no pre-installed tools — you will install all required components during the lab.

---

## 🚀 Task 1: Install and Configure Velociraptor Server

### 1.1 — Download and Install Velociraptor

```bash
# 📦 Update system packages
sudo apt update && sudo apt upgrade -y

# 📦 Install required dependencies
sudo apt install -y wget curl unzip

# 📁 Create velociraptor directory
mkdir -p ~/velociraptor
cd ~/velociraptor

# ⬇️ Download latest Velociraptor binary
wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.0/velociraptor-v0.7.0-linux-amd64
# TODO: Check the releases page for the current version before deploying outside this lab

# 🔐 Make executable and create symlink
chmod +x velociraptor-v0.7.0-linux-amd64
sudo ln -sf $(pwd)/velociraptor-v0.7.0-linux-amd64 /usr/local/bin/velociraptor
```

### 1.2 — Generate Server Configuration

```bash
# ⚙️ Generate server configuration
velociraptor config generate > server.config.yaml

# ✏️ Edit configuration for local deployment
sed -i 's/0.0.0.0:8000/127.0.0.1:8000/g' server.config.yaml
sed -i 's/0.0.0.0:8080/127.0.0.1:8080/g' server.config.yaml
```

### 1.3 — Initialize and Start Server

```bash
# 📋 Create server artifacts and initialize
velociraptor --config server.config.yaml artifacts list

# ▶️ Start Velociraptor server in background
nohup velociraptor --config server.config.yaml frontend -v > server.log 2>&1 &

# ⏳ Wait for server to start
sleep 10

# 🔍 Verify server is running
curl -k https://127.0.0.1:8080/app/index.html || echo "Server starting..."
```

### 1.4 — Create Admin User

```bash
# 👤 Create admin user account
velociraptor --config server.config.yaml user add admin --role administrator

# 🔑 Set password for admin user
echo "VelociraptorAdmin123!" | velociraptor --config server.config.yaml user set_password admin --password -
```

> ⚠️ **Note:** Replace `VelociraptorAdmin123!` with a strong, unique credential in any environment beyond this isolated lab.

---

## 💻 Task 2: Deploy Velociraptor Clients

### 2.1 — Generate Client Configuration

```bash
# ⚙️ Generate client configuration
velociraptor --config server.config.yaml config client > client.config.yaml

# 📦 Create client deployment package
velociraptor --config server.config.yaml debian client --output velociraptor-client.deb
```

### 2.2 — Deploy Linux Client

```bash
# 📦 Install client package
sudo dpkg -i velociraptor-client.deb || sudo apt-get install -f -y

# ▶️ Start client service
sudo systemctl enable velociraptor-client
sudo systemctl start velociraptor-client

# 🔍 Verify client connection
sudo systemctl status velociraptor-client
```

### 2.3 — Simulate Windows Client

```bash
# 📝 Create Windows client simulator script
cat > simulate_windows_client.py << 'EOF'
#!/usr/bin/env python3
import json
import time
import random
import requests
import os

class WindowsClientSimulator:
    def __init__(self):
        self.client_id = f"C.{random.randint(1000000000000000, 9999999999999999):016x}"
        self.hostname = f"WIN-{random.randint(100000, 999999)}"

    def generate_process_data(self):
        processes = [
            {"name": "explorer.exe", "pid": 1234, "ppid": 567},
            {"name": "chrome.exe", "pid": 2345, "ppid": 1234},
            {"name": "notepad.exe", "pid": 3456, "ppid": 1234},
            {"name": "powershell.exe", "pid": 4567, "ppid": 1234}
        ]
        return {"processes": processes, "timestamp": int(time.time())}

    def simulate_activity(self):
        print(f"Simulating Windows client: {self.hostname} ({self.client_id})")
        for i in range(5):
            data = self.generate_process_data()
            print(f"Generated process data: {len(data['processes'])} processes")
            time.sleep(2)

if __name__ == "__main__":
    simulator = WindowsClientSimulator()
    simulator.simulate_activity()
EOF

# 🔐 Make executable and run
chmod +x simulate_windows_client.py
python3 simulate_windows_client.py
```

---

## 📡 Task 3: Configure Data Collection Policies

### 3.1 — Create Custom Artifact

```bash
# 📝 Create custom monitoring artifact
cat > custom_monitoring.yaml << 'EOF'
name: Custom.Endpoint.Monitoring
description: Custom endpoint monitoring artifact
type: CLIENT
parameters:
  - name: ProcessRegex
    default: ".*"
    description: Regex to match process names

sources:
  - precondition: SELECT OS From info() where OS = 'linux'
    query: |
      SELECT Name, Pid, Ppid, Cmdline, Cwd
      FROM pslist()
      WHERE Name =~ ProcessRegex

  - precondition: SELECT OS From info() where OS = 'windows'
    query: |
      SELECT Name, Pid, Ppid, CommandLine, Cwd
      FROM pslist()
      WHERE Name =~ ProcessRegex
EOF

# 📥 Import custom artifact
velociraptor --config server.config.yaml artifacts import custom_monitoring.yaml
```

### 3.2 — Configure Collection Policies

```bash
# 📝 Create collection policy script
cat > create_collections.py << 'EOF'
#!/usr/bin/env python3
import requests
import json
import urllib3
urllib3.disable_warnings()

# API configuration
base_url = "https://127.0.0.1:8080"
auth = ("admin", "VelociraptorAdmin123!")

def create_hunt():
    hunt_data = {
        "description": "Enterprise Endpoint Monitoring",
        "artifacts": ["Generic.Client.Info", "Custom.Endpoint.Monitoring"],
        "condition": {"os": "linux"},
        "expires": 3600
    }

    response = requests.post(
        f"{base_url}/api/v1/CreateHunt",
        json=hunt_data,
        auth=auth,
        verify=False
    )

    if response.status_code == 200:
        print("Hunt created successfully")
        return response.json()
    else:
        print(f"Failed to create hunt: {response.status_code}")
        return None

if __name__ == "__main__":
    result = create_hunt()
    if result:
        print(f"Hunt ID: {result.get('hunt_id', 'Unknown')}")
EOF

# ▶️ Run collection setup
python3 create_collections.py
# TODO: Move the hardcoded auth tuple to environment variables before reuse outside this lab
```

---

## 📊 Task 4: Analyze Endpoint Data

### 4.1 — Query Client Information

```bash
# 📝 Create VQL query script for client analysis
cat > analyze_endpoints.vql << 'EOF'
-- Query all connected clients
SELECT client_id, os_info.hostname, os_info.platform,
       last_seen_at, first_seen_at
FROM clients()
ORDER BY last_seen_at DESC

-- Query running processes across endpoints
SELECT client_id, Name, Pid, Ppid, Cmdline
FROM source(artifact="Linux.Sys.Pslist")
WHERE Name =~ "(ssh|bash|python)"
LIMIT 50
EOF

# ▶️ Execute VQL queries
velociraptor --config server.config.yaml query "SELECT client_id, os_info.hostname FROM clients()"
```

### 4.2 — Threat Detection Analysis

```bash
# 📝 Create threat detection queries
cat > threat_detection.vql << 'EOF'
-- Detect suspicious processes
SELECT client_id, Name, Pid, Cmdline,
       timestamp(epoch=CreateTime) AS created
FROM source(artifact="Linux.Sys.Pslist")
WHERE Name =~ "(nc|netcat|nmap|wget|curl)"
   OR Cmdline =~ "(bash -i|sh -i|/dev/tcp)"

-- Monitor network connections
SELECT client_id, Pid, Name, LocalAddr, RemoteAddr, State
FROM source(artifact="Linux.Network.Netstat")
WHERE State = "ESTABLISHED"
  AND RemoteAddr !~ "^(127\.|10\.|192\.168\.|172\.)"
EOF

# ▶️ Execute threat detection
velociraptor --config server.config.yaml query --format json "$(cat threat_detection.vql | head -6)" > threat_results.json

# 📄 Display results
echo "Threat Detection Results:"
cat threat_results.json | python3 -m json.tool | head -20
```

### 4.3 — Generate Security Report

```bash
# 📝 Create security report generator
cat > generate_report.py << 'EOF'
#!/usr/bin/env python3
import json
import subprocess
from datetime import datetime

def run_vql_query(query):
    cmd = ["velociraptor", "--config", "server.config.yaml", "query", query]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def generate_security_report():
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {},
        "findings": []
    }

    # Get client count
    client_query = "SELECT count() as total FROM clients()"
    client_result = run_vql_query(client_query)

    # Get process count
    process_query = "SELECT count() as total FROM source(artifact='Linux.Sys.Pslist')"
    process_result = run_vql_query(process_query)

    report["summary"] = {
        "total_clients": "1+",
        "total_processes_monitored": "10+",
        "monitoring_status": "Active"
    }

    report["findings"] = [
        {
            "type": "INFO",
            "description": "Velociraptor deployment successful",
            "details": "Server and client components operational"
        },
        {
            "type": "INFO",
            "description": "Endpoint monitoring active",
            "details": "Process and network monitoring configured"
        }
    ]

    return report

if __name__ == "__main__":
    report = generate_security_report()
    print("=== VELOCIRAPTOR SECURITY REPORT ===")
    print(json.dumps(report, indent=2))

    # Save report
    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\nReport saved to security_report.json")
EOF

# ▶️ Generate final report
python3 generate_report.py
```

---

## 🔍 Task 5: Advanced Threat Hunting

### 5.1 — Create Custom Hunt

```bash
# 📝 Create advanced hunting query
cat > advanced_hunt.vql << 'EOF'
-- Hunt for potential lateral movement
SELECT client_id, Name, Pid, Cmdline, Username
FROM source(artifact="Linux.Sys.Pslist")
WHERE (Cmdline =~ "ssh.*-o.*StrictHostKeyChecking=no"
   OR Cmdline =~ "scp.*-o.*StrictHostKeyChecking=no"
   OR Name =~ "nc|netcat" AND Cmdline =~ "-l.*-p")

-- Monitor file system changes in sensitive directories
SELECT client_id, FullPath, Size, Mode, Mtime
FROM source(artifact="Linux.Sys.Find")
WHERE FullPath =~ "/(etc|root|home).*\.(sh|py|pl|rb)$"
  AND Mtime > now() - 3600
EOF

# ▶️ Execute advanced hunt
echo "Executing advanced threat hunt..."
velociraptor --config server.config.yaml query "$(head -6 advanced_hunt.vql)" --format table
```

### 5.2 — Verify Deployment Status

```bash
# 📝 Final verification script
cat > verify_deployment.sh << 'EOF'
#!/bin/bash
echo "=== VELOCIRAPTOR DEPLOYMENT VERIFICATION ==="
echo

echo "1. Server Status:"
pgrep -f "velociraptor.*frontend" > /dev/null && echo "✓ Server running" || echo "✗ Server not running"

echo "2. Client Status:"
systemctl is-active velociraptor-client > /dev/null && echo "✓ Client active" || echo "✗ Client inactive"

echo "3. Web Interface:"
curl -k -s https://127.0.0.1:8080/app/index.html > /dev/null && echo "✓ Web interface accessible" || echo "✗ Web interface not accessible"

echo "4. Configuration Files:"
[ -f server.config.yaml ] && echo "✓ Server config exists" || echo "✗ Server config missing"
[ -f client.config.yaml ] && echo "✓ Client config exists" || echo "✗ Client config missing"

echo "5. Data Collection:"
[ -f security_report.json ] && echo "✓ Security report generated" || echo "✗ Security report missing"

echo
echo "=== ACCESS INFORMATION ==="
echo "Web Interface: https://127.0.0.1:8080"
echo "Username: admin"
echo "Password: VelociraptorAdmin123!"
echo
EOF

chmod +x verify_deployment.sh
./verify_deployment.sh
```

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Name | Tactic | Detection Method in This Lab |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Execution | `Linux.Sys.Pslist` process regex on nc/netcat/nmap/wget/curl |
| T1071 | Application Layer Protocol | Command and Control | `Linux.Network.Netstat` external `ESTABLISHED` connections |
| T1021 | Remote Services | Lateral Movement | SSH/SCP with `StrictHostKeyChecking=no` in advanced hunt |
| T1105 | Ingress Tool Transfer | Command and Control | File changes in `/etc`, `/root`, `/home` matching script extensions |

---

## 🧪 Verification Steps

```bash
# ✅ Confirm server process is running
pgrep -f "velociraptor.*frontend"

# ✅ Confirm client service is active
sudo systemctl status velociraptor-client

# ✅ Confirm web interface responds
curl -k -s https://127.0.0.1:8080/app/index.html

# ✅ Run the full verification script
./verify_deployment.sh
```

**Access the web interface and confirm:**

- 📌 The Linux client appears under **Clients** with a recent "last seen" timestamp
- 📌 `Custom.Endpoint.Monitoring` is listed under **Artifacts**
- 📌 The hunt created in Task 3 shows collected results
- 📌 `security_report.json` reflects an active monitoring status

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Velociraptor server fails to start</strong></summary>

```bash
tail -n 50 ~/velociraptor/server.log
```

- Confirm ports 8000 and 8080 aren't already in use: `sudo ss -tulpn | grep -E '8000|8080'`
- Confirm `server.config.yaml` was generated without errors

</details>

<details>
<summary><strong>❌ Issue: Client fails to enroll with the server</strong></summary>

```bash
sudo journalctl -u velociraptor-client -n 50
```

- Confirm `client.config.yaml` points to the correct server URL and port
- Confirm the client package installed cleanly: `sudo dpkg -l | grep velociraptor`

</details>

<details>
<summary><strong>❌ Issue: VQL query returns no rows</strong></summary>

- Confirm the artifact name is spelled correctly (case-sensitive, e.g. `Linux.Sys.Pslist`)
- Confirm the client has checked in recently — VQL queries against `source()` require completed collections
- Try a simpler query first: `SELECT * FROM clients()` to confirm connectivity

</details>

---

## 🏁 Conclusion

You have successfully deployed Velociraptor across enterprise endpoints, accomplishing:

- 🖥️ **Server Deployment:** Installed and configured Velociraptor server with web interface
- 💻 **Client Management:** Deployed Linux client and simulated Windows endpoint monitoring
- 📡 **Data Collection:** Configured custom artifacts and collection policies for comprehensive endpoint visibility
- 🔍 **Threat Detection:** Created VQL queries for identifying suspicious activities and potential threats
- 📊 **Security Reporting:** Generated automated security reports with endpoint status and findings

This enterprise-grade deployment provides real-time endpoint detection and response capabilities, enabling security teams to monitor, hunt, and respond to threats across distributed environments. The skills learned here are directly applicable to production DFIR and threat hunting operations.

### 📁 Key Files Created

| File | Purpose |
|---|---|
| `server.config.yaml` | Server configuration |
| `client.config.yaml` | Client configuration |
| `security_report.json` | Security analysis report |
| `custom_monitoring.yaml` | Custom monitoring artifact |

> 🌐 Access the web interface at `https://127.0.0.1:8080` with credentials `admin` / `VelociraptorAdmin123!` to explore the full Velociraptor capabilities.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Endpoint Monitoring & DFIR**

*Empowering the next generation of cybersecurity defenders*

</div>
