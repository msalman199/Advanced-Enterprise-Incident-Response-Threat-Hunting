<div align="center">

# 🛡️ Build Collaborative Case Management with TheHive + Cortex

### Al Nafi Cloud Labs — Blue Team / Incident Response Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![TheHive](https://img.shields.io/badge/TheHive-Case%20Management-FF6900?style=for-the-badge&logo=thehive&logoColor=white)
![Cortex](https://img.shields.io/badge/Cortex-Threat%20Analysis-2C3E50?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.17-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **TheHive** and **Cortex** as a containerized collaborative incident response platform. You'll stand up the full stack with Elasticsearch and Cassandra, build case templates and sample incidents with observables, integrate automated analyzers, and script response automation for security operations workflows.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Install and configure TheHive and Cortex for collaborative incident response
- ✅ Create, manage, and track security incident cases
- ✅ Automate threat analysis using Cortex analyzers
- ✅ Implement collaborative workflows for security teams

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat-square&logo=docker&logoColor=white) | Containerized deployment via Docker Compose |
| ![Java](https://img.shields.io/badge/-Java%2011-007396?style=flat-square&logo=openjdk&logoColor=white) | Runtime dependency for TheHive & Cortex |
| ![Elasticsearch](https://img.shields.io/badge/-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white) | Search & indexing backend |
| ![Cassandra](https://img.shields.io/badge/-Cassandra-1287B1?style=flat-square&logo=apachecassandra&logoColor=white) | Graph/database storage (JanusGraph backend) |
| ![TheHive](https://img.shields.io/badge/-TheHive-FF6900?style=flat-square) | Collaborative security incident case management |
| ![Cortex](https://img.shields.io/badge/-Cortex-2C3E50?style=flat-square) | Observable analysis & analyzer orchestration engine |
| ![Bash](https://img.shields.io/badge/-Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white) | API automation & response scripting |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of incident response concepts
- Familiarity with JSON data structures
- Basic networking concepts

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you'll install all required components during the lab.

---

## 🚀 Task 1: Set Up TheHive and Cortex Infrastructure

### 1.1 — Install Dependencies

```bash
# 📦 Update the system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y wget curl gnupg2 software-properties-common apt-transport-https ca-certificates

# ☕ Install Java 11 (required for both applications)
sudo apt install -y openjdk-11-jdk
java -version
# TODO: Confirm Java 11 is active if multiple JDKs are present (update-alternatives --config java)

# 🐳 Install Docker and Docker Compose
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

### 1.2 — Deploy TheHive and Cortex with Docker

```bash
# 📁 Create a project directory
mkdir ~/thehive-lab && cd ~/thehive-lab

# 📝 Create the Docker Compose configuration
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch
    restart: unless-stopped
    ports:
      - "9200:9200"
    environment:
      - http.host=0.0.0.0
      - discovery.type=single-node
      - cluster.name=hive
      - script.allowed_types=inline
      - thread_pool.search.queue_size=100000
      - thread_pool.write.queue_size=10000
      - gateway.recover_after_nodes=1
      - xpack.security.enabled=false
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms256m -Xmx256m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ./elasticsearch/data:/usr/share/elasticsearch/data
      - ./elasticsearch/logs:/usr/share/elasticsearch/logs

  cassandra:
    image: cassandra:3.11
    container_name: cassandra
    restart: unless-stopped
    ports:
      - "9042:9042"
    environment:
      - MAX_HEAP_SIZE=1G
      - HEAP_NEWSIZE=1G
      - CASSANDRA_CLUSTER_NAME=thp
    volumes:
      - ./cassandra/data:/var/lib/cassandra/data

  thehive:
    image: thehiveproject/thehive4:latest
    container_name: thehive4
    restart: unless-stopped
    depends_on:
      - elasticsearch
      - cassandra
    ports:
      - "9000:9000"
    volumes:
      - ./thehive/application.conf:/etc/thehive/application.conf
      - ./thehive/data:/opt/thp/thehive/data
      - ./thehive/index:/opt/thp/thehive/index
    command: --no-config --no-config-secret

  cortex:
    image: thehiveproject/cortex:latest
    container_name: cortex
    restart: unless-stopped
    volumes:
      - ./cortex/application.conf:/etc/cortex/application.conf
      - /var/run/docker.sock:/var/run/docker.sock
      - /tmp:/tmp
    depends_on:
      - elasticsearch
    ports:
      - "9001:9001"
    command: --no-config --no-config-secret
EOF
```

### 1.3 — Configure TheHive

```bash
# 📁 Create TheHive configuration directory and file
mkdir -p thehive
cat > thehive/application.conf << 'EOF'
include file("/etc/thehive/secret.conf")

http.address = 0.0.0.0
http.port = 9000

play.http.secret.key = "ThHiv3App"

scalligraph {
  database {
    provider = janusgraph
    janusgraph {
      storage {
        backend = cql
        hostname = ["cassandra"]
        cql {
          cluster-name = thp
          keyspace = thehive
        }
      }
      index.search {
        backend = elasticsearch
        hostname = ["elasticsearch"]
        index-name = thehive
      }
    }
  }
}

storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/data
}

play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
cortex {
  servers = [
    {
      name = local
      url = "http://cortex:9001"
      auth {
        type = "bearer"
        key = "cortex-api-key"
      }
    }
  ]
}
EOF
# TODO: Replace play.http.secret.key with a securely generated value outside this lab
```

### 1.4 — Configure Cortex

```bash
# 📁 Create Cortex configuration
mkdir -p cortex
cat > cortex/application.conf << 'EOF'
include file("/etc/cortex/secret.conf")

http.address = 0.0.0.0
http.port = 9001

play.http.secret.key = "CortexTestPassword"

search {
  index = cortex
  uri = "http://elasticsearch:9200"
}

storage {
  provider = localfs
  localfs.location = /tmp/cortex-jobs
}

job {
  runner = [docker]
}

docker {
  job {
    directory = /tmp/cortex-jobs
  }
}

analyzer {
  urls = [
    "https://download.thehive-project.org/analyzers.json"
  ]
}
EOF
```

### 1.5 — Start the Services

```bash
# 📁 Create necessary directories and start services
mkdir -p elasticsearch/data elasticsearch/logs cassandra/data thehive/data thehive/index
sudo chown -R 1000:1000 elasticsearch/
sudo chown -R 999:999 cassandra/
docker-compose up -d

# ⏳ Wait for services to start and verify
sleep 60
docker-compose ps
curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[^"]*"'
# TODO: Confirm cluster status is "green" or "yellow" before moving to Task 2
```

---

## 📂 Task 2: Create and Manage Incident Reports

### 2.1 — Initial Setup and User Creation

```bash
# 🌐 Access TheHive web interface
echo "TheHive is available at: http://localhost:9000"
echo "Default login: admin@thehive.local / secret"
```

> 🌐 Open a web browser and navigate to `http://localhost:9000`. Log in with the default credentials above, then change the password immediately.

```bash
# 🔑 Get admin session
ADMIN_SESSION=$(curl -s -X POST http://localhost:9000/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin@thehive.local","password":"secret"}' | \
  grep -o '"[^"]*"' | tail -1 | tr -d '"')

# 🏢 Create organization
curl -X POST http://localhost:9000/api/organisation \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SecurityTeam",
    "description": "Main Security Operations Team"
  }'

# 👤 Create analyst user
curl -X POST http://localhost:9000/api/user \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "analyst@securityteam.local",
    "name": "Security Analyst",
    "roles": ["read", "write"],
    "password": "analyst123",
    "organisation": "SecurityTeam"
  }'
# TODO: Rotate analyst123 to a strong password before any real-world use
```

### 2.2 — Create Case Templates

```bash
# 📝 Create a case template for standardized incident handling
curl -X POST http://localhost:9000/api/case/template \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Malware Incident Template",
    "displayName": "Malware Incident Response",
    "titlePrefix": "MAL-",
    "description": "Standard template for malware incidents",
    "severity": 2,
    "tlp": 2,
    "tags": ["malware", "incident-response"],
    "customFields": {},
    "tasks": [
      {"title": "Initial Triage", "description": "Perform initial assessment of the malware incident", "order": 0},
      {"title": "Containment", "description": "Isolate affected systems", "order": 1},
      {"title": "Analysis", "description": "Analyze malware samples and indicators", "order": 2},
      {"title": "Eradication", "description": "Remove malware from affected systems", "order": 3},
      {"title": "Recovery", "description": "Restore systems to normal operation", "order": 4},
      {"title": "Lessons Learned", "description": "Document findings and improvements", "order": 5}
    ]
  }'
```

> 🧭 This template mirrors the classic **NIST incident response lifecycle**: Triage → Containment → Analysis → Eradication → Recovery → Lessons Learned.

### 2.3 — Create Sample Incident Cases

```bash
# 📌 Create a sample malware incident case
curl -X POST http://localhost:9000/api/case \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious Email Attachment - Potential Malware",
    "description": "User reported suspicious email with attachment. Initial analysis suggests potential malware infection.",
    "severity": 2,
    "tlp": 2,
    "pap": 2,
    "tags": ["email", "malware", "phishing"],
    "template": "Malware Incident Template"
  }' > case_response.json

CASE_ID=$(cat case_response.json | grep -o '"_id":"[^"]*"' | cut -d'"' -f4)
echo "Created case with ID: $CASE_ID"
```

**🔬 Add observables to the case**

```bash
# ✉️ Add suspicious email address
curl -X POST http://localhost:9000/api/case/$CASE_ID/artifact \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "mail",
    "data": "suspicious@malicious-domain.com",
    "message": "Sender email address from suspicious attachment",
    "tlp": 2,
    "ioc": true,
    "tags": ["email", "sender"]
  }'

# 🧬 Add suspicious file hash
curl -X POST http://localhost:9000/api/case/$CASE_ID/artifact \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "hash",
    "data": "d41d8cd98f00b204e9800998ecf8427e",
    "message": "MD5 hash of suspicious attachment",
    "tlp": 2,
    "ioc": true,
    "tags": ["malware", "hash", "md5"]
  }'

# 🌐 Add suspicious IP address
curl -X POST http://localhost:9000/api/case/$CASE_ID/artifact \
  -H "Authorization: Bearer $ADMIN_SESSION" \
  -H "Content-Type: application/json" \
  -d '{
    "dataType": "ip",
    "data": "192.168.1.100",
    "message": "Affected workstation IP address",
    "tlp": 2,
    "ioc": false,
    "tags": ["internal", "affected-system"]
  }'
```

---

## 🤖 Task 3: Automate Case Handling and Analysis

### 3.1 — Configure Cortex Integration

```bash
# ⏳ Wait for Cortex to be ready
sleep 30
curl -s http://localhost:9001/api/status

# 🗄️ Create Cortex superadmin user
curl -X POST http://localhost:9001/api/maintenance/migrate
sleep 10

# 🏢 Create organization and user in Cortex
CORTEX_SETUP=$(curl -s -X POST http://localhost:9001/api/user \
  -H "Content-Type: application/json" \
  -d '{
    "login": "admin",
    "name": "admin",
    "password": "admin123"
  }')

# 🔑 Login to Cortex
CORTEX_SESSION=$(curl -s -X POST http://localhost:9001/api/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin123"}' | \
  grep -o '"[^"]*"' | tail -1 | tr -d '"')

# 🔐 Create API key
curl -X POST http://localhost:9001/api/user/admin/key/renew \
  -H "Authorization: Bearer $CORTEX_SESSION" \
  -H "Content-Type: application/json" > cortex_key.json

CORTEX_API_KEY=$(cat cortex_key.json | grep -o '"[^"]*"' | tail -1 | tr -d '"')
echo "Cortex API Key: $CORTEX_API_KEY"
# TODO: Store CORTEX_API_KEY in a secrets manager, never commit to version control
```

### 3.2 — Install and Configure Analyzers

```bash
# 📋 Get available analyzers
curl -X GET http://localhost:9001/api/analyzer \
  -H "Authorization: Bearer $CORTEX_SESSION" > available_analyzers.json

# 📄 Enable File_Info analyzer
curl -X POST http://localhost:9001/api/organization/analyzer/File_Info_8_0/enable \
  -H "Authorization: Bearer $CORTEX_SESSION"

# 🧬 Enable Hash analyzers
curl -X POST http://localhost:9001/api/organization/analyzer/Hashdd_Detail_1_0/enable \
  -H "Authorization: Bearer $CORTEX_SESSION"

curl -X POST http://localhost:9001/api/organization/analyzer/Hashdd_Status_1_0/enable \
  -H "Authorization: Bearer $CORTEX_SESSION"

# 🌐 Enable IP analyzers
curl -X POST http://localhost:9001/api/organization/analyzer/Abuse_Finder_3_0/enable \
  -H "Authorization: Bearer $CORTEX_SESSION"

echo "Analyzers enabled successfully"
```

### 3.3 — Run Automated Analysis

```bash
# 📝 Create a script to automate analysis of observables
cat > analyze_observables.sh << 'EOF'
#!/bin/bash

THEHIVE_SESSION="$1"
CORTEX_SESSION="$2"
CASE_ID="$3"

echo "Starting automated analysis for case: $CASE_ID"

# Get all observables from the case
OBSERVABLES=$(curl -s -X GET "http://localhost:9000/api/case/$CASE_ID/artifact" \
  -H "Authorization: Bearer $THEHIVE_SESSION")

echo "$OBSERVABLES" | grep -o '"_id":"[^"]*"' | while read -r line; do
  OBSERVABLE_ID=$(echo $line | cut -d'"' -f4)
  echo "Analyzing observable: $OBSERVABLE_ID"

  # Run analysis on observable
  curl -X POST "http://localhost:9000/api/connector/cortex/job" \
    -H "Authorization: Bearer $THEHIVE_SESSION" \
    -H "Content-Type: application/json" \
    -d "{
      \"cortexId\": \"local\",
      \"artifactId\": \"$OBSERVABLE_ID\"
    }"

  sleep 2
done

echo "Analysis jobs submitted"
EOF

chmod +x analyze_observables.sh

# ▶️ Run the automated analysis
./analyze_observables.sh "$ADMIN_SESSION" "$CORTEX_SESSION" "$CASE_ID"
```

### 3.4 — Create Automated Response Playbook

```bash
# 📝 Create a response automation script
cat > incident_response_automation.sh << 'EOF'
#!/bin/bash

THEHIVE_SESSION="$1"
CASE_ID="$2"
SEVERITY="$3"

echo "Executing automated response for case $CASE_ID with severity $SEVERITY"

# Auto-assign case based on severity
if [ "$SEVERITY" -ge "3" ]; then
  ASSIGNEE="analyst@securityteam.local"
  echo "High severity case - assigning to senior analyst"
else
  ASSIGNEE="analyst@securityteam.local"
  echo "Standard severity case - assigning to analyst"
fi

# Update case assignment
curl -X PATCH "http://localhost:9000/api/case/$CASE_ID" \
  -H "Authorization: Bearer $THEHIVE_SESSION" \
  -H "Content-Type: application/json" \
  -d "{\"assignee\": \"$ASSIGNEE\"}"

# Add automated response log
curl -X POST "http://localhost:9000/api/case/$CASE_ID/log" \
  -H "Authorization: Bearer $THEHIVE_SESSION" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"Automated response initiated. Case assigned to $ASSIGNEE based on severity level $SEVERITY.\"
  }"

# Create follow-up task if high severity
if [ "$SEVERITY" -ge "3" ]; then
  curl -X POST "http://localhost:9000/api/case/$CASE_ID/task" \
    -H "Authorization: Bearer $THEHIVE_SESSION" \
    -H "Content-Type: application/json" \
    -d "{
      \"title\": \"Urgent: Management Notification Required\",
      \"description\": \"High severity incident requires immediate management notification and escalation procedures.\"
    }"
fi

echo "Automated response completed"
EOF

chmod +x incident_response_automation.sh

# ▶️ Execute the automated response
./incident_response_automation.sh "$ADMIN_SESSION" "$CASE_ID" "2"
# TODO: Parameterize severity thresholds and assignee routing per team roster
```

### 3.5 — Verify Integration and Results

```bash
# 📄 Get case details
curl -s -X GET "http://localhost:9000/api/case/$CASE_ID" \
  -H "Authorization: Bearer $ADMIN_SESSION" | \
  grep -E '"title"|"status"|"assignee"|"severity"'

# 🧪 Get analysis jobs
curl -s -X GET "http://localhost:9001/api/job" \
  -H "Authorization: Bearer $CORTEX_SESSION" | \
  grep -E '"status"|"analyzerName"' | head -10

# 📝 Get case logs
curl -s -X GET "http://localhost:9000/api/case/$CASE_ID/log" \
  -H "Authorization: Bearer $ADMIN_SESSION" | \
  grep -o '"message":"[^"]*"' | head -5

echo "Integration verification completed"
```

```bash
# 📊 Create a summary report
cat > lab_summary.txt << EOF
=== TheHive + Cortex Lab Summary ===

Case ID: $CASE_ID
TheHive URL: http://localhost:9000
Cortex URL: http://localhost:9001

Services Status:
- TheHive: Running on port 9000
- Cortex: Running on port 9001
- Elasticsearch: Running on port 9200
- Cassandra: Running on port 9042

Created Resources:
- Security Team organization
- Analyst user account
- Malware incident template
- Sample incident case with observables
- Automated analysis workflows
- Response automation scripts

Key Features Demonstrated:
- Collaborative case management
- Observable analysis automation
- Integration between TheHive and Cortex
- Automated response workflows
- Template-based incident handling

Next Steps:
- Explore additional analyzers in Cortex
- Create custom case templates
- Implement advanced automation rules
- Configure external threat intelligence feeds
EOF

cat lab_summary.txt
```

---

## 🗺️ MITRE ATT&CK / NIST IR Alignment

| Case Phase | NIST IR Stage | Related ATT&CK Consideration |
|---|---|---|
| Initial Triage | Detection & Analysis | Observable/IOC validation (T1566, T1204) |
| Containment | Containment | Isolate affected hosts identified via IP observables |
| Analysis | Detection & Analysis | Cortex analyzer output (hash, IP, mail reputation) |
| Eradication | Eradication | Removal actions tracked as case tasks |
| Recovery | Recovery | System restoration logged in case notes |
| Lessons Learned | Post-Incident Activity | Documented in final case summary |

---

## 🧪 Verification and Testing

```bash
# ✅ Confirm all containers are healthy
docker-compose ps

# ✅ Confirm Elasticsearch cluster health
curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[^"]*"'

# ✅ Confirm TheHive is reachable
curl -s -o /dev/null -w "%{http_code}" http://localhost:9000

# ✅ Confirm Cortex is reachable
curl -s -o /dev/null -w "%{http_code}" http://localhost:9001
```

**Access the TheHive dashboard and confirm:**

- 📌 The sample case is visible with all three observables attached
- 📌 Cortex analyzers show as enabled under **Organization → Analyzers**
- 📌 Analysis jobs return results under the case's **Observables** tab
- 📌 Case logs reflect the automated response actions

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Elasticsearch container exits immediately</strong></summary>

```bash
docker-compose logs elasticsearch
```

- Confirm `vm.max_map_count` is sufficient: `sudo sysctl -w vm.max_map_count=262144`
- Confirm the `elasticsearch/data` directory ownership is `1000:1000`

</details>

<details>
<summary><strong>❌ Issue: TheHive can't connect to Cassandra</strong></summary>

```bash
docker-compose logs cassandra
docker-compose logs thehive4
```

- Cassandra can take 60–90 seconds to initialize; re-check with `docker-compose ps` before restarting TheHive
- Confirm the `cassandra/data` directory ownership is `999:999`

</details>

<details>
<summary><strong>❌ Issue: Cortex jobs stay in "Waiting" status</strong></summary>

- Confirm `/var/run/docker.sock` is correctly mounted into the Cortex container
- Confirm the analyzer's Docker image was pulled successfully: `docker images | grep cortexneurons`
- Check job logs: `curl -s http://localhost:9001/api/job/<job_id>/report -H "Authorization: Bearer $CORTEX_SESSION"`

</details>

---

## 🏁 Conclusion

You have successfully built a collaborative case management system using TheHive and Cortex. This lab demonstrated how to:

- ⚙️ Deploy and configure TheHive and Cortex in a containerized environment
- 📋 Create structured incident response workflows with templates and tasks
- 🤖 Integrate automated threat analysis capabilities
- 🤝 Implement collaborative features for security teams
- 🔁 Automate routine incident response procedures

This setup provides a foundation for enterprise-grade security incident response, enabling teams to efficiently manage, analyze, and respond to security threats through standardized processes and automated analysis capabilities. The integration between TheHive's case management and Cortex's analysis engine creates a powerful platform for modern security operations centers.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Incident Response & Case Management**

*Empowering the next generation of cybersecurity defenders*

</div>
