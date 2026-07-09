<div align="center">

# 🛡️ Set Up MITRE ATT&CK Navigator for Intel-Driven Detection

### Al Nafi Cloud Labs — Blue Team / Threat Intelligence Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-14%2B-339933?style=for-the-badge&logo=node.js&logoColor=white)
![ATT&CK Navigator](https://img.shields.io/badge/MITRE-ATT%26CK%20Navigator-D62C1A?style=for-the-badge&logo=mitre&logoColor=white)
![Threat Intel](https://img.shields.io/badge/Focus-Threat%20Intelligence-2E8B57?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **MITRE ATT&CK Navigator** on a Linux system and using it as a visual platform for intel-driven detection engineering. You'll ingest sample threat intelligence, build custom scoring layers, map techniques to detection coverage, and generate a gap analysis to prioritize where defenses need improvement.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Install and configure MITRE ATT&CK Navigator on a Linux system
- ✅ Integrate threat intelligence data into the Navigator platform
- ✅ Create detection strategies based on ATT&CK tactics, techniques, and procedures (TTPs)
- ✅ Develop skills in threat hunting and adversary behavior mapping

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![Node.js](https://img.shields.io/badge/-Node.js-339933?style=flat-square&logo=node.js&logoColor=white) | Runtime for the Navigator web application |
| ![npm](https://img.shields.io/badge/-npm-CB3837?style=flat-square&logo=npm&logoColor=white) | Dependency management & build tooling |
| ![Git](https://img.shields.io/badge/-Git-F05032?style=flat-square&logo=git&logoColor=white) | Cloning the ATT&CK Navigator repository |
| ![JSON](https://img.shields.io/badge/-JSON-000000?style=flat-square&logo=json&logoColor=white) | Threat intel layers & detection coverage data |
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | Detection gap analysis scripting |
| ![MITRE ATT&CK](https://img.shields.io/badge/-MITRE%20ATT%26CK-D62C1A?style=flat-square&logo=mitre&logoColor=white) | Adversary TTP framework |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of cybersecurity fundamentals
- Familiarity with web browsers and JSON file formats
- Basic knowledge of threat intelligence concepts

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The provided machine is bare metal with no pre-installed tools — you will install all required components during the lab.

---

## 🚀 Task 1: Install and Configure MITRE ATT&CK Navigator

### 1.1 — Update System and Install Dependencies

```bash
# 📦 Update package repositories
sudo apt update && sudo apt upgrade -y

# 📦 Install Node.js and npm
sudo apt install -y nodejs npm git curl

# 🔍 Verify installations
node --version
npm --version
# TODO: Confirm Node.js version is 14.x or higher before proceeding
```

### 1.2 — Clone and Set Up ATT&CK Navigator

```bash
# 📥 Clone the ATT&CK Navigator repository
git clone https://github.com/mitre-attack/attack-navigator.git

# 📂 Navigate to the project directory
cd attack-navigator/nav-app

# 📦 Install dependencies
npm install

# 🏗️ Build the application
npm run build
# TODO: Watch build output for dependency errors before continuing
```

### 1.3 — Start the Navigator Application

```bash
# ▶️ Start the development server
npm start
```

> 🌐 The application will start on `http://localhost:4200`. Open a web browser and navigate to this address to access the Navigator interface.

### 1.4 — Verify Installation

- 🌐 Open your web browser and go to `http://localhost:4200`
- 👀 Confirm the MITRE ATT&CK Navigator interface loads
- 🧩 Verify that the Enterprise ATT&CK matrix loads properly
- 🖱️ Test basic navigation by clicking on different tactics and techniques

---

## 🧠 Task 2: Integrate Threat Intelligence into the Platform

### 2.1 — Download Sample Threat Intelligence Data

```bash
# 📁 Create a directory for threat intelligence data
mkdir ~/threat-intel-data
cd ~/threat-intel-data

# ⬇️ Download sample APT group data (APT29/Cozy Bear)
curl -o apt29-techniques.json "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/attack-pattern/attack-pattern--0f4a0c76-ab2d-4cb0-85d3-3f0efb8cba4d.json"

# ⬇️ Download additional sample data for demonstration
curl -o sample-layer.json "https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/layers/samples/Bear_APT.json"
# TODO: Replace sample data with a live threat feed if available in your environment
```

### 2.2 — Create Custom Threat Intelligence Layer

```bash
# 📝 Create a custom layer file
cat > custom-threat-layer.json << 'EOF'
{
    "name": "Custom Threat Intelligence Layer",
    "versions": {
        "attack": "12",
        "navigator": "4.8.1",
        "layer": "4.4"
    },
    "domain": "enterprise-attack",
    "description": "Custom layer based on threat intelligence analysis",
    "techniques": [
        {
            "techniqueID": "T1566.001",
            "color": "#ff6666",
            "comment": "Spearphishing Attachment - High priority based on recent intel",
            "score": 90
        },
        {
            "techniqueID": "T1059.001",
            "color": "#ffcc66",
            "comment": "PowerShell execution observed in recent campaigns",
            "score": 75
        },
        {
            "techniqueID": "T1055",
            "color": "#ff9999",
            "comment": "Process injection technique commonly used",
            "score": 80
        }
    ],
    "gradient": {
        "colors": ["#ffffff", "#ff0000"],
        "minValue": 0,
        "maxValue": 100
    }
}
EOF
```

### 2.3 — Import Threat Intelligence into Navigator

- ➕ In the Navigator web interface, click **"+ Create New Layer"**
- 📤 Select **"Upload from local"**
- 📁 Upload the `custom-threat-layer.json` file you created
- ✅ Verify that the techniques are highlighted according to your threat intelligence data

---

## 🔎 Task 3: Create Detection Strategies Based on ATT&CK TTPs

### 3.1 — Analyze High-Priority Techniques

```bash
# 📝 Create a detection strategy document
cat > detection-strategy.md << 'EOF'
# Detection Strategy Based on ATT&CK TTPs

## High-Priority Techniques for Detection

### T1566.001 - Spearphishing Attachment
**Detection Methods:**
- Email gateway analysis for suspicious attachments
- Endpoint detection for unusual file execution patterns
- User behavior analytics for abnormal email interactions

### T1059.001 - PowerShell
**Detection Methods:**
- PowerShell execution logging and monitoring
- Command-line argument analysis
- Script block logging for suspicious PowerShell activities

### T1055 - Process Injection
**Detection Methods:**
- Process creation monitoring
- Memory analysis for injection indicators
- API call monitoring for injection-related functions
EOF
```

### 3.2 — Create Detection Rules Layer

```bash
# 📝 Create a detection coverage layer
cat > detection-coverage-layer.json << 'EOF'
{
    "name": "Detection Coverage Assessment",
    "versions": {
        "attack": "12",
        "navigator": "4.8.1",
        "layer": "4.4"
    },
    "domain": "enterprise-attack",
    "description": "Assessment of current detection capabilities",
    "techniques": [
        {
            "techniqueID": "T1566.001",
            "color": "#00ff00",
            "comment": "Full detection coverage implemented",
            "metadata": [
                {"name": "Detection Tool", "value": "Email Security Gateway"},
                {"name": "Coverage Level", "value": "High"}
            ]
        },
        {
            "techniqueID": "T1059.001",
            "color": "#ffff00",
            "comment": "Partial detection coverage",
            "metadata": [
                {"name": "Detection Tool", "value": "PowerShell Logging"},
                {"name": "Coverage Level", "value": "Medium"}
            ]
        },
        {
            "techniqueID": "T1055",
            "color": "#ff0000",
            "comment": "Limited detection coverage - needs improvement",
            "metadata": [
                {"name": "Detection Tool", "value": "Basic Process Monitoring"},
                {"name": "Coverage Level", "value": "Low"}
            ]
        }
    ],
    "gradient": {
        "colors": ["#ff0000", "#ffff00", "#00ff00"],
        "minValue": 0,
        "maxValue": 100
    }
}
EOF
```

### 3.3 — Import and Analyze Detection Coverage

- ➕ In the Navigator interface, create a new layer
- 📤 Upload the `detection-coverage-layer.json` file
- ⚙️ Use the **"Layer Controls"** to adjust visualization settings
- 📊 Export your analysis by clicking **"Export"** and selecting **"Excel (.xlsx)"**

### 3.4 — Generate Detection Gap Analysis

```python
#!/usr/bin/env python3
import json

# 📂 Load the detection coverage layer
with open('detection-coverage-layer.json', 'r') as f:
    coverage_data = json.load(f)

print("Detection Gap Analysis Report")
print("=" * 40)

for technique in coverage_data['techniques']:
    technique_id = technique['techniqueID']
    comment = technique['comment']

    if 'Limited' in comment or 'Low' in comment:
        print(f"GAP IDENTIFIED: {technique_id}")
        print(f"Issue: {comment}")
        print(f"Recommendation: Implement enhanced detection controls")
        print("-" * 30)

print("\nAnalysis complete. Review gaps and prioritize improvements.")
# TODO: Extend script to auto-generate remediation tickets from identified gaps
```

```bash
# 🏃 Make the script executable and run it
chmod +x gap-analysis.py
python3 gap-analysis.py
```

---

## 🗺️ MITRE ATT&CK Technique Coverage

| Technique ID | Name | Tactic | Priority Score | Detection Coverage |
|---|---|---|:---:|:---:|
| T1566.001 | Spearphishing Attachment | Initial Access | 90 🔴 | 🟢 High |
| T1059.001 | PowerShell | Execution | 75 🟠 | 🟡 Medium |
| T1055 | Process Injection | Defense Evasion / Privilege Escalation | 80 🔴 | 🔴 Low |

---

## 🧪 Verification and Testing

### Verify Navigator Functionality

```bash
# 🔎 Check if the Navigator is still running
curl -s http://localhost:4200 | grep -q "ATT&CK Navigator" && echo "Navigator is running successfully" || echo "Navigator is not accessible"

# 📋 List created files
ls -la ~/threat-intel-data/
```

### Test Layer Management

- 🌐 Open the Navigator in your browser
- 📚 Load multiple layers simultaneously using the **"+"** button
- 🎛️ Use the **"Layer Controls"** to toggle between different views
- 🔍 Test the search functionality by searching for specific technique IDs
- 📤 Verify export functionality by downloading layers in different formats

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Navigator fails to start</strong></summary>

```bash
# Check Node.js version compatibility
node --version
# Ensure version is 14.x or higher

# Clear npm cache if needed
npm cache clean --force
cd ~/attack-navigator/nav-app
npm install
```

</details>

<details>
<summary><strong>❌ Issue: JSON layer import fails</strong></summary>

- Verify JSON syntax using: `python3 -m json.tool your-file.json`
- Ensure all required fields are present in the layer file

</details>

---

## 🏁 Conclusion

You have successfully set up MITRE ATT&CK Navigator for intel-driven detection. This lab covered:

- ⚙️ Installation and configuration of the Navigator platform on Linux
- 🧠 Integration of threat intelligence data through custom layers
- 🎯 Creation of detection strategies based on ATT&CK TTPs
- 📊 Gap analysis to identify areas for security improvement

These skills are essential for threat hunters, security analysts, and detection engineers who need to map adversary behavior to defensive capabilities. The Navigator provides a visual framework for understanding attack patterns and developing comprehensive detection strategies based on real-world threat intelligence.

The techniques learned in this lab form the foundation for advanced threat hunting operations and help organizations prioritize their security investments based on actual adversary tactics and techniques.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Threat Intelligence & Detection Engineering**

*Empowering the next generation of cybersecurity defenders*

</div>
