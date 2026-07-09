<div align="center">

# 🛡️ Deploy MISP for Intel Ingestion and IOC Sharing

### Al Nafi Cloud Labs — Blue Team / Threat Intelligence Track

![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![MISP](https://img.shields.io/badge/MISP-Threat%20Intel%20Platform-003366?style=for-the-badge&logo=misp&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-2.4-D22128?style=for-the-badge&logo=apache&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-Database-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-Backend-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Lab%20Ready-brightgreen?style=for-the-badge)

</div>

---

## 📋 Overview

This lab walks through deploying **MISP (Malware Information Sharing Platform)** on a Linux system as a centralized threat intelligence hub. You'll stand up the full LAMP-based stack, ingest external OSINT feeds, create and tag Indicators of Compromise (IOCs), and configure correlation and export mechanisms for downstream SIEM integration.

## 🎯 Learning Objectives

By completing this lab, you will:

- ✅ Deploy and configure MISP (Malware Information Sharing Platform) on Linux
- ✅ Integrate external threat intelligence feeds into MISP
- ✅ Create, manage, and share Indicators of Compromise (IOCs)
- ✅ Track IOCs across enterprise systems using MISP's correlation features

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| ![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black) | Base lab environment (bare metal, no pre-installed tools) |
| ![Apache](https://img.shields.io/badge/-Apache-D22128?style=flat-square&logo=apache&logoColor=white) | Web server hosting the MISP application |
| ![MariaDB](https://img.shields.io/badge/-MariaDB-003545?style=flat-square&logo=mariadb&logoColor=white) | Relational database backend for MISP |
| ![PHP](https://img.shields.io/badge/-PHP-777BB4?style=flat-square&logo=php&logoColor=white) | Application runtime & Composer dependency management |
| ![Redis](https://img.shields.io/badge/-Redis-DC382D?style=flat-square&logo=redis&logoColor=white) | Caching & background job queueing |
| ![Git](https://img.shields.io/badge/-Git-F05032?style=flat-square&logo=git&logoColor=white) | Cloning the MISP repository & submodules |
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white) | MISP scripting & automation bindings |
| ![STIX](https://img.shields.io/badge/-STIX%2FCSV-000000?style=flat-square&logo=json&logoColor=white) | IOC export formats for SIEM integration |

## ✅ Prerequisites

- Basic Linux command-line knowledge
- Understanding of cybersecurity concepts (IOCs, threat intelligence)
- Familiarity with web browsers and JSON data formats
- Network connectivity for downloading packages and feeds

## 🖥️ Lab Environment

> Al Nafi provides a Linux-based cloud machine for this lab. Simply click **Start Lab** to access your dedicated environment. The provided machine is bare metal with no pre-installed tools — you will install all required components during the lab.

---

## 🚀 Task 1: Set Up MISP Platform on Al Nafi Cloud

### 1.1 — System Preparation and Dependencies

```bash
# 📦 Update the system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mariadb-server php php-cli php-dev php-json php-mysql php-opcache php-readline php-redis php-xml php-mbstring php-zip php-intl php-bcmath php-gd php-fpm libapache2-mod-php git curl wget unzip redis-server python3 python3-pip
# TODO: Confirm all packages installed without errors before proceeding

# ▶️ Start and enable services
sudo systemctl start apache2 mariadb redis-server
sudo systemctl enable apache2 mariadb redis-server
```

### 1.2 — Database Configuration

```bash
# 🔒 Secure MariaDB installation
sudo mysql_secure_installation
# Follow prompts: set root password, remove anonymous users,
# disable remote root login, remove test database

# 🗄️ Create MISP database
sudo mysql -u root -p
```

```sql
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'MISPdbpass123!';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> ⚠️ **Note:** Replace `MISPdbpass123!` with a strong, unique credential in any environment beyond this isolated lab.

### 1.3 — Download and Install MISP

```bash
# 📥 Clone MISP repository
cd /var/www/html
sudo git clone https://github.com/MISP/MISP.git
cd MISP
sudo git checkout tags/$(git describe --tags `git rev-list --tags --max-count=1`)
sudo git submodule update --init --recursive

# 🔐 Set proper permissions
sudo chown -R www-data:www-data /var/www/html/MISP
sudo chmod -R 755 /var/www/html/MISP
```

### 1.4 — Install PHP Dependencies

```bash
# 📦 Install Composer and PHP dependencies
cd /var/www/html/MISP/app
sudo -u www-data php composer.phar install --no-dev

# 🔁 If composer.phar doesn't exist:
sudo -u www-data curl -sS https://getcomposer.org/installer | php
sudo -u www-data php composer.phar install --no-dev
# TODO: Verify composer install completes with no dependency conflicts
```

### 1.5 — Configure MISP

```bash
# 📝 Copy configuration files
sudo -u www-data cp -a /var/www/html/MISP/app/Config/bootstrap.default.php /var/www/html/MISP/app/Config/bootstrap.php
sudo -u www-data cp -a /var/www/html/MISP/app/Config/database.default.php /var/www/html/MISP/app/Config/database.php
sudo -u www-data cp -a /var/www/html/MISP/app/Config/core.default.php /var/www/html/MISP/app/Config/core.php
sudo -u www-data cp -a /var/www/html/MISP/app/Config/config.default.php /var/www/html/MISP/app/Config/config.php

# ✏️ Edit database configuration
sudo nano /var/www/html/MISP/app/Config/database.php
```

```php
public $default = array(
    'datasource' => 'Database/Mysql',
    'persistent' => false,
    'host' => 'localhost',
    'login' => 'misp',
    'password' => 'MISPdbpass123!',
    'database' => 'misp',
    'prefix' => '',
    'encoding' => 'utf8',
);
```

### 1.6 — Initialize MISP Database

```bash
# ⚙️ Run database initialization
cd /var/www/html/MISP/app/Console
sudo -u www-data ./cake Admin setSetting "MISP.baseurl" "http://localhost/MISP"
sudo -u www-data ./cake Admin setSetting "MISP.python_bin" "/usr/bin/python3"

# 🗄️ Import database schema
sudo -u www-data ./cake Admin createDatabase
sudo -u www-data ./cake Admin migrate
# TODO: Check console output for migration errors before continuing
```

### 1.7 — Configure Apache

```bash
# 📝 Create MISP virtual host
sudo nano /etc/apache2/sites-available/misp.conf
```

```apache
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html/MISP/app/webroot

    <Directory /var/www/html/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Require all granted
    </Directory>

    LogLevel warn
    ErrorLog /var/log/apache2/misp_error.log
    CustomLog /var/log/apache2/misp_access.log combined
</VirtualHost>
```

```bash
# ✅ Enable site and modules
sudo a2ensite misp
sudo a2enmod rewrite
sudo a2dissite 000-default
sudo systemctl restart apache2
```

---

## 🌐 Task 2: Integrate Threat Intel Feeds

### 2.1 — Access MISP Web Interface

- 🌐 Open your browser and navigate to `http://localhost/MISP`

| Field | Value |
|---|---|
| Username | `admin@admin.test` |
| Password | `admin` |

> ⚠️ **Change the default password immediately after first login.**

### 2.2 — Configure Feed Sources

- 🧭 Navigate to **Administration → List Feeds**
- ➕ Click **Add Feed** and configure the **CIRCL OSINT Feed**:

| Field | Value |
|---|---|
| Name | CIRCL OSINT Feed |
| Provider | CIRCL |
| URL | `https://www.circl.lu/doc/misp/feed-osint/` |
| Source Format | MISP Feed |
| Fixed Event | No |
| Target Event | 0 |
| Published | Yes |
| Override IDS | No |

- ✅ Click **Submit**

### 2.3 — Enable Additional Feeds

- ➕ Click **Add Feed** and configure **Botvrij.eu**:

| Field | Value |
|---|---|
| Name | Botvrij.eu |
| Provider | Botvrij.eu |
| URL | `https://www.botvrij.eu/data/feed-osint/` |
| Source Format | MISP Feed |
| Published | Yes |

- ✅ Click **Submit**

### 2.4 — Fetch Feed Data

- 👀 For each configured feed, click **Preview** to test connectivity
- ⬇️ Click **Fetch and store** to import IOCs
- 📊 Monitor the **Jobs** section for import progress

```bash
# 🔄 Verify feed import via CLI
cd /var/www/html/MISP/app/Console
sudo -u www-data ./cake Server fetchFeed 1
sudo -u www-data ./cake Server fetchFeed 2
# TODO: Confirm imported event counts match expected feed volume
```

---

## 🔗 Task 3: Share IOCs and Track Them Across Enterprise Systems

### 3.1 — Create Custom Event with IOCs

- 🧭 Navigate to **Event Actions → Add Event**

| Field | Value |
|---|---|
| Date | Current date |
| Distribution | Your organization only |
| Threat Level | Medium |
| Analysis | Initial |
| Event Info | Custom IOC Collection - Lab Exercise |

- ✅ Click **Submit**

### 3.2 — Add IOC Attributes

**🌐 IP Address IOC**

| Field | Value |
|---|---|
| Category | Network activity |
| Type | `ip-dst` |
| Value | `192.168.1.100` |
| Comment | Suspicious C2 server |
| IDS | Yes |

**🌍 Domain IOC**

| Field | Value |
|---|---|
| Category | Network activity |
| Type | `domain` |
| Value | `malicious-domain.com` |
| Comment | Known malware domain |
| IDS | Yes |

**🧬 File Hash IOC**

| Field | Value |
|---|---|
| Category | Payload delivery |
| Type | `sha256` |
| Value | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Comment | Malware sample hash |
| IDS | Yes |

### 3.3 — Configure IOC Correlation

- 🧭 Navigate to **Administration → Server Settings & Maintenance**
- ⚙️ Go to the **MISP Settings** tab
- 🔧 Configure correlation settings:

| Setting | Value |
|---|---|
| `MISP.correlation_default_event_threshold` | 5 |
| `MISP.correlation_max_correlations` | 100 |

- ✅ Click **Update** for each setting

### 3.4 — Export IOCs for SIEM Integration

```bash
# 📤 Export as STIX
# Go to your event → Download as... → STIX → save file for SIEM integration

# 📤 Export as CSV
# Navigate to Attributes → Search Attributes → set search criteria → Download results as CSV

# 🔌 Generate API export
curl -H "Authorization: YOUR_API_KEY" \
     -H "Accept: application/json" \
     -H "Content-type: application/json" \
     http://localhost/MISP/attributes/restSearch/json
# TODO: Store YOUR_API_KEY in a secrets manager, never hardcode in scripts
```

### 3.5 — Set Up Automated IOC Sharing

- 🧭 Navigate to **Sync Actions → List Servers**
- ➕ Click **Add Server** (for demonstration)

| Field | Value |
|---|---|
| Base URL | `https://partner-misp.example.com` |
| Organization | Partner Organization |
| Authkey | (Partner's API key) |
| Push | Yes |
| Pull | Yes |

### 3.6 — Monitor IOC Correlations

- 🧭 Navigate to your event → click **View Correlations**
- 🔍 Review correlated attributes across events
- 📈 Analyze the correlation graph for threat patterns

```bash
# 📊 Generate correlation report
cd /var/www/html/MISP/app/Console
sudo -u www-data ./cake Admin generateCorrelations
```

### 3.7 — Create IOC Watchlist

- 🧭 Navigate to **Event Actions → Automation**
- ➕ Create a new automation rule:

| Field | Value |
|---|---|
| Name | Critical IOC Alert |
| Conditions | Attribute type = `ip-dst` AND TLP = RED |
| Actions | Send email notification |

- 🧪 Test automation with a new IOC addition

---

## 🗺️ MITRE ATT&CK Alignment

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1583 | Acquire Infrastructure | Resource Development | Tracked via C2 IP/domain IOCs |
| T1071 | Application Layer Protocol | Command and Control | Correlated network IOCs |
| T1204 | User Execution | Execution | Linked to payload/hash IOCs |

---

## 🧪 Verification Steps

```bash
# ✅ Check Apache status
sudo systemctl status apache2

# ✅ Check database connectivity
mysql -u misp -p misp -e "SHOW TABLES;"

# ✅ Verify feed imports
curl -s http://localhost/MISP/feeds/index | grep -i "feed"

# ✅ Check correlation engine
cd /var/www/html/MISP/app/Console
sudo -u www-data ./cake Admin getSetting MISP.correlation_default_event_threshold
```

**Access the MISP dashboard and confirm:**

- 📌 Events are visible with proper IOCs
- 📌 Feeds are actively importing
- 📌 Correlations are functioning
- 📌 Export capabilities work correctly

---

## 🛠️ Troubleshooting

<details>
<summary><strong>❌ Issue: Apache fails to serve the MISP interface</strong></summary>

```bash
sudo apache2ctl configtest
sudo systemctl status apache2
sudo tail -n 50 /var/log/apache2/misp_error.log
```

- Confirm `misp.conf` is enabled with `sudo a2ensite misp`
- Confirm the default site was disabled with `sudo a2dissite 000-default`

</details>

<details>
<summary><strong>❌ Issue: Database connection errors</strong></summary>

- Verify credentials in `/var/www/html/MISP/app/Config/database.php` match the MySQL user created in Task 1.2
- Confirm MariaDB is running: `sudo systemctl status mariadb`
- Test manual login: `mysql -u misp -p misp`

</details>

<details>
<summary><strong>❌ Issue: Feed fetch fails or returns no data</strong></summary>

- Confirm outbound network connectivity from the lab VM
- Re-check the feed URL for typos in **Administration → List Feeds**
- Review job status under the **Jobs** section for error details

</details>

---

## 🏁 Conclusion

You have successfully deployed MISP as a comprehensive threat intelligence platform. This lab demonstrated how to set up MISP for IOC ingestion from external feeds, create custom threat intelligence events, and establish IOC sharing mechanisms across enterprise systems.

MISP now serves as your centralized hub for threat intelligence, enabling automated correlation of indicators, streamlined sharing with security partners, and enhanced threat detection capabilities. The platform's correlation engine helps identify patterns across different security events, while the standardized export formats ensure seamless integration with existing security tools and SIEM systems.

This deployment provides the foundation for building a robust threat intelligence program that can scale with organizational security needs and facilitate collaborative defense against emerging threats.

---

<div align="center">

### 🎓 Al Nafi Cloud Labs
**Blue Team Track — Threat Intelligence & Detection Engineering**

*Empowering the next generation of cybersecurity defenders*

</div>
