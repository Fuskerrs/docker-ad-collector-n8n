# AD Collector for n8n

<div align="center">

![AD Collector Logo](https://raw.githubusercontent.com/Fuskerrs/n8n-nodes-ad-admin/master/icons/activeDirectoryAdmin.svg)

**Active Directory Security Auditing & Management API**

A secure, production-ready REST API for Active Directory security auditing and automation

[![Docker Image](https://img.shields.io/docker/v/fuskerrs97/ad-collector-n8n?label=Docker%20Image&logo=docker)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![Docker Pulls](https://img.shields.io/docker/pulls/fuskerrs97/ad-collector-n8n)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![Docker Image Size](https://img.shields.io/docker/image-size/fuskerrs97/ad-collector-n8n/latest)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

###  Support this project

<a href="https://buymeacoffee.com/freelancerc5" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

*If you find this collector useful, consider buying me a coffee! Your support helps maintain and improve this project.* 

</div>

---

## 📖 Table of Contents

- [What is AD Collector?](#what-is-ad-collector)
- [How It Works](#how-it-works)
  - [Architecture Overview](#architecture-overview)
  - [Security Audit Engine](#security-audit-engine)
  - [Management Endpoints](#management-endpoints)
- [Quick Links](#quick-links)
- [Latest Updates](#latest-updates)
- [Features](#features)
- [Installation](#installation)

---

##  What is AD Collector?

**AD Collector** is a **standalone REST API server** for Active Directory security and automation. It provides two core capabilities:

1. **🔍 Security Auditing** - Comprehensive Active Directory vulnerability assessment (87 detections)
2. **⚙️ AD Management** - Safe automation of user/group/computer operations via REST API

**Use it standalone** for security monitoring, compliance reporting, or integrate it with automation tools like [n8n](https://n8n.io) using the [n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin) community node.

### Common Use Cases

**Standalone Usage:**
- 🔐 **Security Auditing** - Regular AD vulnerability scans with JSON export
- 📊 **Compliance Reporting** - Automated security assessments for ISO/NIST compliance
- 🌐 **Web Dashboard Integration** - Connect to custom frontend for AD security monitoring
- 📈 **SIEM Integration** - Feed audit data to security platforms (Splunk, ELK, etc.)
- 🔄 **Scheduled Scans** - Cron jobs exporting audit results for analysis

**With n8n Integration:**
- 🤖 **User Provisioning** - Automated onboarding/offboarding workflows
- 📧 **Security Alerts** - Notify teams when critical vulnerabilities detected
- 🔄 **AD Sync Workflows** - Keep external systems in sync with AD
- 🛠️ **Bulk Operations** - Mass user/group modifications via workflows

### Key Advantages

**vs Direct LDAP Access:**

| **Direct LDAP** | **AD Collector** ⭐ |
|-----------------|---------------------|
|  Requires LDAP ports (389/636) open |  Only HTTP/HTTPS (8443) |
|  Complex network configuration |  Simple Docker deployment |
|  Certificate management per client |  Centralized certificate handling |
|  Multiple connections per client |  Connection pooling and optimization |
|  No rate limiting |  Built-in rate limiting and monitoring |
|  No audit capabilities |  87 built-in vulnerability detections |
|  Manual security checks |  Automated compliance reporting |

**Perfect for:**
-  🏢 Enterprise environments with strict network policies
-  🔒 Security-conscious organizations requiring audit trails
-  ☁️ Cloud-hosted applications (no direct AD access)
-  🚀 High-performance automation at scale
-   📋 Compliance and security monitoring (ISO 27001, NIST CSF)
-  🌐 Custom web dashboards and security portals
-  🔄 Integration with SIEM, monitoring, and automation platforms

---

## 🔧 How It Works

### Architecture Overview

```
┌─────────────────┐         HTTPS (8443)        ┌──────────────────┐         LDAP/LDAPS        ┌─────────────────┐
│                 │ ◄──────────────────────────► │                  │ ◄──────────────────────► │                 │
│  Any HTTP       │     JWT Authentication      │  AD Collector    │   Service Account Auth   │ Active Directory│
│  Client:        │      REST API Calls          │   (Docker)       │    Connection Pooling    │                 │
│                 │                              │                  │                          │                 │
│ • Web Frontend  │                              │  - Audit Engine  │                          │  Users, Groups, │
│ • n8n Workflow  │                              │  - REST API      │                          │  Computers,     │
│ • SIEM Platform │                              │  - Token Mgmt    │                          │  GPOs, ADCS     │
│ • curl/Postman  │                              │  - Rate Limiting │                          │                 │
│ • Python Script │                              │                  │                          │                 │
└─────────────────┘                              └──────────────────┘                          └─────────────────┘
                                                         │
                                                         │ Persistent Storage
                                                         ▼
                                                  ┌──────────────────┐
                                                  │ Token Usage DB   │
                                                  │ (token-data/)    │
                                                  └──────────────────┘
```

**Key Components:**

1. **REST API Server** (Node.js + Express)
   - Listens on port 8443 (configurable)
   - JWT token authentication with usage quotas
   - Rate limiting and request validation

2. **LDAP/LDAPS Client** (ldapjs)
   - Persistent connection pooling to Active Directory
   - Automatic reconnection on failures
   - TLS certificate validation (optional)

3. **Token Management System**
   - Consumable tokens (max uses: 3-100 or unlimited)
   - Usage tracking with SQLite persistence
   - Automatic expired token cleanup

4. **Audit Engine**
   - Real-time LDAP queries with minimal performance impact
   - 74 SSE progress steps for live feedback
   - Export to JSON for offline analysis

---

### 🔍 Security Audit Engine

The collector includes a **comprehensive Active Directory security assessment engine** that detects **87 vulnerability types** across users, groups, and computers.

#### What Gets Audited?

**Users & Groups (71 vulnerabilities)**
- 🔴 **Critical (12)**: Password vulnerabilities, unconstrained delegation, ASREP roasting, ESC1-ESC8 certificate attacks
- 🟠 **High (21)**: Kerberoasting, privilege escalation paths, ACL abuse, ADCS misconfigurations
- 🟡 **Medium (32)**: Weak policies, group nesting issues, LAPS deployment gaps
- 🔵 **Low (6)**: Informational findings, legacy compatibility issues

**Computer Accounts (16 vulnerabilities)** *(v2.5.0+)*
- 🔴 **Critical (4)**: Constrained delegation, RBCD, admin group membership, DCSync rights
- 🟠 **High (6)**: Stale accounts, old passwords, Kerberoastable SPNs, missing LAPS, ACL abuse
- 🟡 **Medium (5)**: Disabled computers not deleted, wrong OU placement, weak encryption, sensitive descriptions
- 🔵 **Low (2)**: AdminCount attribute anomalies, SMB signing status

#### How Auditing Works

1. **Connection** - Collector connects to AD using service account
2. **Enumeration** - Queries users, groups, computers, GPOs, ADCS templates
3. **Analysis** - Runs 87 detection rules against collected data
4. **Scoring** - Calculates security score (0-100) based on findings
5. **Export** - Returns JSON with vulnerabilities categorized by severity

#### Audit Modes

**Standard Audit** (`POST /api/audit`)
```json
{
  "includeDetails": true,      // Full vulnerability details
  "includeComputers": true     // Include computer-specific checks
}
```

**Real-Time Streaming** (`POST /api/audit/stream`)
- Server-Sent Events (SSE) with 74 progress steps
- Live progress tracking for UI integration
- Same data as standard audit, delivered incrementally

**Export to JSON** (`POST /api/audit/export`)
- Downloadable JSON file for offline analysis
- Metadata in HTTP headers (duration, score, counts)
- Perfect for compliance reporting and historical tracking

**CLI Export** (v2.6.0)
```bash
docker exec ad-collector node export-audit.js \
  --output audit.json \
  --include-details \
  --include-computers \
  --pretty
```

#### Performance

| AD Size | Audit Duration | Memory Usage |
|---------|----------------|--------------|
| 1,000 objects | ~15 seconds | ~80 MB |
| 10,000 objects | ~45 seconds | ~120 MB |
| 50,000 objects | ~3 minutes | ~200 MB |
| 100,000+ objects | ~5-8 minutes | ~350 MB |

**Optimization:** Audits run entirely in-memory with no database writes. Only findings are returned.

---

### ⚙️ Management Endpoints

Beyond auditing, the collector provides **Active Directory management operations** for automation workflows.

#### User Management
- `POST /api/users/create` - Create new user accounts
- `POST /api/users/modify` - Update user attributes
- `POST /api/users/delete` - Remove user accounts
- `POST /api/users/disable` - Disable accounts
- `POST /api/users/enable` - Enable accounts
- `POST /api/users/reset-password` - Reset user passwords
- `POST /api/users/unlock` - Unlock locked accounts
- `POST /api/users/move` - Move users between OUs

#### Group Management
- `POST /api/groups/create` - Create new groups
- `POST /api/groups/modify` - Update group attributes
- `POST /api/groups/delete` - Remove groups
- `POST /api/groups/add-member` - Add users to groups
- `POST /api/groups/remove-member` - Remove users from groups
- `POST /api/groups/list-members` - Query group membership

#### Computer Management
- `POST /api/computers/create` - Create computer accounts
- `POST /api/computers/delete` - Remove computer accounts
- `POST /api/computers/move` - Move computers between OUs

#### Query Endpoints
- `POST /api/query` - Custom LDAP queries with filters
- `POST /api/search` - Search users/groups/computers
- `POST /api/test-connection` - Verify LDAP connectivity

#### Access Control Modes

The collector supports **3 endpoint access modes** (configurable during installation):

1. **`full`** (Default) - All endpoints enabled
   - Audit + modifications
   - Use for: Full-featured automation workflows

2. **`audit-only`** - Only audit endpoints
   - No user/group/computer modifications
   - Use for: Security monitoring, compliance scanning

3. **`no-audit`** - All endpoints except audit
   - User management only
   - Use for: Provisioning workflows without security scanning overhead

**Example:** Deploy one collector in `audit-only` mode for monitoring, another in `full` mode for automation.

---

## 🔗 Quick Links

### 📚 Documentation

- **[API Guide](API_GUIDE.md)** - Complete API reference with examples
- **[Vulnerabilities List](VULNERABILITIES.md)** - All 87 detections with remediation steps
- **[Export Guide](EXPORT.md)** - Audit export workflows and examples
- **[Azure Audit Guide](AZURE_AUDIT_GUIDE.md)** - Azure AD/Entra ID configuration and usage
- **[Frontend Integration](FRONTEND_CHANGELOG.md)** - Guide for UI developers

### 🔐 Security & Compliance

- **[MITRE ATT&CK Mapping](VULNERABILITIES.md#compliance-mapping)** - T1558, T1003, T1484, T1098
- **[Risk Scoring Methodology](VULNERABILITIES.md#risk-scoring-methodology)** - Score calculation (0-100)
- **[ISO 27001 Alignment](VULNERABILITIES.md#compliance-mapping)** - A.9, A.14
- **[NIST CSF Coverage](VULNERABILITIES.md#compliance-mapping)** - PR.AC, DE.CM

### 🚀 Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh | bash

# Update
cd ~/ad-collector && ./install.sh --update

# Reset Token
./install.sh --reset-token

# Export Audit
docker exec ad-collector node export-audit.js --output audit.json --pretty
```

---

##  Latest Updates

### v2.7.0 (December 2025) ☁️ **AZURE ENTRA ID AUDIT**
**Cloud AD Audit alongside On-Premises AD**

#### ☁️ Azure AD / Entra ID Integration
- ✅ **Microsoft Graph API** - Comprehensive Azure AD security audit
- ✅ **20 SSE Progress Steps** - Real-time progress streaming for Azure audit
- ✅ **Hybrid Format** - Universal format compatible with existing AD frontends
- ✅ **Identity Protection** - Risky users/sign-ins detection (requires Azure AD P2)
- ✅ **Conditional Access** - Policy analysis and MFA enforcement checks
- ✅ **Privileged Access** - Role assignment and Global Admin monitoring
- ✅ **Application Security** - Credential expiration and vulnerability detection
- ✅ **Guest User Analysis** - External access risk assessment
- 🎯 **Use Case**: Unified on-premises + cloud AD security monitoring
- 📖 **Documentation**: See [AZURE_AUDIT_GUIDE.md](AZURE_AUDIT_GUIDE.md) for complete guide

**New Endpoints:**
- `POST /api/audit/azure/stream` - Run Azure audit with SSE streaming
- `POST /api/audit/azure/status` - Check if Azure is configured

**Configuration:**
Run `./install.sh` and choose "Configure Azure AD audit" option, or manually set environment variables:
```bash
AZURE_ENABLED=true
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

### v2.6.1 (December 2025) 🌐 **API EXPORT ENDPOINT**
**Server-to-Server JSON Export**

#### 🌐 API Export Endpoint
- ✅ **New Endpoint** - `POST /api/audit/export` for programmatic exports
- ✅ **Local Network Ready** - Export from one server to another on local network
- ✅ **Metadata Headers** - Audit summary in HTTP headers (duration, score, counts)
- ✅ **Downloadable JSON** - `Content-Disposition: attachment` for file downloads
- ✅ **All Options Supported** - `includeDetails`, `includeComputers`, `filename`, `pretty`
- 🎯 **Use Case**: Local network exports, automated backup workflows
- 📖 **Documentation**: See [API_GUIDE.md](API_GUIDE.md) for endpoint details

### v2.6.0 (December 2025) 📤 **LOCAL EXPORT FEATURE**
**Audit Export for Air-Gapped Environments**

#### 📤 CLI Export Script
- ✅ **Standalone Export Script** - `export-audit.js` for offline audit exports
- ✅ **No Network Exposure** - Run audits without exposing API publicly
- ✅ **JSON Export** - Full audit data with all 87 vulnerability detections
- ✅ **CLI Options** - `--include-details`, `--include-computers`, `--pretty`
- ✅ **Enterprise Ready** - Perfect for security-conscious organizations
- ✅ **Docker Integration** - `docker exec ad-collector node export-audit.js`
- 🎯 **Use Case**: Air-gapped environments, enterprises with strict network policies
- 📖 **Documentation**: See [EXPORT.md](EXPORT.md) for complete guide

### v2.5.0 (December 2025) 🖥️ **COMPUTER VULNERABILITIES**
**16 New Computer-Specific Detections (87 Total)**

#### 🖥️ Computer Security Assessment
- ✅ **16 New Detections** - Comprehensive computer account security checks
- ✅ **CRITICAL (4)** - Constrained delegation, RBCD, admin groups, DCSync rights
- ✅ **HIGH (6)** - Stale accounts, password age, SPNs, LAPS, ACL abuse
- ✅ **MEDIUM (5)** - Disabled computers, wrong OU, weak encryption, sensitive descriptions
- ✅ **LOW (2)** - adminCount attribute, SMB signing
- 🎯 **Total Vulnerabilities**: 71 → 87 (+16)
- 📖 **Documentation**: See [VULNERABILITIES.md](VULNERABILITIES.md)

### v2.4.0 (December 2025) 🔒 **MAJOR SECURITY UPDATE**
**Token Usage Quota & Endpoint Access Control**

#### 🛡️ Token Usage Quota (Anti-Theft Protection)
- ✅ **Consumable Tokens** - Each JWT can only be used a limited number of times
- ✅ **Configurable Limits** - Set max uses (3-100 or unlimited) during installation
- ✅ **Usage Tracking** - Per-token usage counter with persistence across restarts
- ✅ **HTTP Headers** - `X-Token-Usage`, `X-Token-Max-Uses`, `X-Token-Remaining`
- ✅ **Automatic Cleanup** - Expired tokens removed every 5 minutes
- 🎯 **Prevents Stolen Token Abuse** - Even if leaked, tokens have limited lifespan
- 🔒 **Default**: 10 uses per token (vs unlimited in previous versions)

#### 🎯 Endpoint Access Control
- ✅ **3 Access Modes**:
  - **full** - All endpoints enabled (audit + modifications)
  - **audit-only** - Only audit endpoints (no user/group modifications)
  - **no-audit** - All endpoints except audit (user management only)
- ✅ **Interactive Selection** - Choose mode during installation
- ✅ **Granular Security** - Deploy different collectors with different capabilities
- 🎯 **Use Cases**: Monitoring-only collectors, restricted modification access

#### 🔐 Enhanced Token Security
- ✅ **Token File Persistence** - Token saved to file during installation
- ✅ **Automatic Cleanup** - Token file deleted after user confirmation
- ✅ **Hidden in Logs** - `SHOW_TOKEN` disabled by default (only shown during install)
- ✅ **Reset Command** - `./install.sh --reset-token` regenerates token with new settings
- 🔒 **Secure by Default** - No token visible in logs after installation

#### 🚀 Installation Improvements
- ✅ **Auto-Copy Script** - `install.sh` copied to collector directory automatically
- ✅ **Easy Uninstall** - Run `./install.sh --uninstall` from collector directory
- ✅ **Portable Permissions** - Works with any UID/GID on any system
- ✅ **LDAP Hostname Check** - Automatically enabled for IP-based connections
- ✅ **Interactive Configuration** - Token expiry, max uses, endpoint mode

### v2.3.0 (December 2025) 🔒
**Security Hardening & Production-Ready Defaults**

- ✅ **Secure Binding** - Default to `127.0.0.1` (localhost only)
- ✅ **Token Expiry** - Default changed from 365 days to 1 hour
- ✅ **Rate Limiting** - Built-in protection against abuse
- ✅ **Read-Only Mode** - Deploy collectors with query-only access
- ✅ **Enhanced Logging** - Security-focused audit trails

### v1.7.2 (November 2025)
**Enhanced Audit Details - Full AD Attributes**

- ✅ **Extended Account Details** - Added 15+ additional AD attributes to audit results
- ✅ **Security-Critical Fields**: `whenCreated`, `lastLogonTimestamp`, `pwdLastSet`, `adminCount`
- ✅ **Contact Information**: `mail`, `userPrincipalName`, `description`
- ✅ **Complete Context**: `title`, `department`, `manager`, `company`, `employeeID`, `telephoneNumber`

### v1.7.0 (November 2025)
**Server-Sent Events (SSE) for Real-Time Progress**

- ✅ **New Endpoint**: `POST /api/audit/stream` - Real-time audit progress via SSE
- ✅ **15 Progress Events** - Step-by-step feedback during audit execution
- ✅ **Better UX** - Enable progress bars and real-time status updates in UI

---

##  Features

###  Security First 🔒
-  **Token Usage Quota** (v2.4.0) - Consumable tokens prevent stolen token abuse
-  **Endpoint Access Control** (v2.4.0) - Granular control over audit/modification access
-  **Full LDAPS Support** - Encrypted LDAP connections (port 636)
-  **JWT Authentication** - Secure API access with bearer tokens
-  **Rate Limiting** (v2.3.0) - Built-in protection against abuse
-  **Secure Defaults** (v2.3.0) - Localhost binding, 1h token expiry
-  **Self-Signed Certificates** - Built-in support for internal PKI
-  **Environment-Based Config** - No hardcoded credentials
-  **Non-Root Container** - Runs with minimal privileges (UID 1001)

###  Performance & Reliability
-  **Lightweight** - Only 138 MB Alpine-based Docker image
-  **Health Checks** - Built-in monitoring and auto-recovery
-  **Connection Pooling** - Efficient LDAP connection management
-  **Auto-Restart** - Resilient to network interruptions
-  **Comprehensive Logging** - Detailed error tracking

###  Complete AD Operations
-  **User Management** - Create, modify, enable/disable, password reset
-  **Group Management** - Create, modify, add/remove members
-  **OU Management** - Create, modify, list organizational units
-  **Advanced Search** - Filter and find users, groups, OUs
-  **Activity Tracking** - Login times, password expiry, account status
-  **Security Audit** - Enterprise-grade AD security audit with 15-step progressive tracking, risk scoring (0-100), Kerberos security analysis, password security, privileged accounts detection, advanced security checks (LAPS, DCSync, Protected Users, weak encryption, sensitive delegation), findings by severity

### ☁️ Cloud Integration (v2.7.0)
-  **Azure AD / Entra ID Audit** - Microsoft Graph API integration for cloud AD security
-  **Hybrid Deployment** - Audit both on-premises AD and cloud Azure AD from single collector
-  **Identity Protection** - Risky users and sign-ins detection (Azure AD P2)
-  **Conditional Access** - Policy analysis and MFA enforcement validation
-  **Privileged Access Monitoring** - Global Administrator and role assignment tracking
-  **Application Security** - Credential expiration and OAuth permission analysis
-  **Guest User Analysis** - External access risk assessment and compliance
-  **Real-Time Streaming** - 20-step SSE progress tracking for Azure audits

###  Developer Friendly
-  **29 REST API Endpoints** - Full CRUD operations (27 AD + 2 Azure)
-  **Docker Compose Ready** - One-command deployment
-  **Comprehensive Documentation** - Setup guides, troubleshooting, best practices
-  **Environment Variables** - Flexible configuration
-  **Open Source** - MIT License, contributions welcome

---

##  Quick Start

### Prerequisites

- **Active Directory** domain controller accessible via LDAPS (port 636)
- **Service Account** with AD management permissions
- **n8n instance** with [n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin) installed
- **Linux Server** (CentOS/RHEL/AlmaLinux/Ubuntu/Debian/Fedora)

**Note:** Docker is NOT required if using the automated installer - it will install Docker for you!

---

##  Installation Methods

### Method 1: Automated Installation Script ⭐ **RECOMMENDED**

The easiest way to install AD Collector with automatic dependency checks, Docker installation, and interactive configuration.

** Note:** This script requires an **interactive terminal** and cannot be run via `curl | bash`. Use the download method below.

#### Installation Steps

```bash
# Download the script
wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh

# Make it executable
chmod +x install.sh

# Run the interactive installer
./install.sh
```

#### What the Script Does

 **Automatically detects your OS** (CentOS, AlmaLinux, RHEL, Ubuntu, Debian, Fedora)
 **Checks system requirements** (disk space, memory)
 **Installs Docker** if not present
 **Interactive configuration** with validation
 **Tests LDAP connection** before finishing
 **Displays beautiful summary table** with all connection info
 **Saves API token** for easy retrieval

#### Script Options

```bash
./install.sh                # Run interactive installation
./install.sh --get-token    # Display current API token (from file)
./install.sh --reset-token  # Regenerate API token with new settings (v2.4.0)
./install.sh --status       # Check collector status
./install.sh --uninstall    # Remove AD Collector
./install.sh --help         # Show help
```

**New in v2.4.0:**
- Script automatically copied to collector directory
- Run commands from anywhere: `cd ~/ad-collector && ./install.sh --reset-token`
- Token reset now prompts for new `TOKEN_MAX_USES` setting

 **[Full Installation Script Documentation](INSTALL.md)**

---

### Method 2: Docker Run (Quick Test)

```bash
docker run -d \
  --name ad-collector \
  -e LDAP_URL=ldaps://dc.example.com:636 \
  -e LDAP_BASE_DN=DC=example,DC=com \
  -e LDAP_BIND_DN=CN=n8n-service,CN=Users,DC=example,DC=com \
  -e LDAP_BIND_PASSWORD=YourSecurePassword \
  -e LDAP_TLS_VERIFY=false \
  -p 8443:8443 \
  --restart unless-stopped \
  fuskerrs97/ad-collector-n8n:latest
```

### Method 3: Docker Compose (Manual Setup)

1. **Create project directory:**
```bash
mkdir ad-collector && cd ad-collector
```

2. **Create `docker-compose.yml`:**
```yaml
services:
  ad-collector:
    image: fuskerrs97/ad-collector-n8n:latest
    container_name: ad-collector
    restart: unless-stopped
    ports:
      - "8443:8443"
    env_file:
      - .env
    volumes:
      - ./certs:/app/certs:ro  # Optional: for custom AD certificates
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
```

3. **Create `.env` file:**
```env
# Active Directory Configuration
LDAP_URL=ldaps://dc01.example.com:636
LDAP_BASE_DN=DC=example,DC=com
LDAP_BIND_DN=CN=n8n-service,CN=Users,DC=example,DC=com
LDAP_BIND_PASSWORD=YourSecurePassword

# Security Settings
LDAP_TLS_VERIFY=false  # Set to 'true' for production with valid certificates
LDAP_SKIP_CERT_HOSTNAME_CHECK=true  # For IP-based LDAP_URL connections

# Network & Port
PORT=8443
BIND_ADDRESS=127.0.0.1  # Localhost only (use 0.0.0.0 for all interfaces)

# JWT Authentication (v2.3.0+)
TOKEN_EXPIRY=1h  # Options: 1h, 24h, 7d, 30d (default: 1h)
# API_TOKEN=  # Optional: provide your own JWT (auto-generated if not set)

# Token Usage Quota (v2.4.0+) - Anti-Theft Protection
TOKEN_MAX_USES=10  # Max uses per token (3-100 or 'unlimited', default: 10)

# Endpoint Access Control (v2.4.0+)
ENDPOINT_MODE=full  # Options: full, audit-only, no-audit (default: full)

# Rate Limiting (v2.3.0+)
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW_MS=60000  # 1 minute
RATE_LIMIT_MAX_REQUESTS=100
```

4. **Start the collector:**
```bash
docker-compose up -d
```

5. **Get your API token:**
```bash
docker-compose logs | grep "API Token"
```

**Save this token!** You'll need it to configure n8n.

---

##  Connecting to n8n

Once your AD Collector is running, configure it in n8n:

### Step 1: Install n8n-nodes-ad-admin

If you haven't already, install the **n8n-nodes-ad-admin** community node:

1. In n8n, go to **Settings** → **Community Nodes**
2. Click **Install**
3. Enter: `n8n-nodes-ad-admin`
4. Click **Install**

 **Full n8n node documentation:** https://github.com/Fuskerrs/n8n-nodes-ad-admin

### Step 2: Create Collector Credentials

1. In n8n, go to **Credentials** → **New Credential**
2. Search for: **Active Directory API**
3. Configure as follows:

| Field | Value | Description |
|-------|-------|-------------|
| **Connection Mode** | **Collector** | Select Collector mode |
| **Collector URL** | `http://ad-collector:8443` | Use container name if on same Docker network<br>OR `http://your-server-ip:8443` for external |
| **API Token** | *paste token from logs* | The token displayed when container starts |
| **Skip SSL Verification** |  **Checked** | Check this box |

4. Click **Test Connection** → Should show  **Connected successfully**
5. Click **Save**

### Step 3: Use in Workflows

Add an **Active Directory Admin** node to your workflow and start automating!

**Example - Get User:**
```json
{
  "resource": "user",
  "operation": "getUser",
  "getUserSAM": "john.doe"
}
```

---

##  Full Documentation

- **[Complete Setup Guide](SETUP.md)** - Detailed installation, configuration, and troubleshooting
- **[API Reference](#api-endpoints)** - All 26 available endpoints
- **[n8n Node Documentation](https://github.com/Fuskerrs/n8n-nodes-ad-admin)** - How to use with n8n

---

##  API Endpoints

The AD Collector provides 26 REST API endpoints:

### System (2)
- `GET /health` - Health check
- `POST /api/test-connection` - Test LDAP connectivity

### Users (12)
- `POST /api/users/get` - Get user details
- `POST /api/users/find-by-sam` - Find user
- `POST /api/users/list` - List users
- `POST /api/users/create` - Create user
- `POST /api/users/enable` - Enable account
- `POST /api/users/disable` - Disable account
- `POST /api/users/reset-password` - Reset password
- `POST /api/users/unlock` - Unlock account
- `POST /api/users/check-password-expiry` - Check expiry
- `POST /api/users/set-attributes` - Modify attributes
- `POST /api/users/get-groups` - Get group memberships
- `POST /api/users/get-activity` - Get activity info

### Groups (8)
- `POST /api/groups/get` - Get group
- `POST /api/groups/list` - List groups
- `POST /api/groups/create` - Create group
- `POST /api/groups/modify` - Modify group
- `POST /api/groups/delete` - Delete group
- `POST /api/groups/add-member` - Add member
- `POST /api/groups/remove-member` - Remove member
- `POST /api/groups/search` - Search groups

### OUs (6)
- `POST /api/ous/get` - Get OU
- `POST /api/ous/list` - List OUs
- `POST /api/ous/create` - Create OU
- `POST /api/ous/modify` - Modify OU
- `POST /api/ous/delete` - Delete OU
- `POST /api/ous/search` - Search OUs

**Authentication:** All endpoints (except `/health`) require JWT Bearer token.

---

##  Security Best Practices

### Token Security (v2.4.0+) 🔒
 **Set Token Max Uses** - Use `TOKEN_MAX_USES=10` (default) or lower for high-security environments
 **Short Token Expiry** - Use `TOKEN_EXPIRY=1h` (default) for production, not 365d
 **Delete Token Files** - Always delete token files after installation
 **Regenerate Tokens** - Use `./install.sh --reset-token` to create new tokens with updated limits
 **Hide Tokens in Logs** - Keep `SHOW_TOKEN=false` (default) in production
 **Monitor Usage** - Check `X-Token-Usage` headers to track token consumption

### Endpoint Access Control (v2.4.0+) 🎯
 **Audit-Only Collectors** - Use `ENDPOINT_MODE=audit-only` for monitoring-only deployments
 **No-Audit Collectors** - Use `ENDPOINT_MODE=no-audit` when audit endpoints aren't needed
 **Principle of Least Privilege** - Deploy multiple collectors with different modes if needed
 **Example**: One audit-only collector for security team, one full collector for automation

### Network Security
 **Localhost Binding** - Default `BIND_ADDRESS=127.0.0.1` (use `0.0.0.0` only with firewall)
 **Internal Network Only** - Never expose directly to internet
 **Docker Networks** - Use Docker networks for n8n ↔ Collector communication
 **Firewall Port 8443** - Restrict access to authorized hosts only
 **Rate Limiting** - Keep `RATE_LIMIT_ENABLED=true` (100 req/min default)

### Credentials
 Use dedicated service account
 Minimal required permissions (NOT Domain Admin)
 Rotate passwords regularly
 `.env` file permissions: `chmod 600`
 Store tokens securely (password manager, secrets vault)

### SSL/TLS
 Always use LDAPS (port 636) in production
 Valid SSL certificates when possible
 `LDAP_TLS_VERIFY=true` for production
 `LDAP_SKIP_CERT_HOSTNAME_CHECK=true` only for IP-based connections

---

##  Troubleshooting

### Quick Tests

**Test 1: Health Check**
```bash
curl http://localhost:8443/health
# Expected: {"status":"ok","service":"ad-collector","version":"1.0.0"}
```

**Test 2: LDAP Connection**
```bash
TOKEN="your-api-token"
curl -X POST http://localhost:8443/api/test-connection \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
# Expected: {"success":true,"connected":true}
```

### Common Issues

**Container won't start:**
- Check logs: `docker logs ad-collector`
- Verify all required env vars are set
- Check port 8443 is not in use

**LDAP connection fails:**
- Verify DC hostname/IP is correct
- Test connectivity: `telnet dc.example.com 636`
- Check service account credentials
- Review AD event logs

**Certificate errors:**
- For development: `LDAP_TLS_VERIFY=false`
- For production: provide AD root CA certificate

See [SETUP.md](SETUP.md) for comprehensive troubleshooting guide.

---

##  Technical Details

- **Runtime:** Node.js 18 (Alpine Linux)
- **Size:** 138 MB (optimized)
- **Memory:** ~50-150 MB
- **Startup:** < 3 seconds
- **Response Time:** ~50-200ms (typical)

---

##  Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a Pull Request

**Report bugs:** [GitHub Issues](https://github.com/Fuskerrs/docker-ad-collector-n8n/issues)
**Suggest features:** [GitHub Discussions](https://github.com/Fuskerrs/docker-ad-collector-n8n/discussions)

---

##  License

MIT License - Copyright (c) 2025

See [LICENSE](LICENSE) file for full details.

---

##  Related Projects

- **[n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin)** - The n8n community node (required)
- **[n8n](https://n8n.io)** - Workflow automation platform
- **[Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)** - Official Docker image

---

##  Support

-  **Documentation:** [SETUP.md](SETUP.md)
-  **Bug Reports:** [GitHub Issues](https://github.com/Fuskerrs/docker-ad-collector-n8n/issues)
-  **Discussions:** [GitHub Discussions](https://github.com/Fuskerrs/docker-ad-collector-n8n/discussions)
-  **n8n Community:** [community.n8n.io](https://community.n8n.io)

### Show Your Support

<a href="https://buymeacoffee.com/freelancerc5" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60" width="217">
</a>

**Other ways to support:**
- ⭐ Star on [GitHub](https://github.com/Fuskerrs/docker-ad-collector-n8n)
-  Rate on [Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
-  Share on social media
-  Contribute code or docs

---

<div align="center">

**Made with  for the n8n community**

*Active Directory automation made simple*

**[Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)** | **[GitHub](https://github.com/Fuskerrs/docker-ad-collector-n8n)** | **[n8n Node](https://github.com/Fuskerrs/n8n-nodes-ad-admin)**

</div>
