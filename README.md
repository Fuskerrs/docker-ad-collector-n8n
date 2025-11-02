# AD Collector for n8n

<div align="center">

![AD Collector Logo](https://raw.githubusercontent.com/Fuskerrs/n8n-nodes-ad-admin/master/icons/activeDirectoryAdmin.svg)

**The official Active Directory Collector API for n8n automation**

A secure, lightweight, and production-ready bridge between n8n and Active Directory LDAP/LDAPS

[![Docker Image](https://img.shields.io/docker/v/fuskerrs97/ad-collector-n8n?label=Docker%20Image&logo=docker)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![Docker Pulls](https://img.shields.io/docker/pulls/fuskerrs97/ad-collector-n8n)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![Docker Image Size](https://img.shields.io/docker/image-size/fuskerrs97/ad-collector-n8n/latest)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### ☕ Support this project

<a href="https://buymeacoffee.com/freelancerc5" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

*If you find this collector useful, consider buying me a coffee! Your support helps maintain and improve this project.* 🚀

</div>

---

## 🎯 What is AD Collector?

**AD Collector** is a **lightweight REST API server** that acts as a secure bridge between [n8n](https://n8n.io) and your Active Directory infrastructure. It enables the [n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin) community node to perform powerful AD operations in **Collector Mode**.

### 🤔 Why Use Collector Mode?

| **Direct Mode** | **Collector Mode** ⭐ |
|-----------------|---------------------|
| ❌ Requires opening LDAP ports (389/636) to n8n | ✅ Only needs HTTP/HTTPS (8443) access |
| ❌ Complex network configuration | ✅ Simple Docker deployment |
| ❌ Certificate management per workflow | ✅ Centralized certificate handling |
| ❌ Multiple LDAP connections | ✅ Connection pooling and optimization |
| ⚠️ Limited connection control | ✅ Rate limiting and monitoring |

**Perfect for:**
- 🏢 Enterprise environments with strict network policies
- 🔒 Security-conscious organizations
- ☁️ Cloud-hosted n8n instances
- 🚀 High-performance AD automation at scale

---

## ✨ Features

### 🔐 Security First
- ✅ **Full LDAPS Support** - Encrypted LDAP connections (port 636)
- ✅ **JWT Authentication** - Secure API access with bearer tokens
- ✅ **Self-Signed Certificates** - Built-in support for internal PKI
- ✅ **Environment-Based Config** - No hardcoded credentials
- ✅ **Non-Root Container** - Runs with minimal privileges

### ⚡ Performance & Reliability
- ✅ **Lightweight** - Only 138 MB Alpine-based Docker image
- ✅ **Health Checks** - Built-in monitoring and auto-recovery
- ✅ **Connection Pooling** - Efficient LDAP connection management
- ✅ **Auto-Restart** - Resilient to network interruptions
- ✅ **Comprehensive Logging** - Detailed error tracking

### 🎯 Complete AD Operations
- 👥 **User Management** - Create, modify, enable/disable, password reset
- 👬 **Group Management** - Create, modify, add/remove members
- 🗂️ **OU Management** - Create, modify, list organizational units
- 🔍 **Advanced Search** - Filter and find users, groups, OUs
- 📊 **Activity Tracking** - Login times, password expiry, account status

### 🛠️ Developer Friendly
- ✅ **26 REST API Endpoints** - Full CRUD operations
- ✅ **Docker Compose Ready** - One-command deployment
- ✅ **Comprehensive Documentation** - Setup guides, troubleshooting, best practices
- ✅ **Environment Variables** - Flexible configuration
- ✅ **Open Source** - MIT License, contributions welcome

---

## 🚀 Quick Start

### Prerequisites

- **Active Directory** domain controller accessible via LDAPS (port 636)
- **Service Account** with AD management permissions
- **n8n instance** with [n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin) installed
- **Linux Server** (CentOS/RHEL/AlmaLinux/Ubuntu/Debian/Fedora)

**Note:** Docker is NOT required if using the automated installer - it will install Docker for you!

---

## 📦 Installation Methods

### Method 1: Automated Installation Script ⭐ **RECOMMENDED**

The easiest way to install AD Collector with automatic dependency checks, Docker installation, and interactive configuration.

#### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh | bash
```

Or download and run:

```bash
wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh
chmod +x install.sh
./install.sh
```

#### What the Script Does

✅ **Automatically detects your OS** (CentOS, AlmaLinux, RHEL, Ubuntu, Debian, Fedora)
✅ **Checks system requirements** (disk space, memory)
✅ **Installs Docker** if not present
✅ **Interactive configuration** with validation
✅ **Tests LDAP connection** before finishing
✅ **Displays beautiful summary table** with all connection info
✅ **Saves API token** for easy retrieval

#### Script Options

```bash
./install.sh                # Run interactive installation
./install.sh --get-token    # Display current API token
./install.sh --reset-token  # Regenerate API token
./install.sh --status       # Check collector status
./install.sh --uninstall    # Remove AD Collector
./install.sh --help         # Show help
```

📖 **[Full Installation Script Documentation](INSTALL.md)**

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
version: '3.8'

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

# Optional Settings
PORT=8443
TOKEN_EXPIRY=365d
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

## 🔗 Connecting to n8n

Once your AD Collector is running, configure it in n8n:

### Step 1: Install n8n-nodes-ad-admin

If you haven't already, install the **n8n-nodes-ad-admin** community node:

1. In n8n, go to **Settings** → **Community Nodes**
2. Click **Install**
3. Enter: `n8n-nodes-ad-admin`
4. Click **Install**

📖 **Full n8n node documentation:** https://github.com/Fuskerrs/n8n-nodes-ad-admin

### Step 2: Create Collector Credentials

1. In n8n, go to **Credentials** → **New Credential**
2. Search for: **Active Directory API**
3. Configure as follows:

| Field | Value | Description |
|-------|-------|-------------|
| **Connection Mode** | **Collector** | Select Collector mode |
| **Collector URL** | `http://ad-collector:8443` | Use container name if on same Docker network<br>OR `http://your-server-ip:8443` for external |
| **API Token** | *paste token from logs* | The token displayed when container starts |
| **Skip SSL Verification** | ✅ **Checked** | Check this box |

4. Click **Test Connection** → Should show ✅ **Connected successfully**
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

## 📚 Full Documentation

- **[Complete Setup Guide](SETUP.md)** - Detailed installation, configuration, and troubleshooting
- **[API Reference](#api-endpoints)** - All 26 available endpoints
- **[n8n Node Documentation](https://github.com/Fuskerrs/n8n-nodes-ad-admin)** - How to use with n8n

---

## 🔧 API Endpoints

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

## 🔒 Security Best Practices

### Network Security
✅ Run on internal network only
✅ Use Docker networks for n8n ↔ Collector
✅ Firewall port 8443
❌ Never expose directly to internet

### Credentials
✅ Use dedicated service account
✅ Minimal required permissions
✅ Rotate passwords regularly
✅ `.env` file permissions: `chmod 600`
❌ Never use Domain Admin

### SSL/TLS
✅ Always use LDAPS (port 636) in production
✅ Valid SSL certificates when possible
❌ Don't skip certificate verification in production

---

## 🐛 Troubleshooting

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

## 📊 Technical Details

- **Runtime:** Node.js 18 (Alpine Linux)
- **Size:** 138 MB (optimized)
- **Memory:** ~50-150 MB
- **Startup:** < 3 seconds
- **Response Time:** ~50-200ms (typical)

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a Pull Request

**Report bugs:** [GitHub Issues](https://github.com/Fuskerrs/docker-ad-collector-n8n/issues)
**Suggest features:** [GitHub Discussions](https://github.com/Fuskerrs/docker-ad-collector-n8n/discussions)

---

## 📄 License

MIT License - Copyright (c) 2025

See [LICENSE](LICENSE) file for full details.

---

## 🔗 Related Projects

- **[n8n-nodes-ad-admin](https://github.com/Fuskerrs/n8n-nodes-ad-admin)** - The n8n community node (required)
- **[n8n](https://n8n.io)** - Workflow automation platform
- **[Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)** - Official Docker image

---

## 💬 Support

- 📖 **Documentation:** [SETUP.md](SETUP.md)
- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/Fuskerrs/docker-ad-collector-n8n/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/Fuskerrs/docker-ad-collector-n8n/discussions)
- 🌐 **n8n Community:** [community.n8n.io](https://community.n8n.io)

### Show Your Support

<a href="https://buymeacoffee.com/freelancerc5" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60" width="217">
</a>

**Other ways to support:**
- ⭐ Star on [GitHub](https://github.com/Fuskerrs/docker-ad-collector-n8n)
- 🐳 Rate on [Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
- 🐦 Share on social media
- 🤝 Contribute code or docs

---

<div align="center">

**Made with ❤️ for the n8n community**

*Active Directory automation made simple*

**[Docker Hub](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)** | **[GitHub](https://github.com/Fuskerrs/docker-ad-collector-n8n)** | **[n8n Node](https://github.com/Fuskerrs/n8n-nodes-ad-admin)**

</div>
