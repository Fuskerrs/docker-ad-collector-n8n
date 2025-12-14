# AD Collector - Interactive Installation Script

The `install.sh` script provides a fully automated installation experience with system checks, Docker installation, and interactive configuration management.

## 🚀 Quick Start

**⚠️ Important:** This is an **interactive** installer that requires terminal access. It **cannot** be run via `curl | bash`.

### Installation Steps

```bash
# Step 1: Download the installer
wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh

# Step 2: Make it executable
chmod +x install.sh

# Step 3: Run the interactive installer
./install.sh
```

The installer will guide you through configuration with prompts for:
- Installation directory
- Active Directory connection details (LDAP URL, Base DN, Bind credentials)
- **Azure AD / Entra ID configuration (optional, v2.7.0+)**
- Security settings
- Port configuration

---

## 🔄 Alternative: Non-Interactive Installation

If you need a **non-interactive** installation (e.g., for automation or if you tried `curl | bash`), use Docker Compose directly:

```bash
# 1. Create installation directory
mkdir -p ~/ad-collector && cd ~/ad-collector

# 2. Create docker-compose.yml
cat > docker-compose.yml <<'EOF'
services:
  ad-collector:
    image: fuskerrs97/ad-collector-n8n:latest
    container_name: ad-collector
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      - LDAP_URL=ldaps://dc.example.com:636
      - LDAP_BASE_DN=DC=example,DC=com
      - LDAP_BIND_DN=CN=service,CN=Users,DC=example,DC=com
      - LDAP_BIND_PASSWORD=YourPassword
      - LDAP_TLS_VERIFY=false
EOF

# 3. Start the collector
docker compose up -d

# 4. Get your API token
docker compose logs | grep 'API Token'
```

**📖 See:** [README.md](README.md) for complete Docker Compose documentation.

---

## ✨ Features

- ✅ **Automatic OS Detection** - Supports CentOS, AlmaLinux, RHEL, Ubuntu, Debian, Fedora
- ✅ **Dependency Checks** - Verifies disk space, memory, and required tools
- ✅ **Docker Installation** - Automatically installs Docker if not present
- ✅ **Interactive Configuration** - Guides you through all settings
- ✅ **Connection Testing** - Validates LDAP connection before finishing
- ✅ **Token Management** - Easy token retrieval and regeneration
- ✅ **Comprehensive Summary** - Beautiful table with all connection details

## 📋 What the Script Does

### 1. System Checks

- Detects operating system and version
- Verifies available disk space (minimum 2GB required)
- Checks available memory
- Validates Docker installation

### 2. Dependency Installation

If Docker is not installed, the script will:
- Add Docker repository for your OS
- Install Docker CE and Docker Compose plugin
- Start and enable Docker service
- Add your user to docker group (requires re-login)

### 3. Interactive Configuration

The script prompts for:

| Setting | Example | Description |
|---------|---------|-------------|
| **Installation Directory** | `~/ad-collector` | Where to install |
| **LDAP URL** | `ldaps://dc.example.com:636` | Active Directory server |
| **Base DN** | `DC=example,DC=com` | LDAP search base |
| **Bind DN** | `CN=svc-n8n,CN=Users,DC=example,DC=com` | Service account DN |
| **Bind Password** | `YourSecurePassword` | Service account password |
| **TLS Verify** | `y/n` | Verify SSL certificates |
| **Port** | `8443` | Collector listening port |
| **Token Expiry** | `365d` | API token validity period |
| **Azure AD Audit** *(optional)* | `y/n` | Enable Azure Entra ID audit (v2.7.0+) |
| **Azure Tenant ID** | `12345678-1234-...` | Azure AD Tenant ID (if enabled) |
| **Azure Client ID** | `87654321-4321-...` | App Registration Client ID (if enabled) |
| **Azure Client Secret** | `your-secret-value` | App Registration Secret (if enabled) |

### 4. Installation

- Creates installation directory
- Generates `docker-compose.yml`
- Creates `.env` with your configuration
- Pulls Docker image from Docker Hub
- Starts the container

### 5. Testing & Validation

Performs three tests:
1. **Health Check** - Verifies API responds
2. **LDAP Connection** - Tests Active Directory connectivity
3. **Network Accessibility** - Checks if accessible from network

### 6. Final Summary

Displays a comprehensive table with:
- Service status
- Connection URLs (local and network)
- API token
- LDAP configuration
- Next steps for n8n configuration

## 🛠️ Script Options

The script supports several command-line options:

### Installation (Default)

```bash
./install.sh
```

Runs the full interactive installation.

### Get Current Token

```bash
cd ~/ad-collector
./install.sh --get-token
```

Displays the current API token without restarting.

### Reset Token

```bash
cd ~/ad-collector
./install.sh --reset-token
```

Restarts the container and generates a new API token.

### Check Status

```bash
cd ~/ad-collector
./install.sh --status
```

Shows container status and performs a health check.

### Uninstall

```bash
cd ~/ad-collector
./install.sh --uninstall
```

Removes the container, image, and optionally the installation directory.

### Help

```bash
./install.sh --help
```

Displays usage information.

### Update Installation

```bash
cd ~/ad-collector
./install.sh --update
```

Updates the collector and optionally reconfigures settings (including Azure AD configuration added in v2.7.0).

---

## ☁️ Azure AD / Entra ID Configuration (v2.7.0+)

Starting with v2.7.0, the installer supports optional **Azure AD (Entra ID) audit** configuration alongside on-premises Active Directory.

### Prerequisites

Before enabling Azure audit, you need to create an **App Registration** in Azure Portal:

1. Go to [Azure Portal](https://portal.azure.com) → **Azure Active Directory** → **App registrations**
2. Click **New registration**
3. Name: `AD-Collector-Audit` (or any name)
4. Supported account types: **Accounts in this organizational directory only**
5. Click **Register**

### Required API Permissions

Grant the following **Application permissions** (not Delegated):

**Required:**
- `User.Read.All` - Read all user profiles
- `Directory.Read.All` - Read directory data
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications

**Optional (Enhanced features):**
- `Policy.Read.All` - Read Conditional Access policies
- `IdentityRiskyUser.Read.All` - Read risky users (requires Azure AD P2 license)

After adding permissions, click **Grant admin consent**.

### Create Client Secret

1. In your App Registration, go to **Certificates & secrets**
2. Click **New client secret**
3. Add description: `AD Collector`
4. Select expiration: **12-24 months recommended**
5. Click **Add**
6. **Copy the secret value immediately** (you won't see it again!)

### Gather Required Information

You'll need three values for installation:

- **Tenant ID:** Found in App Registration overview (Directory/Tenant ID)
- **Client ID:** Found in App Registration overview (Application/Client ID)
- **Client Secret:** The secret value you just copied

### During Installation

The installer will prompt:

```
☁️  Azure AD / Entra ID Configuration (Optional)
   Enable Azure cloud audit alongside on-premises AD audit

   Configure Azure AD audit? (y/n) [n]: y

   Azure Tenant ID: 12345678-1234-1234-1234-123456789012
   Azure Client ID (App Registration): 87654321-4321-4321-4321-210987654321
   Azure Client Secret: ********
```

If you skip Azure configuration during installation, you can add it later:

```bash
cd ~/ad-collector
./install.sh --update
# Answer 'y' to "Configure/Update Azure AD audit?"
```

Or manually edit `.env` and add:

```bash
AZURE_ENABLED=true
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

Then restart: `docker compose restart`

### Azure Audit Features

With Azure configured, you get:

- **20 SSE audit steps** for real-time progress monitoring
- **12 Azure-specific vulnerability types** (Critical, High, Medium, Low)
- **Identity Protection** - Risky users and sign-ins (requires Azure AD P2)
- **Conditional Access** - Policy analysis and recommendations
- **Hybrid audits** - Audit both on-premises AD and cloud Azure AD from single collector

**API Endpoints:**
- `POST /api/audit/azure/status` - Check if Azure is configured
- `POST /api/audit/azure/stream` - Run Azure audit with SSE streaming

**Documentation:** See [AZURE_AUDIT_GUIDE.md](https://github.com/Fuskerrs/docker-ad-collector-n8n/blob/main/AZURE_AUDIT_GUIDE.md) for complete guide.

---

## 📊 Example Installation Flow

```
═══════════════════════════════════════════════════════════════
  AD Collector for n8n - Installation
═══════════════════════════════════════════════════════════════

This script will install and configure AD Collector

▶ Detecting operating system...
✅ Detected: AlmaLinux 9.6 (Cerulean Leopard)
▶ Checking available disk space...
✅ Disk space OK (45678MB available)
▶ Checking available memory...
✅ Memory: 3456MB available / 4096MB total
▶ Checking Docker installation...
✅ Docker is installed (version 24.0.7)

═══════════════════════════════════════════════════════════════
  Configuration
═══════════════════════════════════════════════════════════════

Please provide the following information:

Installation directory [/root/ad-collector]:
LDAP/LDAPS URL (e.g., ldaps://dc.example.com:636): ldaps://dc.example.com:636
Base DN (e.g., DC=example,DC=com): DC=example,DC=com
Bind DN (e.g., CN=service,CN=Users,DC=example,DC=com): CN=n8n-service,CN=Users,DC=example,DC=com
Bind Password: ********
Confirm Password: ********
Verify TLS certificates? (y/n) [n]: n
Collector port [8443]:
Token expiry (e.g., 365d, 1y) [365d]:

═══════════════════════════════════════════════════════════════
  Configuration Summary
═══════════════════════════════════════════════════════════════

Installation Settings:
  Directory:     /root/ad-collector
  Port:          8443

Active Directory Settings:
  LDAP URL:      ldaps://dc.example.com:636
  Base DN:       DC=example,DC=com
  Bind DN:       CN=n8n-service,CN=Users,DC=example,DC=com
  TLS Verify:    false
  Token Expiry:  365d

Proceed with installation? (y/n): y

═══════════════════════════════════════════════════════════════
  Creating Project
═══════════════════════════════════════════════════════════════

▶ Creating directory: /root/ad-collector
▶ Creating docker-compose.yml...
▶ Creating .env configuration...
✅ Project created at /root/ad-collector

═══════════════════════════════════════════════════════════════
  Starting AD Collector
═══════════════════════════════════════════════════════════════

▶ Pulling Docker image from Docker Hub...
▶ Starting container...
▶ Waiting for container to be ready...
✅ Container started successfully

▶ Retrieving API token...
✅ Token retrieved

═══════════════════════════════════════════════════════════════
  Connection Tests
═══════════════════════════════════════════════════════════════

▶ Test 1/3: Health check...
✅ Health check passed
▶ Test 2/3: LDAP connection test...
✅ LDAP connection successful
▶ Test 3/3: Network accessibility...
✅ Accessible from network

═══════════════════════════════════════════════════════════════
  Installation Complete!
═══════════════════════════════════════════════════════════════

╔════════════════════════════════════════════════════════════════════════╗
║                    AD Collector Installation Summary                  ║
╠════════════════════════════════════════════════════════════════════════╣
║ Service Information                                                    ║
╠════════════════════════════════════════════════════════════════════════╣
║ Container Status:              running                                 ║
║ Health Status:                 ✅ OK                                    ║
║ LDAP Connection:               ✅ Connected                             ║
║ Network Status:                ✅ Accessible                            ║
╠════════════════════════════════════════════════════════════════════════╣
║ Connection Details                                                     ║
╠════════════════════════════════════════════════════════════════════════╣
║ Local URL:                     http://localhost:8443                   ║
║ Network URL:                   http://192.168.1.107:8443               ║
║ Health Endpoint:               http://192.168.1.107:8443/health        ║
╠════════════════════════════════════════════════════════════════════════╣
║ Active Directory Settings                                              ║
╠════════════════════════════════════════════════════════════════════════╣
║ LDAP URL:                      ldaps://dc.example.com:636              ║
║ Base DN:                       DC=example,DC=com                       ║
║ TLS Verify:                    false                                   ║
╠════════════════════════════════════════════════════════════════════════╣
║ API Token (save this!)                                                 ║
╠════════════════════════════════════════════════════════════════════════╣
║ eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlIjoiYWQtY29sbGVjdG9y ║
║ IiwiY3JlYXRlZCI6MTc2MjA4MTUzNTI0MywiaWF0IjoxNzYyMDgxNTM1LCJleHAiOjE3 ║
║ OTM2MTc1MzV9.jT37ABYXlxpXI9o8DN1GxnIUcHZz03aQ8juKK9exrAE                ║
╚════════════════════════════════════════════════════════════════════════╝

Next Steps:

  1. Configure n8n credentials:
     • Connection Mode: Collector
     • Collector URL: http://192.168.1.107:8443
     • API Token: [token above]
     • Skip SSL Verification: ✓ Checked

  2. Useful commands:
     • View logs:        cd /root/ad-collector && docker compose logs -f
     • Stop collector:   cd /root/ad-collector && docker compose stop
     • Start collector:  cd /root/ad-collector && docker compose start
     • Restart (new token): cd /root/ad-collector && docker compose restart
     • Remove:           cd /root/ad-collector && docker compose down

  3. Documentation:
     • Docker Hub: https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
     • GitHub: https://github.com/Fuskerrs/docker-ad-collector-n8n

ℹ️  Installation summary saved to: /root/ad-collector/INSTALLATION_SUMMARY.txt

✅ Installation completed successfully! 🎉
```

## 🔧 Post-Installation

### View Logs

```bash
cd ~/ad-collector
docker compose logs -f
```

### Restart Container

```bash
cd ~/ad-collector
docker compose restart
```

### Stop/Start Container

```bash
cd ~/ad-collector
docker compose stop
docker compose start
```

### Update to Latest Version

```bash
cd ~/ad-collector
docker compose pull
docker compose up -d
```

## 🔐 Security Notes

### File Permissions

The script automatically sets:
- `.env` file permissions to `600` (owner read/write only)
- Prevents accidental credential exposure

### Password Handling

- Passwords are never logged or displayed
- Confirmation required for password input
- Stored only in `.env` file with restricted permissions

### Token Security

- Tokens are generated with cryptographic randomness
- Long expiry (365 days default) reduces re-configuration
- Can be regenerated anytime with `--reset-token`

## 🆘 Troubleshooting

### Docker Not Starting

If Docker fails to start after installation:

```bash
sudo systemctl status docker
sudo systemctl restart docker
```

### Permission Denied

If you get "permission denied" errors after Docker installation:

```bash
# Log out and log back in for group changes to take effect
exit
# Then SSH back in and run the script again
```

Or use `newgrp` to avoid re-login:

```bash
newgrp docker
./install.sh
```

### Container Won't Start

Check logs:

```bash
cd ~/ad-collector
docker compose logs
```

Common issues:
- Port 8443 already in use (change port in .env)
- Invalid LDAP credentials (check .env)
- LDAP server unreachable (verify network/firewall)

### LDAP Connection Fails

Verify connectivity:

```bash
# Test LDAP port
telnet dc.example.com 636

# Test LDAPS with openssl
openssl s_client -connect dc.example.com:636
```

## 📝 Requirements

### Minimum System Requirements

- **OS:** Linux (CentOS/RHEL/AlmaLinux 7+, Ubuntu 18.04+, Debian 10+)
- **Disk Space:** 2GB free
- **Memory:** 512MB available (1GB+ recommended)
- **Network:** Access to Active Directory server (port 636 for LDAPS)

### Network Requirements

- Outbound HTTPS (443) for Docker Hub image pull
- Inbound port 8443 (or custom) for n8n to connect
- Outbound LDAPS (636) to Active Directory server

## 🔄 Upgrading

To upgrade to a new version:

```bash
cd ~/ad-collector

# Pull latest image
docker compose pull

# Restart with new image (preserves token)
docker compose up -d
```

## 🗑️ Uninstalling

```bash
cd ~/ad-collector
./install.sh --uninstall
```

This will:
1. Stop and remove the container
2. Remove the Docker image
3. Optionally remove the installation directory

## 💡 Tips

### Multiple Installations

You can install multiple instances with different configurations:

```bash
# First instance
./install.sh
# Choose directory: ~/ad-collector-prod
# Choose port: 8443

# Second instance
./install.sh
# Choose directory: ~/ad-collector-dev
# Choose port: 8444
```

### Backup Configuration

```bash
# Backup .env file (contains credentials)
cp ~/ad-collector/.env ~/ad-collector-backup.env

# Backup entire installation
tar -czf ad-collector-backup.tar.gz ~/ad-collector/
```

### Firewall Configuration

If using firewalld (CentOS/RHEL/AlmaLinux):

```bash
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

If using ufw (Ubuntu/Debian):

```bash
sudo ufw allow 8443/tcp
sudo ufw reload
```

## 📞 Support

- **Documentation:** https://github.com/Fuskerrs/docker-ad-collector-n8n
- **Docker Hub:** https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
- **Issues:** https://github.com/Fuskerrs/docker-ad-collector-n8n/issues
- **n8n Node:** https://github.com/Fuskerrs/n8n-nodes-ad-admin

---

**Made with ❤️ for the n8n community**
