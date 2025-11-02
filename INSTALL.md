# AD Collector - Quick Installation Script

The `install.sh` script provides a fully automated installation experience with system checks, Docker installation, and configuration management.

## 🚀 Quick Start

### One-Line Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh | bash
```

Or download and run:

```bash
wget https://raw.githubusercontent.com/Fuskerrs/docker-ad-collector-n8n/main/install.sh
chmod +x install.sh
./install.sh
```

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
