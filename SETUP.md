# AD Collector for n8n - Setup Guide

## Version 1.0.0

Complete installation and configuration guide for AD Collector.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Active Directory Certificate Setup](#active-directory-certificate-setup)
6. [n8n Configuration](#n8n-configuration)
7. [Testing](#testing)
8. [Troubleshooting](#troubleshooting)
9. [Security Best Practices](#security-best-practices)

---

## Quick Start

```bash
# 1. Create directory
mkdir ad-collector && cd ad-collector

# 2. Create .env file
cat > .env <<EOF
LDAP_URL=ldaps://your-dc.domain.com:636
LDAP_BASE_DN=DC=domain,DC=com
LDAP_BIND_DN=CN=service-account,CN=Users,DC=domain,DC=com
LDAP_BIND_PASSWORD=YourPassword
LDAP_TLS_VERIFY=false
EOF

# 3. Run with Docker
docker run -d \
  --name ad-collector \
  --env-file .env \
  -p 8443:8443 \
  --restart unless-stopped \
  fuskerrs97/ad-collector-n8n:1.0

# 4. Check the API token
docker logs ad-collector | grep "API Token"
```

---

## Prerequisites

### Required

- **Docker** version 20.10 or higher
- **Active Directory** domain controller accessible via LDAPS (port 636)
- **Service Account** in AD with appropriate permissions:
  - Read permissions on user/group objects
  - Write permissions to create/modify/delete users and groups
  - Example: Member of "Account Operators" group

### Recommended

- **Docker Compose** (optional, but recommended for easier management)
- **n8n** instance running (for using the AD automation features)

---

## Installation Methods

### Method 1: Docker Run (Simple)

```bash
# Create configuration directory
mkdir -p ~/ad-collector/certs

# Create .env file
nano ~/ad-collector/.env
# (Fill in your configuration - see Configuration section below)

# Run container
docker run -d \
  --name ad-collector \
  --env-file ~/ad-collector/.env \
  -p 8443:8443 \
  -v ~/ad-collector/certs:/app/certs:ro \
  --restart unless-stopped \
  fuskerrs97/ad-collector-n8n:1.0
```

### Method 2: Docker Compose (Recommended)

```bash
# Create project directory
mkdir -p ~/ad-collector && cd ~/ad-collector

# Create docker-compose.yml
cat > docker-compose.yml <<'EOF'
services:
  ad-collector:
    image: fuskerrs97/ad-collector-n8n:1.0
    container_name: ad-collector
    restart: unless-stopped
    ports:
      - "8443:8443"
    env_file:
      - .env
    volumes:
      - ./certs:/app/certs:ro
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
EOF

# Copy .env.example and configure
cp .env.example .env
nano .env

# Start the container
docker-compose up -d

# View logs
docker-compose logs -f
```

---

## Configuration

### Step 1: Create .env File

Copy the example configuration:

```bash
cp .env.example .env
```

### Step 2: Edit Configuration

Edit `.env` with your AD details:

```bash
nano .env
```

**Minimum Required Configuration:**

```env
# Your AD Domain Controller
LDAP_URL=ldaps://dc01.company.local:636

# Your AD Domain
LDAP_BASE_DN=DC=company,DC=local

# Service Account (must exist in AD)
LDAP_BIND_DN=CN=n8n,CN=Users,DC=company,DC=local

# Service Account Password
LDAP_BIND_PASSWORD=YourSecurePassword123!

# Skip certificate verification (for self-signed certs)
LDAP_TLS_VERIFY=false
```

### Step 3: Verify Configuration

After starting the container, check the logs:

```bash
docker logs ad-collector
```

You should see:

```
========================================
AD Collector for n8n - v1.0.0
========================================
Configuration:
  LDAP URL: ldaps://dc01.company.local:636
  Base DN: DC=company,DC=local
  Bind DN: CN=n8n,CN=Users,DC=company,DC=local
  TLS Verify: false
========================================
API Token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
========================================
✅ AD Collector listening on port 8443
```

**IMPORTANT:** Save the API Token displayed in the logs - you'll need it for n8n!

---

## Active Directory Certificate Setup

If you're using LDAPS with self-signed certificates, you can optionally provide the AD root CA certificate.

### Step 1: Export AD Certificate (On Windows DC)

#### Method A: Using PowerShell

```powershell
# Export the root CA certificate
$cert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*DC=*"}
Export-Certificate -Cert $cert -FilePath C:\ad-root-ca.cer -Type CERT

# Convert to PEM format (requires OpenSSL)
openssl x509 -inform DER -in C:\ad-root-ca.cer -out C:\ad-root-ca.pem
```

#### Method B: Using Certificate Manager

1. Open `certmgr.msc` on the Domain Controller
2. Navigate to: Trusted Root Certification Authorities → Certificates
3. Find your AD certificate
4. Right-click → All Tasks → Export
5. Choose: Base-64 encoded X.509 (.CER)
6. Save as `ad-root-ca.cer`
7. Rename to `ad-root-ca.pem`

### Step 2: Copy Certificate to Collector

```bash
# Create certs directory
mkdir -p ~/ad-collector/certs

# Copy the certificate (adjust path as needed)
cp /path/to/ad-root-ca.pem ~/ad-collector/certs/

# Verify the file
cat ~/ad-collector/certs/ad-root-ca.pem
# Should show: -----BEGIN CERTIFICATE-----
```

### Step 3: Restart Container

```bash
docker restart ad-collector
```

**Note:** Even with the certificate file, keep `LDAP_TLS_VERIFY=false` in your `.env` unless you want strict certificate validation.

---

## n8n Configuration

### Step 1: Get API Token

```bash
# Get the API token from container logs
docker logs ad-collector 2>&1 | grep -A 2 "API Token"
```

Copy the token that looks like: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

### Step 2: Configure n8n Credential

1. Open your n8n instance
2. Go to **Credentials** (🔑 icon)
3. Click **New Credential**
4. Search for: **"Active Directory API"**
5. Fill in the form:

   ```
   Connection Mode: Collector

   Collector URL: http://ad-collector:8443
   (or http://your-server-ip:8443 if n8n is on different host)

   API Token: (paste the token from Step 1)

   ✅ Skip SSL Verification: Checked
   ```

6. Click **Test Connection**
   - Should show: ✅ Connection successful
7. Click **Save**

### Step 3: Test in n8n Workflow

Create a simple test workflow:

1. Add **Manual Trigger** node
2. Add **Active Directory Admin** node
3. Configure:
   - **Credential:** Select your AD credential
   - **Resource:** User
   - **Operation:** Get
   - **Username:** (any existing AD username)
4. Click **Execute Node**
5. Should return user details from AD

---

## Testing

### Test 1: Health Check

```bash
curl http://localhost:8443/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "ad-collector",
  "version": "1.0.0"
}
```

### Test 2: LDAP Connection

```bash
# Replace TOKEN with your actual API token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:8443/api/test-connection \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

Expected response:
```json
{
  "success": true,
  "status": "ok",
  "message": "LDAP connection successful",
  "connected": true
}
```

### Test 3: Get User

```bash
# Replace TOKEN and USERNAME
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
USERNAME="testuser"

curl -X POST http://localhost:8443/api/users/get \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"samAccountName\":\"$USERNAME\"}"
```

Expected response:
```json
{
  "success": true,
  "user": {
    "objectName": "CN=Test User,CN=Users,DC=company,DC=local",
    "attributes": [...]
  }
}
```

---

## Troubleshooting

### Issue 1: "Connection refused" error

**Symptoms:**
```
Error: connect ECONNREFUSED 127.0.0.1:8443
```

**Solutions:**
1. Check if container is running: `docker ps | grep ad-collector`
2. Check container logs: `docker logs ad-collector`
3. Verify port mapping: `docker port ad-collector`

---

### Issue 2: "LDAP bind failed" error

**Symptoms:**
```
Error: LDAP bind failed
```

**Solutions:**
1. Verify LDAP credentials in `.env`:
   ```bash
   docker exec ad-collector sh -c 'echo $LDAP_BIND_DN && echo $LDAP_BIND_PASSWORD'
   ```
2. Test LDAP connectivity from container:
   ```bash
   docker exec ad-collector nc -zv your-dc-hostname 636
   ```
3. Verify service account password hasn't expired in AD
4. Check if service account is locked in AD

---

### Issue 3: "Certificate verification failed"

**Symptoms:**
```
Error: self signed certificate in certificate chain
```

**Solutions:**
1. Set `LDAP_TLS_VERIFY=false` in `.env`
2. Or provide the AD root CA certificate (see Certificate Setup section)
3. Restart container: `docker restart ad-collector`

---

### Issue 4: "Invalid token" error from n8n

**Symptoms:**
```
Error: Invalid token (401)
```

**Solutions:**
1. Get the current token:
   ```bash
   docker logs ad-collector 2>&1 | grep "API Token" -A 1
   ```
2. Update the token in n8n credential
3. Test connection in n8n

---

### Issue 5: Container keeps restarting

**Check logs:**
```bash
docker logs ad-collector --tail 50
```

**Common causes:**
- Missing required environment variable (LDAP_BIND_PASSWORD)
- Invalid .env file format
- Port 8443 already in use

**Solutions:**
1. Verify all required variables are set in `.env`
2. Check for syntax errors in `.env`
3. Change port if needed:
   ```env
   PORT=8444
   ```
   And update docker run command:
   ```bash
   -p 8444:8444
   ```

---

## Security Best Practices

### 1. Protect Your .env File

```bash
# Set restrictive permissions
chmod 600 .env

# Never commit to git
echo ".env" >> .gitignore
```

### 2. Use Strong Service Account Password

- Minimum 16 characters
- Mix of uppercase, lowercase, numbers, and symbols
- Rotate password regularly
- Set password to never expire (for service accounts)

### 3. Limit Service Account Permissions

Create a dedicated service account with **minimal required permissions**:

```powershell
# On AD Domain Controller
# Create service account
New-ADUser -Name "n8n-service" -SamAccountName "n8n-service" `
  -AccountPassword (ConvertTo-SecureString "YourSecurePassword" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Add to appropriate groups (adjust as needed)
Add-ADGroupMember -Identity "Account Operators" -Members "n8n-service"
```

### 4. Network Security

- Keep AD Collector on internal network only
- Use firewall rules to restrict access
- Consider using Docker networks for isolation
- Use HTTPS reverse proxy for external access

### 5. Token Security

- Keep API tokens secret
- Rotate tokens periodically by restarting the container
- Or set a fixed `JWT_SECRET` in `.env` for consistent tokens

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LDAP_URL` | Yes | `ldaps://localhost:636` | AD LDAP URL |
| `LDAP_BASE_DN` | Yes | `DC=example,DC=com` | AD Base DN |
| `LDAP_BIND_DN` | Yes | `CN=admin,CN=Users,DC=example,DC=com` | Service account DN |
| `LDAP_BIND_PASSWORD` | **YES** | - | Service account password |
| `LDAP_TLS_VERIFY` | No | `false` | Verify SSL certificates |
| `PORT` | No | `8443` | API server port |
| `JWT_SECRET` | No | Random | JWT signing secret |
| `API_TOKEN` | No | Auto-generated | Fixed API token |
| `TOKEN_EXPIRY` | No | `365d` | Token expiration time |

---

## Support & Documentation

- **GitHub:** https://github.com/fuskerrs97/ad-collector-n8n
- **Docker Hub:** https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
- **n8n Community:** https://community.n8n.io
- **Issues:** https://github.com/fuskerrs97/ad-collector-n8n/issues

---

## License

MIT License - See LICENSE file for details

---

**AD Collector for n8n v1.0.0**
Compatible with n8n-nodes-ad-admin v0.3.0+
