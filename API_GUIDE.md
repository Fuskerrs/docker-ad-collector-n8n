# AD Collector API Guide

## Version: 2.8.0

This guide describes all available API endpoints in the Docker AD Collector for n8n.

**Version 2.8.0:** API harmonization with provider-specific endpoints, detailed test connections with domain/tenant info, global status endpoint, and sensitive data masking

---

## Configuration

### Environment Variables

#### LDAP Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `LDAP_URL` | AD server URL | `ldaps://localhost:636` |
| `LDAP_BASE_DN` | Base DN for searches | `DC=example,DC=com` |
| `LDAP_BIND_DN` | Service account DN | `CN=admin,CN=Users,DC=example,DC=com` |
| `LDAP_BIND_PASSWORD` | Account password | `password` |
| `LDAP_TLS_VERIFY` | Verify TLS certificate | `true` |
| `LDAP_SKIP_CERT_HOSTNAME_CHECK` | Skip cert hostname check (for IP-based) | `false` |
| `LDAP_TIMEOUT` | LDAP query timeout (ms) | `10000` |
| `LDAP_CONNECT_TIMEOUT` | Connection timeout (ms) | `5000` |

#### Network & Binding
| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Listening port | `8443` |
| `BIND_ADDRESS` | Binding address (127.0.0.1 or 0.0.0.0) | `127.0.0.1` |

#### JWT Authentication (v2.4.0+)
| Variable | Description | Default |
|----------|-------------|---------|
| `API_TOKEN` | Custom JWT token | Auto-generated |
| `TOKEN_EXPIRY` | Token validity duration | `7d` |
| `TOKEN_MAX_USES` | Max uses per token (anti-theft) | `10` |
| `SHOW_TOKEN` | Show token in logs | `false` |

#### Access Control (v2.4.0+)
| Variable | Description | Default |
|----------|-------------|---------|
| `ENDPOINT_MODE` | Endpoint access mode (full/audit-only/no-audit) | `full` |
| `READ_ONLY_MODE` | (Deprecated) Read-only mode | `false` |

#### Rate Limiting (v2.3.0+)
| Variable | Description | Default |
|----------|-------------|---------|
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window (ms) | `60000` |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | `100` |

#### Audit Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_PWD_AGE_DAYS` | Max password age for alerts | `90` |

#### Azure AD / Entra ID Configuration (v2.7.0+)
| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_ENABLED` | Enable Azure audit | `false` |
| `AZURE_TENANT_ID` | Azure Tenant ID | - |
| `AZURE_CLIENT_ID` | Azure App Client ID | - |
| `AZURE_CLIENT_SECRET` | Azure App Client Secret | - |

**Azure App Registration Required Permissions:**
- `User.Read.All` - Read all user profiles
- `Directory.Read.All` - Read directory data
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications
- `Policy.Read.All` - Read Conditional Access policies (optional)
- `IdentityRiskyUser.Read.All` - Read risky users (requires Azure AD P2, optional)

---

## Authentication

All API requests (except `/health`) require an Authorization header:

```
Authorization: Bearer <API_TOKEN>
```

The token is displayed in the logs at container startup:
```
docker logs ad-collector
```

---

## Endpoints

### Health Check

#### GET /health

Checks if the service is online.

**Authentication required:** No

**Example:**
```bash
curl http://localhost:8443/health
```

**Response:**
```json
{
  "status": "ok",
  "service": "ad-collector",
  "version": "1.1.1"
}
```

---

### Connection Testing Endpoints

#### POST /api/test-connection

**Deprecated - Use provider-specific endpoints instead**

Legacy endpoint that tests Active Directory connection. For backward compatibility only.

**Recommendation:** Use `/api/test-connection/ad` for detailed Active Directory information.

**Body:** None

**Example:**
```bash
curl -X POST http://localhost:8443/api/test-connection \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Success response:**
```json
{
  "success": true,
  "status": "ok",
  "message": "LDAP connection successful",
  "connected": true
}
```

---

#### POST /api/test-connection/ad

**NEW in v2.8.0** - Tests Active Directory connection and returns detailed domain information.

**Why use this endpoint?**
- ✅ Detailed Active Directory domain information (name, functional level, DC hostname)
- ✅ LDAP server metadata (version, security, naming contexts)
- ✅ Optional sensitive data masking
- ✅ Better diagnostics than legacy endpoint

**Body:**
```json
{
  "maskSensitiveData": false
}
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maskSensitiveData` | boolean | `false` | Mask domain names, DNs, and server hostnames |

**Example:**
```bash
TOKEN="your-api-token"

# Standard test with full details
curl -X POST http://localhost:8443/api/test-connection/ad \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Test with masked sensitive data
curl -X POST http://localhost:8443/api/test-connection/ad \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"maskSensitiveData": true}'
```

**Success response:**
```json
{
  "success": true,
  "connected": true,
  "provider": "active-directory",
  "domain": {
    "name": "example.com",
    "dn": "DC=example,DC=com",
    "controller": "dc01.example.com",
    "functionalLevel": "Windows Server 2016",
    "forestLevel": "Windows Server 2016"
  },
  "ldap": {
    "version": 3,
    "secure": true,
    "port": 636
  },
  "contexts": {
    "default": "DC=example,DC=com",
    "configuration": "CN=Configuration,DC=example,DC=com",
    "schema": "CN=Schema,CN=Configuration,DC=example,DC=com"
  },
  "serverTime": "2025-12-15T10:30:45.123Z"
}
```

**Response with masked data:**
```json
{
  "success": true,
  "connected": true,
  "provider": "active-directory",
  "domain": {
    "name": "***MASKED***",
    "dn": "***MASKED***",
    "controller": "***MASKED***",
    "functionalLevel": "Windows Server 2016",
    "forestLevel": "Windows Server 2016"
  },
  "ldap": {
    "version": 3,
    "secure": true,
    "port": 636
  },
  "contexts": {
    "default": "***MASKED***",
    "configuration": "***MASKED***",
    "schema": "***MASKED***"
  },
  "serverTime": "2025-12-15T10:30:45.123Z"
}
```

**Functional Levels Detected:**
- `Windows 2000` (Level 0)
- `Windows Server 2003` (Level 2)
- `Windows Server 2008` (Level 3)
- `Windows Server 2008 R2` (Level 4)
- `Windows Server 2012` (Level 5)
- `Windows Server 2012 R2` (Level 6)
- `Windows Server 2016` (Level 7)
- `Windows Server 2025` (Level 10)

---

#### POST /api/test-connection/azure

**NEW in v2.8.0** - Tests Azure Entra ID connection and returns detailed tenant information.

**Prerequisites:**
- Azure credentials configured via environment variables or `install.sh`
- App Registration with required permissions (User.Read.All, Directory.Read.All)

**Body:**
```json
{
  "maskSensitiveData": false
}
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maskSensitiveData` | boolean | `false` | Mask tenant ID, tenant name, domains, and client ID |

**Example:**
```bash
TOKEN="your-api-token"

# Standard test with full details
curl -X POST http://localhost:8443/api/test-connection/azure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Test with masked sensitive data
curl -X POST http://localhost:8443/api/test-connection/azure \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"maskSensitiveData": true}'
```

**Success response:**
```json
{
  "success": true,
  "connected": true,
  "provider": "azure-entra-id",
  "tenant": {
    "id": "12345678-1234-1234-1234-123456789012",
    "name": "Contoso Ltd",
    "country": "US",
    "defaultDomain": "contoso.onmicrosoft.com",
    "verifiedDomains": [
      "contoso.onmicrosoft.com",
      "contoso.com"
    ]
  },
  "authentication": {
    "method": "client-credentials",
    "tokenValid": true,
    "clientId": "87654321-4321-4321-4321-210987654321"
  }
}
```

**Error response (not configured):**
```json
{
  "success": false,
  "connected": false,
  "provider": "azure-entra-id",
  "error": "Azure credentials not configured"
}
```

---

#### POST /api/status

**NEW in v2.8.0** - Global status endpoint showing all configured providers (AD, Azure, AWS) with 30-second cache.

**Why use this endpoint?**
- ✅ Single endpoint to check all providers
- ✅ Cached for 30 seconds (reduces load)
- ✅ Force refresh option
- ✅ Returns version, connectivity, and basic info for each provider

**Body:**
```json
{
  "maskSensitiveData": false,
  "forceRefresh": false
}
```

**Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maskSensitiveData` | boolean | `false` | Mask all sensitive information |
| `forceRefresh` | boolean | `false` | Bypass cache and fetch fresh data |

**Example:**
```bash
TOKEN="your-api-token"

# Standard status check (uses cache)
curl -X POST http://localhost:8443/api/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Force refresh (bypass cache)
curl -X POST http://localhost:8443/api/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"forceRefresh": true}'
```

**Success response (cached):**
```json
{
  "success": true,
  "version": "2.8.0",
  "providers": {
    "ad": {
      "available": true,
      "connected": true,
      "domainName": "example.com",
      "domainController": "dc01.example.com",
      "functionalLevel": "Windows Server 2016"
    },
    "azure": {
      "available": true,
      "configured": true,
      "connected": true,
      "tenantName": "Contoso Ltd",
      "tenantId": "12345678-1234-1234-1234-123456789012",
      "defaultDomain": "contoso.onmicrosoft.com"
    },
    "aws": {
      "available": false,
      "configured": false,
      "connected": false
    }
  },
  "cached": true,
  "cacheAge": "12s"
}
```

**Success response (fresh, no Azure configured):**
```json
{
  "success": true,
  "version": "2.8.0",
  "providers": {
    "ad": {
      "available": true,
      "connected": true,
      "domainName": "example.com",
      "domainController": "dc01.example.com",
      "functionalLevel": "Windows Server 2016"
    },
    "azure": {
      "available": true,
      "configured": false,
      "connected": false
    },
    "aws": {
      "available": false,
      "configured": false,
      "connected": false
    }
  },
  "cached": false
}
```

**Cache Behavior:**
- Cache TTL: 30 seconds
- Automatically refreshed on first request after expiration
- Use `forceRefresh: true` to bypass cache
- Cache includes all provider status checks

---

## Local Audit Export (v2.6.0)

### 📤 Standalone Export Script

**NEW in v2.6.0:** Export complete AD security audits to JSON without exposing the API publicly.

#### Usage

```bash
# Basic export
docker exec ad-collector node export-audit.js

# Detailed export with all options
docker exec ad-collector node export-audit.js \
  --output /tmp/audit.json \
  --include-details \
  --include-computers \
  --pretty

# Copy to host
docker cp ad-collector:/tmp/audit.json ./audit.json
```

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output <file>` | Output file path | `audit-YYYY-MM-DD-HHmmss.json` |
| `--include-details` | Include full vulnerability details | `false` (summary only) |
| `--include-computers` | Include computer account analysis | `false` |
| `--pretty` | Pretty-print JSON output | `false` (minified) |
| `--help` | Show help message | - |

#### Output Format

**Summary Mode (default):**
```json
{
  "success": true,
  "audit": {
    "metadata": {
      "timestamp": "2025-12-08T12:34:56.789Z",
      "duration": "45.23s",
      "includeDetails": false,
      "includeComputers": false,
      "exportedBy": "export-audit.js",
      "version": "2.6.0"
    },
    "summary": {
      "users": 1234,
      "groups": 156,
      "computers": 0,
      "vulnerabilities": {
        "critical": 5,
        "high": 12,
        "medium": 23,
        "low": 8,
        "total": 48,
        "score": 72
      }
    },
    "findings": {
      "critical": 5,
      "high": 12,
      "medium": 23,
      "low": 8
    }
  }
}
```

**Detailed Mode (`--include-details`):**
```json
{
  "success": true,
  "audit": {
    "metadata": { ... },
    "progress": [...],
    "summary": { ... },
    "findings": {
      "critical": [
        {
          "type": "PASSWORD_NOT_REQUIRED",
          "samAccountName": "testuser",
          "dn": "CN=testuser,CN=Users,DC=example,DC=com",
          "message": "Account does not require a password"
        }
      ],
      "high": [...],
      "medium": [...],
      "low": [...]
    }
  }
}
```

#### Use Cases

- ✅ **Enterprise Security Requirements** - No public API exposure needed
- ✅ **Air-Gapped Environments** - Works in isolated networks
- ✅ **Offline Analysis** - Export for external security teams
- ✅ **Compliance Documentation** - Generate audit reports for regulatory compliance

#### Complete Documentation

For comprehensive guide, workflows, and automation examples, see **[EXPORT.md](EXPORT.md)**.

---

## User Operations

### GET /api/users/get

Récupère un utilisateur par son samAccountName.

**Body :**
```json
{
  "samAccountName": "john.doe",
  "includeAll": true
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `samAccountName` | string | Oui | Identifiant de l'utilisateur |
| `includeAll` | boolean | Non | Inclure tous les attributs |

**Example:**
```bash
curl -X POST http://localhost:8443/api/users/get \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"samAccountName": "john.doe"}'
```

**Response:**
```json
{
  "success": true,
  "user": {
    "objectName": "CN=John Doe,OU=Users,DC=example,DC=com",
    "attributes": [...]
  }
}
```

---

### POST /api/users/find-by-sam

Recherche un utilisateur (retourne found: true/false sans erreur si non trouvé).

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Réponse si trouvé :**
```json
{
  "success": true,
  "user": {...},
  "found": true
}
```

**Réponse si non trouvé :**
```json
{
  "success": true,
  "found": false
}
```

---

### POST /api/users/list

Liste les utilisateurs avec pagination automatique.

**Body :**
```json
{
  "filter": "(&(objectClass=user)(objectCategory=person)(sAMAccountName=john*))",
  "maxResults": 100,
  "attributes": ["sAMAccountName", "displayName", "mail"]
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `filter` | string | Non | Filtre LDAP personnalisé |
| `maxResults` | number | Non | Nombre max de résultats (défaut: 1000) |
| `attributes` | array | Non | Attributs à retourner (défaut: tous) |

**Exemple - Lister tous les utilisateurs commençant par "j" :**
```bash
curl -X POST http://localhost:8443/api/users/list \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "filter": "(&(objectClass=user)(objectCategory=person)(sAMAccountName=j*))",
    "maxResults": 50
  }'
```

**Response:**
```json
{
  "success": true,
  "users": [...],
  "count": 25
}
```

---

### POST /api/users/create

Crée un nouvel utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe",
  "password": "P@ssw0rd123!",
  "firstName": "John",
  "lastName": "Doe",
  "ou": "OU=Users,DC=example,DC=com",
  "email": "john.doe@example.com",
  "displayName": "John Doe",
  "description": "Développeur",
  "userPrincipalName": "john.doe@example.com"
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `samAccountName` | string | Oui | Identifiant unique |
| `firstName` | string | Oui | Prénom |
| `lastName` | string | Oui | Nom |
| `password` | string | Non | Mot de passe initial |
| `ou` | string | Non | OU de destination |
| `email` | string | Non | Adresse email |
| `displayName` | string | Non | Nom d'affichage |
| `description` | string | Non | Description |
| `userPrincipalName` | string | Non | UPN (défaut: sam@domain) |

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "created": true
}
```

---

### POST /api/users/enable

Active un compte utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```
OU
```json
{
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "enabled": true
}
```

---

### POST /api/users/disable

Désactive un compte utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "disabled": true
}
```

---

### POST /api/users/reset-password

Réinitialise le mot de passe d'un utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe",
  "newPassword": "NewP@ssw0rd123!",
  "forceChange": true
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `samAccountName` | string | Oui* | Identifiant (*ou dn) |
| `dn` | string | Oui* | DN de l'utilisateur (*ou samAccountName) |
| `newPassword` | string | Oui | Nouveau mot de passe |
| `forceChange` | boolean | Non | Forcer le changement à la prochaine connexion |

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "passwordReset": true
}
```

---

### POST /api/users/delete

Supprime un utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```
OU
```json
{
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "deleted": true
}
```

---

### POST /api/users/unlock

Déverrouille un compte utilisateur verrouillé.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "unlocked": true
}
```

---

### POST /api/users/check-password-expiry

Vérifie l'expiration du mot de passe d'un utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Response:**
```json
{
  "success": true,
  "samAccountName": "john.doe",
  "pwdLastSet": "134086708855025798",
  "pwdLastSetDate": "2025-11-26 22:48:05 UTC",
  "accountExpires": "9223372036854775807",
  "accountExpiresDate": "Never",
  "passwordExpiresDate": "2026-02-24 22:48:05 UTC",
  "maxPwdAge": 90,
  "willExpire": true,
  "expiryDays": 90,
  "daysUntilExpiry": 90
}
```

---

### POST /api/users/set-attributes

Modifie les attributs d'un utilisateur.

**Body :**
```json
{
  "samAccountName": "john.doe",
  "attributes": {
    "displayName": "John D. Doe",
    "department": "IT",
    "title": "Senior Developer",
    "telephoneNumber": "+33 1 23 45 67 89"
  }
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `samAccountName` | string | Oui* | Identifiant (*ou dn) |
| `dn` | string | Oui* | DN de l'utilisateur (*ou samAccountName) |
| `attributes` | object | Oui | Attributs à modifier (clé: valeur) |

**Response:**
```json
{
  "success": true,
  "dn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "modified": true
}
```

---

### POST /api/users/get-groups

Récupère les groupes dont l'utilisateur est membre.

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Response:**
```json
{
  "success": true,
  "samAccountName": "john.doe",
  "groups": [
    "CN=IT Staff,OU=Groups,DC=example,DC=com",
    "CN=Developers,OU=Groups,DC=example,DC=com"
  ],
  "count": 2
}
```

---

### POST /api/users/get-activity

Récupère l'activité d'un utilisateur (dernière connexion, etc.).

**Body :**
```json
{
  "samAccountName": "john.doe"
}
```

**Response:**
```json
{
  "success": true,
  "samAccountName": "john.doe",
  "activity": {
    "lastLogon": "133472345678901234",
    "lastLogonTimestamp": "133472345678901234",
    "whenCreated": "20231115120000.0Z",
    "whenChanged": "20241127150000.0Z"
  }
}
```

---

## Active Directory Audit Endpoints (v2.8.0)

### Provider-Specific AD Audit Endpoints

**NEW in v2.8.0:** All AD audit endpoints have been harmonized with provider-specific naming:
- `/api/audit/ad` - Non-streaming audit (alias of `/api/audit`)
- `/api/audit/ad/stream` - SSE streaming audit (alias of `/api/audit/stream`)
- `/api/audit/ad/status` - AD audit status with detailed domain info

**Legacy endpoints** (`/api/audit`, `/api/audit/stream`) remain for backward compatibility.

---

### POST /api/audit/ad/status

**NEW in v2.8.0** - Returns Active Directory audit availability status with detailed domain information.

**Why use this endpoint?**
- ✅ Check if AD audit is available before running
- ✅ Get detailed domain information without running full audit
- ✅ Lightweight status check (no full audit execution)
- ✅ Optional sensitive data masking

**Body:**
```json
{
  "maskSensitiveData": false
}
```

**Example:**
```bash
TOKEN="your-api-token"

curl -X POST http://localhost:8443/api/audit/ad/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Success response:**
```json
{
  "success": true,
  "provider": "active-directory",
  "available": true,
  "connected": true,
  "domain": {
    "name": "example.com",
    "dn": "DC=example,DC=com",
    "controller": "dc01.example.com",
    "functionalLevel": "Windows Server 2016",
    "forestLevel": "Windows Server 2016"
  },
  "ldap": {
    "version": 3,
    "secure": true,
    "port": 636
  },
  "contexts": {
    "default": "DC=example,DC=com",
    "configuration": "CN=Configuration,DC=example,DC=com",
    "schema": "CN=Schema,CN=Configuration,DC=example,DC=com"
  },
  "serverTime": "2025-12-15T10:30:45.123Z"
}
```

**Use Cases:**
1. **Pre-flight Check**: Verify AD is reachable before running full audit
2. **Dashboard Display**: Show domain info without running audit
3. **Multi-Provider UI**: Check which providers are available

---

### POST /api/audit/ad

**NEW in v2.8.0** - Provider-specific alias of `/api/audit`.

Performs a comprehensive enterprise-grade security audit of Active Directory (without SSE streaming).

**Recommendation:** Use `/api/audit/ad/stream` for real-time progress updates.

**Body:** Same as `/api/audit` (see Comprehensive Active Directory Audit section below)

**Example:**
```bash
curl -X POST http://localhost:8443/api/audit/ad \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false, "includeComputers": false}'
```

---

### POST /api/audit/ad/stream

**NEW in v2.8.0** - Provider-specific alias of `/api/audit/stream`.

Performs comprehensive AD audit with Server-Sent Events (SSE) streaming for real-time progress.

**Body:** Same as `/api/audit/stream` (see SSE Audit section below)

**Example:**
```bash
curl -N -X POST http://localhost:8443/api/audit/ad/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false, "includeComputers": false}'
```

---

## Comprehensive Active Directory Audit

### POST /api/audit

**Deprecated - Use `/api/audit/ad` instead**

Legacy endpoint for backward compatibility. Performs a comprehensive enterprise-grade security audit of Active Directory with step-by-step progress tracking.

**Body :**
```json
{
  "includeDetails": false,
  "includeComputers": false
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `includeDetails` | boolean | No | Include detailed lists (default: false = counts only) |
| `includeComputers` | boolean | No | Include computer analysis (slower, default: false) |

#### Enhanced Account Details (v1.7.2+)

When `includeDetails: true`, each affected account now includes **15+ additional AD attributes** for enhanced security analysis and identification:

**🔴 Security-Critical Fields:**
- `whenCreated` - Account creation date (detect suspicious new accounts)
- `lastLogonTimestamp` / `lastLogon` - Last logon time (identify dormant accounts)
- `pwdLastSet` - Last password change date (password age analysis)
- `adminCount` - Privileged account indicator

**🟡 Identification/Contact:**
- `displayName` - Full display name
- `mail` - Email address (for remediation contact)
- `userPrincipalName` - UPN (alternative identifier)
- `description` - Account description (may contain sensitive data!)

**🟢 Organizational Context:**
- `title` - Job title
- `department` - Department name
- `manager` - Manager DN
- `company` - Company name
- `employeeID` - Employee ID
- `telephoneNumber` - Phone number

**Note:** Null values are automatically filtered to minimize payload size.

**Example:**
```bash
curl -X POST http://localhost:8443/api/audit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false, "includeComputers": false}'
```

---

### Audit Steps and Progress Tracking

The audit executes in 70 granular steps, each with a specific code:

| Step Code | Description |
|-----------|-------------|
| `STEP_01` | Audit initialization |
| `STEP_02` | User enumeration |
| `STEP_03` | Password not required check |
| `STEP_04` | Reversible encryption check |
| `STEP_05` | Password never expires check |
| `STEP_06` | AS-REP roasting check |
| `STEP_07` | Kerberoasting check |
| `STEP_08` | Unconstrained delegation check |
| `STEP_09` | Constrained delegation check |
| `STEP_10` | Account status analysis |
| `STEP_11` | Privileged groups enumeration |
| `STEP_12` | AdminCount=1 check |
| `STEP_13` | Golden Ticket risk assessment |
| `STEP_14` | Service accounts detection (SPN) |
| `STEP_15` | Service accounts detection (name pattern) |
| `STEP_16` | Duplicate SPN check |
| `STEP_17` | Password in description check |
| `STEP_18` | Test accounts check |
| `STEP_19` | Shared accounts check |
| `STEP_20` | Unix user password check |
| `STEP_21` | SID History check |
| `STEP_22` | Weak Kerberos encryption check |
| `STEP_23` | Sensitive delegation check |
| `STEP_24` | LAPS readable check |
| `STEP_25` | DCSync capable check |
| `STEP_26` | Protected Users bypass check |
| `STEP_27` | GPO modify rights check |
| `STEP_28` | DNS Admins check |
| `STEP_29` | Replication rights check |
| `STEP_30` | Delegation privilege check |
| `STEP_38` | Temporal analysis |
| `STEP_39` | Group enumeration |
| `STEP_40` | Group analysis |
| `STEP_41` | Computer analysis (optional) |
| `STEP_42` | OU analysis |
| `STEP_43` | Domain configuration security checks |
| `STEP_44` | Computer unconstrained delegation check |
| `STEP_45` | Foreign security principals check (Phase 2) |
| `STEP_46` | NTLM relay opportunity check (Phase 2) |
| `STEP_47` | Shadow Credentials check (Phase 3) |
| `STEP_48` | RBCD abuse check (Phase 3) |
| `STEP_49` | Dangerous group nesting check (Phase 3) |
| `STEP_50` | AdminSDHolder backdoor check (Phase 3) |
| `STEP_51` | ACL GenericAll check (Phase 3) |
| `STEP_52` | ACL WriteDACL check (Phase 3) |
| `STEP_53` | ACL WriteOwner check (Phase 3) |
| `STEP_54` | Everyone in ACL check (Phase 3) |
| `STEP_55` | ACL GenericWrite check (Phase 3) |
| `STEP_56` | ACL Force Change Password check (Phase 3) |
| `STEP_57` | WriteSPN abuse check (Phase 3) |
| `STEP_58` | GPO link poisoning check (Phase 3) |
| `STEP_59` | ESC1 vulnerable template check (Phase 4) |
| `STEP_60` | ESC2 any purpose check (Phase 4) |
| `STEP_61` | ESC3 enrollment agent check (Phase 4) |
| `STEP_62` | ESC4 vulnerable template ACL check (Phase 4) |
| `STEP_63` | ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 check (Phase 4) |
| `STEP_64` | ESC8 HTTP enrollment check (Phase 4) |
| `STEP_65` | LAPS not deployed check (Phase 4) |
| `STEP_66` | LAPS password readable check (Phase 4) |
| `STEP_67` | LAPS legacy attribute check (Phase 4) |
| `STEP_68` | ADCS weak permissions check (Phase 4) |
| `STEP_69` | Risk scoring calculation |
| `STEP_70` | Audit completed |

---

### Response Structure

**Response (includeDetails: false):**
```json
{
  "success": true,
  "audit": {
    "metadata": {
      "timestamp": "2025-11-28T10:30:15.234Z",
      "duration": "45.23s",
      "includeDetails": false,
      "includeComputers": false
    },
    "progress": [
      {
        "step": "STEP_01_INIT",
        "description": "Audit initialization",
        "status": "completed",
        "count": 1,
        "duration": "0.00s"
      },
      {
        "step": "STEP_02_USER_ENUM",
        "description": "User enumeration",
        "status": "completed",
        "count": 1250,
        "duration": "3.45s"
      },
      {
        "step": "STEP_03_PASSWORD_SEC",
        "description": "Password security analysis",
        "status": "completed",
        "count": 1250,
        "duration": "2.15s",
        "findings": {
          "critical": 15,
          "high": 8,
          "medium": 45
        }
      }
    ],
    "summary": {
      "users": {
        "total": 1250,
        "enabled": 1205,
        "disabled": 45
      },
      "groups": {
        "total": 87,
        "empty": 8
      },
      "ous": {
        "total": 23
      },
      "computers": {
        "total": 0,
        "enabled": 0,
        "disabled": 0
      }
    },
    "riskScore": {
      "critical": 15,
      "high": 42,
      "medium": 78,
      "low": 23,
      "total": 158,
      "score": 67
    },
    "findings": {
      "critical": [
        {
          "type": "PASSWORD_NOT_REQUIRED",
          "sam": "guest",
          "dn": "CN=Guest,CN=Users,DC=example,DC=com"
        },
        {
          "type": "REVERSIBLE_ENCRYPTION",
          "sam": "legacy.app",
          "dn": "CN=Legacy App,OU=Service,DC=example,DC=com"
        }
      ],
      "high": [...],
      "medium": [...],
      "low": [...],
      "info": [...]
    },
    "passwordSecurity": {
      "neverExpires": 42,
      "notRequired": 2,
      "reversibleEncryption": 1,
      "expired": 15,
      "veryOld": 67,
      "cannotChange": 8
    },
    "kerberosSecurity": {
      "spnAccounts": 12,
      "noPreauth": 0,
      "unconstrainedDelegation": 1,
      "constrainedDelegation": 3
    },
    "accountStatus": {
      "disabled": 45,
      "locked": 3,
      "expired": 5,
      "neverLoggedOn": 12,
      "inactive90": 34,
      "inactive180": 56,
      "inactive365": 78
    },
    "privilegedAccounts": {
      "domainAdmins": 5,
      "enterpriseAdmins": 2,
      "schemaAdmins": 1,
      "administrators": 8,
      "accountOperators": 0,
      "backupOperators": 2,
      "serverOperators": 0,
      "printOperators": 0,
      "remoteDesktopUsers": 3,
      "gpCreatorOwners": 1,
      "dnsAdmins": 4,
      "adminCount": 15,
      "protectedUsers": 8
    },
    "serviceAccounts": {
      "withSpn": 12,
      "byNaming": 8,
      "byDescription": 5
    },
    "dangerousPatterns": {
      "passwordInDescription": 0,
      "testAccounts": 3,
      "sharedAccounts": 2,
      "defaultAccounts": 4,
      "unixUserPassword": 0,
      "sidHistory": 0
    },
    "advancedSecurity": {
      "lapsReadable": 0,
      "dcsyncCapable": 20,
      "protectedUsersBypass": 15,
      "weakEncryption": 0,
      "sensitiveDelegation": 0,
      "gpoModifyRights": 1,
      "dnsAdmins": 4,
      "delegationPrivilege": 9,
      "replicationRights": 46
    },
    "temporalAnalysis": {
      "createdLast7Days": 2,
      "createdLast30Days": 8,
      "createdLast90Days": 15,
      "modifiedLast7Days": 12,
      "modifiedLast30Days": 45
    },
    "groupAnalysis": {
      "empty": 8,
      "oversized500": 3,
      "oversized1000": 1,
      "modifiedRecently": 5
    },
    "computerAnalysis": {
      "total": 0,
      "enabled": 0,
      "disabled": 0,
      "inactive90": 0,
      "servers": 0,
      "workstations": 0,
      "domainControllers": 0
    }
  }
}
```

---

### Security Findings Categories

**Total: 60 vulnerability types** (v1.7.5: 23 → v2.0.0: 60 = **+161%**)

**🔴 Critical Findings (10):**
- `PASSWORD_NOT_REQUIRED` - Account with no password required (UAC 0x20)
- `REVERSIBLE_ENCRYPTION` - Password stored with reversible encryption (UAC 0x80)
- `ASREP_ROASTING_RISK` - Account vulnerable to AS-REP roasting (UAC 0x400000)
- `UNCONSTRAINED_DELEGATION` - Account with unconstrained delegation (UAC 0x80000)
- `PASSWORD_IN_DESCRIPTION` - Password detected in description/info field
- `UNIX_USER_PASSWORD` - Unix password attribute set (plaintext password risk)
- `WEAK_ENCRYPTION_DES` - Account configured for DES Kerberos encryption (msDS-SupportedEncryptionTypes)
- `SENSITIVE_DELEGATION` - Privileged account (adminCount=1) with delegation enabled
- `GOLDEN_TICKET_RISK` - **[Phase 2]** krbtgt password age > 180 days (Golden Ticket persistence risk)
- `SHADOW_CREDENTIALS` - **[NEW Phase 3]** msDS-KeyCredentialLink abuse for Kerberos bypass
- `RBCD_ABUSE` - **[NEW Phase 3]** Resource-Based Constrained Delegation privilege escalation

**🟠 High Findings (18):**
- `KERBEROASTING_RISK` - Account with SPN (Kerberoasting vulnerable)
- `CONSTRAINED_DELEGATION` - Account with constrained delegation (msDS-AllowedToDelegateTo)
- `SID_HISTORY` - SID History attribute populated (privilege escalation risk)
- `WEAK_ENCRYPTION_RC4` - Account configured for RC4-only encryption (no AES)
- `WEAK_ENCRYPTION_FLAG` - Account with USE_DES_KEY_ONLY flag set (UAC 0x200000)
- `GPO_MODIFY_RIGHTS` - Member of Group Policy Creator Owners (can modify GPOs)
- `DNS_ADMINS_MEMBER` - Member of DnsAdmins (can execute code on DC via DLL)
- `REPLICATION_RIGHTS` - AdminCount=1 account outside standard admin groups (potential DCSync)
- `OVERSIZED_GROUP_CRITICAL` - Very large group (>1000 members)
- `BACKUP_OPERATORS_MEMBER` - **[Phase 1]** Member of Backup Operators (can read NTDS.dit)
- `ACCOUNT_OPERATORS_MEMBER` - **[Phase 1]** Member of Account Operators (can create accounts)
- `SERVER_OPERATORS_MEMBER` - **[Phase 1]** Member of Server Operators (RCE via services)
- `PRINT_OPERATORS_MEMBER` - **[Phase 1]** Member of Print Operators (SYSTEM escalation)
- `COMPUTER_UNCONSTRAINED_DELEGATION` - **[Phase 2]** Computer with unconstrained delegation (TGT capture risk)
- `MACHINE_ACCOUNT_QUOTA_ABUSE` - **[Phase 2]** ms-DS-MachineAccountQuota > 0 (default join abuse)
- `ACL_GENERICALL` - **[NEW Phase 3]** GenericAll permission on sensitive objects (full control)
- `ACL_WRITEDACL` - **[NEW Phase 3]** WriteDACL permission (ACL modification attack)
- `ACL_WRITEOWNER` - **[NEW Phase 3]** WriteOwner permission (ownership takeover)

**🟡 Medium Findings (28):**
- `PASSWORD_VERY_OLD` - Password older than 1 year (pwdLastSet > 365 days)
- `INACTIVE_365_DAYS` - Account inactive for 365+ days
- `SHARED_ACCOUNT` - Possible shared account (samAccountName pattern)
- `WEAK_ENCRYPTION_RC4_WITH_AES` - RC4 enabled alongside AES (downgrade attack risk)
- `NOT_IN_PROTECTED_USERS` - Privileged account not in Protected Users group
- `DELEGATION_PRIVILEGE` - Member of Account/Server Operators (can modify delegation)
- `OVERSIZED_GROUP_HIGH` - Group with 500-1000 members
- `PASSWORD_NEVER_EXPIRES` - **[Phase 1]** Account with password that never expires (UAC 0x10000)
- `SCHEMA_ADMINS_MEMBER` - **[Phase 1]** Member of Schema Admins (can modify AD schema)
- `ENTERPRISE_ADMINS_MEMBER` - **[Phase 1]** Member of Enterprise Admins (forest control)
- `DOMAIN_ADMINS_MEMBER` - **[Phase 1]** Member of Domain Admins (domain control)
- `ADMINISTRATORS_MEMBER` - **[Phase 1]** Member of builtin Administrators group
- `WEAK_PASSWORD_POLICY` - **[NEW Phase 2]** Domain password policy weak (minPwdLength < 14, etc.)
- `DOMAIN_ADMIN_IN_DESCRIPTION` - **[NEW Phase 2]** Admin keywords in description/info fields
- `LAPS_PASSWORD_LEAKED` - **[NEW Phase 2]** LAPS password exposed in description
- `DANGEROUS_LOGON_SCRIPTS` - **[NEW Phase 2]** scriptPath attribute set (logon script abuse)
- `PRE_WINDOWS_2000_ACCESS` - **[NEW Phase 2]** Everyone/Authenticated Users in Pre-Win2K group
- `EXPIRED_ACCOUNT_IN_ADMIN_GROUP` - **[NEW Phase 2]** Expired account in admin groups
- `DISABLED_ACCOUNT_IN_ADMIN_GROUP` - **[Phase 2]** Disabled account in admin groups
- `PRIMARYGROUPID_SPOOFING` - **[Phase 2]** primaryGroupID=512 without Domain Admins memberOf (hidden membership)
- `FOREIGN_SECURITY_PRINCIPALS` - **[Phase 2]** Cross-forest principals in sensitive groups
- `DANGEROUS_GROUP_NESTING` - **[NEW Phase 3]** Nested groups in Domain/Enterprise Admins
- `ADMINSDHOLDER_BACKDOOR` - **[NEW Phase 3]** AdminSDHolder recently modified (persistence backdoor)
- `EVERYONE_IN_ACL` - **[NEW Phase 3]** Everyone/Auth Users with dangerous ACL permissions
- `ACL_GENERICWRITE` - **[NEW Phase 3]** GenericWrite permission on sensitive objects
- `ACL_FORCECHANGEPASSWORD` - **[NEW Phase 3]** ControlAccess for password reset abuse
- `WRITESPN_ABUSE` - **[NEW Phase 3]** WriteProperty for targeted Kerberoasting
- `GPO_LINK_POISONING` - **[NEW Phase 3]** Weak ACLs on Group Policy Objects

**🔵 Low Findings (4):**
- `TEST_ACCOUNT` - Possible test account (samAccountName pattern)
- `USER_CANNOT_CHANGE_PASSWORD` - **[Phase 1]** User cannot change password (UAC 0x40)
- `SMARTCARD_NOT_REQUIRED` - **[Phase 1]** Privileged account without smartcard requirement (UAC 0x40000)
- `WEAK_KERBEROS_POLICY` - **[Phase 2]** Kerberos policy weak (maxTicketAge > 10 hours)
- `DUPLICATE_SPN` - **[Phase 2]** Same SPN on multiple accounts (Kerberos auth issues)
- `NTLM_RELAY_OPPORTUNITY` - **[Phase 2]** NTLM enabled (informational - relay attack risk)

**ℹ️ Info Findings:**
- `PRIVILEGED_GROUP_DOMAINADMINS` - Domain Admins group member count
- `PRIVILEGED_GROUP_ENTERPRISEADMINS` - Enterprise Admins group member count
- `PRIVILEGED_GROUP_SCHEMAADMINS` - Schema Admins group member count
- `LAPS_PASSWORD_SET` - Computer has LAPS password set (informational)
- `DCSYNC_CAPABLE` - Account member of DA/EA/Administrators (DCSync capable)
- `OVERSIZED_GROUP` - Group with 100-500 members

---

### Risk Scoring Algorithm (Hybrid Approach)

The security score ranges from 0 (very bad) to 100 (perfect) using a hybrid scoring system that combines weighted risk points with direct penalties.

**Weighted Risk Points:**
- Critical finding: 15 points (increased from 10)
- High finding: 8 points (increased from 5)
- Medium finding: 2 points
- Low finding: 1 point

**Hybrid Score Formula:**
```
Step 1: Calculate weighted risk points
weightedRiskPoints = (critical × 15) + (high × 8) + (medium × 2) + (low × 1)

Step 2: Calculate max risk (stricter denominator)
maxRiskPoints = totalUsers × 2.5 (reduced from 5.0 for stricter scoring)

Step 3: Calculate percentage-based deduction
percentageDeduction = floor((weightedRiskPoints / maxRiskPoints) × 100)

Step 4: Calculate direct penalty (flat deduction)
directPenalty = floor((critical × 0.3) + (high × 0.1))

Step 5: Final score
score = max(0, min(100, 100 - percentageDeduction - directPenalty))
```

**Why Hybrid Scoring?**
The hybrid approach punishes critical vulnerabilities more severely than the previous formula:
- **Heavier weights**: Critical findings count for 50% more (15 vs 10 points)
- **Stricter denominator**: Maximum risk reduced by 50% (2.5x vs 5x users)
- **Direct penalties**: Each critical finding directly removes 0.3 points from score
- **More realistic**: With 56 critical findings, score drops to ~76 instead of 99

**Example Calculation:**
For an audit with 7426 users, 56 critical, 25 high findings:
```
weightedRiskPoints = (56 × 15) + (25 × 8) = 840 + 200 = 1040
maxRiskPoints = 7426 × 2.5 = 18,565
percentageDeduction = floor((1040 / 18,565) × 100) = 5
directPenalty = floor((56 × 0.3) + (25 × 0.1)) = floor(16.8 + 2.5) = 19
score = 100 - 5 - 19 = 76
```

**Score Interpretation:**
- 90-100: Excellent security posture
- 75-89: Good security, minor issues
- 50-74: Moderate security, needs attention
- 25-49: Poor security, immediate action required
- 0-24: Critical security issues, urgent remediation needed

---

### Analysis Categories Detail

**1. Password Security (6 checks):**
- Never expires (UAC flag 0x10000)
- Not required (UAC flag 0x20)
- Reversible encryption (UAC flag 0x80)
- Expired passwords
- Very old passwords (>1 year since last set)
- Cannot change password (UAC flag 0x40)

**2. Kerberos Security (4 checks):**
- SPN accounts (Kerberoasting vulnerability)
- No preauth required (AS-REP roasting vulnerability)
- Unconstrained delegation (UAC flag 0x80000)
- Constrained delegation (trustedToAuthForDelegation)

**3. Account Status (7 checks):**
- Disabled accounts
- Locked accounts
- Expired accounts
- Never logged on
- Inactive 90 days
- Inactive 180 days
- Inactive 365 days

**4. Privileged Accounts (13 groups):**
- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators
- Account Operators
- Backup Operators
- Server Operators
- Print Operators
- Remote Desktop Users
- Group Policy Creator Owners
- DnsAdmins
- AdminCount=1
- Protected Users group

**5. Service Accounts (3 detection methods):**
- Accounts with SPNs
- Naming patterns (svc_, service_, sa_, srv_)
- Description patterns (service, application, app)

**6. Dangerous Patterns (6 types):**
- Password in description field (strict regex)
- Test accounts (naming patterns)
- Shared accounts (naming patterns)
- Default accounts (guest, krbtgt, administrator)
- UnixUserPassword attribute set (plaintext password risk)
- SID History populated (privilege escalation vector)

**7. Advanced Security (9 enterprise checks):**
- LAPS passwords readable (ms-Mcs-AdmPwd attribute)
- DCSync capable accounts (DA/EA/Administrators membership)
- Protected Users bypass (privileged accounts NOT in Protected Users)
- Weak Kerberos encryption (DES-only or USE_DES_KEY_ONLY flag)
- Sensitive delegation (adminCount=1 + unconstrained delegation)
- GPO modify rights (Group Policy Creator Owners membership)
- DnsAdmins members (can execute code on DC via DLL loading)
- Delegation privilege (Account/Server Operators membership)
- Replication rights (adminCount=1 outside standard admin groups)

**8. Temporal Analysis (5 time periods):**
- Created in last 7 days
- Created in last 30 days
- Created in last 90 days
- Modified in last 7 days
- Modified in last 30 days

**9. Group Analysis (3 checks):**
- Empty groups (no members)
- Oversized groups (>100, >500, or >1000 members with severity levels)
- Recently modified groups (last 30 days)

**10. Computer Analysis (7 metrics, optional):**
- Total computers
- Enabled/disabled computers
- Inactive computers (90+ days)
- Servers (UAC flag 0x2000)
- Workstations
- Domain controllers (UAC flag 0x2000 + primaryGroupID 516)

---

### Performance Notes

**Execution Time:**
- Small directory (<500 users): 5-15 seconds
- Medium directory (500-2000 users): 15-45 seconds
- Large directory (2000-10000 users): 45-120 seconds
- Very large directory (>10000 users): 2-5 minutes

**Resource Usage:**
- Uses LDAP pagination to handle large directories
- Maximum 10,000 objects per query
- Computer analysis adds 30-50% to execution time

**Recommendations:**
- Use `includeDetails: false` for regular monitoring
- Use `includeDetails: true` only when investigating specific issues
- Enable `includeComputers: true` only when needed (slower)
- Run comprehensive audits during off-peak hours for large directories

---

### POST /api/audit/stream

**Deprecated - Use `/api/audit/ad/stream` instead**

**NEW in v1.7.0** - Legacy endpoint for backward compatibility. Performs the same comprehensive audit as `/api/audit` but streams real-time progress updates using Server-Sent Events (SSE).

**Why use SSE?**
- ✅ Real-time progress tracking (15 steps)
- ✅ Display status of each step as it completes
- ✅ Duration and count for each step
- ✅ Better user experience (no blank screen during 2-5s audit)
- ✅ Implement progress bars and step-by-step UI feedback

**Body:** (same as `/api/audit`)
```json
{
  "includeDetails": false,
  "includeComputers": false
}
```

**Response:** Server-Sent Events (SSE) stream

**Event Types:**

| Event | When | Data |
|-------|------|------|
| `connected` | On connection | Connection timestamp |
| `progress` | 15 times during audit | Step completion with stats |
| `complete` | At the end | Full audit report (identical to `/api/audit` response) |
| `error` | On error | Error message |

**Example using curl:**
```bash
TOKEN="your-api-token"

curl -N -X POST http://localhost:8443/api/audit/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false, "includeComputers": false}'
```

**Example output:**
```
event: connected
data: {"message":"Audit stream connected","timestamp":"2025-03-29T10:30:45.123Z"}

event: progress
data: {"step":"STEP_01_INIT","description":"Audit initialization","status":"completed","count":1,"duration":"0.01s"}

event: progress
data: {"step":"STEP_02_USER_ENUM","description":"User enumeration","status":"completed","count":7443,"duration":"1.23s"}

event: progress
data: {"step":"STEP_03_PASSWORD_SEC","description":"Password security analysis","status":"completed","count":892,"duration":"0.45s","findings":{"neverExpires":712,"notRequired":9,"reversibleEncryption":0,"expired":171}}

... (12 more progress events)

event: complete
data: {"success":true,"audit":{...full audit report...}}
```

**JavaScript Example:**
```javascript
async function startAuditWithSSE() {
  const response = await fetch('http://localhost:8443/api/audit/stream', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer YOUR_TOKEN',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ includeDetails: false, includeComputers: false })
  });

  const reader = response.body.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const chunk = decoder.decode(value);
    const lines = chunk.split('\n\n');

    for (const line of lines) {
      if (!line.trim()) continue;

      const eventMatch = line.match(/^event: (.+)\ndata: (.+)$/s);
      if (eventMatch) {
        const eventType = eventMatch[1];
        const data = JSON.parse(eventMatch[2]);

        switch (eventType) {
          case 'connected':
            console.log('Connected:', data.timestamp);
            break;

          case 'progress':
            const progress = (parseInt(data.step.match(/\d+/)[0]) / 15) * 100;
            console.log(`Progress: ${progress.toFixed(0)}% - ${data.description}`);
            updateProgressBar(progress, data.description);
            break;

          case 'complete':
            console.log('Audit complete!', data.audit);
            displayResults(data.audit);
            break;

          case 'error':
            console.error('Error:', data.error);
            break;
        }
      }
    }
  }
}

function updateProgressBar(percent, description) {
  document.getElementById('progress-bar').style.width = `${percent}%`;
  document.getElementById('progress-text').textContent = description;
}

function displayResults(audit) {
  document.getElementById('risk-score').textContent = audit.riskScore.score;
  document.getElementById('critical-findings').textContent = audit.riskScore.critical;
  // ... display other results
}
```

**React Hook Example:**
```jsx
import { useState, useEffect } from 'react';

function useAuditSSE(includeDetails = false, includeComputers = false) {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [auditResult, setAuditResult] = useState(null);
  const [error, setError] = useState(null);

  const startAudit = async () => {
    const response = await fetch('/api/audit/stream', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${YOUR_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ includeDetails, includeComputers })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;

        const eventMatch = line.match(/^event: (.+)\ndata: (.+)$/s);
        if (eventMatch) {
          const eventType = eventMatch[1];
          const data = JSON.parse(eventMatch[2]);

          if (eventType === 'progress') {
            const stepNumber = parseInt(data.step.match(/\d+/)[0]);
            setProgress((stepNumber / 15) * 100);
            setCurrentStep(data.description);
          } else if (eventType === 'complete') {
            setProgress(100);
            setAuditResult(data.audit);
          } else if (eventType === 'error') {
            setError(data.error);
          }
        }
      }
    }
  };

  return { progress, currentStep, auditResult, error, startAudit };
}
```

**Important Notes:**
- SSE is unidirectional (server → client only)
- No feedback loop required - server continues automatically
- Connection closes automatically after `complete` or `error` event
- Handle network errors and implement reconnection logic
- Consider a 30-second timeout on the client side
- The final `complete` event contains the exact same data structure as `/api/audit`

**UI/UX Recommendations:**
- Display a progress bar showing completion percentage (step / 15 × 100)
- Show the current step description in real-time
- List completed steps with their durations
- Display intermediate counts (users found, issues detected)
- Animate step completions for better visual feedback

---

### POST /api/audit/export

**NEW in v2.6.1** - Export audit results as a downloadable JSON file with optional filename.

**Why use this endpoint?**
- ✅ **Local Network Export** - Call from another server on local network (no public exposure)
- ✅ **Downloadable File** - Returns audit as attachment with `Content-Disposition` header
- ✅ **Custom Filename** - Specify your own filename
- ✅ **Pretty Print** - Optional human-readable JSON formatting
- ✅ **Full Audit** - Same complete audit as `/api/audit` (all 87 vulnerability detections)
- ✅ **Metadata Headers** - Audit summary in HTTP headers for quick parsing

**Body:**
```json
{
  "includeDetails": true,
  "includeComputers": true,
  "filename": "my-audit-2025-12-08.json",
  "pretty": true
}
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `includeDetails` | boolean | No | Include full vulnerability details (default: false) |
| `includeComputers` | boolean | No | Include computer account analysis (default: false) |
| `filename` | string | No | Custom filename (default: `audit-YYYY-MM-DD.json`) |
| `pretty` | boolean | No | Pretty-print JSON output (default: false) |

**Example Request:**
```bash
# Basic export (summary only)
curl -X POST http://localhost:8443/api/audit/export \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{}' \
  -o audit.json

# Detailed export with custom filename
curl -X POST http://localhost:8443/api/audit/export \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "includeDetails": true,
    "includeComputers": true,
    "filename": "security-audit-december-2025.json",
    "pretty": true
  }' \
  -o security-audit.json

# From another local server
curl -X POST http://ad-collector.local:8443/api/audit/export \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": true, "includeComputers": true}' \
  -o /var/audits/audit-$(date +%Y-%m-%d).json
```

**Response Headers:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Disposition: attachment; filename="audit-2025-12-08.json"
X-Audit-Duration: 45.23s
X-Audit-Users: 1234
X-Audit-Groups: 156
X-Audit-Computers: 89
X-Audit-Vulnerabilities-Total: 48
X-Audit-Vulnerabilities-Critical: 5
X-Audit-Vulnerabilities-High: 12
X-Audit-Vulnerabilities-Medium: 23
X-Audit-Vulnerabilities-Low: 8
X-Audit-Security-Score: 72
```

**Response Body:**
```json
{
  "success": true,
  "audit": {
    "metadata": {
      "timestamp": "2025-12-08T12:34:56.789Z",
      "duration": "45.23s",
      "includeDetails": true,
      "includeComputers": true,
      "version": "2.6.1"
    },
    "summary": {
      "users": 1234,
      "groups": 156,
      "computers": 89,
      "vulnerabilities": {
        "critical": 5,
        "high": 12,
        "medium": 23,
        "low": 8,
        "total": 48,
        "score": 72
      }
    },
    "findings": {
      "critical": [...],
      "high": [...],
      "medium": [...],
      "low": [...]
    }
  }
}
```

**Use Cases:**

1. **Local Network Export Without Public Exposure**
   ```bash
   # From another server on same network
   curl -X POST http://10.10.0.21:8443/api/audit/export \
     -H "Authorization: Bearer TOKEN" \
     -d '{"includeDetails": true}' \
     -o /shared/audit.json
   ```

2. **Automated Scheduled Exports**
   ```bash
   #!/bin/bash
   # /etc/cron.daily/ad-audit-export

   DATE=$(date +%Y-%m-%d)
   curl -X POST http://ad-collector:8443/api/audit/export \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"includeDetails": true, "includeComputers": true, "pretty": true}' \
     -o /var/audits/audit-${DATE}.json
   ```

3. **Parse Metadata from Headers**
   ```bash
   # Get security score without downloading full audit
   SCORE=$(curl -sI -X POST http://localhost:8443/api/audit/export \
     -H "Authorization: Bearer TOKEN" \
     -d '{}' | grep -i "X-Audit-Security-Score" | cut -d' ' -f2)

   echo "Security Score: $SCORE/100"
   ```

**Comparison: Export Methods**

| Method | Network | Use Case |
|--------|---------|----------|
| `export-audit.js` | None (local only) | Air-gapped environments, no API exposure |
| `/api/audit/export` | Local network | Internal server-to-server transfers |
| `/api/audit` | Any (requires auth) | n8n workflows, external integrations |

---

### GET /api/audit/last

**NEW in v1.7.1** - Returns the last cached audit result without re-running the audit.

**Why use this endpoint?**
- ✅ No re-execution of the audit (instant response)
- ✅ Useful as fallback when SSE `complete` event is not received
- ✅ Cached result valid for 5 minutes
- ✅ Includes cache metadata (age, timestamp)

**Parameters:** None (GET request, no body)

**Cache Behavior:**
- Results are cached in memory for **5 minutes** after each audit execution
- Cache is populated by both `POST /api/audit` and `POST /api/audit/stream`
- If cache is empty or expired, returns 404/410 error

**Example:**
```bash
TOKEN="your-api-token"

curl -X GET http://localhost:8443/api/audit/last \
  -H "Authorization: Bearer $TOKEN"
```

**Success Response (200):**
```json
{
  "success": true,
  "audit": {
    "metadata": { ... },
    "summary": { ... },
    "riskScore": { ... },
    "findings": { ... },
    ...
  },
  "cacheMetadata": {
    "cached": true,
    "cacheAge": "42s",
    "cachedAt": "2025-11-29T01:35:00.000Z"
  }
}
```

**Error Response - No Cache (404):**
```json
{
  "success": false,
  "error": "No cached audit result available. Run an audit first.",
  "cacheStatus": "empty"
}
```

**Error Response - Expired (410):**
```json
{
  "success": false,
  "error": "Cached audit result expired. Please run a new audit.",
  "cacheStatus": "expired",
  "cacheAge": "320s"
}
```

**Use Cases:**
1. **SSE Fallback**: When `POST /api/audit/stream` doesn't send `complete` event, frontend can fetch the cached result instead of re-running
2. **Quick Refresh**: Get latest audit results without waiting 2-3 seconds
3. **Dashboard Display**: Show cached results immediately while new audit runs in background

**Important Notes:**
- Cache is **in-memory only** - cleared on server restart
- Cache TTL is **5 minutes** (300 seconds)
- Each new audit (via `/api/audit` or `/api/audit/stream`) updates the cache
- Returns the **complete audit object**, identical to `/api/audit` response

---

## Azure AD / Entra ID Audit (v2.7.0)

### POST /api/audit/azure/stream

**NEW in v2.7.0** - Performs comprehensive security audit of Azure AD/Entra ID using Microsoft Graph API with real-time SSE progress streaming (20 steps).

**Prerequisites:**
- Azure App Registration with appropriate permissions:
  - `User.Read.All` - Read all user profiles
  - `Directory.Read.All` - Read directory data
  - `Policy.Read.All` - Read Conditional Access policies
  - `IdentityRiskyUser.Read.All` - Read risky users (requires Azure AD P2)
- Credentials configured via `install.sh` or environment variables

**Body:**
```json
{
  "skipPremiumCheck": false,
  "includeRiskyUsers": true
}
```

**Request Body Options:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `skipPremiumCheck` | boolean | `false` | Skip Premium P2 features to allow auditing free tenants |
| `includeRiskyUsers` | boolean | `true` | Include Identity Protection (risky users) - requires Azure AD P2 |

**For Free/Basic Azure AD Tenants:**

If you have a **free Azure AD tenant** (without Premium P1/P2), use the `skipPremiumCheck` option:

```json
{
  "skipPremiumCheck": true,
  "includeRiskyUsers": false
}
```

**What works without Premium:**
- ✅ User enumeration and analysis
- ✅ Group enumeration
- ✅ Directory roles and privileged access detection
- ✅ Application and Service Principal analysis
- ✅ Conditional Access policy review (with Policy.Read.All permission)
- ✅ Inactive user detection
- ✅ Guest user analysis
- ✅ Password age checking
- ✅ Application credential expiration

**What requires Premium P2:**
- ❌ Identity Protection (risky users, risky sign-ins)
- ❌ Advanced risk detection

**SSE Progress Steps (20 total):**
```
AZURE_STEP_01_INIT              → Initializing Azure audit
AZURE_STEP_02_AUTH              → Authenticating to Microsoft Graph API
AZURE_STEP_03_ORG_INFO          → Fetching organization information
AZURE_STEP_04_USERS             → Fetching all users
AZURE_STEP_05_GROUPS            → Fetching all groups
AZURE_STEP_06_ROLES             → Fetching directory roles
AZURE_STEP_07_APPS              → Fetching applications
AZURE_STEP_08_SPS               → Fetching service principals
AZURE_STEP_09_CA_POLICIES       → Fetching Conditional Access policies
AZURE_STEP_10_RISKY_USERS       → Fetching risky users (Identity Protection)
AZURE_STEP_11_USER_MFA          → Checking user MFA status
AZURE_STEP_12_INACTIVE_USERS    → Detecting inactive users
AZURE_STEP_13_GUEST_ACCESS      → Analyzing guest user access
AZURE_STEP_14_PASSWORD_AGE      → Checking password age
AZURE_STEP_15_PRIVILEGED        → Analyzing privileged roles
AZURE_STEP_16_APP_CREDS         → Checking application credentials
AZURE_STEP_17_CA_ANALYSIS       → Analyzing Conditional Access policies
AZURE_STEP_18_RISK_ANALYSIS     → Processing Identity Protection risks
AZURE_STEP_19_SCORING           → Calculating security score
AZURE_STEP_20_COMPLETE          → Azure audit complete
```

**Example:**
```bash
TOKEN="your-api-token"

# Standard audit (requires Premium P2 for risky users)
curl -N -X POST http://localhost:8443/api/audit/azure/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Free tenant audit (skip Premium features)
curl -N -X POST http://localhost:8443/api/audit/azure/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"skipPremiumCheck": true, "includeRiskyUsers": false}'
```

**SSE Response Format:**

Azure audit uses **Server-Sent Events (SSE)** with the same format as on-premises AD audit for compatibility:

**Connection Event:**
```
event: connected
data: {"message":"Azure audit stream connected","timestamp":"2025-12-14T13:35:22.418Z"}

```

**Progress Events:**
```
event: progress
data: {"step":"AZURE_STEP_01_INIT","description":"Initializing Azure audit","status":"completed","count":1,"duration":"0.01s"}

event: progress
data: {"step":"AZURE_STEP_02_AUTH","description":"Authenticating to Microsoft Graph API","status":"completed","count":1,"duration":"0.34s"}

event: progress
data: {"step":"AZURE_STEP_04_USERS","description":"Fetching all users","status":"completed","count":1234,"duration":"2.15s"}

event: progress
data: {"step":"AZURE_STEP_20_COMPLETE","description":"Azure audit complete","status":"completed","count":87,"duration":"0.12s","findings":{"critical":12,"high":34,"medium":56,"low":10}}

```

**Final Audit Result:**
```
event: complete
data: {
  "success": true,
  "audit": {
    "metadata": {
      "provider": "azure",
      "tenantId": "12345678-1234-1234-1234-123456789012",
      "organizationName": "Contoso Ltd",
      "timestamp": "2025-12-08T10:30:45.123Z",
      "duration": "45.23s",
      "version": "2.7.0"
    },
    "summary": {
      "users": 1234,
      "groups": 89,
      "applications": 150,
      "servicePrincipals": 200,
      "conditionalAccessPolicies": 5,
      "vulnerabilities": {
        "critical": 12,
        "high": 34,
        "medium": 56,
        "low": 10,
        "total": 112,
        "score": 68
      }
    },
    "findings": {
      "critical": [...],
      "high": [...],
      "medium": [...],
      "low": [...]
    },
    "azure": {
      "userSecurity": {
        "totalUsers": 1234,
        "enabledUsers": 1180,
        "guestUsers": 45,
        "inactiveUsers": 23,
        "riskyUsers": 5
      },
      "privilegedAccess": {
        "totalRoles": 12,
        "totalAssignments": 45,
        "globalAdmins": 3,
        "roleAssignments": { ... }
      },
      "applicationSecurity": {
        "totalApplications": 150,
        "totalServicePrincipals": 200,
        "credentialIssues": 8
      },
      "conditionalAccess": {
        "totalPolicies": 5,
        "enabledPolicies": 4,
        "disabledPolicies": 1,
        "policies": [...]
      },
      "identityProtection": {
        "riskyUsers": 5,
        "available": true
      },
      "groupAnalysis": {
        "totalGroups": 89,
        "securityGroups": 67,
        "dynamicGroups": 12
      }
    }
  }
}
```

**Hybrid Format Benefits:**
- **Universal `summary` and `findings`**: Compatible with existing AD audit frontends
- **Azure-specific `azure.*`**: Detailed Azure metrics for specialized UIs
- **Easy Comparison**: Same structure allows side-by-side AD vs Azure analysis

**Detected Vulnerabilities (Examples):**
- `AZURE_GLOBAL_ADMIN_NO_MFA` - Global Administrator without MFA (CRITICAL)
- `AZURE_USER_INACTIVE` - User inactive for 90+ days (HIGH)
- `AZURE_GUEST_PRIVILEGED_ACCESS` - Guest with privileged role (CRITICAL)
- `AZURE_PASSWORD_OLD` - Password not changed for 180+ days (MEDIUM)
- `AZURE_APP_CREDENTIAL_EXPIRED` - Application credential expired (HIGH)
- `AZURE_RISKY_USER` - User flagged by Identity Protection (CRITICAL/HIGH)
- `AZURE_NO_MFA_CA_POLICY` - No MFA enforcement via Conditional Access (CRITICAL)
- `AZURE_CA_POLICY_DISABLED` - Conditional Access policy disabled (MEDIUM)

**Error Response (Azure not configured):**
```
event: error
data: {"success":false,"error":"Azure credentials not configured. Run install.sh to configure Azure audit."}
```

**SSE Event Types:**

| Event | When | Data |
|-------|------|------|
| `connected` | On connection | Connection timestamp |
| `progress` | 20 times during audit | Step completion with stats (in_progress or completed) |
| `complete` | At the end | Full audit report |
| `error` | On error | Error message |

**Progress Status Values:**
- `in_progress` - Step is currently executing
- `completed` - Step finished successfully
- `skipped` - Step skipped (e.g., Premium features on free tenant)

**Event Data Fields:**
- `step` - Step identifier (AZURE_STEP_XX)
- `description` - Human-readable step description
- `status` - Step status (in_progress, completed, skipped)
- `count` - Number of items processed
- `duration` - Step execution time (e.g., "0.52s")
- `findings` - Vulnerability counts by severity (optional)

---

### POST /api/audit/azure/status

**NEW in v2.7.0** - Check if Azure AD audit is configured and ready to use.

**Body:**
```json
{}
```

**Example:**
```bash
TOKEN="your-api-token"

curl -X POST http://localhost:8443/api/audit/azure/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response (Configured):**
```json
{
  "success": true,
  "azure": {
    "configured": true,
    "tenantId": "12345678-1234-1234-1234-123456789012",
    "clientId": "87654321-4321-4321-4321-210987654321",
    "message": "Azure audit is configured and ready"
  }
}
```

**Response (Not Configured):**
```json
{
  "success": true,
  "azure": {
    "configured": false,
    "tenantId": null,
    "clientId": null,
    "message": "Azure audit not configured. Run install.sh to configure Azure credentials."
  }
}
```

**Use Cases:**
1. **Frontend Check**: Determine whether to show Azure audit option
2. **Health Monitoring**: Verify Azure configuration before running audits
3. **Multi-tenant Support**: Identify which tenant is configured

---

## Opérations sur les Groupes

### POST /api/groups/get

Récupère un groupe par DN ou samAccountName.

**Body :**
```json
{
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com"
}
```
OU
```json
{
  "samAccountName": "IT Staff"
}
```

**Response:**
```json
{
  "success": true,
  "group": {
    "objectName": "CN=IT Staff,OU=Groups,DC=example,DC=com",
    "attributes": [...]
  }
}
```

---

### POST /api/groups/list

Liste les groupes avec pagination automatique.

**Body :**
```json
{
  "filter": "(objectClass=group)",
  "maxResults": 100
}
```

**Response:**
```json
{
  "success": true,
  "groups": [...],
  "count": 50
}
```

---

### POST /api/groups/search

Recherche des groupes par nom.

**Body :**
```json
{
  "searchTerm": "IT",
  "maxResults": 50
}
```

**Response:**
```json
{
  "success": true,
  "groups": [...],
  "count": 5
}
```

---

### POST /api/groups/create

Crée un nouveau groupe.

**Body :**
```json
{
  "samAccountName": "IT-Developers",
  "name": "IT Developers",
  "ou": "OU=Groups,DC=example,DC=com",
  "description": "Groupe des développeurs IT",
  "groupType": "-2147483646"
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `samAccountName` | string | Oui | Identifiant unique |
| `name` | string | Oui | Nom du groupe |
| `ou` | string | Non | OU de destination |
| `description` | string | Non | Description |
| `groupType` | string | Non | Type de groupe AD |

**Types de groupe :**
| Type | groupType |
|------|-----------|
| Global Security | `-2147483646` (défaut) |
| Domain Local Security | `-2147483644` |
| Universal Security | `-2147483640` |
| Global Distribution | `2` |
| Domain Local Distribution | `4` |
| Universal Distribution | `8` |

**Response:**
```json
{
  "success": true,
  "dn": "CN=IT Developers,OU=Groups,DC=example,DC=com",
  "created": true
}
```

---

### POST /api/groups/modify

Modifie les attributs d'un groupe.

**Body :**
```json
{
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "attributes": {
    "description": "Nouvelle description",
    "mail": "it-staff@example.com"
  }
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "modified": true
}
```

---

### POST /api/groups/delete

Supprime un groupe.

**Body :**
```json
{
  "dn": "CN=Old Group,OU=Groups,DC=example,DC=com"
}
```
OU
```json
{
  "samAccountName": "Old Group"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=Old Group,OU=Groups,DC=example,DC=com",
  "deleted": true
}
```

---

### POST /api/groups/add-member

Ajoute un utilisateur à un groupe.

**Body :**
```json
{
  "userDn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "groupDn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "skipIfMember": true
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `userDn` | string | Oui | DN de l'utilisateur |
| `groupDn` | string | Oui | DN du groupe |
| `skipIfMember` | boolean | Non | Ne pas échouer si déjà membre |

**Response:**
```json
{
  "success": true,
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "memberAdded": true
}
```

**Réponse si déjà membre (avec skipIfMember: true) :**
```json
{
  "success": true,
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "memberAdded": false,
  "alreadyMember": true
}
```

---

### POST /api/groups/remove-member

Retire un utilisateur d'un groupe.

**Body :**
```json
{
  "userDn": "CN=John Doe,OU=Users,DC=example,DC=com",
  "groupDn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "skipIfNotMember": true
}
```

**Response:**
```json
{
  "success": true,
  "dn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
  "memberRemoved": true
}
```

---

## Opérations sur les OUs

### POST /api/ous/get

Récupère une OU par DN.

**Body :**
```json
{
  "dn": "OU=Users,DC=example,DC=com"
}
```

**Response:**
```json
{
  "success": true,
  "ou": {
    "objectName": "OU=Users,DC=example,DC=com",
    "attributes": [...]
  }
}
```

---

### POST /api/ous/list

Liste les OUs.

**Body :**
```json
{
  "searchFilter": "(objectClass=organizationalUnit)",
  "maxResults": 100
}
```

**Response:**
```json
{
  "success": true,
  "ous": [...],
  "count": 15
}
```

---

### POST /api/ous/search

Recherche des OUs par nom.

**Body :**
```json
{
  "searchTerm": "Users",
  "maxResults": 50
}
```

**Response:**
```json
{
  "success": true,
  "ous": [...],
  "count": 3
}
```

---

### POST /api/ous/create

Crée une nouvelle OU.

**Body :**
```json
{
  "name": "Contractors",
  "parentDn": "OU=Users,DC=example,DC=com",
  "description": "Utilisateurs externes"
}
```

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `name` | string | Oui | Nom de l'OU |
| `parentDn` | string | Non | OU parente (défaut: Base DN) |
| `description` | string | Non | Description |

**Response:**
```json
{
  "success": true,
  "dn": "OU=Contractors,OU=Users,DC=example,DC=com",
  "created": true
}
```

---

### POST /api/ous/modify

Modifie les attributs d'une OU.

**Body :**
```json
{
  "dn": "OU=Contractors,DC=example,DC=com",
  "attributes": {
    "description": "Nouvelle description"
  }
}
```

**Response:**
```json
{
  "success": true,
  "dn": "OU=Contractors,DC=example,DC=com",
  "modified": true
}
```

---

### POST /api/ous/delete

Supprime une OU (doit être vide).

**Body :**
```json
{
  "dn": "OU=Old OU,DC=example,DC=com"
}
```

**Response:**
```json
{
  "success": true,
  "dn": "OU=Old OU,DC=example,DC=com",
  "deleted": true
}
```

---

## Exemples avec curl

### Lister les utilisateurs dont le nom commence par "j"

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR..."

curl -X POST http://localhost:8443/api/users/list \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "filter": "(&(objectClass=user)(objectCategory=person)(sAMAccountName=j*))",
    "maxResults": 10
  }'
```

### Créer un utilisateur avec mot de passe

```bash
curl -X POST http://localhost:8443/api/users/create \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "samAccountName": "jane.doe",
    "firstName": "Jane",
    "lastName": "Doe",
    "password": "TempP@ss123!",
    "ou": "OU=Users,DC=example,DC=com",
    "email": "jane.doe@example.com"
  }'
```

### Modifier les attributs d'un groupe

```bash
curl -X POST http://localhost:8443/api/groups/modify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "samAccountName": "IT-Staff",
    "attributes": {
      "description": "Équipe IT - Support Niveau 2",
      "info": "Contact: it@example.com"
    }
  }'
```

### Ajouter un utilisateur à un groupe

```bash
curl -X POST http://localhost:8443/api/groups/add-member \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userDn": "CN=Jane Doe,OU=Users,DC=example,DC=com",
    "groupDn": "CN=IT Staff,OU=Groups,DC=example,DC=com",
    "skipIfMember": true
  }'
```

---

## Codes d'erreur

| Code | Description |
|------|-------------|
| 200 | Succès |
| 400 | Paramètres manquants ou invalides |
| 401 | Non authentifié (token manquant ou invalide) |
| 404 | Entrée non trouvée |
| 500 | Erreur serveur / LDAP |

---

## Notes

1. **Pagination automatique** : Les opérations de liste utilisent la pagination LDAP pour éviter les erreurs "Size Limit Exceeded".

2. **DN ou samAccountName** : La plupart des opérations acceptent soit un DN soit un samAccountName pour identifier l'objet.

3. **Protection injection LDAP** : Tous les paramètres sont automatiquement échappés pour prévenir les injections LDAP.

4. **TLS/SSL** : Par défaut, la vérification du certificat est désactivée. Pour l'activer, définir `LDAP_TLS_VERIFY=true` et monter le certificat CA.
