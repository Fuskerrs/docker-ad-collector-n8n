# Azure Entra ID Audit Guide

## Version: 2.7.0

Complete guide for configuring and using Azure AD/Entra ID audit functionality in the AD Collector.

---

## Overview

The AD Collector v2.7.0 introduces comprehensive Azure AD/Entra ID security audit capabilities alongside the existing on-premises Active Directory audit. This allows you to:

- Audit both on-premises AD and cloud Azure AD from a single collector
- Detect Azure-specific security vulnerabilities
- Analyze Conditional Access policies
- Monitor Identity Protection risks (requires Azure AD P2)
- Track privileged role assignments
- Identify inactive users and guest access risks

---

## Prerequisites

### 1. Azure App Registration

You must create an App Registration in Azure Portal with the following permissions:

**Required Permissions (Application type):**
- `User.Read.All` - Read all user profiles
- `Directory.Read.All` - Read directory data
- `Group.Read.All` - Read all groups
- `Application.Read.All` - Read applications

**Optional Permissions (Enhanced features):**
- `Policy.Read.All` - Read Conditional Access policies
- `IdentityRiskyUser.Read.All` - Read risky users (requires Azure AD P2 license)

**Steps to create App Registration:**

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**
3. Name: `AD-Collector-Audit` (or any name you prefer)
4. Supported account types: **Accounts in this organizational directory only**
5. Click **Register**
6. Note the **Application (client) ID** and **Directory (tenant) ID**
7. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions**
8. Add the required permissions listed above
9. Click **Grant admin consent** (requires Global Administrator)
10. Go to **Certificates & secrets** → **New client secret**
11. Add a description and select expiration (recommended: 12-24 months)
12. Copy the **secret value** immediately (you won't see it again)

### 2. License Requirements

**Basic Azure AD (Free):**
- User, group, application audits
- Basic Conditional Access analysis
- Privileged role detection

**Azure AD Premium P1:**
- Advanced Conditional Access policies
- Dynamic groups analysis

**Azure AD Premium P2:**
- Identity Protection (risky users, risky sign-ins)
- Privileged Identity Management insights

---

## Configuration

### Option 1: During Initial Installation

When running `./install.sh`, you'll be prompted:

```
☁️  Azure AD / Entra ID Configuration (Optional)
   Enable Azure cloud audit alongside on-premises AD audit

   Configure Azure AD audit? (y/n) [n]: y

Azure App Registration Required:
   1. Go to Azure Portal → App registrations → New registration
   2. Grant API permissions: User.Read.All, Directory.Read.All, etc.
   3. Create a client secret

   Azure Tenant ID: 12345678-1234-1234-1234-123456789012
   Azure Client ID (App Registration): 87654321-4321-4321-4321-210987654321
   Azure Client Secret: ********
```

### Option 2: Manual Configuration

Edit the `.env` file in your installation directory:

```bash
cd ~/ad-collector
nano .env
```

Add or update these lines:

```
# Azure AD / Entra ID Configuration (v2.7.0)
AZURE_ENABLED=true
AZURE_TENANT_ID=12345678-1234-1234-1234-123456789012
AZURE_CLIENT_ID=87654321-4321-4321-4321-210987654321
AZURE_CLIENT_SECRET=your-secret-value-here
```

Restart the collector:

```bash
docker compose restart
```

---

## Usage

### Check Azure Configuration Status

Before running an audit, verify Azure is configured:

```bash
TOKEN="your-api-token"

curl -X POST http://localhost:8443/api/audit/azure/status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Response (configured):**
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

### Run Azure Audit with SSE Streaming

**Basic Usage (works with all license types):**

```bash
TOKEN="your-api-token"

curl -N -X POST http://localhost:8443/api/audit/azure/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**For Free/Basic Azure AD Tenants:**

If you have a **free Azure AD tenant** (without Premium P1/P2), use the `skipPremiumCheck` option:

```bash
TOKEN="your-api-token"

curl -N -X POST http://localhost:8443/api/audit/azure/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "skipPremiumCheck": true,
    "includeRiskyUsers": false
  }'
```

**Request Body Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `skipPremiumCheck` | boolean | `false` | Skip Premium P2 features to allow auditing free tenants |
| `includeRiskyUsers` | boolean | `true` | Include Identity Protection (risky users) - requires Azure AD P2 |

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

**Progress Steps (20 total):**
```
AZURE_STEP_01_INIT          → Initializing Azure audit
AZURE_STEP_02_AUTH          → Authenticating to Microsoft Graph API
AZURE_STEP_03_ORG_INFO      → Fetching organization information
AZURE_STEP_04_USERS         → Fetching all users
AZURE_STEP_05_GROUPS        → Fetching all groups
AZURE_STEP_06_ROLES         → Fetching directory roles
AZURE_STEP_07_APPS          → Fetching applications
AZURE_STEP_08_SPS           → Fetching service principals
AZURE_STEP_09_CA_POLICIES   → Fetching Conditional Access policies
AZURE_STEP_10_RISKY_USERS   → Fetching risky users (Identity Protection)
AZURE_STEP_11_USER_MFA      → Checking user MFA status
AZURE_STEP_12_INACTIVE_USERS→ Detecting inactive users
AZURE_STEP_13_GUEST_ACCESS  → Analyzing guest user access
AZURE_STEP_14_PASSWORD_AGE  → Checking password age
AZURE_STEP_15_PRIVILEGED    → Analyzing privileged roles
AZURE_STEP_16_APP_CREDS     → Checking application credentials
AZURE_STEP_17_CA_ANALYSIS   → Analyzing Conditional Access policies
AZURE_STEP_18_RISK_ANALYSIS → Processing Identity Protection risks
AZURE_STEP_19_SCORING       → Calculating security score
AZURE_STEP_20_COMPLETE      → Azure audit complete
```

---

## Detected Vulnerabilities

### CRITICAL Severity

| Vulnerability Type | Description | Remediation |
|-------------------|-------------|-------------|
| `AZURE_GLOBAL_ADMIN_NO_MFA` | Global Administrator without MFA | Enable MFA for all privileged accounts |
| `AZURE_GUEST_PRIVILEGED_ACCESS` | Guest user with privileged role | Remove privileged roles from guest accounts |
| `AZURE_NO_MFA_CA_POLICY` | No MFA enforcement via Conditional Access | Create CA policy requiring MFA |
| `AZURE_RISKY_USER` (high risk) | User flagged as high risk by Identity Protection | Investigate and require password reset |

### HIGH Severity

| Vulnerability Type | Description | Remediation |
|-------------------|-------------|-------------|
| `AZURE_USER_INACTIVE` | User inactive for 90+ days | Disable or delete inactive accounts |
| `AZURE_APP_CREDENTIAL_EXPIRED` | Application credential expired | Renew or remove expired credentials |
| `AZURE_RISKY_USER` (medium risk) | User flagged as medium risk | Review risk detections |

### MEDIUM Severity

| Vulnerability Type | Description | Remediation |
|-------------------|-------------|-------------|
| `AZURE_PASSWORD_OLD` | Password not changed for 180+ days | Enforce password rotation |
| `AZURE_USER_NEVER_SIGNED_IN` | Enabled account never used | Review if account is needed |
| `AZURE_APP_CREDENTIAL_EXPIRING` | Credential expiring within 30 days | Plan credential renewal |
| `AZURE_CA_POLICY_DISABLED` | Conditional Access policy disabled | Enable or delete policy |

### LOW Severity

| Vulnerability Type | Description | Remediation |
|-------------------|-------------|-------------|
| `AZURE_RISKY_USER` (low risk) | User flagged as low risk | Monitor activity |

---

## Response Format

### Hybrid Format Design

The Azure audit response uses a hybrid format compatible with both AD and Azure frontends:

```json
{
  "success": true,
  "audit": {
    "metadata": {
      "provider": "azure",  // Distinguishes from "ad"
      "tenantId": "...",
      "organizationName": "Contoso Ltd",
      "timestamp": "2025-12-08T10:30:45.123Z",
      "duration": "45.23s",
      "version": "2.7.0"
    },

    // UNIVERSAL FORMAT - Compatible with AD audit
    "summary": {
      "users": 1234,
      "groups": 89,
      "applications": 150,  // Azure-specific
      "servicePrincipals": 200,  // Azure-specific
      "vulnerabilities": {
        "critical": 12,
        "high": 34,
        "medium": 56,
        "low": 10,
        "total": 112,
        "score": 68
      }
    },

    // UNIVERSAL FORMAT - Compatible with AD audit
    "findings": {
      "critical": [...],
      "high": [...],
      "medium": [...],
      "low": [...]
    },

    // AZURE-SPECIFIC FORMAT - Detailed Azure metrics
    "azure": {
      "userSecurity": { ... },
      "privilegedAccess": { ... },
      "applicationSecurity": { ... },
      "conditionalAccess": { ... },
      "identityProtection": { ... },
      "groupAnalysis": { ... }
    }
  }
}
```

**Benefits:**
1. **Frontend Compatibility**: Existing AD audit frontends can display Azure results using `summary` and `findings`
2. **Azure-Specific UI**: Specialized UIs can use `azure.*` for detailed metrics
3. **Easy Comparison**: Same structure allows side-by-side AD vs Azure analysis
4. **SIEM Integration**: Both universal and detailed formats available for log aggregation

---

## Troubleshooting

### "Azure credentials not configured"

**Cause:** Azure environment variables not set

**Solution:**
1. Run `./install.sh --update` and configure Azure when prompted
2. OR manually edit `.env` file and add Azure credentials
3. Restart: `docker compose restart`

### "Authentication failed: Unauthorized"

**Cause:** Invalid credentials or expired secret

**Solution:**
1. Verify `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` are correct
2. Check if client secret has expired in Azure Portal
3. Create new secret if needed and update `.env`

### "Insufficient privileges"

**Cause:** Missing API permissions

**Solution:**
1. Go to Azure Portal → App registrations → Your app
2. Navigate to **API permissions**
3. Ensure all required permissions are added
4. Click **Grant admin consent**
5. Wait a few minutes for permissions to propagate

### "risky users: Insufficient permissions or Azure AD P2 license required"

**Cause:** Identity Protection requires Azure AD P2 license

**Solution:**
- This is expected if you don't have P2 license
- Audit will continue without Identity Protection data
- Consider upgrading to Azure AD P2 for advanced risk detection

### "Conditional Access policies: Insufficient permissions"

**Cause:** Missing `Policy.Read.All` permission

**Solution:**
1. Add `Policy.Read.All` permission in Azure Portal
2. Grant admin consent
3. Re-run audit

---

## Performance Considerations

### Microsoft Graph API Rate Limits

Microsoft Graph enforces rate limiting:
- **Throttling threshold:** ~10,000 requests per 10 minutes
- **Per-user limit:** 5,000 requests per 10 minutes

The collector implements automatic pagination and respects rate limits.

**Large tenants (10,000+ users):**
- Audit duration: 2-5 minutes
- Consider running during off-peak hours

**Small-medium tenants (1,000 users):**
- Audit duration: 30-60 seconds
- Safe to run during business hours

### Recommended Audit Frequency

- **Daily:** Security monitoring
- **Weekly:** Compliance reporting
- **On-demand:** Incident investigation

---

## Security Best Practices

### 1. Least Privilege

Only grant **read** permissions to the app registration:
- Never grant write/modify permissions
- Use Application permissions (not Delegated)
- Grant admin consent only after verification

### 2. Credential Management

- Store credentials in `.env` file (never hardcode)
- Set client secret expiration to 12-24 months (not "Never")
- Rotate secrets before expiration
- Use Azure Key Vault for production (future enhancement)

### 3. Network Security

- Keep collector on private network (localhost binding)
- Use reverse proxy with TLS for external access
- Implement firewall rules to restrict access
- Monitor API token usage via `TOKEN_MAX_USES`

### 4. Audit Logging

- Enable Azure AD audit logs
- Monitor app registration usage
- Alert on unusual API activity
- Review collector logs regularly

---

## Integration Examples

### n8n Workflow Integration

```json
{
  "nodes": [
    {
      "name": "Azure Audit Trigger",
      "type": "n8n-nodes-base.cron",
      "parameters": {
        "triggerTimes": {
          "item": [{ "mode": "everyDay", "hour": 2, "minute": 0 }]
        }
      }
    },
    {
      "name": "Run Azure Audit",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://ad-collector:8443/api/audit/azure/stream",
        "method": "POST",
        "authentication": "genericCredentialType",
        "options": {
          "redirect": { "redirect": { "followRedirects": true } }
        }
      }
    },
    {
      "name": "Parse Results",
      "type": "n8n-nodes-base.set",
      "parameters": {
        "values": {
          "critical": "={{ $json.audit.summary.vulnerabilities.critical }}",
          "high": "={{ $json.audit.summary.vulnerabilities.high }}",
          "score": "={{ $json.audit.summary.vulnerabilities.score }}"
        }
      }
    },
    {
      "name": "Send Alert",
      "type": "n8n-nodes-base.slack",
      "parameters": {
        "message": "Azure AD Audit Complete\\nCritical: {{$json.critical}}\\nHigh: {{$json.high}}\\nScore: {{$json.score}}"
      }
    }
  ]
}
```

### SIEM Integration (Splunk, ELK)

Forward audit results to SIEM for centralized monitoring:

```bash
#!/bin/bash
# azure-audit-to-siem.sh

TOKEN="your-api-token"
SIEM_ENDPOINT="https://siem.example.com/api/events"

# Run Azure audit
AUDIT_RESULT=$(curl -s -X POST http://localhost:8443/api/audit/azure/stream \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | tail -1)

# Forward to SIEM
curl -X POST "$SIEM_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "$AUDIT_RESULT"
```

---

## Roadmap

**Planned features for future versions:**

- Azure Key Vault integration for credential storage
- Multi-tenant support (audit multiple Azure tenants)
- Azure resource audits (VMs, storage, networks)
- Compliance reporting (CIS Azure benchmarks)
- Automated remediation workflows
- Historical audit comparison

---

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/Fuskerrs/docker-ad-collector-n8n/issues
- Documentation: https://github.com/Fuskerrs/docker-ad-collector-n8n

---

## Version History

**v2.7.0 (December 2025)**
- Initial Azure AD/Entra ID audit support
- 20 SSE progress steps
- Microsoft Graph API integration
- Hybrid format (universal + Azure-specific)
- Identity Protection support (P2 required)
- Conditional Access policy analysis
- Privileged role detection
- Application credential monitoring
