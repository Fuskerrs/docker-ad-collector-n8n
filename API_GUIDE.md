# AD Collector API Guide

## Version: 1.6.0

Ce guide décrit tous les endpoints API disponibles dans le Docker AD Collector pour n8n.

---

## Configuration

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `LDAP_URL` | URL du serveur AD | `ldaps://localhost:636` |
| `LDAP_BASE_DN` | Base DN pour les recherches | `DC=example,DC=com` |
| `LDAP_BIND_DN` | DN du compte de service | `CN=admin,CN=Users,DC=example,DC=com` |
| `LDAP_BIND_PASSWORD` | Mot de passe du compte | `password` |
| `LDAP_TLS_VERIFY` | Vérifier le certificat TLS | `false` |
| `PORT` | Port d'écoute | `8443` |
| `API_TOKEN` | Token JWT personnalisé | Auto-généré |
| `TOKEN_EXPIRY` | Durée de validité du token | `365d` |
| `MAX_PWD_AGE_DAYS` | Durée max du mot de passe | `90` |

---

## Authentification

Toutes les requêtes API (sauf `/health`) nécessitent un header Authorization :

```
Authorization: Bearer <API_TOKEN>
```

Le token est affiché dans les logs au démarrage du conteneur :
```
docker logs ad-collector
```

---

## Endpoints

### Health Check

#### GET /health

Vérifie que le service est en ligne.

**Authentification requise :** Non

**Exemple :**
```bash
curl http://localhost:8443/health
```

**Réponse :**
```json
{
  "status": "ok",
  "service": "ad-collector",
  "version": "1.1.1"
}
```

---

### Test de connexion LDAP

#### POST /api/test-connection

Teste la connexion au serveur Active Directory.

**Body :** Aucun

**Exemple :**
```bash
curl -X POST http://localhost:8443/api/test-connection \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json"
```

**Réponse succès :**
```json
{
  "success": true,
  "status": "ok",
  "message": "LDAP connection successful",
  "connected": true
}
```

---

## Opérations sur les Utilisateurs

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

**Exemple :**
```bash
curl -X POST http://localhost:8443/api/users/get \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"samAccountName": "john.doe"}'
```

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

## Comprehensive Active Directory Audit

### POST /api/audit

Performs a comprehensive enterprise-grade security audit of Active Directory with step-by-step progress tracking.

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

**Example:**
```bash
curl -X POST http://localhost:8443/api/audit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"includeDetails": false, "includeComputers": false}'
```

---

### Audit Steps and Progress Tracking

The audit executes in 15 logical steps, each with a specific code:

| Step Code | Description |
|-----------|-------------|
| `STEP_01_INIT` | Audit initialization |
| `STEP_02_USER_ENUM` | User enumeration |
| `STEP_03_PASSWORD_SEC` | Password security analysis |
| `STEP_04_KERBEROS_SEC` | Kerberos security analysis |
| `STEP_05_ACCOUNT_STATUS` | Account status analysis |
| `STEP_06_PRIVILEGED_ACCTS` | Privileged accounts analysis |
| `STEP_07_SERVICE_ACCTS` | Service accounts detection |
| `STEP_08_DANGEROUS_PATTERNS` | Dangerous patterns detection |
| `STEP_09_TEMPORAL_ANALYSIS` | Temporal analysis |
| `STEP_10_GROUP_ENUM` | Group enumeration |
| `STEP_11_GROUP_ANALYSIS` | Group analysis |
| `STEP_12_COMPUTER_ANALYSIS` | Computer analysis (optional) |
| `STEP_13_OU_ANALYSIS` | OU analysis |
| `STEP_14_RISK_SCORING` | Risk scoring calculation |
| `STEP_15_COMPLETED` | Audit completed |

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

**Critical Findings:**
- `PASSWORD_NOT_REQUIRED` - Account with no password required
- `REVERSIBLE_ENCRYPTION` - Password stored with reversible encryption
- `ASREP_ROASTING_RISK` - Account vulnerable to AS-REP roasting
- `UNCONSTRAINED_DELEGATION` - Account with unconstrained delegation (very dangerous)
- `UNIX_USER_PASSWORD` - Unix password attribute set (plaintext password risk)
- `SENSITIVE_DELEGATION` - Privileged account (adminCount=1) with unconstrained delegation

**High Findings:**
- `KERBEROASTING_RISK` - Account with SPN (Kerberoasting vulnerable)
- `PASSWORD_NEVER_EXPIRES` - Account with password that never expires
- `ACCOUNT_LOCKED` - Locked account (possible attack)
- `PRIVILEGED_ACCOUNT` - Highly privileged account detected
- `SID_HISTORY` - SID History attribute populated (privilege escalation risk)
- `WEAK_ENCRYPTION_DES` - Account configured for DES-only Kerberos encryption
- `OVERSIZED_GROUP_HIGH` - Group with >500 members (management difficulty)
- `GPO_MODIFY_RIGHTS` - Member of Group Policy Creator Owners (can modify GPOs)
- `DNS_ADMINS_MEMBER` - Member of DnsAdmins (can execute code on DC via DLL)
- `REPLICATION_RIGHTS` - AdminCount=1 account outside standard admin groups (potential DCSync)

**Medium Findings:**
- `PASSWORD_VERY_OLD` - Password older than 1 year
- `PASSWORD_EXPIRED` - Expired password
- `INACTIVE_180_DAYS` - Account inactive for 180+ days
- `CONSTRAINED_DELEGATION` - Account with constrained delegation
- `NOT_IN_PROTECTED_USERS` - Privileged account not in Protected Users group
- `WEAK_ENCRYPTION_FLAG` - Account with USE_DES_KEY_ONLY flag set
- `OVERSIZED_GROUP` - Group with >100 members
- `DELEGATION_PRIVILEGE` - Member of Account/Server Operators (can modify delegation settings)

**Low Findings:**
- `INACTIVE_90_DAYS` - Account inactive for 90+ days
- `PASSWORD_CANNOT_CHANGE` - User cannot change password
- `ACCOUNT_DISABLED` - Disabled account
- `NEVER_LOGGED_ON` - Account never used

**Info Findings:**
- `EMPTY_GROUP` - Group with no members
- `OVERSIZED_GROUP_CRITICAL` - Very large group (>1000 members)
- `TEST_ACCOUNT` - Possible test account
- `SHARED_ACCOUNT` - Possible shared account
- `LAPS_PASSWORD_SET` - Computer has LAPS password set (informational)
- `DCSYNC_CAPABLE` - Account member of DA/EA/Administrators (DCSync capable)

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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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

**Réponse :**
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
