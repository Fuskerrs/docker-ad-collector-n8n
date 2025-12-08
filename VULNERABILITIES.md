# Active Directory Security Vulnerabilities Detection

## Overview

The AD Collector currently detects **87 vulnerability types** across 4 severity levels, providing comprehensive Active Directory security assessment.

**Statistics:**
- 🔴 **Critical**: 16 vulnerabilities
- 🟠 **High**: 27 vulnerabilities
- 🟡 **Medium**: 38 vulnerabilities
- 🔵 **Low**: 6 vulnerabilities

**Evolution:**
- v1.7.5: 23 vulnerabilities (baseline)
- v1.8.0-phase1: 33 vulnerabilities (+10)
- v1.9.0-phase2: 48 vulnerabilities (+25)
- v2.0.0: 60 vulnerabilities (+12) - Phase 3: Complete ACL parsing
- v2.1.0: 70 vulnerabilities (+10) - Phase 4: ADCS/PKI + LAPS
- v2.2.0: 70 vulnerabilities - Major refactor with 58 audit steps
- v2.2.3: 71 vulnerabilities (+1) - Added DOMAIN_ADMIN_IN_DESCRIPTION detection
- v2.2.4: 71 vulnerabilities - Fixed SSE stream missing detections + added SSE step mapping table
- **v2.5.0**: 87 vulnerabilities (+16) - Added 16 computer-specific vulnerability detections
- **v2.6.1**: 87 vulnerabilities - 74 total SSE audit steps (includes process steps + vulnerability detections)

---

## SSE Audit Steps

The audit process includes **74 SSE (Server-Sent Events) steps** that provide real-time progress tracking:

**Process Steps (11):** Infrastructure and enumeration steps that don't detect specific vulnerabilities
- `STEP_01_INIT` - Audit initialization
- `STEP_02_USER_ENUM` - User enumeration
- `STEP_09_SVC_SPN` - Service SPN enumeration
- `STEP_10_SVC_NAME` - Service name analysis
- `STEP_19_LAPS_READ` - LAPS configuration check
- `STEP_26_TEMPORAL` - Temporal analysis
- `STEP_27_GROUP_ENUM` - Group enumeration
- `STEP_29_COMPUTER_ANALYSIS` - Computer object analysis
- `STEP_30_OU_ANALYSIS` - Organizational Unit analysis
- `STEP_57_RISK_SCORING` - Risk score calculation
- `STEP_58_COMPLETE` - Audit completion

**Vulnerability Detection Steps (63):** Steps that actively detect the 87 security vulnerabilities
- Some steps detect multiple vulnerabilities (e.g., `STEP_03_PASSWORD_SEC` detects 4 password-related vulnerabilities)
- Each step is mapped to its detected vulnerabilities in the table below

---

## Complete Vulnerability Detection List

| # | Vulnerability Name | Brief Description | SSE Step | Detected |
|---|-------------------|-------------------|----------|----------|
| 1 | PASSWORD_NOT_REQUIRED | Account does not require a password | STEP_03_PASSWORD_SEC | ✅ |
| 2 | REVERSIBLE_ENCRYPTION | Password stored with reversible encryption | STEP_03_PASSWORD_SEC | ✅ |
| 3 | ASREP_ROASTING_RISK | Account without Kerberos pre-authentication | STEP_04_KERBEROS_SEC | ✅ |
| 4 | UNCONSTRAINED_DELEGATION | Unconstrained Kerberos delegation enabled | STEP_04_KERBEROS_SEC | ✅ |
| 5 | PASSWORD_IN_DESCRIPTION | Password detected in description field | STEP_12_PWD_DESC | ✅ |
| 6 | UNIX_USER_PASSWORD | Unix password attribute present (cleartext) | STEP_15_UNIX_PWD | ✅ |
| 7 | WEAK_ENCRYPTION_DES | DES encryption algorithms enabled | STEP_17_WEAK_KERB | ✅ |
| 8 | SENSITIVE_DELEGATION | Admin account with unconstrained delegation | STEP_18_SENS_DELEG | ✅ |
| 9 | GOLDEN_TICKET_RISK | krbtgt password unchanged for 180+ days | STEP_08_GOLDEN_TICKET | ✅ |
| 10 | SHADOW_CREDENTIALS | msDS-KeyCredentialLink attribute configured | STEP_35_SHADOW_CRED | ✅ |
| 11 | RBCD_ABUSE | Resource-Based Constrained Delegation configured | STEP_36_RBCD | ✅ |
| 12 | ESC1_VULNERABLE_TEMPLATE | ADCS template with client auth + enrollee supplies subject | STEP_47_ESC1 | ✅ |
| 13 | KERBEROASTING_RISK | User account with Service Principal Name | STEP_04_KERBEROS_SEC | ✅ |
| 14 | CONSTRAINED_DELEGATION | Constrained Kerberos delegation configured | STEP_04_KERBEROS_SEC | ✅ |
| 15 | SID_HISTORY | sIDHistory attribute present | STEP_16_SID_HISTORY | ✅ |
| 16 | WEAK_ENCRYPTION_RC4 | RC4 encryption only (without AES) | STEP_17_WEAK_KERB | ✅ |
| 17 | WEAK_ENCRYPTION_FLAG | USE_DES_KEY_ONLY flag enabled | STEP_17_WEAK_KERB | ✅ |
| 18 | GPO_MODIFY_RIGHTS | Member of Group Policy Creator Owners | STEP_22_GPO_MODIFY | ✅ |
| 19 | DNS_ADMINS_MEMBER | Member of DnsAdmins group | STEP_23_DNS_ADMINS | ✅ |
| 20 | REPLICATION_RIGHTS | Account with potential DCSync capability | STEP_24_REPLICATION | ✅ |
| 21 | OVERSIZED_GROUP_CRITICAL | Group with 1000+ members | STEP_28_GROUP_ANALYSIS | ✅ |
| 22 | BACKUP_OPERATORS_MEMBER | Member of Backup Operators group | STEP_06_PRIV_GROUPS | ✅ |
| 23 | ACCOUNT_OPERATORS_MEMBER | Member of Account Operators group | STEP_06_PRIV_GROUPS | ✅ |
| 24 | SERVER_OPERATORS_MEMBER | Member of Server Operators group | STEP_06_PRIV_GROUPS | ✅ |
| 25 | PRINT_OPERATORS_MEMBER | Member of Print Operators group | STEP_06_PRIV_GROUPS | ✅ |
| 26 | DCSYNC_CAPABLE | Account with replication permissions | STEP_20_DCSYNC | ✅ |
| 27 | ACL_GENERICALL | GenericAll permission on sensitive objects | STEP_39_ACL_GENERIC_ALL | ✅ |
| 28 | ACL_WRITEDACL | WriteDACL permission on sensitive objects | STEP_40_ACL_WRITE_DACL | ✅ |
| 29 | ACL_WRITEOWNER | WriteOwner permission on sensitive objects | STEP_41_ACL_WRITE_OWNER | ✅ |
| 30 | ESC2_ANY_PURPOSE | ADCS template with Any Purpose EKU | STEP_48_ESC2 | ✅ |
| 31 | ESC3_ENROLLMENT_AGENT | ADCS template with enrollment agent EKU | STEP_49_ESC3 | ✅ |
| 32 | ESC4_VULNERABLE_TEMPLATE_ACL | Certificate template with weak ACLs | STEP_50_ESC4 | ✅ |
| 33 | ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2 | ADCS CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag | STEP_51_ESC6 | ✅ |
| 34 | LAPS_PASSWORD_READABLE | Non-admin users can read LAPS passwords | STEP_54_LAPS_PWD_READ | ✅ |
| 35 | PASSWORD_NEVER_EXPIRES | Password set to never expire | STEP_03_PASSWORD_SEC | ✅ |
| 36 | PASSWORD_VERY_OLD | Password older than 365 days | STEP_03_PASSWORD_SEC | ✅ |
| 37 | INACTIVE_365_DAYS | Account inactive for 365+ days | STEP_05_ACCOUNT_STATUS | ✅ |
| 38 | TEST_ACCOUNT | Account name suggests test/demo purpose | STEP_13_TEST_ACCT | ✅ |
| 39 | SHARED_ACCOUNT | Account name suggests shared usage | STEP_14_SHARED_ACCT | ✅ |
| 40 | OVERSIZED_GROUP_HIGH | Group with 500-1000 members | STEP_28_GROUP_ANALYSIS | ✅ |
| 41 | OVERSIZED_GROUP | Group with 100-500 members | STEP_28_GROUP_ANALYSIS | ✅ |
| 42 | NOT_IN_PROTECTED_USERS | Privileged account not in Protected Users group | STEP_21_PROT_USERS | ✅ |
| 43 | DUPLICATE_SPN | Service Principal Name registered multiple times | STEP_11_DUP_SPN | ✅ |
| 44 | USER_CANNOT_CHANGE_PASSWORD | User forbidden from changing own password | STEP_03_PASSWORD_SEC | ✅ |
| 45 | SMARTCARD_NOT_REQUIRED | Account exempt from smartcard requirement | STEP_21_PROT_USERS | ✅ |
| 46 | WEAK_PASSWORD_POLICY | Domain password policy below minimum standards | STEP_31_DOMAIN_CONFIG | ✅ |
| 47 | WEAK_KERBEROS_POLICY | Kerberos ticket lifetimes exceed recommendations | STEP_31_DOMAIN_CONFIG | ✅ |
| 48 | MACHINE_ACCOUNT_QUOTA_ABUSE | ms-DS-MachineAccountQuota > 0 | STEP_31_DOMAIN_CONFIG | ✅ |
| 49 | PRE_WINDOWS_2000_ACCESS | Pre-Windows 2000 Compatible Access group has members | STEP_06_PRIV_GROUPS | ✅ |
| 50 | DELEGATION_PRIVILEGE | Account has SeEnableDelegationPrivilege | STEP_25_DELEGATION | ✅ |
| 51 | DANGEROUS_GROUP_NESTING | Sensitive group nested in less sensitive group | STEP_37_GROUP_NEST | ✅ |
| 52 | ADMINSDHOLDER_BACKDOOR | Unexpected ACL on AdminSDHolder object | STEP_38_ADMINSDHOLDER | ✅ |
| 53 | ACL_GENERICWRITE | GenericWrite permission on sensitive objects | STEP_43_ACL_GENERIC_WRITE | ✅ |
| 54 | ACL_FORCECHANGEPASSWORD | ExtendedRight to force password change | STEP_44_ACL_FORCE_PWD | ✅ |
| 55 | EVERYONE_IN_ACL | Everyone/Authenticated Users with write permissions | STEP_42_ACL_EVERYONE | ✅ |
| 56 | WRITESPN_ABUSE | WriteProperty permission for servicePrincipalName | STEP_45_WRITE_SPN | ✅ |
| 57 | GPO_LINK_POISONING | Weak ACLs on Group Policy Objects | STEP_46_GPO_LINK_POISON | ✅ |
| 58 | ESC8_HTTP_ENROLLMENT | ADCS web enrollment via HTTP | STEP_52_ESC8 | ✅ |
| 59 | LAPS_NOT_DEPLOYED | LAPS not deployed on domain computers | STEP_53_LAPS_NOT_DEPLOYED | ✅ |
| 60 | LAPS_LEGACY_ATTRIBUTE | Legacy LAPS attribute used instead of Windows LAPS | STEP_55_LAPS_LEGACY | ✅ |
| 61 | ADCS_WEAK_PERMISSIONS | Weak permissions on ADCS objects or templates | STEP_56_ADCS_WEAK_PERMS | ✅ |
| 62 | COMPUTER_UNCONSTRAINED_DELEGATION | Computer account with unconstrained delegation | STEP_32_COMP_UNCONSTR | ✅ |
| 63 | FOREIGN_SECURITY_PRINCIPALS | Foreign security principals from external forests | STEP_33_FOREIGN_SEC | ✅ |
| 64 | NTLM_RELAY_OPPORTUNITY | LDAP signing or channel binding not enforced | STEP_34_NTLM_RELAY | ✅ |
| 65 | DISABLED_ACCOUNT_IN_ADMIN_GROUP | Disabled account still in privileged group | STEP_07_ADMIN_COUNT | ✅ |
| 66 | EXPIRED_ACCOUNT_IN_ADMIN_GROUP | Expired account still in privileged group | STEP_07_ADMIN_COUNT | ✅ |
| 67 | LAPS_PASSWORD_SET | LAPS password successfully managed (informational) | STEP_18_SENS_DELEG | ✅ |
| 68 | LAPS_PASSWORD_LEAKED | LAPS password visible to too many users | STEP_12_PWD_DESC | ✅ |
| 69 | PRIMARYGROUPID_SPOOFING | Non-standard primaryGroupID value | STEP_07_ADMIN_COUNT | ✅ |
| 70 | DANGEROUS_LOGON_SCRIPTS | Logon scripts with weak ACLs | STEP_12_PWD_DESC | ✅ |
| 71 | DOMAIN_ADMIN_IN_DESCRIPTION | Sensitive terms in description field | STEP_12_PWD_DESC | ✅ |
| 72 | COMPUTER_CONSTRAINED_DELEGATION | Computer with constrained Kerberos delegation | STEP_32_1_COMP_CONSTR_DELEG | ✅ |
| 73 | COMPUTER_RBCD | Computer with RBCD configured | STEP_32_2_COMP_RBCD | ✅ |
| 74 | COMPUTER_IN_ADMIN_GROUP | Computer account in Domain Admins or Enterprise Admins | STEP_32_3_COMP_ADMIN_GROUP | ✅ |
| 75 | COMPUTER_DCSYNC_RIGHTS | Computer with DCSync replication rights | STEP_32_4_COMP_DCSYNC | ✅ |
| 76 | COMPUTER_STALE_INACTIVE | Computer inactive for 90+ days | STEP_32_5_COMP_STALE | ✅ |
| 77 | COMPUTER_PASSWORD_OLD | Computer password never changed (>90 days) | STEP_32_6_COMP_PWD_OLD | ✅ |
| 78 | COMPUTER_WITH_SPNS | Computer with SPNs (Kerberoastable) | STEP_32_7_COMP_SPNS | ✅ |
| 79 | COMPUTER_NO_LAPS | Computer without LAPS deployed | STEP_32_8_COMP_NO_LAPS | ✅ |
| 80 | COMPUTER_ACL_ABUSE | Computer with dangerous ACL permissions | STEP_32_9_COMP_ACL_ABUSE | ✅ |
| 81 | COMPUTER_DISABLED_NOT_DELETED | Disabled computer not deleted (>30 days) | STEP_32_10_COMP_DISABLED | ✅ |
| 82 | COMPUTER_WRONG_OU | Computer in unexpected OU location | STEP_32_11_COMP_WRONG_OU | ✅ |
| 83 | COMPUTER_WEAK_ENCRYPTION | Computer with weak encryption types (DES/RC4 only) | STEP_32_12_COMP_WEAK_ENC | ✅ |
| 84 | COMPUTER_DESCRIPTION_SENSITIVE | Computer description contains sensitive data | STEP_32_13_COMP_DESC_SENS | ✅ |
| 85 | COMPUTER_PRE_WINDOWS_2000 | Pre-Windows 2000 computer account | STEP_32_14_COMP_PRE_W2K | ✅ |
| 86 | COMPUTER_ADMIN_COUNT | Computer with adminCount attribute set | STEP_32_15_COMP_ADMIN_COUNT | ✅ |
| 87 | COMPUTER_SMB_SIGNING_DISABLED | Computer with SMB signing disabled | STEP_32_16_COMP_SMB_SIGN | ✅ |

---

## 🔴 CRITICAL - Critical Vulnerabilities (16)

### 1. PASSWORD_NOT_REQUIRED
**Description:** User account does not require a password (UAC flag 0x20)

**Impact:** An attacker can authenticate without credentials

**Detection:** `userAccountControl & 0x20`

**Remediation:**
```powershell
Set-ADUser -Identity username -PasswordNotRequired $false
```

---

### 2. REVERSIBLE_ENCRYPTION
**Description:** Password stored with reversible encryption (plaintext-equivalent)

**Impact:** Passwords can be easily decrypted if AD database is compromised

**Detection:** `userAccountControl & 0x80`

**Remediation:**
```powershell
Set-ADUser -Identity username -AllowReversiblePasswordEncryption $false
```

---

### 3. ASREP_ROASTING_RISK
**Description:** Account without Kerberos pre-authentication required (UAC flag 0x400000)

**Impact:** Enables AS-REP Roasting attack - extraction of offline crackable TGT hash

**Detection:** `userAccountControl & 0x400000`

**Reference:** [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)

**Remediation:**
```powershell
Set-ADAccountControl -Identity username -DoesNotRequirePreAuth $false
```

---

### 4. UNCONSTRAINED_DELEGATION
**Description:** Unconstrained Kerberos delegation enabled (UAC flag 0x80000)

**Impact:** Account can impersonate any domain user (Silver/Golden Ticket attack vector)

**Detection:** `userAccountControl & 0x80000`

**Reference:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remediation:**
```powershell
Set-ADAccountControl -Identity username -TrustedForDelegation $false
# Or migrate to constrained delegation
```

---

### 5. PASSWORD_IN_DESCRIPTION
**Description:** Password detected in description or info field

**Impact:** Direct credential exposure

**Detection:** Regex `/password|passwd|pwd|motdepasse|mdp[:=]\s*[\w!@#$%^&*()]+/i`

**Remediation:**
```powershell
Set-ADUser -Identity username -Description "Valid description" -Clear info
```

---

### 6. UNIX_USER_PASSWORD
**Description:** `unixUserPassword` attribute present (stores Unix passwords in cleartext)

**Impact:** Cleartext password exposure

**Detection:** Presence of `unixUserPassword` attribute

**Remediation:**
```powershell
Set-ADUser -Identity username -Clear unixUserPassword
```

---

### 7. WEAK_ENCRYPTION_DES
**Description:** DES encryption algorithms enabled (DES-CBC-CRC, DES-CBC-MD5)

**Impact:** DES is crackable in hours with modern hardware

**Detection:** `msDS-SupportedEncryptionTypes & 0x3` (flags 0x1 or 0x2)

**Reference:** [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

**Remediation:**
```powershell
# Force AES only
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
# 24 = 0x18 = AES128 + AES256
```

---

### 8. SENSITIVE_DELEGATION
**Description:** Administrative account (adminCount=1) with unconstrained delegation enabled

**Impact:** Extremely dangerous combination - account compromise = domain compromise

**Detection:** `adminCount=1 AND userAccountControl & 0x80000`

**Remediation:**
```powershell
Set-ADAccountControl -Identity admin_username -TrustedForDelegation $false
Set-ADUser -Identity admin_username -AccountNotDelegated $true
```

---

### 9. GOLDEN_TICKET_RISK
**Description:** krbtgt account with password unchanged for more than 180 days

**Impact:** Enables Golden Ticket creation for long-term domain persistence

**Detection:** krbtgt `pwdLastSet` > 180 days

**Reference:** [MITRE ATT&CK T1558.001](https://attack.mitre.org/techniques/T1558/001/)

**Remediation:**
```powershell
# Rotate krbtgt password (sensitive operation, plan carefully)
# Use official Microsoft script:
# https://github.com/microsoft/New-KrbtgtKeys.ps1
```

---

### 10. SHADOW_CREDENTIALS
**Description:** msDS-KeyCredentialLink attribute configured (Shadow Credentials attack)

**Impact:** Allows Kerberos authentication bypass by adding arbitrary public keys

**Detection:** Presence of `msDS-KeyCredentialLink`

**Reference:** [Shadow Credentials Attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)

**Remediation:**
```powershell
# Check attribute:
Get-ADUser -Identity username -Properties msDS-KeyCredentialLink | Select-Object -ExpandProperty msDS-KeyCredentialLink

# Remove if not legitimate:
Set-ADUser -Identity username -Clear msDS-KeyCredentialLink
```

---

### 11. RBCD_ABUSE
**Description:** msDS-AllowedToActOnBehalfOfOtherIdentity attribute configured (Resource-Based Constrained Delegation)

**Impact:** Enables privilege escalation via resource-based delegation

**Detection:** Presence of `msDS-AllowedToActOnBehalfOfOtherIdentity`

**Reference:** [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)

**Remediation:**
```powershell
# Check attribute:
Get-ADComputer -Identity computername -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Remove if unnecessary:
Set-ADComputer -Identity computername -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

### 12. ESC1_VULNERABLE_TEMPLATE
**Description:** ADCS certificate template with client authentication + enrollee supplies subject

**Impact:** Enables complete domain compromise by obtaining certificate for any user (including Domain Admin)

**Detection:**
- `pKIExtendedKeyUsage` contains OID 1.3.6.1.5.5.7.3.2 (Client Authentication)
- `msPKI-Certificate-Name-Flag & 0x00000001` (ENROLLEE_SUPPLIES_SUBJECT)

**Reference:** [Certified Pre-Owned - ESC1](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:**
```powershell
# Disable "Supply in the request" in certificate template
# Via GUI: Certificate Templates Console > Properties > Subject Name >
# Uncheck "Supply in the request"

# Or via PowerShell (requires PSPKI module):
Get-CertificateTemplate -Name "VulnerableTemplate" |
  Set-CertificateTemplateProperty -Property msPKI-Certificate-Name-Flag -Value 0
```

---

### 13. COMPUTER_CONSTRAINED_DELEGATION
**Description:** Computer account with constrained Kerberos delegation configured

**Impact:** Computer can impersonate users to specified services, enabling privilege escalation

**Detection:** `msDS-AllowedToDelegateTo` attribute present on computer objects

**Reference:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remediation:**
```powershell
Set-ADComputer -Identity computername -Clear msDS-AllowedToDelegateTo
```

---

### 14. COMPUTER_RBCD
**Description:** Computer with Resource-Based Constrained Delegation (RBCD) configured

**Impact:** Enables privilege escalation via RBCD attack chain

**Detection:** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute present on computer objects

**Reference:** [MITRE ATT&CK T1134](https://attack.mitre.org/techniques/T1134/)

**Remediation:**
```powershell
Set-ADComputer -Identity computername -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

### 15. COMPUTER_IN_ADMIN_GROUP
**Description:** Computer account member of Domain Admins or Enterprise Admins

**Impact:** Extremely dangerous - computer compromise leads to immediate domain admin access

**Detection:** Computer object memberOf Domain Admins or Enterprise Admins groups

**Remediation:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members computername$ -Confirm:$false
```

---

### 16. COMPUTER_DCSYNC_RIGHTS
**Description:** Computer account with DCSync replication rights

**Impact:** Computer can extract all domain password hashes via DCSync attack

**Detection:** Replication permissions (DS-Replication-Get-Changes) on domain root for computer object

**Reference:** [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)

**Remediation:**
```powershell
# Remove replication rights using AD ACL Editor or dsacls
```

---

## 🟠 HIGH - High Severity Vulnerabilities (27)

### 13. KERBEROASTING_RISK
**Description:** User account with Service Principal Name (SPN) configured

**Impact:** Enables Kerberoasting attack - extraction of offline crackable service ticket hash

**Detection:** Presence of `servicePrincipalName`

**Reference:** [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)

**Remediation:**
```powershell
# Use Managed Service Accounts (gMSA) or complex passwords (>25 characters)
# Check SPNs:
Get-ADUser -Identity username -Properties servicePrincipalName | Select-Object servicePrincipalName
```

---

### 14. CONSTRAINED_DELEGATION
**Description:** Constrained Kerberos delegation configured (`msDS-AllowedToDelegateTo` attribute)

**Impact:** Account can impersonate other users but only to specified services

**Detection:** Presence of `msDS-AllowedToDelegateTo`

**Reference:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remediation:** Audit regularly and limit to strict requirements

---

### 15. SID_HISTORY
**Description:** `sIDHistory` attribute present (used for domain migrations)

**Impact:** Can be exploited for privilege escalation if contains SIDs of former privileged accounts

**Detection:** Presence of `sIDHistory`

**Reference:** [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)

**Remediation:**
```powershell
# Check content:
Get-ADUser -Identity username -Properties sIDHistory
# Clean if unnecessary:
Set-ADUser -Identity username -Clear sIDHistory
```

---

### 16. WEAK_ENCRYPTION_RC4
**Description:** RC4 encryption only (without AES)

**Impact:** RC4 has known cryptographic weaknesses (NOMORE, RC4NOMORE attacks)

**Detection:** `msDS-SupportedEncryptionTypes & 0x4 AND NOT (& 0x18)`

**Remediation:**
```powershell
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

---

### 17. WEAK_ENCRYPTION_FLAG
**Description:** "USE_DES_KEY_ONLY" flag enabled in userAccountControl

**Impact:** Forces exclusive use of DES (obsolete and weak algorithm)

**Detection:** `userAccountControl & 0x200000`

**Remediation:**
```powershell
Set-ADAccountControl -Identity username -UseDESKeyOnly $false
```

---

### 18. GPO_MODIFY_RIGHTS
**Description:** Member of "Group Policy Creator Owners" group

**Impact:** Can create/modify GPOs and potentially execute code on all domain machines

**Detection:** Membership in `Group Policy Creator Owners`

**Reference:** [MITRE ATT&CK T1484.001](https://attack.mitre.org/techniques/T1484/001/)

**Remediation:** Strictly limit members of this group

---

### 19. DNS_ADMINS_MEMBER
**Description:** Member of DnsAdmins group

**Impact:** Can load arbitrary DLLs on domain controllers via DNS service (escalation to Domain Admin)

**Detection:** Membership in `DnsAdmins`

**Reference:** [DNSAdmin Privilege Escalation](https://adsecurity.org/?p=4064)

**Remediation:**
```powershell
Remove-ADGroupMember -Identity DnsAdmins -Members username -Confirm:$false
```

---

### 20. REPLICATION_RIGHTS
**Description:** Account with adminCount=1 but outside standard admin groups

**Impact:** May have replication rights (DCSync) to extract all domain hashes

**Detection:** `adminCount=1 AND NOT (Domain Admins OR Enterprise Admins OR Administrators)`

**Reference:** [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)

**Remediation:**
```powershell
# Check domain ACLs:
(Get-ACL "AD:\DC=domain,DC=com").Access | Where-Object {$_.IdentityReference -like "*username*"}
```

---

### 21. OVERSIZED_GROUP_CRITICAL
**Description:** Group with more than 1000 members

**Impact:**
- Management and audit difficulty
- Risk of excessive privileges (large blast radius)
- Performance issues

**Detection:** `member.length > 1000`

**Remediation:** Segment into smaller, more specialized sub-groups

---

### 22. BACKUP_OPERATORS_MEMBER
**Description:** Member of Backup Operators group

**Impact:** Can read/write any file on DCs (ACL bypass, NTDS.dit theft)

**Detection:** Membership in `Backup Operators`

**Reference:** [Backup Operators Abuse](https://www.hackingarticles.in/windows-privilege-escalation-backup-operators-group/)

**Remediation:**
```powershell
Remove-ADGroupMember -Identity "Backup Operators" -Members username -Confirm:$false
```

---

### 23. ACCOUNT_OPERATORS_MEMBER
**Description:** Member of Account Operators group

**Impact:** Can create/modify accounts and groups (excluding Domain Admins)

**Detection:** Membership in `Account Operators`

**Remediation:** Limit membership to strict requirements

---

### 24. SERVER_OPERATORS_MEMBER
**Description:** Member of Server Operators group

**Impact:** Can manage servers and potentially escalate privileges

**Detection:** Membership in `Server Operators`

**Remediation:**
```powershell
Remove-ADGroupMember -Identity "Server Operators" -Members username -Confirm:$false
```

---

### 25. PRINT_OPERATORS_MEMBER
**Description:** Member of Print Operators group

**Impact:** Can load printer drivers and potentially execute arbitrary code

**Detection:** Membership in `Print Operators`

**Reference:** [Print Operators Abuse](https://www.tarlogic.com/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)

**Remediation:**
```powershell
Remove-ADGroupMember -Identity "Print Operators" -Members username -Confirm:$false
```

---

### 26. DCSYNC_CAPABLE
**Description:** Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights

**Impact:** Can perform DCSync attack to extract all password hashes

**Detection:** Replication permissions on domain root

**Reference:** [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)

**Remediation:**
```powershell
# Remove replication rights (requires careful AD ACL editing)
# Use AD ACL Editor or dsacls command
```

---

### 27. ACL_GENERICALL
**Description:** GenericAll permission on sensitive AD objects

**Impact:** Full control over object (can reset passwords, modify group membership, etc.)

**Detection:** ACE with GenericAll right on users/groups/computers

**Remediation:**
```powershell
# Review and remove excessive ACLs
# Use AD ACL Editor or Set-Acl cmdlet
```

---

### 28. ACL_WRITEDACL
**Description:** WriteDACL permission on sensitive AD objects

**Impact:** Can modify object's security descriptor to grant additional permissions

**Detection:** ACE with WriteDACL right

**Remediation:** Review and remove excessive ACLs

---

### 29. ACL_WRITEOWNER
**Description:** WriteOwner permission on sensitive AD objects

**Impact:** Can take ownership of object and then modify permissions

**Detection:** ACE with WriteOwner right

**Remediation:** Review and remove excessive ACLs

---

### 30. ESC2_ANY_PURPOSE
**Description:** ADCS certificate template with Any Purpose EKU or no usage restriction

**Impact:** Certificate can be used for any purpose, including domain authentication

**Detection:**
- `pKIExtendedKeyUsage` contains OID 2.5.29.37.0 (Any Purpose)
- OR `pKIExtendedKeyUsage` is empty/undefined

**Reference:** [Certified Pre-Owned - ESC2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:**
```powershell
# Define specific EKUs instead of "Any Purpose"
# Via GUI: Certificate Templates Console > Properties > Extensions > Application Policies
```

---

### 31. ESC3_ENROLLMENT_AGENT
**Description:** ADCS certificate template with enrollment agent EKU

**Impact:** Can request certificates on behalf of other users

**Detection:** `pKIExtendedKeyUsage` contains OID 1.3.6.1.4.1.311.20.2.1 (Certificate Request Agent)

**Reference:** [Certified Pre-Owned - ESC3](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:** Restrict enrollment agent template usage

---

### 32. ESC4_VULNERABLE_TEMPLATE_ACL
**Description:** Certificate template with weak ACLs (WriteDACL, WriteOwner, GenericAll)

**Impact:** Can modify template to make it vulnerable to ESC1/ESC2

**Detection:** Excessive permissions on certificate template object

**Reference:** [Certified Pre-Owned - ESC4](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:** Restrict template modification permissions

---

### 33. ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2
**Description:** ADCS CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag

**Impact:** Allows specifying arbitrary SAN in certificate requests

**Detection:** CA registry flag check

**Reference:** [Certified Pre-Owned - ESC6](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:**
```cmd
certutil -config "CA-Server\CA-Name" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

---

### 34. LAPS_PASSWORD_READABLE
**Description:** Non-admin users can read LAPS password attributes

**Impact:** Exposure of local admin passwords to unauthorized users

**Detection:** Read access to ms-Mcs-AdmPwd attribute by non-privileged users

**Remediation:**
```powershell
# Restrict access to LAPS password attribute
Import-Module AdmPwd.PS
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Computers,DC=domain,DC=com" -AllowedPrincipals "Domain Admins"
```

---

### 35. COMPUTER_STALE_INACTIVE
**Description:** Computer account inactive for 90+ days

**Impact:** Orphaned computer accounts could be exploited without detection

**Detection:** `lastLogonTimestamp` > 90 days for computer objects

**Remediation:**
```powershell
Disable-ADComputer -Identity computername
# Or remove after verification
Remove-ADComputer -Identity computername -Confirm:$false
```

---

### 36. COMPUTER_PASSWORD_OLD
**Description:** Computer account password never changed (>90 days old)

**Impact:** Increases risk of password-based attacks on computer accounts

**Detection:** `pwdLastSet` > 90 days for computer objects

**Remediation:**
```powershell
Reset-ComputerMachinePassword -Server DC01
```

---

### 37. COMPUTER_WITH_SPNS
**Description:** Computer account with Service Principal Names configured

**Impact:** Enables Kerberoasting attack against computer account

**Detection:** `servicePrincipalName` attribute present on computer objects

**Reference:** [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)

**Remediation:**
```powershell
# Audit SPNs and remove if unnecessary
Set-ADComputer -Identity computername -ServicePrincipalNames @{Remove="HTTP/server.domain.com"}
```

---

### 38. COMPUTER_NO_LAPS
**Description:** Computer without LAPS (Local Administrator Password Solution) deployed

**Impact:** Shared/static local admin passwords across workstations

**Detection:** Missing `ms-Mcs-AdmPwd` attribute on computer objects

**Remediation:**
```powershell
# Deploy LAPS via Group Policy
# https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview
```

---

### 39. COMPUTER_ACL_ABUSE
**Description:** Computer object with dangerous ACL permissions (GenericAll, WriteDACL, WriteOwner)

**Impact:** Can modify computer object properties and potentially escalate privileges

**Detection:** Excessive permissions on computer object ACL

**Remediation:**
```powershell
# Review and remove excessive ACLs using AD ACL Editor
```

---

## 🟡 MEDIUM - Medium Severity Vulnerabilities (38)

### 35. PASSWORD_NEVER_EXPIRES
**Description:** Password set to never expire

**Impact:** Password aging is disabled, increasing compromise risk over time

**Detection:** `userAccountControl & 0x10000`

**Remediation:**
```powershell
Set-ADUser -Identity username -PasswordNeverExpires $false
```

---

### 36. PASSWORD_VERY_OLD
**Description:** Password older than 365 days

**Impact:** Increased risk of password compromise

**Detection:** `pwdLastSet` > 365 days

**Remediation:**
```powershell
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

---

### 37. INACTIVE_365_DAYS
**Description:** Account inactive for more than 365 days

**Impact:** Orphaned account that could be compromised without detection

**Detection:** `lastLogonTimestamp` > 365 days

**Remediation:**
```powershell
Disable-ADAccount -Identity username
# Or remove after verification
```

---

### 38. TEST_ACCOUNT
**Description:** Account name suggests test/demo purpose

**Impact:** Often has weak passwords or excessive permissions

**Detection:** Name matches `/test|demo|temp|training/i`

**Remediation:** Remove or disable test accounts from production

---

### 39. SHARED_ACCOUNT
**Description:** Account name suggests shared usage

**Impact:** No accountability, difficult to audit

**Detection:** Name matches `/shared|generic|service|admin|common/i`

**Remediation:** Replace with individual accounts or service accounts

---

### 40. OVERSIZED_GROUP_HIGH
**Description:** Group with 500-1000 members

**Impact:** Management difficulty and potential privilege creep

**Detection:** `member.length > 500`

**Remediation:** Review membership and segment if needed

---

### 41. OVERSIZED_GROUP
**Description:** Group with 100-500 members

**Impact:** May indicate overly broad permissions

**Detection:** `member.length > 100`

**Remediation:** Review group purpose and membership

---

### 42. NOT_IN_PROTECTED_USERS
**Description:** Privileged account not in Protected Users security group

**Impact:** Missing additional security protections (no NTLM, no DES, no delegation)

**Detection:** `adminCount=1 AND NOT memberOf cn=Protected Users`

**Reference:** [Protected Users Security Group](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)

**Remediation:**
```powershell
Add-ADGroupMember -Identity "Protected Users" -Members username
```

---

### 43. DUPLICATE_SPN
**Description:** Service Principal Name (SPN) registered multiple times

**Impact:** Can cause Kerberos authentication failures

**Detection:** Same SPN on multiple accounts

**Remediation:**
```powershell
# Remove duplicate SPN
Set-ADUser -Identity username -ServicePrincipalNames @{Remove="HTTP/server.domain.com"}
```

---

### 44. USER_CANNOT_CHANGE_PASSWORD
**Description:** User forbidden from changing own password

**Impact:** Increases risk if password is compromised

**Detection:** `userAccountControl & 0x40`

**Remediation:**
```powershell
Set-ADUser -Identity username -CannotChangePassword $false
```

---

### 45. SMARTCARD_NOT_REQUIRED
**Description:** Account exempt from smartcard requirement

**Impact:** Weakens multi-factor authentication policy

**Detection:** `userAccountControl & 0x40000`

**Remediation:**
```powershell
Set-ADAccountControl -Identity username -SmartcardLogonNotRequired $false
```

---

### 46. WEAK_PASSWORD_POLICY
**Description:** Domain password policy below minimum standards

**Impact:** Enables easier password cracking

**Detection:**
- Minimum password length < 14 characters
- Maximum password age > 90 days
- Minimum password age < 1 day
- Password history < 24

**Remediation:**
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity domain.com `
  -MinPasswordLength 14 `
  -MaxPasswordAge (New-TimeSpan -Days 90) `
  -MinPasswordAge (New-TimeSpan -Days 1) `
  -PasswordHistoryCount 24
```

---

### 47. WEAK_KERBEROS_POLICY
**Description:** Kerberos ticket lifetimes exceed recommended values

**Impact:** Longer window for ticket-based attacks

**Detection:**
- MaxTicketAge > 10 hours
- MaxRenewAge > 7 days

**Remediation:**
```powershell
# Modify via Group Policy or Kerberos Policy settings
```

---

### 48. MACHINE_ACCOUNT_QUOTA_ABUSE
**Description:** ms-DS-MachineAccountQuota > 0

**Impact:** Non-admin users can join computers to domain (potential for Kerberos attacks)

**Detection:** Domain attribute ms-DS-MachineAccountQuota > 0

**Reference:** [MITRE ATT&CK T1098.001](https://attack.mitre.org/techniques/T1098/001/)

**Remediation:**
```powershell
Set-ADDomain -Identity domain.com -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

---

### 49. PRE_WINDOWS_2000_ACCESS
**Description:** Pre-Windows 2000 Compatible Access group has members

**Impact:** Overly permissive read access to AD objects

**Detection:** Non-empty "Pre-Windows 2000 Compatible Access" group

**Remediation:**
```powershell
# Remove all members except required system accounts
Get-ADGroupMember "Pre-Windows 2000 Compatible Access" |
  Where-Object {$_.SamAccountName -ne "ANONYMOUS LOGON"} |
  ForEach-Object {Remove-ADGroupMember "Pre-Windows 2000 Compatible Access" -Members $_ -Confirm:$false}
```

---

### 50. DELEGATION_PRIVILEGE
**Description:** Account has SeEnableDelegationPrivilege

**Impact:** Can enable delegation on user/computer accounts

**Detection:** UserAccountControl flags or explicit permission

**Remediation:** Remove privilege if not required

---

### 51. DANGEROUS_GROUP_NESTING
**Description:** Sensitive group nested in less sensitive group

**Impact:** Unintended privilege escalation path

**Detection:** Protected groups with unexpected group memberships

**Remediation:** Review and flatten group nesting

---

### 52. ADMINSDHOLDER_BACKDOOR
**Description:** Unexpected ACL on AdminSDHolder object

**Impact:** Persistent permissions on admin accounts

**Detection:** Non-standard ACEs on cn=AdminSDHolder

**Reference:** [AdminSDHolder Abuse](https://adsecurity.org/?p=1906)

**Remediation:**
```powershell
# Review AdminSDHolder ACL and remove non-standard permissions
```

---

### 53. ACL_GENERICWRITE
**Description:** GenericWrite permission on sensitive AD objects

**Impact:** Can modify many object attributes

**Detection:** ACE with GenericWrite right

**Remediation:** Review and remove excessive ACLs

---

### 54. ACL_FORCECHANGEPASSWORD
**Description:** ExtendedRight to force password change on user accounts

**Impact:** Can reset user passwords without knowing current password

**Detection:** ACE with User-Force-Change-Password extended right

**Remediation:** Remove permission if not required

---

### 55. EVERYONE_IN_ACL
**Description:** "Everyone" or "Authenticated Users" with write permissions in ACL

**Impact:** Overly permissive access

**Detection:** ACE with SID S-1-1-0 or S-1-5-11 with write rights

**Remediation:** Replace with specific security principals

---

### 56. WRITESPN_ABUSE
**Description:** WriteProperty permission for servicePrincipalName attribute

**Impact:** Can set SPNs for targeted Kerberoasting

**Detection:** ACE with WriteProperty for SPN attribute

**Reference:** [Targeted Kerberoasting](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

**Remediation:** Remove permission if not required

---

### 57. GPO_LINK_POISONING
**Description:** Weak ACLs on Group Policy Objects

**Impact:** Can modify GPO to execute code on targeted systems

**Detection:** GenericAll/GenericWrite/WriteDACL on GPO by non-admin principals

**Reference:** [GPO Abuse](https://labs.f-secure.com/blog/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/)

**Remediation:** Restrict GPO modification to Domain Admins only

---

### 58. ESC8_HTTP_ENROLLMENT
**Description:** ADCS web enrollment endpoint accessible via HTTP

**Impact:** Enables NTLM relay attacks against certificate enrollment

**Detection:** HTTP-based certificate enrollment service

**Reference:** [Certified Pre-Owned - ESC8](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

**Remediation:**
```powershell
# Disable HTTP, enforce HTTPS only
# Configure Extended Protection for Authentication (EPA)
```

---

### 59. LAPS_NOT_DEPLOYED
**Description:** LAPS not deployed on domain computers

**Impact:** Shared/static local admin passwords across workstations

**Detection:** Missing ms-Mcs-AdmPwd attribute on computer objects

**Remediation:**
```powershell
# Deploy LAPS using Group Policy
# https://docs.microsoft.com/en-us/windows-server/identity/laps/laps-overview
```

---

### 60. LAPS_LEGACY_ATTRIBUTE
**Description:** Legacy LAPS attribute (ms-Mcs-AdmPwd) used instead of Windows LAPS

**Impact:** Less secure implementation

**Detection:** Presence of ms-Mcs-AdmPwd but not msLAPS-Password

**Remediation:** Migrate to Windows LAPS (Windows Server 2025+)

---

### 61. ADCS_WEAK_PERMISSIONS
**Description:** Weak permissions on ADCS objects or certificate templates

**Impact:** Can lead to certificate-based attacks

**Detection:** Excessive modify permissions on PKI objects

**Remediation:** Restrict permissions to Certificate Admins only

---

### 62. COMPUTER_UNCONSTRAINED_DELEGATION
**Description:** Computer account with unconstrained delegation

**Impact:** Servers can be used for privilege escalation attacks

**Detection:** `userAccountControl & 0x80000` on computer objects

**Remediation:**
```powershell
Set-ADComputer -Identity computername -TrustedForDelegation $false
```

---

### 63. FOREIGN_SECURITY_PRINCIPALS
**Description:** Foreign security principals from external forests

**Impact:** Potential for cross-forest privilege escalation

**Detection:** Objects in cn=ForeignSecurityPrincipals

**Remediation:** Review and validate external trust relationships

---

### 64. NTLM_RELAY_OPPORTUNITY
**Description:** LDAP signing or channel binding not enforced

**Impact:** Enables NTLM relay attacks

**Detection:** Domain controller LDAP configuration

**Remediation:**
```powershell
# Enforce LDAP signing and channel binding via Group Policy
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Domain controller: LDAP server signing requirements" = Require signing
```

---

### 65. DISABLED_ACCOUNT_IN_ADMIN_GROUP
**Description:** Disabled account still member of privileged group

**Impact:** Could be re-enabled for unauthorized access

**Detection:** `userAccountControl & 0x2` AND memberOf admin group

**Remediation:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members username -Confirm:$false
```

---

### 66. EXPIRED_ACCOUNT_IN_ADMIN_GROUP
**Description:** Expired account still member of privileged group

**Impact:** Cleanup oversight, potential security gap

**Detection:** Expired accountExpires AND memberOf admin group

**Remediation:** Remove from privileged groups

---

### 67. COMPUTER_DISABLED_NOT_DELETED
**Description:** Disabled computer account not deleted (>30 days)

**Impact:** Clutters AD, potential security oversight

**Detection:** `userAccountControl & 0x2` AND disabled > 30 days for computer objects

**Remediation:**
```powershell
Remove-ADComputer -Identity computername -Confirm:$false
```

---

### 68. COMPUTER_WRONG_OU
**Description:** Computer in unexpected Organizational Unit

**Impact:** May indicate misconfiguration or security policy bypass

**Detection:** Computer object location in unexpected OU structure

**Remediation:**
```powershell
Move-ADObject -Identity "CN=COMP01,OU=WrongOU,DC=domain,DC=com" -TargetPath "OU=Computers,DC=domain,DC=com"
```

---

### 69. COMPUTER_WEAK_ENCRYPTION
**Description:** Computer with weak encryption types (DES/RC4 only)

**Impact:** Vulnerable to Kerberos encryption downgrade attacks

**Detection:** `msDS-SupportedEncryptionTypes` contains only DES/RC4 flags

**Remediation:**
```powershell
Set-ADComputer -Identity computername -Replace @{'msDS-SupportedEncryptionTypes'=24}
# 24 = 0x18 = AES128 + AES256
```

---

### 70. COMPUTER_DESCRIPTION_SENSITIVE
**Description:** Computer description field contains sensitive data (passwords, IPs, etc.)

**Impact:** Information disclosure

**Detection:** Regex patterns for passwords, credentials, or sensitive data in description

**Remediation:**
```powershell
Set-ADComputer -Identity computername -Description "Sanitized description"
```

---

### 71. COMPUTER_PRE_WINDOWS_2000
**Description:** Pre-Windows 2000 compatible computer account

**Impact:** Weak security settings, potential compatibility mode exploits

**Detection:** Account creation or naming patterns indicating legacy systems

**Remediation:**
```powershell
# Upgrade or decommission legacy systems
```

---

## 🔵 LOW - Low Severity Vulnerabilities (6)

### 67. LAPS_PASSWORD_SET
**Description:** LAPS password successfully managed

**Impact:** Informational - indicates proper LAPS deployment

**Detection:** Presence of current LAPS password attribute

**Remediation:** None - this is a positive security indicator

---

### 68. LAPS_PASSWORD_LEAKED
**Description:** LAPS password visible to too many users

**Impact:** Reduces effectiveness of LAPS

**Detection:** More than expected users can read LAPS attribute

**Remediation:**
```powershell
# Audit and restrict LAPS read permissions
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Computers,DC=domain,DC=com" -AllowedPrincipals "Domain Admins"
```

---

### 69. PRIMARYGROUPID_SPOOFING
**Description:** Non-standard primaryGroupID value

**Impact:** Can hide group membership from enumeration

**Detection:** primaryGroupID != 513 (Domain Users)

**Reference:** [Primary Group ID Manipulation](https://adsecurity.org/?p=1772)

**Remediation:**
```powershell
Set-ADUser -Identity username -Replace @{primaryGroupID=513}
```

---

### 70. DANGEROUS_LOGON_SCRIPTS
**Description:** Logon scripts with write permissions for regular users

**Impact:** Script modification could lead to code execution

**Detection:** Logon script path with weak ACLs

**Remediation:** Ensure logon scripts are read-only for users

---

### 71. DOMAIN_ADMIN_IN_DESCRIPTION
**Description:** Description field contains sensitive terms like "domain admin" or "administrator"

**Impact:** Information disclosure that may aid attackers in targeting privileged accounts

**Detection:** Regex `/domain\s*admin|administrator/i` in description or info field

**Remediation:**
```powershell
Set-ADUser -Identity username -Description "Sanitized description without sensitive information"
```

---

### 72. COMPUTER_ADMIN_COUNT
**Description:** Computer account with adminCount attribute set to 1

**Impact:** May indicate current or former administrative privileges

**Detection:** `adminCount=1` on computer objects

**Remediation:**
```powershell
# Audit to confirm administrative status, remove if no longer needed
Set-ADComputer -Identity computername -Clear adminCount
```

---

### 73. COMPUTER_SMB_SIGNING_DISABLED
**Description:** Computer with SMB signing disabled

**Impact:** Vulnerable to SMB relay attacks (informational finding)

**Detection:** SMB signing configuration check

**Remediation:**
```powershell
# Enable SMB signing via Group Policy
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network client/server: Digitally sign communications" = Enabled
```

---

## Risk Scoring Methodology

Security score calculation (0-100):

**Formula:**
```
Weighted Points = (Critical × 15) + (High × 8) + (Medium × 2) + (Low × 1)
Security Score = max(0, 100 - (Weighted Points / Total Users * 100))
```

**Interpretation:**
- **90-100**: Excellent - Minimal vulnerabilities, strong security posture
- **70-89**: Good - Some issues to address, generally secure
- **50-69**: Fair - Multiple vulnerabilities requiring attention
- **30-49**: Poor - Significant security gaps, urgent remediation needed
- **0-29**: Critical - Severe security risk, immediate action required

---

## Compliance Mapping

This vulnerability detection aligns with:

**ISO 27001:2022**
- A.9: Access Control
- A.14: System Acquisition, Development and Maintenance

**NIST Cybersecurity Framework**
- PR.AC: Identity Management, Authentication and Access Control
- DE.CM: Security Continuous Monitoring

**MITRE ATT&CK**
- T1558: Steal or Forge Kerberos Tickets
- T1003: OS Credential Dumping
- T1484: Domain Policy Modification
- T1098: Account Manipulation

**CIS Controls v8**
- Control 5: Account Management
- Control 6: Access Control Management
- Control 16: Application Software Security

---

## Version History

**Current Version:** v2.5.0
- Added 16 computer-specific vulnerability detections (87 total vulnerabilities)
- Enhanced computer security assessment with constrained delegation, RBCD, and privilege checks
- Added computer password age, stale accounts, and LAPS deployment checks

**v2.2.2:** Increased search limits to 50k objects
**v2.2.1:** STEP_29 always sent fix
**v2.2.0:** Major refactor - 58 audit steps with verbose naming
**v2.1.0:** Phase 4 - ADCS/PKI + LAPS (70 vulnerabilities)
**v2.0.0:** Phase 3 - Complete ACL parsing (60 vulnerabilities)
**v1.9.0:** Phase 2 - Advanced detections (48 vulnerabilities)
**v1.8.0:** Phase 1 - Enhanced enumeration (33 vulnerabilities)
**v1.7.5:** Baseline (23 vulnerabilities)

---

## Repository & License

**Repository:** [docker-ad-collector-n8n](https://github.com/Fuskerrs/docker-ad-collector-n8n)
**License:** MIT
**Author:** AD Security Assessment Project

**Contributing:** Issues and pull requests welcome!
