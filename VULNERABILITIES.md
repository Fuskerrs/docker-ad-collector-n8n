# Active Directory Security Vulnerabilities Detection

## Vue d'ensemble

Le collecteur AD détecte actuellement **48 types de vulnérabilités** répartis en 4 niveaux de sévérité.

**Statistiques:**
- 🔴 **Critique**: 8 vulnérabilités
- 🟠 **High**: 15 vulnérabilités
- 🟡 **Medium**: 21 vulnérabilités
- 🔵 **Low**: 4 vulnérabilités

**Évolution:**
- v1.7.5: 23 vulnérabilités (baseline)
- v1.8.0-phase1: 33 vulnérabilités (+10)
- v1.9.0-phase2: **48 vulnérabilités (+25)** = **+108% d'amélioration**

---

## 🔴 CRITICAL - Vulnérabilités Critiques (8)

### 1. PASSWORD_NOT_REQUIRED
**Description:** Compte utilisateur ne nécessitant pas de mot de passe (UAC flag 0x20)

**Impact:** Un attaquant peut se connecter sans authentification

**Détection:** `userAccountControl & 0x20`

**Remédiation:**
```powershell
Set-ADUser -Identity username -PasswordNotRequired $false
```

---

### 2. REVERSIBLE_ENCRYPTION
**Description:** Mot de passe stocké avec chiffrement réversible (équivalent plaintext)

**Impact:** Les mots de passe peuvent être déchiffrés facilement en cas de compromission de la base AD

**Détection:** `userAccountControl & 0x80`

**Remédiation:**
```powershell
Set-ADUser -Identity username -AllowReversiblePasswordEncryption $false
```

---

### 3. ASREP_ROASTING_RISK
**Description:** Compte sans pré-authentification Kerberos requise (UAC flag 0x400000)

**Impact:** Permet l'attaque AS-REP Roasting - extraction de hash TGT crackable offline

**Détection:** `userAccountControl & 0x400000`

**Référence:** [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)

**Remédiation:**
```powershell
Set-ADAccountControl -Identity username -DoesNotRequirePreAuth $false
```

---

### 4. UNCONSTRAINED_DELEGATION
**Description:** Délégation Kerberos non contrainte activée (UAC flag 0x80000)

**Impact:** Le compte peut impersonner n'importe quel utilisateur du domaine (attaque de type Silver/Golden Ticket)

**Détection:** `userAccountControl & 0x80000`

**Référence:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remédiation:**
```powershell
Set-ADAccountControl -Identity username -TrustedForDelegation $false
# OU migrer vers constrained delegation
```

---

### 5. PASSWORD_IN_DESCRIPTION
**Description:** Mot de passe détecté dans le champ description ou info

**Impact:** Exposition directe des credentials

**Détection:** Regex `/password|passwd|pwd|motdepasse|mdp[:=]\s*[\w!@#$%^&*()]+/i`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Description "Valid description" -Clear info
```

---

### 6. UNIX_USER_PASSWORD
**Description:** Attribut `unixUserPassword` présent (stocke les mots de passe Unix en clair)

**Impact:** Exposition des mots de passe en texte clair

**Détection:** Présence de l'attribut `unixUserPassword`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Clear unixUserPassword
```

---

### 7. WEAK_ENCRYPTION_DES
**Description:** Algorithmes de chiffrement DES activés (DES-CBC-CRC, DES-CBC-MD5)

**Impact:** DES est crackable en quelques heures avec du matériel moderne

**Détection:** `msDS-SupportedEncryptionTypes & 0x3` (flags 0x1 ou 0x2)

**Référence:** [NIST SP 800-57](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

**Remédiation:**
```powershell
# Forcer AES uniquement
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
# 24 = 0x18 = AES128 + AES256
```

---

### 8. SENSITIVE_DELEGATION
**Description:** Compte administrateur (adminCount=1) avec délégation non contrainte activée

**Impact:** Combinaison extrêmement dangereuse - compromission du compte = compromission du domaine

**Détection:** `adminCount=1 AND userAccountControl & 0x80000`

**Remédiation:**
```powershell
Set-ADAccountControl -Identity admin_username -TrustedForDelegation $false
Set-ADUser -Identity admin_username -AccountNotDelegated $true
```

---

### 9. GOLDEN_TICKET_RISK **[NEW Phase 2]**
**Description:** Compte krbtgt avec mot de passe non changé depuis plus de 180 jours

**Impact:** Permet la création de Golden Tickets pour une persistance longue durée dans le domaine

**Détection:** `pwdLastSet` de krbtgt > 180 jours

**Référence:** [MITRE ATT&CK T1558.001](https://attack.mitre.org/techniques/T1558/001/)

**Remédiation:**
```powershell
# Rotation du mot de passe krbtgt (opération sensible, à planifier)
# Utiliser le script Microsoft officiel:
# https://github.com/microsoft/New-KrbtgtKeys.ps1
```

---

## 🟠 HIGH - Vulnérabilités Importantes (15)

### 10. KERBEROASTING_RISK
**Description:** Compte utilisateur avec Service Principal Name (SPN) configuré

**Impact:** Permet l'attaque Kerberoasting - extraction de hash de ticket de service crackable offline

**Détection:** Présence de `servicePrincipalName`

**Référence:** [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)

**Remédiation:**
```powershell
# Utiliser des Managed Service Accounts (gMSA) ou des mots de passe complexes (>25 caractères)
# Vérifier les SPNs:
Get-ADUser -Identity username -Properties servicePrincipalName | Select-Object servicePrincipalName
```

---

### 11. CONSTRAINED_DELEGATION
**Description:** Délégation contrainte Kerberos configurée (attribut `msDS-AllowedToDelegateTo`)

**Impact:** Le compte peut impersonner d'autres utilisateurs mais uniquement vers les services spécifiés

**Détection:** Présence de `msDS-AllowedToDelegateTo`

**Référence:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remédiation:** Auditer régulièrement et limiter aux besoins stricts

---

### 12. SID_HISTORY
**Description:** Attribut `sIDHistory` présent (utilisé pour migrations de domaine)

**Impact:** Peut être exploité pour élévation de privilèges si contient des SIDs d'anciens comptes privilégiés

**Détection:** Présence de `sIDHistory`

**Référence:** [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)

**Remédiation:**
```powershell
# Vérifier le contenu:
Get-ADUser -Identity username -Properties sIDHistory
# Nettoyer si non nécessaire:
Set-ADUser -Identity username -Clear sIDHistory
```

---

### 13. WEAK_ENCRYPTION_RC4
**Description:** Chiffrement RC4 uniquement (sans AES)

**Impact:** RC4 a des faiblesses cryptographiques connues (attaques de type NOMORE, RC4NOMORE)

**Détection:** `msDS-SupportedEncryptionTypes & 0x4 AND NOT (& 0x18)`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

---

### 14. WEAK_ENCRYPTION_FLAG
**Description:** Flag "USE_DES_KEY_ONLY" activé dans userAccountControl

**Impact:** Force l'utilisation exclusive de DES (algorithme obsolète et faible)

**Détection:** `userAccountControl & 0x200000`

**Remédiation:**
```powershell
Set-ADAccountControl -Identity username -UseDESKeyOnly $false
```

---

### 15. GPO_MODIFY_RIGHTS
**Description:** Membre du groupe "Group Policy Creator Owners"

**Impact:** Peut créer/modifier des GPOs et potentiellement exécuter du code sur tous les postes du domaine

**Détection:** Appartenance au groupe `Group Policy Creator Owners`

**Référence:** [MITRE ATT&CK T1484.001](https://attack.mitre.org/techniques/T1484/001/)

**Remédiation:** Limiter strictement les membres de ce groupe

---

### 16. DNS_ADMINS_MEMBER
**Description:** Membre du groupe DnsAdmins

**Impact:** Peut charger des DLLs arbitraires sur les contrôleurs de domaine via le service DNS (escalade vers Domain Admin)

**Détection:** Appartenance au groupe `DnsAdmins`

**Référence:** [DNSAdmin Privilege Escalation](https://adsecurity.org/?p=4064)

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity DnsAdmins -Members username -Confirm:$false
```

---

### 17. REPLICATION_RIGHTS
**Description:** Compte avec adminCount=1 mais hors des groupes d'admin standards

**Impact:** Peut avoir des droits de réplication (DCSync) pour extraire tous les hashs du domaine

**Détection:** `adminCount=1 AND NOT (Domain Admins OR Enterprise Admins OR Administrators)`

**Référence:** [MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)

**Remédiation:**
```powershell
# Vérifier les ACLs sur le domaine:
(Get-ACL "AD:\DC=domain,DC=com").Access | Where-Object {$_.IdentityReference -like "*username*"}
```

---

### 18. OVERSIZED_GROUP_CRITICAL
**Description:** Groupe avec plus de 1000 membres

**Impact:**
- Difficulté de gestion et d'audit
- Risque de privilèges excessifs (blast radius important)
- Problèmes de performance

**Détection:** `member.length > 1000`

**Remédiation:** Segmenter en sous-groupes plus petits et spécialisés

---

### 19. BACKUP_OPERATORS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Backup Operators

**Impact:** Peut lire/écrire n'importe quel fichier sur les DCs (bypass des ACLs, vol de NTDS.dit)

**Détection:** Appartenance au groupe `Backup Operators`

**Référence:** [Backup Operators Abuse](https://www.hackingarticles.in/windows-privilege-escalation-backup-operators-group/)

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity "Backup Operators" -Members username
```

---

### 20. ACCOUNT_OPERATORS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Account Operators

**Impact:** Peut créer/modifier des comptes et groupes (sauf Domain Admins), potentiel d'escalade

**Détection:** Appartenance au groupe `Account Operators`

**Remédiation:** Limiter strictement les membres

---

### 21. SERVER_OPERATORS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Server Operators

**Impact:** Peut modifier les services sur les DCs, potentiel d'exécution de code privilégié

**Détection:** Appartenance au groupe `Server Operators`

**Remédiation:** Limiter strictement les membres

---

### 22. PRINT_OPERATORS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Print Operators

**Impact:** Peut charger des drivers d'imprimante sur les DCs (escalade vers SYSTEM)

**Détection:** Appartenance au groupe `Print Operators`

**Remédiation:** Limiter strictement les membres

---

### 23. COMPUTER_UNCONSTRAINED_DELEGATION **[NEW Phase 2]**
**Description:** Ordinateur avec délégation Kerberos non contrainte

**Impact:** Peut capturer des TGTs d'utilisateurs s'y connectant (attaque PrinterBug + unconstrained delegation)

**Détection:** `(objectClass=computer) AND (userAccountControl:1.2.840.113556.1.4.803:=524288)`

**Référence:** [MITRE ATT&CK T1187](https://attack.mitre.org/techniques/T1187/)

**Remédiation:**
```powershell
Set-ADComputer -Identity computername -TrustedForDelegation $false
```

---

### 24. MACHINE_ACCOUNT_QUOTA_ABUSE **[NEW Phase 2]**
**Description:** ms-DS-MachineAccountQuota > 0 (par défaut 10)

**Impact:** N'importe quel utilisateur du domaine peut joindre 10 machines, potentiel d'abus (RBCD, etc.)

**Détection:** `ms-DS-MachineAccountQuota` au niveau du domaine

**Référence:** [MAQ Exploitation](https://www.netspi.com/blog/technical/network-penetration-testing/machineaccountquota-transitive-quota/)

**Remédiation:**
```powershell
Set-ADDomain -Identity "DC=domain,DC=com" -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

---

## 🟡 MEDIUM - Vulnérabilités Moyennes (21)

### 25. PASSWORD_VERY_OLD
**Description:** Mot de passe non changé depuis plus d'un an (365 jours)

**Impact:** Plus un mot de passe est ancien, plus il a de chances d'avoir été compromis ou divulgué

**Détection:** `pwdLastSet` > 365 jours

**Remédiation:**
```powershell
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

---

### 26. INACTIVE_365_DAYS
**Description:** Compte inactif depuis plus d'un an

**Impact:** Compte potentiellement oublié et non surveillé, cible facile pour les attaquants

**Détection:** `lastLogonTimestamp` > 365 jours

**Remédiation:**
```powershell
Disable-ADAccount -Identity username
# OU
Remove-ADUser -Identity username -Confirm:$true
```

---

### 27. SHARED_ACCOUNT
**Description:** Compte partagé détecté (commence par shared, common, generic, team)

**Impact:**
- Pas de traçabilité des actions
- Mot de passe généralement faible et partagé largement
- Non-conformité (ISO 27001, SOC 2, PCI-DSS)

**Détection:** Regex `/^(shared|common|generic|team)/i`

**Remédiation:** Créer des comptes individuels pour chaque utilisateur

---

### 28. WEAK_ENCRYPTION_RC4_WITH_AES
**Description:** RC4 activé en plus d'AES (downgrade attack possible)

**Impact:** Un attaquant peut forcer l'utilisation de RC4 via une attaque de downgrade

**Détection:** `msDS-SupportedEncryptionTypes & 0x4 AND & 0x18`

**Remédiation:**
```powershell
# Désactiver RC4, garder uniquement AES:
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

---

### 29. NOT_IN_PROTECTED_USERS
**Description:** Compte privilégié (DA/EA/SA) non membre du groupe "Protected Users"

**Impact:**
- Pas de protection contre délégation de credentials
- Pas de restriction d'algorithmes faibles
- Pas de limitation TGT (10h max)

**Détection:** Membre de DA/EA/SA mais PAS dans `Protected Users`

**Référence:** [Protected Users Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)

**Remédiation:**
```powershell
Add-ADGroupMember -Identity "Protected Users" -Members admin_username
```

**⚠️ Attention:** Tester avant (incompatibilité avec certains services)

---

### 30. DELEGATION_PRIVILEGE
**Description:** Membre des groupes Account Operators ou Server Operators

**Impact:** Peut modifier des objets AD et potentiellement élever ses privilèges

**Détection:** Appartenance à `Account Operators` ou `Server Operators`

**Remédiation:** Limiter strictement les membres

---

### 31. OVERSIZED_GROUP_HIGH
**Description:** Groupe avec 500-1000 membres

**Impact:** Difficulté de gestion et risque de privilèges excessifs

**Détection:** `500 < member.length <= 1000`

**Remédiation:** Segmenter en sous-groupes

---

### 32. PASSWORD_NEVER_EXPIRES **[NEW Phase 1]**
**Description:** Mot de passe configuré pour ne jamais expirer (UAC flag 0x10000)

**Impact:** Le mot de passe ne sera jamais renouvelé, augmentant le risque de compromission

**Détection:** `userAccountControl & 0x10000`

**Remédiation:**
```powershell
Set-ADUser -Identity username -PasswordNeverExpires $false
```

---

### 33. SCHEMA_ADMINS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Schema Admins

**Impact:** Peut modifier le schéma AD (opération irréversible, risque de corruption)

**Détection:** Appartenance au groupe `Schema Admins`

**Remédiation:** Ce groupe doit être vide par défaut (membership temporaire uniquement)

---

### 34. ENTERPRISE_ADMINS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Enterprise Admins

**Impact:** Contrôle total sur la forêt AD entière (tous les domaines)

**Détection:** Appartenance au groupe `Enterprise Admins`

**Remédiation:** Limiter au strict minimum (0-2 comptes maximum)

---

### 35. DOMAIN_ADMINS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Domain Admins

**Impact:** Contrôle total sur le domaine AD

**Détection:** Appartenance au groupe `Domain Admins`

**Remédiation:** Limiter au strict minimum et utiliser des comptes séparés (admin/user)

---

### 36. ADMINISTRATORS_MEMBER **[NEW Phase 1]**
**Description:** Membre du groupe Administrators (builtin)

**Impact:** Droits administrateurs sur les DCs et stations de travail du domaine

**Détection:** Appartenance au groupe `Administrators`

**Remédiation:** Limiter strictement les membres

---

### 37. WEAK_PASSWORD_POLICY **[NEW Phase 2]**
**Description:** Politique de mot de passe faible au niveau du domaine

**Impact:** Facilite les attaques par bruteforce et password spraying

**Détection:**
- `minPwdLength < 14` (recommandé: 14+)
- `pwdHistoryLength < 24` (recommandé: 24+)
- `minPwdAge < 1 jour` (recommandé: 1+)

**Remédiation:**
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity domain.com -MinPasswordLength 14 -PasswordHistoryCount 24 -MinPasswordAge 1.00:00:00
```

---

### 38. DOMAIN_ADMIN_IN_DESCRIPTION **[NEW Phase 2]**
**Description:** Mots-clés sensibles dans les champs description/info (admin, administrator, domain admin)

**Impact:** Fuite d'informations sur les comptes privilégiés

**Détection:** Regex `/(domain\s*admin|administrateur|admin\s*domain)/i`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Description "Sanitized description" -Clear info
```

---

### 39. LAPS_PASSWORD_LEAKED **[NEW Phase 2]**
**Description:** Mot de passe LAPS exposé dans le champ description/info

**Impact:** Exposition des mots de passe administrateur local

**Détection:** Regex `/(laps|local\s*admin\s*password)/i`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Clear description,info
```

---

### 40. DANGEROUS_LOGON_SCRIPTS **[NEW Phase 2]**
**Description:** Script de logon configuré (attribut scriptPath)

**Impact:** Potentiel d'exécution de code malveillant au logon de l'utilisateur

**Détection:** Présence de l'attribut `scriptPath`

**Remédiation:** Auditer le contenu du script ou utiliser des GPOs préférentiellement

---

### 41. PRE_WINDOWS_2000_ACCESS **[NEW Phase 2]**
**Description:** Groupe "Pre-Windows 2000 Compatible Access" contient Everyone ou Authenticated Users

**Impact:** Accès en lecture complet à l'annuaire AD pour tous les utilisateurs

**Détection:** Appartenance de `Everyone` (S-1-1-0) ou `Authenticated Users` (S-1-5-11)

**Référence:** [Pre-Win2K Access Abuse](https://support.microsoft.com/en-us/topic/using-the-pre-windows-2000-compatible-access-group-b5f32f74-6c53-4a20-9de4-e0f25a548a8e)

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Members "Authenticated Users","Everyone"
```

---

### 42. EXPIRED_ACCOUNT_IN_ADMIN_GROUP **[NEW Phase 2]**
**Description:** Compte expiré membre d'un groupe administrateur

**Impact:** Compte inutilisable mais toujours présent dans les groupes sensibles

**Détection:** `accountExpires < now AND memberOf contains admin groups`

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members expired_username
```

---

### 43. DISABLED_ACCOUNT_IN_ADMIN_GROUP **[NEW Phase 2]**
**Description:** Compte désactivé membre d'un groupe administrateur

**Impact:** Compte inutilisable mais toujours présent dans les groupes sensibles, peut être réactivé

**Détection:** `userAccountControl & 0x2 AND memberOf contains admin groups`

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity "Domain Admins" -Members disabled_username
```

---

### 44. PRIMARYGROUPID_SPOOFING **[NEW Phase 2]**
**Description:** primaryGroupID=512 (Domain Admins) sans memberOf correspondant

**Impact:** Technique de persistence - membership caché aux outils classiques

**Détection:** `primaryGroupID=512 AND NOT memberOf contains "CN=Domain Admins"`

**Référence:** [PrimaryGroupID Abuse](https://adsecurity.org/?p=1772)

**Remédiation:**
```powershell
Set-ADUser -Identity username -Replace @{primaryGroupID=513}  # 513 = Domain Users
```

---

### 45. FOREIGN_SECURITY_PRINCIPALS **[NEW Phase 2]**
**Description:** Foreign Security Principal membre d'un groupe sensible

**Impact:** Compte externe (autre forêt) avec des privilèges élevés - risque de compromission inter-forêts

**Détection:** `objectClass=foreignSecurityPrincipal AND memberOf contains sensitive groups`

**Remédiation:** Auditer les trusts inter-forêts et limiter les FSPs aux besoins stricts

---

## 🔵 LOW - Vulnérabilités Mineures (4)

### 46. TEST_ACCOUNT
**Description:** Compte de test détecté (commence par test, demo, temp, sample, example)

**Impact:** Généralement mal sécurisé, peut servir de point d'entrée

**Détection:** Regex `/^(test|demo|temp|sample|example)/i`

**Remédiation:**
```powershell
# Si nécessaire, isoler dans une OU spécifique avec GPO restrictive
# Sinon supprimer:
Remove-ADUser -Identity testaccount -Confirm:$true
```

---

### 47. USER_CANNOT_CHANGE_PASSWORD **[NEW Phase 1]**
**Description:** L'utilisateur ne peut pas changer son propre mot de passe (UAC flag 0x40)

**Impact:** Si le mot de passe est compromis, l'utilisateur ne peut pas le changer lui-même

**Détection:** `userAccountControl & 0x40`

**Remédiation:**
```powershell
Set-ADUser -Identity username -CannotChangePassword $false
```

---

### 48. SMARTCARD_NOT_REQUIRED **[NEW Phase 1]**
**Description:** Compte privilégié sans obligation de smartcard (UAC flag 0x40000 non défini)

**Impact:** Authentification par mot de passe possible au lieu de smartcard (MFA bypass)

**Détection:** `adminCount=1 AND NOT (userAccountControl & 0x40000)`

**Remédiation:**
```powershell
Set-ADUser -Identity admin_username -SmartcardLogonRequired $true
```

---

### 49. WEAK_KERBEROS_POLICY **[NEW Phase 2]**
**Description:** Politique Kerberos faible (TGT lifetime > 10 heures)

**Impact:** Augmente la fenêtre d'exploitation des tickets Kerberos volés

**Détection:** `maxTicketAge > 10 heures` (défaut AD: 10h)

**Remédiation:**
```powershell
# Configuration via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy
# Recommandé: Maximum lifetime for user ticket = 10 hours
```

---

### 50. DUPLICATE_SPN **[NEW Phase 2]**
**Description:** Même SPN configuré sur plusieurs comptes

**Impact:** Problèmes d'authentification Kerberos, potentiel de confusion d'identité

**Détection:** Multiple accounts with identical `servicePrincipalName` value

**Remédiation:**
```powershell
# Identifier:
Get-ADUser -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName | Group-Object -Property servicePrincipalName | Where-Object {$_.Count -gt 1}
# Supprimer le doublon:
Set-ADUser -Identity username -ServicePrincipalName @{Remove='HTTP/duplicate.spn'}
```

---

### 51. NTLM_RELAY_OPPORTUNITY **[NEW Phase 2]**
**Description:** Authentification NTLM activée sur le domaine (informationnel)

**Impact:** Vulnérable aux attaques NTLM relay si SMB signing non forcé

**Détection:** Détection automatique (NTLM enabled by default)

**Référence:** [MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)

**Remédiation:**
```powershell
# Forcer SMB signing via GPO:
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled

# Désactiver NTLM (après tests approfondis):
# Network security: Restrict NTLM: NTLM authentication in this domain = Deny all
```

---

## 📊 Matrice de Risque

| Sévérité | Nombre | Évolution | Exemples |
|----------|--------|-----------|----------|
| 🔴 Critical | 8 | +1 | AS-REP Roasting, Unconstrained Delegation, DES Encryption, Golden Ticket |
| 🟠 High | 15 | +6 | Kerberoasting, DNS Admins, DCSync Rights, Backup Operators |
| 🟡 Medium | 21 | +15 | Password Policy, LAPS Leak, FSP, PrimaryGroupID Spoofing |
| 🔵 Low | 4 | +3 | Test accounts, Weak Kerberos, Duplicate SPN, NTLM Relay |
| **TOTAL** | **48** | **+25** | **+108% vs v1.7.5** |

---

## 🎯 Score de Sécurité

Le collecteur calcule un **score global de sécurité du domaine** (0-100) basé sur:

```javascript
weightedRiskPoints = (critical × 15) + (high × 8) + (medium × 2) + (low × 1)
maxRiskPoints = totalUsers × 2.5
percentageDeduction = (weightedRiskPoints / maxRiskPoints) × 100
directPenalty = (critical × 0.3) + (high × 0.1)
score = MAX(0, MIN(100, 100 - percentageDeduction - directPenalty))
```

**Interprétation:**
- **90-100**: Excellente posture de sécurité
- **70-89**: Bonne sécurité, quelques améliorations possibles
- **50-69**: Sécurité moyenne, actions recommandées
- **30-49**: Sécurité faible, actions urgentes requises
- **0-29**: Sécurité critique, risque imminent de compromission

---

## 🔍 Frameworks de Conformité

Ces vulnérabilités sont mappées aux standards suivants:

### ISO 27001:2022
- A.5.15 - Contrôle d'accès
- A.5.17 - Informations d'authentification
- A.8.2 - Droits d'accès privilégiés

### NIST Cybersecurity Framework
- PR.AC-1 - Identity Management
- PR.AC-4 - Access Permissions
- PR.AC-7 - Users & Devices Authentication

### MITRE ATT&CK
- T1558 - Steal or Forge Kerberos Tickets
- T1003.006 - OS Credential Dumping: DCSync
- T1484.001 - Domain Policy Modification: Group Policy
- T1557.001 - NTLM Relay

### CIS Controls v8
- Control 5 - Account Management
- Control 6 - Access Control Management
- Control 16 - Application Software Security

---

## 📝 Notes de Version

**Version actuelle du collecteur:** v1.9.0-phase2

**Changelog:**
- v1.9.0-phase2: +25 vulnérabilités (Phase 2: domain config + Phase 3/4: 2 simple checks) = **48 total**
- v1.8.0-phase1: +10 vulnérabilités (group membership + UAC flags) = 33 total
- v1.7.5: Fix SSE complete event flush delay
- v1.7.4: Ajout détection OVERSIZED_GROUP
- v1.7.3: Amélioration détection weak encryption (DES + RC4)
- v1.7.2: Ajout SENSITIVE_DELEGATION check
- v1.7.1: Ajout SID_HISTORY detection

---

## 🚀 Roadmap (Fonctionnalités Premium Backend)

Les vulnérabilités suivantes nécessitent une analyse ACL complexe et seront détectées par le **backend d'analyse premium** (via API fermée):

### ACL-Based Detections (nécessite parser LDAP ACL):
1. **SHADOW_CREDENTIALS** - Exploitation de msDS-KeyCredentialLink (CRITICAL)
2. **RBCD_ABUSE** - Resource-Based Constrained Delegation abuse (CRITICAL)
3. **ACL_GENERICALL** - GenericAll sur objets sensibles (HIGH)
4. **ACL_WRITEDACL** - WriteDACL sur objets sensibles (HIGH)
5. **ACL_WRITEOWNER** - WriteOwner sur objets sensibles (HIGH)
6. **ACL_FORCECHANGEPASSWORD** - ForceChangePassword abuse (MEDIUM)
7. **ACL_GENERICWRITE** - GenericWrite sur objets sensibles (MEDIUM)
8. **WRITESPN_ABUSE** - WriteSPN for targeted Kerberoasting (MEDIUM)
9. **GPO_LINK_POISONING** - Weak ACLs on GPO links (MEDIUM)

### Group Nesting Analysis:
10. **DANGEROUS_GROUP_NESTING** - Nested groups leading to unintended privilege escalation (MEDIUM)

### AdminSDHolder:
11. **ADMINSDHOLDER_BACKDOOR** - Modified AdminSDHolder ACL for persistence (MEDIUM)

### Miscellaneous:
12. **EVERYONE_IN_ACL** - Everyone/Authenticated Users with dangerous permissions (MEDIUM)

### Analyse Multi-Pass (Premium)
- **Pass 1**: Scoring par sévérité brute
- **Pass 2**: Analyse contextuelle (Admin + Weak Crypto = 3× risque)
- **Pass 3**: ML pattern matching (détection de chaînes d'attaque)
- **Confidence Score**: Score de confiance pour chaque vulnérabilité

---

## 📚 Références

1. [MITRE ATT&CK Framework](https://attack.mitre.org/)
2. [Active Directory Security](https://adsecurity.org/)
3. [Microsoft Security Documentation](https://learn.microsoft.com/en-us/windows-server/security/)
4. [NIST Special Publications](https://csrc.nist.gov/publications/sp)
5. [CIS Controls](https://www.cisecurity.org/controls)
6. [ANSSI Guides](https://www.ssi.gouv.fr/)
7. [Backup Operators Abuse](https://www.hackingarticles.in/windows-privilege-escalation-backup-operators-group/)
8. [Machine Account Quota Exploitation](https://www.netspi.com/blog/technical/network-penetration-testing/machineaccountquota-transitive-quota/)

---

**Auteur:** AD Collector for n8n
**Licence:** MIT
**Repository:** https://github.com/fuskerrs/docker-ad-collector-n8n
**Version:** v1.9.0-phase2 (48 vulnerability types)
