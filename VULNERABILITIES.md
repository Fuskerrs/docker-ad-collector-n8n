# Active Directory Security Vulnerabilities Detection

## Vue d'ensemble

Le collecteur AD détecte actuellement **23 types de vulnérabilités** répartis en 4 niveaux de sévérité.

**Statistiques:**
- 🔴 **Critique**: 7 vulnérabilités
- 🟠 **High**: 9 vulnérabilités
- 🟡 **Medium**: 6 vulnérabilités
- 🔵 **Low**: 1 vulnérabilité

---

## 🔴 CRITICAL - Vulnérabilités Critiques (7)

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

## 🟠 HIGH - Vulnérabilités Importantes (9)

### 9. KERBEROASTING_RISK
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

### 10. CONSTRAINED_DELEGATION
**Description:** Délégation contrainte Kerberos configurée (attribut `msDS-AllowedToDelegateTo`)

**Impact:** Le compte peut impersonner d'autres utilisateurs mais uniquement vers les services spécifiés

**Détection:** Présence de `msDS-AllowedToDelegateTo`

**Référence:** [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

**Remédiation:** Auditer régulièrement et limiter aux besoins stricts

---

### 11. SID_HISTORY
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

### 12. WEAK_ENCRYPTION_RC4
**Description:** Chiffrement RC4 uniquement (sans AES)

**Impact:** RC4 a des faiblesses cryptographiques connues (attaques de type NOMORE, RC4NOMORE)

**Détection:** `msDS-SupportedEncryptionTypes & 0x4 AND NOT (& 0x18)`

**Remédiation:**
```powershell
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

---

### 13. WEAK_ENCRYPTION_FLAG
**Description:** Flag "USE_DES_KEY_ONLY" activé dans userAccountControl

**Impact:** Force l'utilisation exclusive de DES (algorithme obsolète et faible)

**Détection:** `userAccountControl & 0x200000`

**Remédiation:**
```powershell
Set-ADAccountControl -Identity username -UseDESKeyOnly $false
```

---

### 14. GPO_MODIFY_RIGHTS
**Description:** Membre du groupe "Group Policy Creator Owners"

**Impact:** Peut créer/modifier des GPOs et potentiellement exécuter du code sur tous les postes du domaine

**Détection:** Appartenance au groupe `Group Policy Creator Owners`

**Référence:** [MITRE ATT&CK T1484.001](https://attack.mitre.org/techniques/T1484/001/)

**Remédiation:** Limiter strictement les membres de ce groupe

---

### 15. DNS_ADMINS_MEMBER
**Description:** Membre du groupe DnsAdmins

**Impact:** Peut charger des DLLs arbitraires sur les contrôleurs de domaine via le service DNS (escalade vers Domain Admin)

**Détection:** Appartenance au groupe `DnsAdmins`

**Référence:** [DNSAdmin Privilege Escalation](https://adsecurity.org/?p=4064)

**Remédiation:**
```powershell
Remove-ADGroupMember -Identity DnsAdmins -Members username -Confirm:$false
```

---

### 16. REPLICATION_RIGHTS
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

### 17. OVERSIZED_GROUP_CRITICAL
**Description:** Groupe avec plus de 1000 membres

**Impact:**
- Difficulté de gestion et d'audit
- Risque de privilèges excessifs (blast radius important)
- Problèmes de performance

**Détection:** `member.length > 1000`

**Remédiation:** Segmenter en sous-groupes plus petits et spécialisés

---

## 🟡 MEDIUM - Vulnérabilités Moyennes (6)

### 18. PASSWORD_VERY_OLD
**Description:** Mot de passe non changé depuis plus d'un an (365 jours)

**Impact:** Plus un mot de passe est ancien, plus il a de chances d'avoir été compromis ou divulgué

**Détection:** `pwdLastSet` > 365 jours

**Remédiation:**
```powershell
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

---

### 19. INACTIVE_365_DAYS
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

### 20. SHARED_ACCOUNT
**Description:** Compte partagé détecté (commence par shared, common, generic, team)

**Impact:**
- Pas de traçabilité des actions
- Mot de passe généralement faible et partagé largement
- Non-conformité (ISO 27001, SOC 2, PCI-DSS)

**Détection:** Regex `/^(shared|common|generic|team)/i`

**Remédiation:** Créer des comptes individuels pour chaque utilisateur

---

### 21. WEAK_ENCRYPTION_RC4_WITH_AES
**Description:** RC4 activé en plus d'AES (downgrade attack possible)

**Impact:** Un attaquant peut forcer l'utilisation de RC4 via une attaque de downgrade

**Détection:** `msDS-SupportedEncryptionTypes & 0x4 AND & 0x18`

**Remédiation:**
```powershell
# Désactiver RC4, garder uniquement AES:
Set-ADUser -Identity username -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

---

### 22. NOT_IN_PROTECTED_USERS
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

### 23. DELEGATION_PRIVILEGE
**Description:** Membre des groupes Account Operators ou Server Operators

**Impact:** Peut modifier des objets AD et potentiellement élever ses privilèges

**Détection:** Appartenance à `Account Operators` ou `Server Operators`

**Remédiation:** Limiter strictement les membres

---

### 24. OVERSIZED_GROUP_HIGH
**Description:** Groupe avec 500-1000 membres

**Impact:** Difficulté de gestion et risque de privilèges excessifs

**Détection:** `500 < member.length <= 1000`

**Remédiation:** Segmenter en sous-groupes

---

## 🔵 LOW - Vulnérabilités Mineures (1)

### 25. TEST_ACCOUNT
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

## 📊 Matrice de Risque

| Sévérité | Nombre | Exemples |
|----------|--------|----------|
| 🔴 Critical | 7 | AS-REP Roasting, Unconstrained Delegation, DES Encryption |
| 🟠 High | 9 | Kerberoasting, DNS Admins, DCSync Rights |
| 🟡 Medium | 6 | Comptes inactifs, RC4+AES, Shared Accounts |
| 🔵 Low | 1 | Comptes de test |
| **TOTAL** | **23** | |

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

### CIS Controls v8
- Control 5 - Account Management
- Control 6 - Access Control Management
- Control 16 - Application Software Security

---

## 📝 Notes de Version

**Version actuelle du collecteur:** v1.7.5

**Changelog:**
- v1.7.5: Fix SSE complete event flush delay
- v1.7.4: Ajout détection OVERSIZED_GROUP
- v1.7.3: Amélioration détection weak encryption (DES + RC4)
- v1.7.2: Ajout SENSITIVE_DELEGATION check
- v1.7.1: Ajout SID_HISTORY detection

---

## 🚀 Roadmap (Fonctionnalités Premium Backend)

Les vulnérabilités suivantes seront détectées par le **backend d'analyse premium** (via API fermée):

### À venir:
1. **NTLM Relay Risk** - Comptes vulnérables aux attaques NTLM relay
2. **Golden Ticket Indicators** - Indicateurs de persistence via Golden Ticket
3. **Shadow Credentials** - Exploitation de msDS-KeyCredentialLink
4. **RBCD Abuse** - Resource-Based Constrained Delegation abuse
5. **ACL Misconfiguration** - ACLs dangereuses (GenericAll, WriteDacl, etc.)
6. **LAPS Not Configured** - Ordinateurs sans LAPS activé
7. **SMB Signing Disabled** - Ordinateurs sans signature SMB
8. **Zerologon Vulnerable** - DCs vulnérables à CVE-2020-1472
9. **PrintNightmare Risk** - Print Spooler activé sur DCs
10. **PetitPotam Vulnerable** - EFS RPC accessible

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

---

**Auteur:** AD Collector for n8n
**Licence:** MIT
**Repository:** https://github.com/fuskerrs/docker-ad-collector-n8n
