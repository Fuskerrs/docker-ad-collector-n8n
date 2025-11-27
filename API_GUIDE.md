# AD Collector API Guide

## Version: 1.1.2

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
