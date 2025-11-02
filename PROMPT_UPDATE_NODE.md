# Prompt Système pour Claude Code - Mise à jour n8n-nodes-ad-admin

## Contexte

Je viens de publier un nouveau projet **AD Collector for n8n** qui est un collecteur Docker officiel pour le node n8n-nodes-ad-admin. Le collecteur est maintenant disponible publiquement sur :

- **Docker Hub:** https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
- **GitHub:** https://github.com/Fuskerrs/docker-ad-collector-n8n
- **Tags Docker:** `fuskerrs97/ad-collector-n8n:1.0` et `fuskerrs97/ad-collector-n8n:latest`

## Objectif

Mettre à jour le repository **n8n-nodes-ad-admin** (https://github.com/Fuskerrs/n8n-nodes-ad-admin) pour :

1. Référencer le nouveau collecteur Docker officiel dans la documentation
2. Ajouter une section dédiée au Collector Mode avec instructions d'installation Docker
3. Mettre à jour le README avec les liens vers Docker Hub et le repo GitHub du collecteur
4. Améliorer la section de configuration du Collector Mode
5. Incrémenter la version du package npm si nécessaire

## Informations sur le Collecteur

**Caractéristiques techniques:**
- Image Docker: `fuskerrs97/ad-collector-n8n:latest`
- Taille: 138 MB (Alpine Linux)
- Port: 8443
- Authentification: JWT Bearer Token
- Protocole: LDAPS (port 636)
- Endpoints: 26 API REST
- Runtime: Node.js 18
- License: MIT

**Installation rapide:**
```bash
docker run -d \
  --name ad-collector \
  -e LDAP_URL=ldaps://dc.example.com:636 \
  -e LDAP_BASE_DN=DC=example,DC=com \
  -e LDAP_BIND_DN=CN=n8n-service,CN=Users,DC=example,DC=com \
  -e LDAP_BIND_PASSWORD=YourSecurePassword \
  -e LDAP_TLS_VERIFY=false \
  -p 8443:8443 \
  --restart unless-stopped \
  fuskerrs97/ad-collector-n8n:latest
```

**Docker Compose:**
```yaml
services:
  ad-collector:
    image: fuskerrs97/ad-collector-n8n:latest
    container_name: ad-collector
    restart: unless-stopped
    ports:
      - "8443:8443"
    env_file:
      - .env
```

## Tâches à réaliser

### 1. Mise à jour du README.md principal

**Ajouter dans la section "Connection Modes":**

Une sous-section dédiée au Collector Mode avec :
- Lien vers le Docker Hub : https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
- Lien vers le GitHub repo : https://github.com/Fuskerrs/docker-ad-collector-n8n
- Badge Docker Hub (pulls, version, size)
- Avantages du Collector Mode vs Direct Mode
- Instructions d'installation complètes

**Exemple de badge à ajouter:**
```markdown
[![Docker Image](https://img.shields.io/docker/v/fuskerrs97/ad-collector-n8n?label=Collector%20Docker&logo=docker)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
[![Docker Pulls](https://img.shields.io/docker/pulls/fuskerrs97/ad-collector-n8n)](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)
```

**Créer une table comparative:**
| Feature | Direct Mode | Collector Mode |
|---------|-------------|----------------|
| Network Access | Requires LDAP ports (389/636) | Only HTTP/HTTPS (8443) |
| Setup Complexity | Medium | Simple (Docker one-liner) |
| Certificate Management | Per workflow | Centralized |
| Performance | Direct connection | Connection pooling |
| Best for | Small deployments | Enterprise/Cloud |

### 2. Créer un nouveau fichier COLLECTOR.md

Documentation complète du Collector Mode avec :

**Sections à inclure:**
- **What is the AD Collector?** - Présentation du collecteur Docker
- **Why Use Collector Mode?** - Avantages et use cases
- **Installation** - Méthodes Docker Run et Docker Compose
- **Configuration** - Variables d'environnement détaillées
- **Connecting to n8n** - Configuration step-by-step dans n8n
- **API Endpoints** - Liste des 26 endpoints disponibles
- **Troubleshooting** - Tests de santé et résolution de problèmes
- **Security Best Practices** - Recommandations réseau, credentials, SSL/TLS
- **Links** - Docker Hub, GitHub, npm package

### 3. Mise à jour de la documentation des credentials

Dans le fichier qui documente la configuration des credentials Active Directory API :

**Ajouter pour le Collector Mode:**
- URL du collecteur : `http://ad-collector:8443` (si même réseau Docker) ou `http://your-server-ip:8443`
- Comment récupérer le token JWT : `docker logs ad-collector | grep "API Token"`
- Configuration "Skip SSL Verification" : À cocher
- Test de connexion : Instructions pour vérifier la connectivité

### 4. Mise à jour du package.json

**Vérifier et mettre à jour si nécessaire:**
- Version du package (considérer un bump de version mineure, ex: 0.3.0 → 0.4.0)
- Keywords : Ajouter "docker", "collector", "ldaps"
- Repository URL : Vérifier qu'il pointe vers le bon repo
- Bugs URL : S'assurer qu'il est correct

### 5. Ajouter une section "Related Projects" ou "Ecosystem"

**Créer une nouvelle section dans le README avec:**
```markdown
## 🔗 Ecosystem

This node is part of a complete AD automation solution:

- **[n8n-nodes-ad-admin](https://www.npmjs.com/package/n8n-nodes-ad-admin)** - This npm package (n8n community node)
- **[AD Collector Docker](https://hub.docker.com/r/fuskerrs97/ad-collector-n8n)** - Official Docker collector (Collector Mode)
- **[AD Collector Source](https://github.com/Fuskerrs/docker-ad-collector-n8n)** - Collector source code on GitHub
```

### 6. Améliorer les exemples de configuration

**Dans les exemples de workflows ou de configuration, ajouter:**

Exemples concrets d'utilisation avec le Collector :
- Configuration de credentials avec URL du collecteur
- Exemples de requêtes réussies
- Gestion des erreurs communes
- Best practices de production

### 7. Mise à jour du CHANGELOG.md (si existant)

**Ajouter une entrée pour la nouvelle version:**
```markdown
## [0.4.0] - 2025-02-01

### Added
- Official Docker Collector support
- Complete Collector Mode documentation
- Link to fuskerrs97/ad-collector-n8n Docker image
- Collector installation guide
- API endpoints reference

### Improved
- Collector Mode configuration documentation
- Credential setup instructions
- Troubleshooting guide
```

## Guidelines de style

**Utiliser le même style que le README actuel du node :**
- Emojis pour les sections (🎯, ✨, 🚀, 🔗, etc.)
- Badges en haut du README
- Sections bien organisées avec des titres clairs
- Code blocks avec syntax highlighting
- Tables pour les comparaisons
- Lien "Buy Me a Coffee" : https://buymeacoffee.com/freelancerc5

## Points importants

1. **Ne pas casser la compatibilité** - Le Direct Mode doit continuer à fonctionner
2. **Référencer systématiquement** - Tous les liens vers le collecteur doivent pointer vers les URLs officielles
3. **Documentation claire** - Les utilisateurs doivent comprendre les deux modes et leurs différences
4. **Exemples concrets** - Donner des exemples fonctionnels prêts à copier-coller
5. **Sécurité** - Mettre en avant les bonnes pratiques de sécurité

## Vérifications finales

Avant de committer :
- ✅ Tous les liens sont valides (Docker Hub, GitHub)
- ✅ Les badges s'affichent correctement
- ✅ Les exemples de code sont testés
- ✅ La documentation est cohérente entre Direct et Collector Mode
- ✅ Le numéro de version est incrémenté si nécessaire
- ✅ Le CHANGELOG est à jour

## Commit et Publication

**Message de commit suggéré :**
```
Add official Docker Collector support

- Add documentation for Collector Mode with fuskerrs97/ad-collector-n8n
- Add Docker Hub and GitHub links to ecosystem
- Create comprehensive COLLECTOR.md guide
- Update README with Collector installation instructions
- Add Docker badges and comparison table
- Bump version to 0.4.0

Related: https://github.com/Fuskerrs/docker-ad-collector-n8n
```

**Après le commit :**
1. Pusher sur GitHub
2. Créer un tag de version si version incrémentée
3. Publier sur npm si version incrémentée (optionnel pour cette mise à jour doc)
4. Créer une GitHub Release avec notes de version

## Ressources

- Repo du node : https://github.com/Fuskerrs/n8n-nodes-ad-admin
- Collecteur Docker Hub : https://hub.docker.com/r/fuskerrs97/ad-collector-n8n
- Collecteur GitHub : https://github.com/Fuskerrs/docker-ad-collector-n8n
- Buy Me a Coffee : https://buymeacoffee.com/freelancerc5
- npm package : https://www.npmjs.com/package/n8n-nodes-ad-admin

---

**Note :** Ce prompt est à utiliser avec Claude Code pour mettre à jour automatiquement le repository n8n-nodes-ad-admin avec toutes les références au nouveau collecteur Docker officiel.
