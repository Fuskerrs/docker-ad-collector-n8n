# Guide de Publication sur Docker Hub

## AD Collector for n8n v1.0.0

Ce guide explique comment publier l'image Docker sur Docker Hub.

---

## ✅ Prérequis

1. **Compte Docker Hub** - Créez un compte sur [hub.docker.com](https://hub.docker.com)
2. **Docker CLI** - Docker est déjà installé sur ce système
3. **Image buildée** - L'image `ad-collector-n8n:1.0` est prête

---

## 📦 État Actuel

L'image Docker a été construite et testée avec succès :

```bash
$ docker images | grep ad-collector-n8n
ad-collector-n8n   1.0      9230e81ea556   XXX ago   138MB
ad-collector-n8n   latest   9230e81ea556   XXX ago   138MB
```

### Tests effectués ✅

- ✅ Health check fonctionne
- ✅ Connexion LDAP fonctionnelle
- ✅ Récupération d'utilisateurs fonctionnelle
- ✅ API Token généré correctement
- ✅ Variables d'environnement fonctionnelles
- ✅ TLS/SSL configuration fonctionnelle

---

## 🚀 Publication sur Docker Hub

### Étape 1: Login Docker Hub

```bash
docker login
```

Entrez vos identifiants Docker Hub :
- **Username** : votre_username_dockerhub
- **Password** : votre_password_dockerhub

### Étape 2: Tag l'image

Remplacez `VOTRE_USERNAME` par votre nom d'utilisateur Docker Hub :

```bash
# Tag version 1.0
docker tag ad-collector-n8n:1.0 VOTRE_USERNAME/ad-collector-n8n:1.0

# Tag latest
docker tag ad-collector-n8n:latest VOTRE_USERNAME/ad-collector-n8n:latest
```

**Exemple** avec le username `johndoe` :
```bash
docker tag ad-collector-n8n:1.0 johndoe/ad-collector-n8n:1.0
docker tag ad-collector-n8n:latest johndoe/ad-collector-n8n:latest
```

### Étape 3: Push l'image

```bash
# Push version 1.0
docker push VOTRE_USERNAME/ad-collector-n8n:1.0

# Push latest
docker push VOTRE_USERNAME/ad-collector-n8n:latest
```

### Étape 4: Vérification

Visitez : `https://hub.docker.com/r/VOTRE_USERNAME/ad-collector-n8n`

Vous devriez voir votre image avec les tags `1.0` et `latest`.

---

## 📝 Mettre à jour la documentation

Après publication, mettez à jour les fichiers suivants avec votre username Docker Hub :

### README.md

Remplacez `YOUR_DOCKERHUB_USERNAME` par votre username :

```bash
sed -i 's/YOUR_DOCKERHUB_USERNAME/votre_username/g' README.md
sed -i 's/YOUR_USERNAME/votre_username/g' README.md
sed -i 's/YOUR_REPO/ad-collector-n8n/g' README.md
```

### SETUP.md

```bash
sed -i 's/YOUR_DOCKERHUB_USERNAME/votre_username/g' SETUP.md
sed -i 's/YOUR_USERNAME/votre_username/g' SETUP.md
```

### docker-compose.yml

```bash
sed -i 's/YOUR_DOCKERHUB_USERNAME/votre_username/g' docker-compose.yml
```

---

## 🌐 Création du Repository GitHub (Optionnel)

Si vous voulez aussi publier le code source sur GitHub :

### 1. Créer un nouveau repository sur GitHub

- Nom : `ad-collector-n8n`
- Description : `Active Directory Collector API for n8n workflow automation`
- Public ou Private : **Public** (recommandé)

### 2. Initialiser Git localement

```bash
cd /opt/ad-collector-docker

# Initialiser git
git init

# Créer .gitignore
cat > .gitignore <<'EOF'
# Environment
.env
.env.*
!.env.example

# Certificates
certs/
*.pem
*.cer
*.crt
*.key

# Node
node_modules/
npm-debug.log
.npm

# Docker
.docker/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
EOF

# Ajouter tous les fichiers
git add .

# Premier commit
git commit -m "Initial release v1.0.0 - AD Collector for n8n"
```

### 3. Pusher sur GitHub

```bash
# Remplacez VOTRE_USERNAME par votre username GitHub
git remote add origin https://github.com/VOTRE_USERNAME/ad-collector-n8n.git

# Push
git branch -M main
git push -u origin main
```

### 4. Créer un Release Tag

```bash
# Créer un tag v1.0.0
git tag -a v1.0.0 -m "Release v1.0.0"

# Push le tag
git push origin v1.0.0
```

Ensuite sur GitHub :
1. Allez dans **Releases**
2. Cliquez sur **Draft a new release**
3. Choisissez le tag `v1.0.0`
4. Titre : `v1.0.0 - Initial Release`
5. Description : Copiez-collez depuis README.md
6. **Publish release**

---

## 📊 Statistiques de l'image

- **Taille** : 138 MB
- **Base Image** : node:18-alpine
- **Layers** : 7
- **Platform** : linux/amd64

---

## 🔄 Publier une Mise à Jour (Future)

Quand vous ferez des modifications :

```bash
# 1. Modifier les fichiers nécessaires

# 2. Rebuild avec une nouvelle version
docker build -t ad-collector-n8n:1.1 .
docker build -t ad-collector-n8n:latest .

# 3. Tester
docker run -d --name test -e LDAP_BIND_PASSWORD=xxx ... ad-collector-n8n:1.1

# 4. Tag et push
docker tag ad-collector-n8n:1.1 VOTRE_USERNAME/ad-collector-n8n:1.1
docker tag ad-collector-n8n:latest VOTRE_USERNAME/ad-collector-n8n:latest
docker push VOTRE_USERNAME/ad-collector-n8n:1.1
docker push VOTRE_USERNAME/ad-collector-n8n:latest

# 5. Git commit et tag
git add .
git commit -m "Release v1.1.0 - Description des changements"
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin main
git push origin v1.1.0
```

---

## 📞 Support

Après publication, ajoutez ces informations dans vos fichiers :

- **Docker Hub** : https://hub.docker.com/r/VOTRE_USERNAME/ad-collector-n8n
- **GitHub** : https://github.com/VOTRE_USERNAME/ad-collector-n8n
- **Issues** : https://github.com/VOTRE_USERNAME/ad-collector-n8n/issues

---

## ✅ Checklist de Publication

Avant de publier, vérifiez :

- [ ] Image construite et testée localement
- [ ] Compte Docker Hub créé et login effectué
- [ ] Tags appliqués correctement
- [ ] Push Docker Hub réussi
- [ ] README.md mis à jour avec le bon username
- [ ] SETUP.md mis à jour avec le bon username
- [ ] docker-compose.yml mis à jour avec le bon username
- [ ] (Optionnel) Repository GitHub créé et code pushé
- [ ] (Optionnel) Release GitHub créée
- [ ] Image testée après pull depuis Docker Hub

---

**AD Collector for n8n v1.0.0**

Prêt pour publication ! 🚀
