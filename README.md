# CyberWatch

Veille technologique cybersécurité : **vulnérabilités (CVE)** + **actualités** +
**mises à jour produits** + **threat intel**, dans un seul pipeline.

## Concept clé

Toute donnée collectée est représentée par un `WatchItem` unique
(`core/models.py`), typé par `ItemType` :

- `vulnerability` — CVE/advisories avec score CVSS (NVD, ZDI, CERT-FR, MSRC)
- `security_news` — actualité cyber générale (The Hacker News, BleepingComputer, Krebs)
- `product_update` — releases/changelogs (GitHub Releases, PSIRT vendors)
- `threat_intel` — campagnes, IOC, groupes APT (Google TAG, Unit42)
- `advisory_vendor` — advisory/blog sécu non-CVE (Talos)

Une seule table SQLite (`watch_items`), un seul pipeline de dédup, un seul
scheduler — mais un routage différent en sortie selon le type et la gravité.

## Installation

```bash
pip install -e ".[dev]"
cp .env.example .env   # renseigner les clés API et webhooks
```

## Utilisation

```bash
# un seul cycle sur toutes les sources actives (utile pour tester)
python -m cyberwatch once

# scheduler continu (respecte l'intervalle propre à chaque source)
python -m cyberwatch run

# forcer l'envoi du digest immédiatement
python -m cyberwatch digest
```

## Ajouter une source

1. Créer `src/cyberwatch/sources/ma_source.py`, hériter de `BaseSource`,
   déclarer `item_type` et implémenter `fetch() -> list[WatchItem]`.
2. Enregistrer la classe dans `SOURCE_CLASS_MAP` (`core/scheduler.py`).
3. Ajouter une entrée dans `config/sources.yaml` avec `type` et `interval`.

## Routage des notifications

- **Temps réel** (Slack/Teams) : vulnérabilités `HIGH`/`CRITICAL` et threat
  intel majeure — configurable dans `sources.yaml > notifications.realtime`.
- **Digest** (email, quotidien/hebdo) : actualités, mises à jour produits,
  advisories vendors — évite le bruit d'une alerte par item.

## Tests

```bash
pytest tests/
```

# Déploiement cyber-watch (Docker + systemd)

## 1. Préparer le serveur
```bash
sudo mkdir -p /opt/cyberwatch
sudo chown $USER:$USER /opt/cyberwatch
cd /opt/cyberwatch
git clone <url-du-repo> .        # récupère pyproject.toml, src/, config/sources.yaml, etc.
```

Le projet a déjà la structure attendue par `docker-compose.yml` :
```
cyber-watch/
├── pyproject.toml
├── src/cyberwatch/...
├── config/sources.yaml      # <- monté en lecture seule dans le conteneur
└── data/                    # <- volume Docker nommé, PAS ce dossier local
```

⚠️ **Le `.env` du dépôt (avec `NVD_API_KEY` etc.) ne doit jamais être committé.**
Vérifie qu'il est bien dans `.gitignore`. En prod, gère-le comme un secret serveur :
```bash
chmod 600 .env
```

## 2. Secrets
Si `.env` n'existe pas encore sur le serveur, pars du modèle fourni :
```bash
cp .env.example .env
nano .env
chmod 600 .env
```
Les clés attendues correspondent aux `api_key_env` / `token_env` de `config/sources.yaml`
(`NVD_API_KEY`, `GITHUB_TOKEN`) + les webhooks/SMTP pour les notifications.

## 3. Build de l'image
```bash
docker compose build
```

## 4. Installer les unités systemd
```bash
sudo cp systemd/cyberwatch-init.service   /etc/systemd/system/
sudo cp systemd/cyberwatch.service        /etc/systemd/system/
sudo cp systemd/cyberwatch-digest.service /etc/systemd/system/
sudo cp systemd/cyberwatch-digest.timer   /etc/systemd/system/

sudo systemctl daemon-reload
```

## 5. Activer le watcher (démarre au boot, redémarre en cas de crash)
```bash
sudo systemctl enable --now cyberwatch.service
sudo systemctl status cyberwatch.service
journalctl -u cyberwatch.service -f
```

## 6. Activer le timer du digest quotidien
```bash
sudo systemctl enable --now cyberwatch-digest.timer
systemctl list-timers | grep cyberwatch
```

Test manuel du digest sans attendre 08:00 :
```bash
sudo systemctl start cyberwatch-digest.service
journalctl -u cyberwatch-digest.service -n 50
```

## 7. Mises à jour
```bash
cd /opt/cyberwatch
git pull
docker compose build
sudo systemctl restart cyberwatch.service
```

## Points d'attention
- Layout `src/` : l'image installe le package via `pip install .` (pyproject.toml), pas de `requirements.txt`. Vérifie que ton `pyproject.toml` déclare bien un `[project.scripts]` ou un `src/cyberwatch/__main__.py`, sinon `python -m cyberwatch` échouera dans le conteneur.
- `database.path` dans `config/sources.yaml` (`data/watch.db` dans ta config d'origine) doit rester cohérent avec le dossier `data/` du projet — c'est ce chemin qui est utilisé *à l'intérieur* du conteneur, sur le volume Docker nommé `cyberwatch-data` (mappé sur `/app/data`), pas sur le `data/` local du dépôt cloné.
- Le volume `cyberwatch-data` est un volume Docker nommé : `docker volume inspect cyberwatch_cyberwatch-data` pour le localiser si tu veux le sauvegarder (ex. `advisories.db`/`watch.db` selon ce que retourne `database.py`).
- `dedup_similarity_threshold: 0.85` dans ta config s'applique aux titres à travers toutes les sources : pense à sauvegarder `watch.db` régulièrement (il contient l'historique de dédup).
- `vendor_changelog` est `enabled: false` dans ta config : rien à faire côté déploiement, mais pense à l'activer une fois les URLs Fortinet/Cisco confirmées, sinon ces flux ne seront jamais pollés.
- Si tu ajoutes un webhook Slack/Teams ou un SMTP interne bloqué par un pare-feu sortant, vérifie les règles egress du serveur — le conteneur n'a pas besoin de port entrant, seulement d'accès sortant HTTPS/SMTP.
- `RandomizedDelaySec=60` sur le timer évite que plusieurs instances (si tu en as sur plusieurs serveurs) tapent la même minute exacte.
