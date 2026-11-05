# LinkedIn Research Agent

Agent de recherche qui répond à une seule question : **que sait-on publiquement
de cette entreprise ou de cette personne ?** Il interroge Wikidata et Wikipédia,
et l'API LinkedIn officielle uniquement si l'exploitant fournit un jeton
autorisé.

**Il ne scrape pas LinkedIn.** Extraire des pages LinkedIn viole les conditions
d'utilisation du site et engage la responsabilité de celui qui exécute le code,
pas seulement la qualité du résultat. L'adaptateur `linkedin_official` le dit
explicitement quand aucun jeton n'est configuré, plutôt que de contourner la
limite par un navigateur automatisé.

## Démarrage

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/macOS

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # API_KEY
# renseigner API_KEY dans .env, puis :
.venv/Scripts/python research_agent.py
```

Sans `API_KEY`, le service **refuse de démarrer**. C'est volontaire : un service
qui démarre sans jeton et renvoie 500 à la première requête n'est pas « configuré
sans authentification », il est cassé.

## Points d'entrée

| Méthode | Route | Jeton | Rôle |
|---|---|---|---|
| GET | `/health` | non | sonde de vie, ne divulgue rien de sensible |
| GET | `/capabilities` | oui | capacités publiées à l'orchestrateur |
| POST | `/research` | oui | `{"query": "Airbus", "kind": "company", "lang": "fr"}` |
| POST | `/preview` | oui | `{"url": "https://fr.wikipedia.org/..."}` — liste blanche d'hôtes |

Exemple :

```bash
curl -s -X POST http://127.0.0.1:9100/research \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"query":"Airbus","kind":"company","limit":3}'
```

Réponse réelle (extrait) :

```
wikipedia:fr | Airbus Commercial Aircraft | Airbus Commercial Aircraft ou Airbus Operations…
wikidata     | Airbus Commercial Aircraft | constructeur aéronautique européen…
linkedin     | LINKEDIN_TOKEN absent : la recherche LinkedIn n'est pas activée
```

## Enregistrement auprès d'un orchestrateur

```bash
ORCHESTRATOR_URL=http://127.0.0.1:8000 ORCH_KEY=... python register.py
```

Battement toutes les `HEARTBEAT_SECONDS` secondes ; l'URL de l'orchestrateur est
validée comme les autres (schéma, absence d'identifiants), avec
`allow_private=True` assumé puisqu'il vit sur le réseau local.

## Protections, et à quoi elles répondent

Chaque garde existe à cause d'un défaut constaté, pas par principe.

| Risque (audit précédent) | Garde | Où |
|---|---|---|
| Authentification coupée par défaut | `auth_config()` : active par défaut, clé obligatoire | `security.py` |
| Clé en dur ou clé de repli | `require_secret()` : aucune valeur par défaut | `security.py` |
| SSRF — le serveur va chercher l'adresse fournie | `validate_url()` : schéma, identifiants, métadonnées, résolution DNS, toutes les IP | `security.py` |
| SSRF par redirection | `safe_get()` : aucune redirection suivie sans revalidation stricte | `security.py` |
| CORS accepté de n'importe quel site | `cors_origins()` : liste explicite, `*` refusé | `security.py` |
| Clé refusée écrite en clair | `log_safe()` : empreinte HMAC tronquée | `security.py` |
| Prompt utilisateur journalisé | `log_safe()` + `/research` ne renvoie qu'une empreinte | `research_agent.py` |
| Écoute sur toutes les interfaces | `bind_host()` : `127.0.0.1` par défaut, `EXPOSE_PUBLIC=1` requis | `security.py` |
| Dépendances vulnérables | pas de `requests` ; sinon borne `>= 2.33.0` (CVE-2024-47081 corrigée en 2.32.4, CVE-2026-25645 en 2.33.0) | `requirements.txt` |
| Abus de ressources | fenêtre glissante `RATE_LIMIT_PER_MINUTE`, `max_bytes` sur chaque lecture | `research_agent.py` |

Deux choix qui méritent d'être dits :

- **Liste blanche d'hôtes plutôt que filtre d'IP seul.** Un agent qui va chercher
  des pages n'a aucune raison de joindre autre chose que ses sources. Le filtre
  d'IP reste en second rideau, pour le cas où un nom de la liste résoudrait vers
  une adresse interne.
- **Les redirections sont revalidées en politique stricte**, même quand la
  première cible a été explicitement autorisée. Sinon une URL interne légitime
  sert de tremplin vers une autre.

## Tests

```bash
.venv/Scripts/python -m unittest discover -s tests -t . -v
```

45 tests, ~2 s, sans réseau : les adaptateurs sont remplacés par des doublures,
mais le serveur HTTP est réel (uvicorn sur la boucle locale), et les cas
« refusé » sont testés autant que les cas acceptés — une garde qui refuse tout
ne protège rien, elle casse le service et finit désactivée.

## Limites assumées

- Wikipédia et Wikidata répondent ce qu'ils veulent : l'agent ne vérifie pas
  l'exactitude, il cite la source et son URL.
- Pas de cache : deux recherches identiques coûtent deux appels.
- L'API LinkedIn officielle demande un jeton et des permissions produit ; sans
  elles, `linkedin.available` vaut `false` avec la raison.
