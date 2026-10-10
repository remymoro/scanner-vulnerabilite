# Scanner de vulnérabilités

API de scan de sécurité web modulaire (FastAPI). On soumet une URL, on obtient un rapport noté de A à F.

## Checks disponibles

| Check | Ce qu'il vérifie |
|---|---|
| Headers | 6 en-têtes de sécurité HTTP (CSP, HSTS, X-Frame-Options...) |
| SSL/TLS | protocoles, suites de chiffrement, certificat, Heartbleed (sslyze) |
| DNS | SPF/DMARC, NS, MX, transfert de zone AXFR |
| WAF | présence d'un pare-feu applicatif (signature + comportement) |
| Rate limiting | blocage d'une rafale de requêtes, en-têtes `X-RateLimit` |

Le score global est une moyenne **pondérée par sévérité** (un check HIGH pèse plus qu'un LOW).

## Lancer le projet

```bash
docker compose up --build      # api + redis + mongodb → http://localhost:8000/docs
```

En local, sans Docker pour l'API :

```bash
docker compose up redis mongodb -d
pip install -e ".[dev]"
uvicorn scanner.api.main:app --reload
```

## API

- `POST /scan/` → lance un scan en arrière-plan, renvoie un `scan_id`
- `GET /scan/{scan_id}` → récupère le rapport (Redis puis MongoDB)
- `POST /scan/stream` → scan avec résultats en temps réel (SSE)
- `GET /health`

Sécurité du scanner : les cibles internes (localhost, 10.x, 169.254.x...) sont refusées (anti-SSRF)
et chaque IP est limitée à 10 scans par minute.

## Ajouter un check

1. Créer `src/scanner/checks/mon_check.py` avec une classe qui hérite de `BaseCheck`.
2. L'ajouter dans `default_checks()` (`src/scanner/services/check_registry.py`).
3. Écrire `tests/unit/checks/test_mon_check.py`.

## Architecture

```
src/scanner/
├── core/            entités, interfaces, exceptions (aucune lib externe)
├── checks/          un fichier = un scanner
├── services/        ScanService (orchestration) + check_registry
├── repositories/    Mongo + Redis
├── api/             routers, schemas, security (anti-SSRF, rate limit)
└── infrastructure/  config, connexions
tests/               unit/ et integration/
scanner/docs/        documentation pédagogique de chaque faille
```

## Tests

```bash
pytest -q
ruff check src tests
```
