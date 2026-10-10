# Rate limiting

## En une phrase
Limiter le nombre de requêtes qu'un même client peut envoyer en peu de temps.

## L'analogie
Un guichet qui sert une personne à la fois : impossible de le saturer en arrivant à cent.

## L'attaque — ce qui arrive sans limite
Force brute sur les mots de passe, bourrage d'identifiants, scraping massif, saturation du service (DoS applicatif).

## Ce que le scanner détecte
Une rafale de 30 requêtes (10 en parallèle) vers l'URL. On cherche des réponses 429/503 et des en-têtes `X-RateLimit-*` / `Retry-After`.
Score : blocage observé = 100, limite annoncée seulement = 70, rien = 30.

## La correction
`limit_req` dans Nginx, le module rate-limit de BunkerWeb, ou un middleware applicatif.

## Références officielles
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429
