# WAF — pare-feu applicatif web

## En une phrase
Un WAF filtre les requêtes HTTP malveillantes (XSS, injection SQL) avant qu'elles n'atteignent l'application.

## L'analogie
Le videur à l'entrée d'un bar : il regarde chaque personne avant de la laisser entrer, même si la porte du bar est ouverte.

## L'attaque — ce qui arrive sans WAF
Une requête comme `?q=<script>alert(1)</script>` ou `?id=1' OR '1'='1` arrive directement sur l'application. Si elle est vulnérable, l'attaque réussit.

## Ce que le scanner détecte
- **Signature (passif)** : en-têtes, valeur de `Server` et cookies propres à Cloudflare, Akamai, Imperva, Sucuri, F5, BunkerWeb, ModSecurity, AWS.
- **Comportement (actif)** : une seule requête avec une chaîne XSS/SQLi factice. Si la requête normale passe et celle-ci est rejetée (403/406/429/501), un filtrage est actif.
- Score : WAF reconnu = 100, filtrage sans signature = 85, rien = 30.

## La correction
Placer un WAF devant l'application (BunkerWeb, ModSecurity + OWASP CRS, Cloudflare...).

## Références officielles
- OWASP Core Rule Set : https://owasp.org/www-project-modsecurity-core-rule-set/
