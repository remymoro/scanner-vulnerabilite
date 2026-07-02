# Strict-Transport-Security (HSTS)

## En une phrase

HSTS dit au navigateur : "ce site n'existe qu'en HTTPS — n'essaie même
pas le HTTP, maintenant et pour les 365 prochains jours."

---

## L'analogie

Imagine que tu appelles un hôtel pour réserver. La standardiste te dit :
"Notre numéro a changé, voici le nouveau." La prochaine fois que tu veux
appeler, tu utilises directement le bon numéro — tu n'essaies plus
l'ancien.

Sans HSTS, le navigateur tape toujours l'ancien numéro (HTTP) en premier,
attend qu'on lui dise de raccrocher et de rappeler (redirect 301), puis
rappelle en HTTPS. Cette fraction de seconde sur l'ancien numéro suffit
à un attaquant pour s'interposer.

Avec HSTS, le navigateur a mémorisé : "ce domaine = HTTPS uniquement,
ne compose même plus le HTTP."

---

## L'attaque — SSL Stripping

Sans HSTS, voici ce qu'un attaquant sur le même réseau WiFi peut faire :

```
SANS HSTS
─────────────────────────────────────────────────────────────────

  Utilisateur          Attaquant (WiFi café)       Serveur
      │                       │                       │
      │  GET http://site.fr   │                       │
      │──────────────────────>│                       │
      │                       │  GET https://site.fr  │
      │                       │──────────────────────>│
      │                       │  200 OK (HTTPS)       │
      │                       │<──────────────────────│
      │  200 OK (HTTP) ← piège│                       │
      │<──────────────────────│                       │
      │                       │                       │
      │ Connexion en CLAIR    │ Voit tout le trafic   │
      │ Cookies, mots de passe│ Peut modifier les     │
      │ visibles              │ réponses              │

AVEC HSTS
─────────────────────────────────────────────────────────────────

  Utilisateur          Attaquant (WiFi café)       Serveur
      │                       │                       │
      │ (navigateur sait :    │                       │
      │  site.fr = HTTPS only)│                       │
      │                                               │
      │  GET https://site.fr (directement)            │
      │──────────────────────────────────────────────>│
      │                                               │
      │ Connexion chiffrée — attaquant voit du bruit  │
      │<──────────────────────────────────────────────│
```

L'attaque s'appelle **SSL Stripping** — l'attaquant "déshabille" le HTTPS
et sert du HTTP à l'utilisateur sans qu'il s'en rende compte. Le cadenas
dans le navigateur n'apparaît jamais.

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4 du scanner

**Librairie** : `httpx` (requête HTTP simple, lecture des headers de réponse)

**Ce qui est analysé** :
```python
# Le scanner cherche ce header dans la réponse
response.headers.get("Strict-Transport-Security")

# Résultat si absent
{
    "header": "Strict-Transport-Security",
    "result": "error",
    "message": "Header manquant — SSL stripping possible"
}

# Résultat si présent mais mal configuré (max-age trop court)
{
    "header": "Strict-Transport-Security",
    "result": "warning",
    "message": "max-age trop court (< 15768000 secondes / 6 mois)"
}

# Résultat idéal
{
    "header": "Strict-Transport-Security",
    "result": "ok",
    "value": "max-age=31536000; includeSubDomains; preload"
}
```

---

## La correction

**Dans Nginx** (`/etc/nginx/sites-available/monsite.conf`) :

```nginx
server {
    listen 443 ssl;
    server_name monsite.fr;

    # HSTS — 3 paramètres importants
    add_header Strict-Transport-Security
        "max-age=31536000; includeSubDomains; preload" always;
    #            │                │               │
    #            │                │               └── Soumettre à la
    #            │                │                   preload list Chrome/Firefox
    #            │                └── Appliquer aussi aux sous-domaines
    #            └── Mémoriser 1 an (en secondes)

    # "always" = envoyer le header même sur les erreurs 404, 500
    # Sans "always", une page d'erreur en HTTP ferait oublier la règle
}
```

**Rediriger HTTP → HTTPS dans un bloc dédié** :

```nginx
# Bloc séparé pour le HTTP — un seul rôle : rediriger
server {
    listen 80;
    server_name monsite.fr;
    return 301 https://$host$request_uri;
    # Pas de if ($host) — anti-pattern Nginx
}
```

---

## Avant / Après

```
AVANT — header absent
─────────────────────────────────────────────
$ curl -I https://monsite.fr

HTTP/2 200
server: nginx
content-type: text/html
                         ← pas de HSTS
                         ← chaque visite commence en HTTP
                         ← SSL stripping possible

APRÈS — header présent
─────────────────────────────────────────────
$ curl -I https://monsite.fr

HTTP/2 200
server: nginx
content-type: text/html
strict-transport-security: max-age=31536000; includeSubDomains; preload
                         ↑
                         Le navigateur mémorise cette règle 1 an
                         Plus aucune requête HTTP ne partira jamais
```

---

## Attention : l'ordre des directives compte

HSTS avec `includeSubDomains` veut dire que **tous** tes sous-domaines
sont aussi forcés en HTTPS. Si `staging.monsite.fr` n'a pas de certificat
valide, les utilisateurs verront une erreur de sécurité bloquante.

Vérifie avant d'activer `includeSubDomains` :
```bash
# Lister tous tes sous-domaines avec un certificat actif
sudo certbot certificates
```

---

## Références officielles

- **RFC 6797** — HTTP Strict Transport Security (HSTS) — définition du standard
- **OWASP** — [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- **MDN Web Docs** — [Strict-Transport-Security](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Strict-Transport-Security)
- **HSTS Preload List** — [hstspreload.org](https://hstspreload.org) — soumettre son domaine
- **CVE-2009-3555** — Attaque de renégotiation TLS liée à l'absence de HSTS