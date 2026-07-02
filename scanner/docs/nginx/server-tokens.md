# server_tokens — fingerprinting de version

## En une phrase

`server_tokens off` empêche Nginx de crier sa version à chaque réponse HTTP
— un attaquant ne peut plus chercher les CVE connues pour cette version.

---

## L'analogie

Imagine un vigile à l'entrée d'un bâtiment. Sans instruction, il répond
à n'importe quelle question : "Oui, notre système de sécurité est un
Securitas modèle XJ-2018." L'attaquant cherche "vulnérabilités Securitas
XJ-2018" et trouve un mode d'emploi pour entrer.

Avec `server_tokens off`, le vigile répond juste : "On a un système de
sécurité." Rien de plus. L'attaquant ne sait pas par où commencer.

---

## L'attaque — fingerprinting

```
SANS server_tokens off
─────────────────────────────────────────────────────────────────

  Attaquant                              Serveur
      │                                     │
      │  curl -I https://cible.fr           │
      │────────────────────────────────────>│
      │                                     │
      │  HTTP/2 200                         │
      │  Server: nginx/1.18.0 (Ubuntu)  <───│
      │                                     │
      │                                     │
      ▼
  Attaquant cherche :
  "nginx 1.18.0 CVE" → liste de vulnérabilités connues
  "ubuntu nginx exploit 2024" → scripts d'attaque prêts
  Shodan : "nginx/1.18.0" → liste de tous les serveurs identiques

AVEC server_tokens off
─────────────────────────────────────────────────────────────────

  Attaquant                              Serveur
      │                                     │
      │  curl -I https://cible.fr           │
      │────────────────────────────────────>│
      │                                     │
      │  HTTP/2 200                         │
      │  Server: nginx                  <───│
      │                                     │
      ▼
  Attaquant sait qu'il y a un Nginx.
  Pas de version. Pas de CVE ciblée.
  Il doit attaquer à l'aveugle.
```

---

## Ce que le scanner détecte

Le `HeadersCheck` ou un check dédié lit le header `Server` :

```python
server_header = response.headers.get("Server", "")

# Mauvais — version exposée
if re.search(r"nginx/[\d.]+", server_header):
    return {
        "result": "error",
        "message": f"Version Nginx exposée : {server_header}",
        "risk": "Fingerprinting — CVE ciblées possibles"
    }

# Acceptable — nom sans version
if "nginx" in server_header.lower():
    return {
        "result": "warning",
        "message": "Serveur identifié comme Nginx sans version"
    }

# Idéal — header absent ou neutre
return {
    "result": "ok",
    "message": "Aucune information de version exposée"
}
```

---

## La correction

Dans `/etc/nginx/nginx.conf`, bloc `http {}` :

```nginx
http {
    # Ligne commentée par défaut — DÉCOMMENTER
    server_tokens off;
    #               ↑
    #               Supprime la version dans le header Server:
    #               et dans les pages d'erreur HTML générées par Nginx
}
```

Pour aller encore plus loin (supprimer même "nginx") :

```nginx
# Nécessite le module headers-more (nginx-extras sur Ubuntu)
# sudo apt install nginx-extras

more_set_headers "Server: ";
# Header Server complètement vide — rien du tout
```

---

## Avant / Après

```
AVANT — server_tokens on (défaut)
──────────────────────────────────────────────
$ curl -I https://monsite.fr | grep -i server
server: nginx/1.24.0 (Ubuntu)
         ↑             ↑
         version       OS — double information

SSL Labs affiche :
"HTTP server signature: nginx/1.24.0 (Ubuntu)"

APRÈS — server_tokens off
──────────────────────────────────────────────
$ curl -I https://monsite.fr | grep -i server
server: nginx

SSL Labs affiche :
"HTTP server signature: nginx"
```

---

## Vérification sur ton VPS

```bash
# Après avoir appliqué server_tokens off et reloadé Nginx :
curl -I https://tondomaine.fr 2>/dev/null | grep -i server

# Résultat attendu :
# server: nginx
```

---

## Important : security by obscurity

`server_tokens off` est de la **discrétion**, pas de la sécurité absolue.
Un attaquant expérimenté peut deviner la version via le comportement
réseau (timing des réponses, particularités des headers HTTP/2).

Mais ça ralentit les scans automatiques (Shodan, Nmap, Nuclei) qui
cherchent des versions spécifiques, et élimine les attaques opportunistes
de scripts kiddies qui ne ciblent que les versions connues vulnérables.

C'est le principe qu'on applique partout : **réduire la surface d'attaque
visible** pour que l'attaquant ait moins de points d'entrée identifiés.

---

## Références officielles

- **Nginx doc** — [server_tokens](https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens)
- **CWE-200** — Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP** — [Fingerprint Web Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)