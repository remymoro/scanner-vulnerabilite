# Documentation pédagogique du scanner de vulnérabilités

Ce dossier documente chaque faille détectée par le scanner.
Chaque fichier suit le même format : analogie → attaque → détection → correction → références.

---

## Headers HTTP de sécurité

| Fichier | Protection | Attaque bloquée |
|---|---|---|
| [hsts.md](headers/hsts.md) | Strict-Transport-Security | SSL stripping, interception HTTP |
| [csp.md](headers/csp.md) | Content-Security-Policy | XSS, injection de ressources |
| [x-frame-options.md](headers/x-frame-options.md) | X-Frame-Options | Clickjacking |
| [x-content-type.md](headers/x-content-type.md) | X-Content-Type-Options | MIME sniffing |
| [referrer-policy.md](headers/referrer-policy.md) | Referrer-Policy | Fuite d'URL sensibles |
| [permissions-policy.md](headers/permissions-policy.md) | Permissions-Policy | Abus d'APIs navigateur |

## Configuration TLS/SSL

| Fichier | Protection | Attaque bloquée |
|---|---|---|
| [protocols.md](tls/protocols.md) | TLS 1.2/1.3 uniquement | BEAST, POODLE, downgrade |
| [ciphers.md](tls/ciphers.md) | Suites de chiffrement | RC4, CBC, forward secrecy |
| [heartbleed.md](tls/heartbleed.md) | CVE-2014-0160 | Lecture mémoire serveur |
| [certificates.md](tls/certificates.md) | Certificat valide | MITM, usurpation |

## DNS

| Fichier | Protection | Attaque bloquée |
|---|---|---|
| [zone-transfer.md](dns/zone-transfer.md) | AXFR désactivé | Énumération complète |
| [spf-dkim-dmarc.md](dns/spf-dkim-dmarc.md) | SPF/DKIM/DMARC | Email spoofing, phishing |
| [subdomain-enum.md](dns/subdomain-enum.md) | Sous-domaines exposés | Reconnaissance attaquant |

## Configuration Nginx

| Fichier | Protection | Attaque bloquée |
|---|---|---|
| [server-tokens.md](nginx/server-tokens.md) | server_tokens off | Fingerprinting version |
| [security-headers.md](nginx/security-headers.md) | Headers complets | Multiples |
| [default-server.md](nginx/default-server.md) | Catch-all return 444 | Scan IP directe |

---

## Format de chaque fichier

```
## En une phrase
## L'analogie
## L'attaque — comment un attaquant l'exploite
## Ce que le scanner détecte
## La correction
## Avant / Après
## Références officielles
```