# Protocoles TLS — versions et vulnérabilités

## En une phrase

TLS est le cadenas de la connexion internet — chaque version est une
génération de cadenas, et les vieilles générations ont des failles connues
qui permettent à un attaquant de les ouvrir.

---

## L'analogie

Imagine les versions TLS comme des serrures de porte :

- **SSL 2.0 / SSL 3.0** — serrure des années 90, clé passe-partout connue
  de tous les cambrioleurs. Inutilisable.
- **TLS 1.0** — serrure améliorée, mais un serrurier patient peut la crocheter
  (attaque BEAST, 2011).
- **TLS 1.1** — légèrement mieux, mais toujours crochetable avec les bons
  outils. Officiellement mise à la retraite en 2021.
- **TLS 1.2** — serrure moderne, solide si bien configurée (bons ciphers).
- **TLS 1.3** — serrure dernière génération. Plus rapide, forward secrecy
  intégré, les anciennes attaques sont structurellement impossibles.

---

## Timeline des protocoles et de leurs vulnérabilités

```
1996        1999        2006        2008        2018        2021
 │           │           │           │           │           │
SSLv3       TLS 1.0     TLS 1.1     TLS 1.2     TLS 1.3    RFC 8996
 │           │           │           │           │           │
 │           │           │           │           │       Dépréciation
 │           │           │           │           │       officielle
 │           │           │           │           │       TLS 1.0 + 1.1
 │           │           │           │           │
 ▼           ▼           ▼           ▼           ▼
POODLE      BEAST     Downgrade    Valide si   Aucune
2014        2011      attacks      bons        vulnéra-
CVE-2014    CVE-2011  (multiples)  ciphers     bilité
-3566       -3389                              connue
 │           │           │
 ✗           ✗           ✗           ✓           ✓
```

---

## Les deux attaques principales

### BEAST — TLS 1.0 (CVE-2011-3389)

```
TLS 1.0 utilise CBC (Cipher Block Chaining)
Chaque bloc chiffré dépend du bloc précédent.
Le vecteur d'initialisation du 1er bloc est PRÉVISIBLE.

  Bloc 1      Bloc 2      Bloc 3
  ┌──────┐    ┌──────┐    ┌──────┐
  │ IV   │──> │ IV   │──> │ IV   │
  │ fixe │    │=C(1) │    │=C(2) │
  └──────┘    └──────┘    └──────┘

Attaquant injecte des données calculées →
devine le contenu déchiffré bloc par bloc.
Comme résoudre des mots croisés lettre par lettre.
```

### POODLE — SSLv3 (CVE-2014-3566)

```
SSLv3 accepte un "padding" de longueur variable en fin de bloc.
L'attaquant force un downgrade vers SSLv3 (même si TLS disponible)
puis exploite le padding prévisible pour déchiffrer les cookies.

  Client          Attaquant        Serveur
    │   "Je veux TLS 1.2"  │          │
    │──────────────────────>│          │
    │                       │ "Erreur" │──> force retry
    │   "Je veux TLS 1.0"  │          │
    │──────────────────────>│          │
    │                       │ "Erreur" │──> force retry
    │   "Je veux SSLv3"    │          │
    │──────────────────────>│──────────>│ accepté
    │                       │          │
    │             Padding oracle → cookie déchiffré
```

---

## Ce que le scanner détecte

**Check** : `SslCheck` — Phase 5 du scanner

**Librairie** : `sslyze`

```python
# SSLyze teste chaque protocole en tentant un handshake
from sslyze import Scanner, ServerScanRequest
from sslyze.plugins.scan_commands import ScanCommand

# Résultat attendu après correction
{
    "ssl_2_0": {"result": "ok",    "message": "Non supporté"},
    "ssl_3_0": {"result": "ok",    "message": "Non supporté"},
    "tls_1_0": {"result": "ok",    "message": "Non supporté"},
    "tls_1_1": {"result": "ok",    "message": "Non supporté"},
    "tls_1_2": {"result": "ok",    "message": "Supporté"},
    "tls_1_3": {"result": "ok",    "message": "Supporté"},
}

# Résultat si TLS 1.0 encore actif
{
    "tls_1_0": {
        "result": "error",
        "message": "TLS 1.0 accepté — BEAST possible (CVE-2011-3389)"
    }
}
```

---

## La correction — nginx.conf

```nginx
http {
    # NE PAS écrire :
    # ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    #                ↑       ↑
    #                cassés depuis 2011 et 2006

    # Écrire :
    ssl_protocols TLSv1.2 TLSv1.3;
    #   TLSv1.2 → compatibilité avec navigateurs modernes
    #   TLSv1.3 → performance + forward secrecy natif

    # Préférer les ciphers du serveur (pas du client)
    ssl_prefer_server_ciphers on;
}
```

---

## Avant / Après

```
AVANT — config par défaut Ubuntu
────────────────────────────────────────────
ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;

SSL Labs : B (TLS 1.0/1.1 détectés)
SslCheck : 2 erreurs (tls_1_0, tls_1_1)

APRÈS — config corrigée
────────────────────────────────────────────
ssl_protocols TLSv1.2 TLSv1.3;

SSL Labs : A+
SslCheck : 0 erreur — 6/6 checks OK
```

---

## Pourquoi ne pas désactiver aussi TLS 1.2 ?

TLS 1.3 est idéal mais certains clients anciens (IE11, Java 8, Android < 5)
ne le supportent pas encore. TLS 1.2 avec de bons ciphers reste sûr.
Désactiver TLS 1.2 casse la compatibilité sans gain de sécurité mesurable.

---

## Références officielles

- **RFC 8996** (2021) — Deprecating TLS 1.0 and TLS 1.1
- **CVE-2011-3389** — BEAST attack on TLS 1.0
- **CVE-2014-3566** — POODLE attack on SSLv3
- **NIST SP 800-52** — Guidelines for TLS implementations
- **OWASP** — [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)