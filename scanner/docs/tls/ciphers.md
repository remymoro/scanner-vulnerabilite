# Suites de chiffrement TLS (Cipher Suites)

## En une phrase

Une suite de chiffrement est une recette complète qui définit
comment deux machines s'accordent pour chiffrer leur conversation —
quel algorithme d'échange de clé, quel algorithme de chiffrement,
quel algorithme d'intégrité.

---

## L'analogie

Imagine deux diplomates qui doivent se parler en secret. Avant de
commencer, ils s'accordent sur :
1. Comment échanger leur clé secrète (par valise diplomatique ?
   par code Morse ?) → algorithme d'échange de clé
2. Quel code chiffré utiliser pour la conversation (César ?
   Enigma ? AES ?) → algorithme de chiffrement
3. Comment vérifier que le message n'a pas été altéré (sceau
   de cire ? signature ?) → algorithme d'intégrité

La suite de chiffrement, c'est le nom de l'accord complet :
"On fait échange par ECDH, chiffrement par AES-256, vérification
par SHA-384."

---

## Anatomie d'une suite de chiffrement

```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 │    │     │        │    │   │    │
 │    │     │        │    │   │    └── Intégrité : SHA-384
 │    │     │        │    │   └─────── Mode : GCM (authentifié)
 │    │     │        │    └─────────── Taille clé : 256 bits
 │    │     │        └──────────────── Chiffrement : AES
 │    │     └───────────────────────── Authentification serveur : RSA
 │    └─────────────────────────────── Échange de clé : ECDHE
 └──────────────────────────────────── Protocole : TLS
```

---

## Ce qui est bon vs ce qui est cassé

```
CASSÉ — ne jamais utiliser
─────────────────────────────────────────────────────────────────

RC4          → algorithme de flux cassé depuis 2013 (RFC 7465)
               bias statistique prévisible

DES / 3DES   → clé trop courte (56 bits DES), SWEET32 sur 3DES
               CVE-2016-2183

NULL         → pas de chiffrement du tout
               WTF

MD5 / SHA1   → fonctions de hachage cassées
               collisions trouvables

EXPORT       → chiffrement volontairement affaibli (40-56 bits)
               héritage de la guerre froide américaine
               FREAK attack (CVE-2015-0204)

CBC sans     → BEAST (TLS 1.0), Lucky13, POODLE
padding safe

ACCEPTABLE — avec les bons paramètres
─────────────────────────────────────────────────────────────────

AES-128-GCM  → solide, rapide, mode authentifié
AES-256-GCM  → plus fort, légèrement plus lent
ECDHE        → échange de clé avec forward secrecy

IDÉAL — TLS 1.3 uniquement
─────────────────────────────────────────────────────────────────

TLS_AES_128_GCM_SHA256         → rapide, sécurisé
TLS_AES_256_GCM_SHA384         → plus fort
TLS_CHACHA20_POLY1305_SHA256   → optimal sur mobile (CPU sans AES-NI)
```

---

## Forward Secrecy — le concept clé

```
SANS Forward Secrecy (RSA classique)
─────────────────────────────────────────────────────────────────

  Clé privée serveur → utilisée pour CHIFFRER la clé de session
  
  Attaquant enregistre tout le trafic chiffré aujourd'hui
  Dans 5 ans, vole la clé privée du serveur
  → Déchiffre TOUT le trafic passé rétroactivement
  
  Une seule clé compromise = tout l'historique exposé

AVEC Forward Secrecy (ECDHE)
─────────────────────────────────────────────────────────────────

  Chaque connexion génère une paire de clés ÉPHÉMÈRE
  La clé privée éphémère est détruite après la connexion
  
  Attaquant enregistre tout le trafic chiffré aujourd'hui
  Dans 5 ans, vole la clé privée du serveur
  → Ne peut RIEN déchiffrer — les clés éphémères n'existent plus
  
  E dans ECDHE = Ephemeral = éphémère = forward secrecy
```

---

## Ce que le scanner détecte

**Check** : `SslCheck` — Phase 5 — via SSLyze

```python
# SSLyze liste toutes les suites négociables
# On cherche les suites dangereuses

WEAK_CIPHERS = ["RC4", "DES", "NULL", "EXPORT", "MD5", "anon"]

for cipher in negotiated_ciphers:
    if any(weak in cipher.name for weak in WEAK_CIPHERS):
        return {
            "result": "error",
            "message": f"Cipher faible détecté : {cipher.name}"
        }

# Vérifier forward secrecy
if not any("ECDHE" in c.name or "DHE" in c.name
           for c in negotiated_ciphers):
    return {
        "result": "warning",
        "message": "Forward secrecy absent — historique déchiffrable si clé volée"
    }
```

---

## La correction Nginx

```nginx
# Laisser Certbot gérer via options-ssl-nginx.conf — il a de bonnes valeurs
# Si tu configures manuellement :

ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
            ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
            ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;

# Toutes commencent par ECDHE → forward secrecy garanti
# Toutes utilisent GCM ou POLY1305 → mode authentifié, pas CBC
# Aucune RC4, DES, NULL, EXPORT
```

---

## Références officielles

- **RFC 7465** — Prohibiting RC4 Cipher Suites (2015)
- **RFC 8446** — TLS 1.3 (définit les nouvelles suites)
- **CVE-2016-2183** — SWEET32 attack on 3DES
- **CVE-2015-0204** — FREAK attack (EXPORT ciphers)
- **NIST SP 800-52** — Guidelines for TLS implementations