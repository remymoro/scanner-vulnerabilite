# Heartbleed — CVE-2014-0160

## En une phrase

Heartbleed permettait à n'importe qui de lire 64 Ko de mémoire vive
d'un serveur OpenSSL à chaque requête — clés privées, mots de passe,
cookies de session, tout ce qui passait par le serveur.

---

## L'analogie

Imagine que tu travailles dans une bibliothèque. Un lecteur s'approche
et dit : "Répète-moi ce mot : BONJOUR — 500 lettres." Tu répètes
"BONJOUR" mais tu continues à lire ce qu'il y a autour dans ta mémoire
pour compléter jusqu'à 500 caractères. Sans le vouloir, tu lis à voix
haute les notes confidentielles posées sur le bureau à côté.

C'est exactement Heartbleed — le serveur répond à une requête de
"validation de connexion" en lisant plus de mémoire qu'il ne devrait,
et renvoie ce surplus à l'attaquant.

---

## L'attaque — lecture de mémoire serveur

```
PROTOCOLE HEARTBEAT (normal)
─────────────────────────────────────────────────────────────────

  Client                              Serveur
    │                                    │
    │  "Je t'envoie BONJOUR (7 lettres)" │
    │───────────────────────────────────>│
    │                                    │
    │  "Répète-moi BONJOUR (7 lettres)"  │
    │<───────────────────────────────────│
    │                                    │
    Connexion toujours vivante — normal

HEARTBLEED (CVE-2014-0160)
─────────────────────────────────────────────────────────────────

  Attaquant                           Serveur OpenSSL vulnérable
    │                                    │
    │  "Je t'envoie A (1 lettre)         │
    │   mais réponds-moi 65535 lettres"  │
    │───────────────────────────────────>│
    │                                    │  Lit 1 lettre dans le buffer
    │                                    │  + 65534 octets de mémoire RAM
    │                                    │  adjacente (clés, mots de passe,
    │                                    │  tokens de session...)
    │   A + [64 Ko de RAM du serveur]    │
    │<───────────────────────────────────│
    │                                    │
    Répéter indéfiniment → vider la mémoire
```

---

## Pourquoi c'était si grave

Heartbleed a été découvert en avril 2014 et existait depuis **2011**
dans OpenSSL. Pendant 2 ans, n'importe quel serveur HTTPS vulnérable
pouvait être lu silencieusement — sans laisser de trace dans les logs
parce que c'était une requête légitime du protocole TLS.

Les données exposées incluaient :
- Les clés privées SSL → permet d'usurper le certificat du serveur
- Les cookies de session → usurpation d'identité d'utilisateurs connectés
- Les mots de passe en clair transitant par le serveur
- Tout autre secret en mémoire RAM au moment de l'attaque

---

## Ce que le scanner détecte

**Check** : `SslCheck` — Phase 5

**Librairie** : `sslyze`

```python
# SSLyze teste Heartbleed via ScanCommand.HEARTBLEED
from sslyze.plugins.scan_commands import ScanCommand

# Le résultat indique si le serveur répond aux requêtes Heartbleed
heartbleed_result = getattr(
    scan_result.scan_result,
    ScanCommand.HEARTBLEED.value,
    None
)

if heartbleed_result and heartbleed_result.is_vulnerable_to_heartbleed:
    return {
        "result": "error",
        "message": "Serveur vulnérable à Heartbleed — CVE-2014-0160",
        "severity": "CRITICAL"
    }

return {
    "result": "ok",
    "message": "Non vulnérable à Heartbleed"
}
```

---

## La correction

Mettre à jour OpenSSL vers une version >= 1.0.1g (patch de 2014).
Sur Ubuntu :

```bash
sudo apt update && sudo apt upgrade openssl
openssl version  # vérifier : doit être >= 1.0.1g
```

Nginx utilise OpenSSL du système — mettre à jour OpenSSL suffit.

---

## Avant / Après

```
AVANT — OpenSSL < 1.0.1g
$ sslyze --heartbleed tezst.test.fr
→ VULNERABLE - Server is vulnerable to Heartbleed

APRÈS — OpenSSL patché
$ sslyze --heartbleed test.test.fr
→ OK - Not vulnerable to Heartbleed
```

---

## Références officielles

- **CVE-2014-0160** — National Vulnerability Database
- **heartbleed.com** — site officiel de divulgation
- **RFC 6520** — TLS/DTLS Heartbeat Extension (le mécanisme exploité)
- **CVSS Score** : 7.5 (HIGH) — accès réseau, sans authentification