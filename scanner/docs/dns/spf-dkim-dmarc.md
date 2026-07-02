# SPF, DKIM, DMARC — protection contre l'email spoofing

## En une phrase

SPF, DKIM et DMARC sont trois couches de protection qui empêchent
un attaquant d'envoyer des emails qui semblent venir de ton domaine.

---

## L'analogie

Imagine que quelqu'un peut envoyer des lettres avec ton adresse
comme expéditeur — sans que la poste vérifie quoi que ce soit.
L'attaquant envoie "Bonjour, je suis votre banque,
cliquez ici" en se faisant passer pour toi.

- **SPF** : une liste officielle des facteurs autorisés à livrer
  tes lettres. Si ce n'est pas sur la liste → suspect.
- **DKIM** : une signature sur l'enveloppe, comme un sceau de cire.
  Le destinataire vérifie que la signature est authentique.
- **DMARC** : la politique si SPF ou DKIM échouent.
  "Si quelqu'un se fait passer pour moi → mets en spam / rejette."

---

## Les trois mécanismes

```
SPF — Sender Policy Framework
─────────────────────────────────────────────────────────────────

Enregistrement TXT sur test.fr :
"v=spf1 include:ovh.com ~all"
         │                │
         │                └── ~all = emails d'autres sources → suspect
         └────────────────── OVH est autorisé à envoyer pour nous

Serveur destinataire reçoit un email "de" remymoro.fr :
→ Vérifie le SPF : cet email vient-il d'un serveur OVH ?
→ OUI → légitime
→ NON → suspect / rejeté selon politique

DKIM — DomainKeys Identified Mail
─────────────────────────────────────────────────────────────────

Enregistrement TXT sur mail._domainkey.remymoro.fr :
"v=DKIM1; k=rsa; p=MIGfMA0GCSq..." (clé publique)

Serveur envoyeur signe l'email avec la clé PRIVÉE :
DKIM-Signature: v=1; a=rsa-sha256; d=test.fr; s=mail; ...

Serveur destinataire :
→ Récupère la clé publique via DNS
→ Vérifie la signature
→ OK → email authentique et non modifié en transit

DMARC — Domain-based Message Authentication
─────────────────────────────────────────────────────────────────

Enregistrement TXT sur _dmarc.test.fr :
"v=DMARC1; p=reject; rua=mailto:dmarc@test.fr"
             │                    │
             │                    └── Envoie-moi les rapports
             └────────────────────── Si SPF/DKIM échouent → rejeter

p=none     → surveiller seulement (mode audit)
p=quarantine → mettre en spam
p=reject   → rejeter complètement l'email
```

---

## L'attaque — email spoofing sans SPF/DMARC

```
SANS SPF/DKIM/DMARC
─────────────────────────────────────────────────────────────────

  Attaquant                              Victime
      │                                     │
      │  From: contact@test.fr          │
      │  "Votre compte est compromis,       │
      │   cliquez ici pour sécuriser"       │
      │────────────────────────────────────>│
      │                                     │
      │  Victime voit "test.fr"         │
      │  dans l'expéditeur → fait confiance │
      │  Clique sur le lien de phishing     │

AVEC SPF + DKIM + DMARC p=reject
─────────────────────────────────────────────────────────────────

  Attaquant                   Serveur mail victime
      │                              │
      │  From: contact@test.fr   │
      │  (envoyé depuis evil.com)    │
      │─────────────────────────────>│
      │                              │ Vérifie SPF : evil.com
      │                              │ n'est pas dans la liste
      │                              │ SPF de tsrt.fr
      │                              │
      │                              │ DMARC p=reject →
      │                              │ Email rejeté
      │                              │ Jamais livré
```

---

## Ce que le scanner détecte

**Check** : `DnsCheck` — Phase 8 — `_check_txt()`

```python
# SPF sur le domaine racine
spf_present = any("v=spf1" in r for r in records)

# DMARC sur _dmarc.domaine
try:
    dmarc = dns.resolver.resolve(f"_dmarc.{root_domain}", "TXT")
    dmarc_present = True
except:
    dmarc_present = False

if not spf_present:
    return {"result": "error", "message": "SPF absent — spoofing possible"}

if not dmarc_present:
    return {"result": "warning", "message": "DMARC absent — politique de rejet manquante"}

return {"result": "ok", "message": "SPF et DMARC configurés"}
```

---

## La correction — enregistrements à ajouter

```dns
# Dans ta zone DNS (panel OVH, Cloudflare...)

# SPF — qui peut envoyer des emails pour ton domaine
remymoro.fr.  TXT  "v=spf1 include:ovh.com ~all"

# DMARC — que faire si SPF/DKIM échouent
_dmarc.test.fr.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@test.fr"
```

---

## Références officielles

- **RFC 7208** — Sender Policy Framework (SPF)
- **RFC 6376** — DomainKeys Identified Mail (DKIM)
- **RFC 7489** — DMARC
- **OWASP** — Email Security Best Practices