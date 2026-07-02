# Zone Transfer DNS (AXFR)

## En une phrase

Un zone transfer ouvert permet à n'importe qui de télécharger
l'intégralité des enregistrements DNS d'un domaine en une seule
requête — tous les sous-domaines, toutes les IPs, tout ce qui
est normalement découvert un enregistrement à la fois.

---

## L'analogie

Imagine l'annuaire téléphonique d'une entreprise. Normalement,
tu peux demander "quel est le numéro de Jean Dupont ?" — tu
obtiens une réponse précise. Mais si quelqu'un laisse la porte
du service RH ouverte, tu peux photocopier l'intégralité de
l'annuaire interne : tous les employés, tous les postes, tous
les services — y compris ceux qui ne sont pas censés être publics.

Le zone transfer AXFR, c'est la photocopieuse laissée ouverte.

---

## L'attaque — énumération complète

```
SANS protection AXFR
─────────────────────────────────────────────────────────────────

  Attaquant                    Serveur NS autoritaire
      │                              │
      │  AXFR ? exemple.fr           │
      │─────────────────────────────>│
      │                              │
      │  Tous les enregistrements :  │
      │                              │
      │  exemple.fr    A   203.0.113.10
      │  www           A   203.0.113.10
      │  app           A   203.0.113.11
      │  staging       A   203.0.113.12
      │  admin         A   203.0.113.13  ← non publié !
      │  api-interne   A   10.0.0.5      ← réseau interne !
      │  vpn           A   203.0.113.14  ← accès VPN !
      │  mail          MX  mail.exemple.fr
      │                              │
      │<─────────────────────────────│
      │                              │
  Attaquant a maintenant la carte complète
  de toute l'infrastructure — en une requête

AVEC protection AXFR
─────────────────────────────────────────────────────────────────

  Attaquant                    Serveur NS autoritaire
      │                              │
      │  AXFR ? exemple.fr           │
      │─────────────────────────────>│
      │                              │
      │           REFUSED            │
      │<─────────────────────────────│
      │                              │
  Rien. L'attaquant doit énumérer un
  sous-domaine à la fois — lent et incomplet.
```

> Les IPs 203.0.113.x sont réservées à la documentation par RFC 5737
> — elles n'appartiennent à personne et ne sont pas routables.

---

## Pourquoi AXFR existe

Le zone transfer est un mécanisme **légitime** entre serveurs DNS.
Quand tu as un serveur DNS primaire et un serveur DNS secondaire
(pour la redondance), le secondaire doit recevoir une copie complète
de la zone. C'est pour ça qu'AXFR existe.

Le problème : certains administrateurs oublient de restreindre AXFR
aux seuls serveurs DNS secondaires autorisés.

```
Utilisation légitime :
  NS primaire ──AXFR──> NS secondaire (IP autorisée)

Utilisation malveillante :
  Attaquant ────AXFR──> NS primaire (restriction oubliée)
```

---

## Ce que le scanner détecte

**Check** : `DnsCheck` — Phase 8 — `_check_axfr()`

```python
import dns.query
import dns.zone

# On va directement au serveur NS autoritaire
# (pas au résolveur local — il ne peut pas faire AXFR)
zone = dns.zone.from_xfr(
    dns.query.xfr(ns_ip, domain, timeout=3)
)

# Si on arrive ici → AXFR accepté → critique
records_count = len(list(zone.nodes.keys()))
return {
    "result": "error",
    "message": f"Zone transfer OUVERT — {records_count} enregistrements exposés",
    "severity": "CRITICAL"
}
```

---

## La correction

Sur le serveur DNS (BIND9, exemple) :

```bash
# /etc/bind/named.conf.options
options {
    # Refuser AXFR par défaut
    allow-transfer { none; };

    # Autoriser uniquement le NS secondaire si besoin
    # allow-transfer { 203.0.113.2; };
};
```

Sur un hébergeur DNS managé (OVH, Cloudflare...) :
Le zone transfer est désactivé par défaut — rien à faire.

---

## Vérification manuelle

```bash
# exemple.fr et ns1.dns-example.net sont fictifs
dig AXFR exemple.fr @ns1.dns-example.net

# Résultat si refusé (normal) :
# ; Transfer failed.

# Résultat si ouvert (problème) :
# exemple.fr.   3600  IN  SOA  ...
# www           300   IN  A    203.0.113.10
# admin         300   IN  A    203.0.113.13
# ...
```

---

## Références officielles

- **RFC 5936** — DNS Zone Transfer Protocol (AXFR)
- **RFC 5737** — IPv4 Address Blocks Reserved for Documentation
- **OWASP Testing Guide** — OTG-INFO-001 : Conduct Search Engine Discovery
- **CWE-200** — Exposure of Sensitive Information