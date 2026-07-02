# Referrer-Policy

## En une phrase

La Referrer-Policy contrôle ce que le navigateur révèle de l'URL
de ta page quand un utilisateur clique sur un lien vers un autre site.

---

## L'analogie

Quand tu passes d'une pièce à une autre dans un hôtel, tu peux soit
dire à l'hôtesse "je viens de la chambre 412" (referrer complet), soit
juste "je viens de cet hôtel" (origine seulement), soit ne rien dire
du tout. Sans politique définie, le navigateur dit tout — y compris
des informations qui ne devraient pas quitter ton site.

---

## L'attaque — fuite d'URL sensibles

```
SANS Referrer-Policy
─────────────────────────────────────────────────────────────────

  Utilisateur est sur :
  https://monsite.fr/admin/rapport?token=abc123&user=dupont
  
  Il clique sur un lien externe (pub, ressource tierce, image CDN)
  
  Navigateur envoie automatiquement :
  Referer: https://monsite.fr/admin/rapport?token=abc123&user=dupont
            ↑
            Le site externe reçoit le token et le nom d'utilisateur
            dans ses logs serveur — gratuitement
  
  Attaquant qui contrôle ce site externe →
  collecte les tokens → usurpe les sessions

AVEC Referrer-Policy: strict-origin-when-cross-origin
─────────────────────────────────────────────────────────────────

  Même situation — clic sur lien externe
  
  Navigateur envoie :
  Referer: https://monsite.fr
            ↑
            Seulement l'origine (domaine) — jamais le chemin,
            jamais les paramètres, jamais les tokens
```

---

## Les valeurs disponibles

```
no-referrer
  → N'envoie jamais rien. Très restrictif, peut casser
    certaines analytics.

no-referrer-when-downgrade (ancien défaut navigateurs)
  → Envoie tout en HTTPS→HTTPS, rien en HTTPS→HTTP.
    Fuite entre sites HTTPS.

origin
  → Envoie seulement le domaine (https://monsite.fr)
    jamais le chemin.

strict-origin-when-cross-origin  ← RECOMMANDÉ
  → Même domaine : envoie tout (utile pour analytics internes)
  → Domaine différent : envoie seulement l'origine
  → HTTP depuis HTTPS : n'envoie rien
  Bon équilibre sécurité / compatibilité.

same-origin
  → Envoie tout sur le même domaine, rien vers l'extérieur.

no-referrer / strict-origin
  → Options les plus restrictives, pour données très sensibles.
```

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4

```python
rp = response.headers.get("Referrer-Policy")

if not rp:
    return {
        "result": "error",
        "message": "Referrer-Policy absent — URLs sensibles potentiellement exposées"
    }

# Valeurs dangereuses
dangerous = ["unsafe-url", "no-referrer-when-downgrade"]
if rp.lower() in dangerous:
    return {
        "result": "warning",
        "message": f"Valeur trop permissive : {rp}"
    }

return {"result": "ok", "value": rp}
```

---

## La correction Nginx

```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
#                            │
#                            └── Recommandé par MDN et OWASP
#                                Bon équilibre sécurité/compatibilité
```

---

## Avant / Après

```
AVANT — utilisateur clique sur lien externe
Referer: https://monsite.fr/dashboard?session=xyz&admin=true
← token et paramètres visibles dans les logs du site externe

APRÈS — avec strict-origin-when-cross-origin
Referer: https://monsite.fr
← seulement le domaine, jamais le chemin ni les paramètres
```

---

## Références officielles

- **MDN Web Docs** — [Referrer-Policy](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Referrer-Policy)
- **W3C** — [Referrer Policy Specification](https://www.w3.org/TR/referrer-policy/)
- **OWASP** — [Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- **CWE-116** — Improper Encoding or Escaping of Output