# X-Frame-Options

## En une phrase

X-Frame-Options dit au navigateur : "refuse d'afficher cette page dans
une iframe — personne ne peut l'encadrer dans un autre site."

---

## L'analogie

Imagine une vitre sans tain dans un magasin. Un escroc colle une fausse
devanture devant la vraie vitrine — les clients croient appuyer sur les
boutons du vrai magasin, mais ils appuient en réalité sur les boutons
de l'escroc, superposés par-dessus.

C'est exactement le clickjacking : ton site est chargé dans une iframe
invisible par-dessus un autre site. L'utilisateur croit cliquer sur
"Télécharger la chanson gratuite" mais clique en réalité sur
"Confirmer le virement bancaire" sur ton site, rendu invisible.

---

## L'attaque — Clickjacking

```
SANS X-Frame-Options
─────────────────────────────────────────────────────────────────

  Site de l'attaquant (concours-gratuit.com)
  ┌─────────────────────────────────────────────┐
  │  FÉLICITATIONS ! Vous avez gagné !          │
  │                                             │
  │  ┌─────────────────────────────────────┐   │
  │  │  [Cliquez ici pour réclamer]        │   │  ← bouton visible
  │  └─────────────────────────────────────┘   │
  │                                             │
  │  ╔═════════════════════════════════════╗   │
  │  ║  iframe invisible (opacity: 0)      ║   │
  │  ║  https://mabanque.fr/virement       ║   │  ← ton site chargé
  │  ║  [Confirmer le virement de 500€]    ║   │     par-dessus
  │  ╚═════════════════════════════════════╝   │
  └─────────────────────────────────────────────┘

  L'utilisateur connecté à sa banque clique sur
  "réclamer son cadeau" → clique en réalité sur
  "Confirmer le virement" dans l'iframe invisible.

AVEC X-Frame-Options: DENY
─────────────────────────────────────────────────────────────────

  Le navigateur refuse de charger mabanque.fr dans l'iframe.
  L'attaque est impossible — la page ne s'affiche jamais dans
  une iframe, peu importe le site qui essaie.
```

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4 du scanner

```python
response.headers.get("X-Frame-Options")

# Absent → erreur
{ "result": "error", "message": "Clickjacking possible" }

# Présent mais valeur incorrecte
{ "result": "warning", "message": "Valeur non reconnue" }

# Correct
{ "result": "ok", "value": "DENY" }
```

---

## La correction

```nginx
# DENY    — personne ne peut encadrer ce site (recommandé)
# SAMEORIGIN — seulement ton propre domaine peut l'encadrer
add_header X-Frame-Options "DENY" always;
```

Choisis `DENY` sauf si ton app a besoin d'être intégrée dans une iframe
sur ton propre domaine (ex: un widget embarqué).

Note : `X-Frame-Options` est remplacé progressivement par la directive
`frame-ancestors` dans la CSP — mais les deux ensemble assurent une
compatibilité maximale avec les vieux navigateurs.

---

## Avant / Après

```
AVANT
$ curl -I https://monsite.fr | grep -i frame
(rien)                         ← iframe possible depuis n'importe où

APRÈS
$ curl -I https://monsite.fr | grep -i frame
x-frame-options: DENY          ← iframe refusée par le navigateur
```

---

## Références officielles

- **OWASP** — [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- **MDN Web Docs** — [X-Frame-Options](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Frame-Options)
- **CWE-1021** — Improper Restriction of Rendered UI Layers