# X-Content-Type-Options

## En une phrase

`X-Content-Type-Options: nosniff` dit au navigateur : "fais confiance
au type de fichier déclaré par le serveur — n'essaie pas de deviner
toi-même ce que c'est."

---

## L'analogie

Imagine un douanier qui reçoit un colis étiqueté "livres". Sans
instruction, il ouvre le colis pour vérifier lui-même ce qu'il
contient — et si ça ressemble à autre chose, il le traite
différemment. Un attaquant peut exploiter ça en envoyant un colis
étiqueté "image" qui contient en réalité un script.

Avec `nosniff`, le douanier applique l'étiquette sans vérifier le
contenu — si le serveur dit "c'est une image", le navigateur la
traite comme une image, même si elle contient du JavaScript.

---

## L'attaque — MIME Sniffing

```
SANS X-Content-Type-Options
─────────────────────────────────────────────────────────────────

  Attaquant uploade un fichier "photo.jpg" qui contient :
  
  ÿØÿà (header JPEG valide)
  ...
  <script>document.cookie = "stolen=" + document.cookie</script>
  
  Serveur sert le fichier avec : Content-Type: image/jpeg
  
  Navigateur sans nosniff :
  → "Hmm, ça ressemble à du JavaScript en fait..."
  → Exécute le contenu comme du JS
  → Cookie volé

AVEC X-Content-Type-Options: nosniff
─────────────────────────────────────────────────────────────────

  Même fichier "photo.jpg" avec JS caché
  
  Serveur sert : Content-Type: image/jpeg
  Header présent : X-Content-Type-Options: nosniff
  
  Navigateur :
  → "Le serveur dit image/jpeg → je traite comme une image"
  → Affiche une image corrompue, n'exécute rien
  → Attaque bloquée
```

---

## Ce que le scanner détecte

**Check** : `HeadersCheck` — Phase 4

```python
xcto = response.headers.get("X-Content-Type-Options")

if not xcto:
    return {
        "result": "error",
        "message": "MIME sniffing possible — X-Content-Type-Options absent"
    }

if xcto.lower() != "nosniff":
    return {
        "result": "warning",
        "message": f"Valeur incorrecte : {xcto} — attendu : nosniff"
    }

return {"result": "ok", "value": "nosniff"}
```

---

## La correction Nginx

```nginx
# Une seule valeur possible — nosniff
add_header X-Content-Type-Options "nosniff" always;
```

---

## Avant / Après

```
AVANT
$ curl -I https://monsite.fr | grep -i content-type-options
(rien) ← navigateur peut deviner et réinterpréter les types

APRÈS
$ curl -I https://monsite.fr | grep -i content-type-options
x-content-type-options: nosniff
← navigateur respecte strictement le Content-Type déclaré
```

---

## Références officielles

- **MDN Web Docs** — [X-Content-Type-Options](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/X-Content-Type-Options)
- **OWASP** — [MIME Sniffing](https://owasp.org/www-community/attacks/MIME_sniffing)
- **CWE-430** — Deployment of Wrong Handler