"""
HeadersCheck — vérifie les en-têtes de sécurité HTTP.

C'est la version améliorée de ton HttpScanner du stage.
Différences clés :
  - Hérite de BaseCheck (au lieu de IScannerInterface)
  - Async (httpx au lieu de requests)
  - Retourne un CheckResult typé (au lieu d'un dict)
  - Chaque header est documenté avec l'attaque qu'il bloque

Références :
  - OWASP Secure Headers : https://owasp.org/www-project-secure-headers/
  - MDN HTTP Headers : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
"""

import httpx

from scanner.core.entities.check_result import (
    CheckDetail,
    CheckResult,
    Severity,
    Status,
)
from scanner.core.interfaces.base_check import BaseCheck

# Les 6 headers de sécurité essentiels — ta liste headers_to_include du stage.
# Chaque tuple : (nom du header, description de l'attaque qu'il bloque)
SECURITY_HEADERS = [
    (
        "Content-Security-Policy",
        "Bloque les attaques XSS en contrôlant quelles sources de scripts "
        "le navigateur est autorisé à exécuter. Sans ce header, un attaquant "
        "peut injecter du JavaScript dans un commentaire ou un champ de recherche.",
    ),
    (
        "Strict-Transport-Security",
        "Force le navigateur à utiliser HTTPS pour toutes les requêtes futures. "
        "Sans ce header, un attaquant sur le même réseau Wi-Fi peut rediriger "
        "le trafic vers HTTP et intercepter les mots de passe (attaque MITM).",
    ),
    (
        "X-Frame-Options",
        "Empêche le site d'être affiché dans une iframe. Sans ce header, "
        "un attaquant peut superposer un bouton invisible sur le site et "
        "piéger l'utilisateur pour qu'il clique dessus (clickjacking).",
    ),
    (
        "X-Content-Type-Options",
        "Empêche le navigateur de deviner le type MIME d'un fichier. "
        "Sans ce header, un fichier uploadé déguisé en image peut être "
        "exécuté comme du JavaScript (MIME sniffing).",
    ),
    (
        "Referrer-Policy",
        "Contrôle quelles informations d'URL sont envoyées quand "
        "l'utilisateur clique sur un lien vers un autre site. Sans ce header, "
        "des tokens ou IDs sensibles dans l'URL peuvent fuiter vers des tiers.",
    ),
    (
        "Permissions-Policy",
        "Restreint l'accès aux fonctionnalités sensibles du navigateur "
        "(caméra, micro, géolocalisation). Sans ce header, un script tiers "
        "inclus sur le site pourrait activer la webcam de l'utilisateur.",
    ),
]


class HeadersCheck(BaseCheck):
    """
    Vérifie la présence des en-têtes de sécurité HTTP.

    Comment ça marche :
    1. Envoie une requête HTTP vers l'URL cible
    2. Récupère les en-têtes de la réponse
    3. Pour chaque header de sécurité, vérifie s'il est présent
    4. Calcule un score : (headers présents / headers total) × 100
    5. Retourne un CheckResult avec le détail de chaque header

    C'est ta méthode scan_category() du stage, mais avec :
    - Le scoring intégré (pas de calculate_score() séparé)
    - Des descriptions d'attaque pour chaque header manquant
    - Un timeout pour ne pas bloquer le scan si le site ne répond pas
    """

    @property
    def name(self) -> str:
        return "HTTP Security Headers"

    @property
    def severity(self) -> str:
        return Severity.HIGH

    async def run(self, url: str) -> CheckResult:
        """
        Lance la vérification des headers sur l'URL cible.

        Pourquoi httpx et pas requests ?
        → requests est synchrone — il bloque l'event loop pendant
          toute la durée de la requête. httpx est async-native :
          pendant qu'on attend la réponse du serveur, l'event loop
          peut traiter d'autres scans en parallèle.

        Pourquoi un timeout de 10 secondes ?
        → Sans timeout, un serveur qui ne répond pas bloquerait le
          scan indéfiniment. 10s est un bon compromis : assez long
          pour les serveurs lents, assez court pour ne pas paralyser
          l'orchestrateur.
        """
        details: list[CheckDetail] = []

        try:
            async with httpx.AsyncClient(
                # follow_redirects : suit les 301/302 pour analyser
                # la vraie page finale, pas la page de redirection
                follow_redirects=True,
                timeout=10.0,
                # verify=True : vérifie le certificat SSL
                # (on ne veut pas se connecter à un faux site)
                verify=True,
            ) as client:
                response = await client.get(url)

            # Analyse chaque header de sécurité
            for header_name, attack_description in SECURITY_HEADERS:
                header_value = response.headers.get(header_name)

                if header_value is not None:
                    # Header présent — le site est protégé contre cette attaque
                    details.append(
                        CheckDetail(
                            name=header_name,
                            status=Status.OK,
                            value=header_value,
                            description=f"Présent : {attack_description}",
                        )
                    )
                else:
                    # Header absent — le site est vulnérable
                    details.append(
                        CheckDetail(
                            name=header_name,
                            status=Status.FAIL,
                            value=None,
                            description=f"Manquant : {attack_description}",
                        )
                    )

        except httpx.TimeoutException:
            # Le serveur n'a pas répondu dans les 10 secondes
            return CheckResult(
                check_name=self.name,
                severity=self.severity,
                score=0,
                grade="F",
                details=[
                    CheckDetail(
                        name="Connection",
                        status=Status.FAIL,
                        description=f"Timeout après 10s en contactant {url}",
                    )
                ],
            )
        except httpx.RequestError as exc:
            # Erreur réseau (DNS, connexion refusée, etc.)
            return CheckResult(
                check_name=self.name,
                severity=self.severity,
                score=0,
                grade="F",
                details=[
                    CheckDetail(
                        name="Connection",
                        status=Status.FAIL,
                        description=f"Erreur réseau : {exc}",
                    )
                ],
            )

        # Calcul du score : pourcentage de headers présents
        # C'est ton calculate_score() du stage, simplifié
        total = len(SECURITY_HEADERS)
        present = sum(1 for d in details if d.status == Status.OK)
        score = int((present / total) * 100)

        return CheckResult(
            check_name=self.name,
            severity=self.severity,
            score=score,
            grade=CheckResult.compute_grade(score),
            details=details,
        )
