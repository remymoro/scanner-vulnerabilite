"""
Interface abstraite BaseCheck — le contrat commun à tous les scanners.

C'est la version améliorée de ton IScannerInterface du stage.
Différences clés :
  - run() est async (non-bloquant pour l'event loop FastAPI)
  - Retourne un CheckResult typé, pas un dict
  - Pas de calculate_score() séparé : chaque check le gère en interne

En Python, on utilise ABC (Abstract Base Class) pour créer une interface.
L'équivalent NestJS serait une interface TypeScript ou une classe abstraite :

    // NestJS
    export abstract class BaseCheck {
        abstract run(url: string): Promise<CheckResult>;
        abstract get name(): string;
    }

    # Python
    class BaseCheck(ABC):
        @abstractmethod
        async def run(self, url: str) -> CheckResult: ...
"""

from abc import ABC, abstractmethod

from scanner.core.entities.check_result import CheckResult


class BaseCheck(ABC):
    """
    Contrat que chaque scanner de sécurité doit respecter.

    Pourquoi ABC et pas Protocol ?

    Python offre deux façons de définir un contrat :
    - ABC (Abstract Base Class) → héritage explicite, Python lève une
      TypeError si tu oublies d'implémenter une méthode abstraite.
      C'est comme "implements" en Java/TypeScript.
    - Protocol (duck typing) → pas d'héritage requis, n'importe quelle
      classe qui a les bonnes méthodes est acceptée. Plus flexible,
      mais aucune erreur si tu oublies une méthode — ça casse au runtime.

    On choisit ABC parce que dans un scanner de sécurité, on veut que
    l'oubli d'une méthode soit détecté le plus tôt possible — à
    l'instanciation, pas au milieu d'un scan en production.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Nom lisible du check, affiché dans le rapport.
        Exemples : "HTTP Security Headers", "SSL/TLS Configuration"

        Pourquoi une @property et pas un attribut de classe ?
        → Parce qu'on veut FORCER chaque sous-classe à le définir.
          Un attribut de classe peut être oublié silencieusement.
          Une @property @abstractmethod lève TypeError si elle manque.
        """
        ...

    @property
    @abstractmethod
    def severity(self) -> str:
        """
        Sévérité par défaut du check (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        Détermine l'urgence dans le rapport final.
        """
        ...

    @abstractmethod
    async def run(self, url: str) -> CheckResult:
        """
        Lance le scan sur l'URL cible et retourne un CheckResult.

        Pourquoi async ?
        → Chaque check fait des appels réseau (HTTP, TLS handshake).
          En synchrone, un scan SSL de 5 secondes bloquerait tout le
          serveur FastAPI — aucun autre utilisateur ne pourrait lancer
          de scan pendant ce temps.
          En async, pendant que le check attend la réponse réseau,
          l'event loop peut traiter d'autres requêtes.

        C'est la même logique qu'en NestJS :
          async run(url: string): Promise<CheckResult>

        L'URL est toujours normalisée (https://, sans slash final)
        avant d'arriver ici — ce n'est pas la responsabilité du check.
        """
        ...