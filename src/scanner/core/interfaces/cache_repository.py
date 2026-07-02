from abc import ABC, abstractmethod
from typing import Any


class ICacheRepository(ABC):
    """
    Contrat pour le cache de résultats de scan par domaine.

    Séparé de IReportRepository parce que c'est une responsabilité
    différente : éviter de relancer un scan récent, pas stocker
    un rapport permanent.

    Seul Redis implémente cette interface — MongoDB n'a pas de TTL
    natif et n'est pas conçu pour du cache court terme.
    """

    @abstractmethod
    async def get_scan(self, domain: str) -> dict[str, Any] | None:
        """
        Récupère le dernier scan d'un domaine si encore valide.
        Retourne None si absent ou expiré.
        """
        ...

    @abstractmethod
    async def set_scan(self, domain: str, report: dict[str, Any], ttl_seconds: int = 3600) -> None:
        """
        Met en cache le résultat d'un scan pour une durée limitée.
        TTL par défaut : 1 heure.
        """
        ...

    @abstractmethod
    async def invalidate(self, domain: str) -> None:
        """
        Invalide le cache d'un domaine manuellement.
        Utile si on veut forcer un nouveau scan.
        """
        ...
