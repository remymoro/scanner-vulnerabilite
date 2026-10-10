"""
Interface du flux d'événements d'un scan.

Le worker PUBLIE les événements (check_complete, scan_complete...) et
l'API les LIT pour les renvoyer en SSE. Les deux ne se parlent jamais
directement : le flux est le seul point de contact, ce qui permet au scan
de survivre à la déconnexion du client.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

# Événements après lesquels il n'y a plus rien à lire.
TERMINAL_EVENTS = frozenset({"scan_complete", "scan_error"})


@dataclass(frozen=True)
class StreamEvent:
    id: str
    event: str
    data: dict[str, Any]


class IScanEventStream(ABC):
    @abstractmethod
    async def publish(self, scan_id: str, event: str, data: dict[str, Any]) -> str:
        """Ajoute un événement au flux du scan et retourne son identifiant."""

    @abstractmethod
    async def read(
        self, scan_id: str, last_id: str = "0-0", block_ms: int = 15000
    ) -> list[StreamEvent]:
        """
        Retourne les événements postérieurs à `last_id`.
        Attend jusqu'à `block_ms` s'il n'y en a pas encore ; liste vide si rien n'arrive.
        """
