"""
Interface abstraite pour les repositories de données.

C'est exactement ton IDatabaseRepository du stage — mêmes méthodes
(get, set, delete) — mais en async.

En NestJS/DDD, c'est un port dans domain/ports/ :
    export abstract class IDatabaseRepository {
        abstract get(key: string): Promise<any>;
        abstract set(key: string, value: any): Promise<void>;
    }

La règle d'or : cette interface vit dans core/ — elle ne connaît
ni MongoDB, ni Redis, ni aucune technologie de stockage.
"""

from abc import ABC, abstractmethod
from typing import Any


class IReportRepository(ABC):
    """
    Contrat pour le stockage et la récupération des rapports de scan.

    Pourquoi IReportRepository et pas IDatabaseRepository ?
    → Dans ton stage, IDatabaseRepository était trop générique
      (get/set/delete/update/get_all pour n'importe quoi).
      Ici on nomme l'interface par sa RESPONSABILITÉ métier :
      stocker et récupérer des rapports. Si demain on a besoin
      d'un repository pour les utilisateurs, on crée IUserRepository
      avec ses propres méthodes — pas une interface fourre-tout.

    C'est le principe Interface Segregation de SOLID : des interfaces
    petites et spécifiques plutôt qu'une grosse interface universelle.
    """

    @abstractmethod
    async def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """
        Récupère un rapport par son scan_id.
        Retourne None si le rapport n'existe pas.
        """
        ...

    @abstractmethod
    async def save_report(self, scan_id: str, report: dict[str, Any]) -> None:
        """
        Sauvegarde ou met à jour un rapport.
        Si le rapport existe déjà (même scan_id), il est écrasé.
        """
        ...

    @abstractmethod
    async def exists(self, scan_id: str) -> bool:
        """
        Vérifie si un rapport existe sans le charger entièrement.
        Plus rapide que get_report() quand on veut juste savoir
        si un scan a déjà été fait.
        """
        ...
