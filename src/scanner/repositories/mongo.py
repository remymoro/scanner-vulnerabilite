"""
Repository MongoDB pour les rapports de scan.

C'est ta classe MongoRepositoryImpl du stage, avec deux différences :
1. Async (motor au lieu de pymongo) — ne bloque plus l'event loop
2. Implémente IReportRepository (interface spécifique) au lieu de
   IDatabaseRepository (interface générique)

motor est un wrapper async autour de pymongo. Même API, mêmes noms
de méthodes (find_one, update_one, etc.) — il suffit d'ajouter await.
"""

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from scanner.core.interfaces.report_repository import IReportRepository


class MongoReportRepository(IReportRepository):
    """
    Stockage persistant des rapports dans MongoDB.

    Les rapports restent en base indéfiniment — c'est l'historique.
    Contrairement à Redis (cache temporaire), MongoDB est la source
    de vérité à long terme.

    Pourquoi on reçoit la database en paramètre du constructeur
    plutôt que de créer la connexion ici ?
    → Inversion de contrôle (le I de SOLID). C'est le même principe
      que l'injection de dépendances en NestJS :
          constructor(@InjectModel('Report') private model: Model)
      La connexion est gérée ailleurs (database.py), ce repository
      ne fait que l'utiliser. Ça le rend testable : dans les tests,
      on lui passe une fausse database au lieu de la vraie.
    """

    def __init__(self, database: AsyncIOMotorDatabase) -> None:
        # On travaille sur une collection "reports" dans la base
        # C'est l'équivalent d'une table en SQL ou d'un Model en NestJS
        self.collection = database["reports"]

    async def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """
        Cherche un rapport par scan_id.

        Dans ton stage, tu cherchais par URL :
            find_one({"url": key})
        Ici on cherche par scan_id — plus précis, car la même URL
        peut être scannée plusieurs fois (scans différents).

        projection {"_id": 0} : exclut le champ _id de MongoDB
        du résultat. Le client n'a pas besoin de l'ObjectId interne.
        """
        document = await self.collection.find_one(
            {"scan_id": scan_id},
            {"_id": 0},
        )
        return document

    async def save_report(self, scan_id: str, report: dict[str, Any]) -> None:
        """
        Sauvegarde un rapport — insert ou update.

        upsert=True : si le scan_id existe déjà, on met à jour.
        Sinon, on insère un nouveau document.
        C'est exactement ton update_one avec upsert=True du stage.
        """
        await self.collection.update_one(
            {"scan_id": scan_id},
            {"$set": report},
            upsert=True,
        )

    async def exists(self, scan_id: str) -> bool:
        """
        Vérifie l'existence sans charger le document entier.
        count_documents avec limit=1 est plus rapide que find_one
        sur une grande collection.
        """
        count = await self.collection.count_documents(
            {"scan_id": scan_id},
            limit=1,
        )
        return count > 0
