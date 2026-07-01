"""
Repository Redis pour le cache des rapports de scan.

Redis est le premier endroit où on cherche un rapport — si il est là,
on le retourne immédiatement sans toucher MongoDB. Comme dans ton stage.

Différence clé avec MongoDB :
- Redis = en mémoire, ultra-rapide, mais données TEMPORAIRES (TTL 24h)
- MongoDB = sur disque, plus lent, mais données PERMANENTES

Le flow sera (Phase 6) :
  1. Client demande un rapport
  2. On cherche dans Redis → trouvé ? On retourne direct
  3. Pas dans Redis → on cherche dans MongoDB
  4. Pas dans MongoDB → on lance un nouveau scan
"""

import json
from typing import Any

from redis.asyncio import Redis

from scanner.core.interfaces.report_repository import IReportRepository

# 24 heures en secondes — durée de vie d'un rapport en cache
# Après ça, Redis le supprime automatiquement et le prochain
# accès ira chercher dans MongoDB (ou relancera un scan)
CACHE_TTL_SECONDS = 86400


class RedisReportRepository(IReportRepository):
    """
    Cache des rapports dans Redis avec expiration automatique.

    Pourquoi JSON et pas pickle/msgpack ?
    → Redis stocke des strings (ou bytes). On doit sérialiser
      nos dicts Python en quelque chose de stockable.
      JSON est lisible (tu peux inspecter le cache avec redis-cli),
      standard, et suffisant pour nos rapports.
      pickle serait plus rapide mais illisible et dangereux
      (vulnérable aux attaques de désérialisation).
    """

    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    async def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """
        Récupère un rapport depuis le cache Redis.

        La clé est préfixée "report:" pour éviter les collisions
        si Redis est utilisé pour autre chose plus tard
        (sessions, rate-limiting, etc.)
        """
        data = await self.redis.get(f"report:{scan_id}")
        if data is None:
            return None
        return json.loads(data)

    async def save_report(self, scan_id: str, report: dict[str, Any]) -> None:
        """
        Sauvegarde un rapport dans le cache avec un TTL de 24h.

        setex = SET + EXpire en une seule opération atomique.
        Pas besoin de faire set() puis expire() séparément —
        si l'app crashe entre les deux, tu aurais un rapport
        sans expiration qui resterait en mémoire pour toujours.
        """
        await self.redis.setex(
            f"report:{scan_id}",
            CACHE_TTL_SECONDS,
            json.dumps(report),
        )

    async def exists(self, scan_id: str) -> bool:
        """
        Vérifie si un rapport existe dans le cache.
        Redis.exists() retourne le nombre de clés trouvées (0 ou 1).
        """
        result = await self.redis.exists(f"report:{scan_id}")
        return result > 0
