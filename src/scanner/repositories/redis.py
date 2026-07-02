"""
Repository Redis — implémente IReportRepository ET ICacheRepository.

Pourquoi Redis fait deux choses à la fois ?
  Redis est déjà dans notre stack pour le cache. Les deux usages
  partagent les mêmes caractéristiques : en mémoire, rapide, TTL.
  Plutôt que d'ajouter un deuxième service, on exploite Redis pour
  ses deux forces naturelles.

La séparation est dans les INTERFACES, pas dans l'infrastructure :
  IReportRepository → "donne-moi un rapport par son scan_id"
  ICacheRepository  → "est-ce que ce domaine a été scanné récemment ?"

Ce sont deux questions différentes, deux contrats différents,
une seule implémentation concrète — Redis répond aux deux.

En NestJS/TypeScript, c'est exactement :
  class RedisRepo implements IReportRepository, ICacheRepository {}

En Python, héritage multiple :
  class RedisRepo(IReportRepository, ICacheRepository): ...

Flow complet avec les deux contrats :
  1. Scan request arrive pour "monsite.fr"
  2. ICacheRepository.get_scan("monsite.fr") → HIT ? retourne direct
  3. MISS → lance les checks réseau
  4. IReportRepository.save_report(scan_id, rapport) → historique 24h
  5. ICacheRepository.set_scan("monsite.fr", rapport) → cache 1h
"""

import json
from typing import Any

from redis.asyncio import Redis

from scanner.core.interfaces.cache_repository import ICacheRepository
from scanner.core.interfaces.report_repository import IReportRepository

# TTL long — les rapports sont conservés 24h pour consultation ultérieure
# Un utilisateur peut retrouver son scan de la matinée en fin de journée
REPORT_TTL_SECONDS = 86400

# TTL court — le cache anti-spam expire après 1h
# Assez long pour absorber le spam sur la même URL
# Assez court pour que les corrections d'un site soient détectées rapidement
SCAN_CACHE_TTL_SECONDS = 3600


class RedisReportRepository(IReportRepository, ICacheRepository):
    """
    Implémentation Redis des deux repositories.

    Deux familles de clés Redis, deux responsabilités distinctes :
      "report:{scan_id}" → rapport identifié par UUID unique
      "cache:{domain}"   → dernier scan du domaine, TTL court

    Exemple en redis-cli pour inspecter :
      KEYS report:*        → liste tous les rapports
      KEYS cache:*         → liste tous les domaines en cache
      TTL cache:monsite.fr → combien de secondes avant expiration
      GET cache:monsite.fr → voir le rapport mis en cache
    """

    def __init__(self, redis_client: Redis) -> None:
        # On injecte le client Redis plutôt que de le créer ici
        # → le client est partagé dans toute l'app (une seule connexion)
        # → en test, on peut injecter un faux client
        self.redis = redis_client

    # ── IReportRepository ────────────────────────────────────────────────
    # Ces méthodes répondent à la question :
    # "donne-moi un rapport précis par son identifiant unique"

    async def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """
        Récupère un rapport par son scan_id unique.

        Préfixe "report:" — convention de namespacing Redis.
        Si Redis est utilisé pour d'autres choses (sessions,
        rate-limiting, queues), les clés ne se mélangent pas.

        Retourne None si le rapport n'existe pas ou a expiré.
        Le consommateur doit toujours vérifier None avant d'utiliser.
        """
        data = await self.redis.get(f"report:{scan_id}")
        if data is None:
            return None
        # Redis stocke des bytes/strings — on désérialise le JSON
        return json.loads(data)

    async def save_report(self, scan_id: str, report: dict[str, Any]) -> None:
        """
        Sauvegarde un rapport avec TTL de 24h.

        setex = SET + EXpire en une seule commande ATOMIQUE.
        Pourquoi atomique ?
          Si l'app crashe entre un SET et un EXPIRE séparés,
          la clé reste en mémoire indéfiniment → fuite mémoire.
          setex garantit que TTL et valeur sont toujours cohérents.

        json.dumps → sérialise le dict en string JSON lisible
        L'alternative pickle serait plus rapide mais :
          - illisible avec redis-cli (debugging difficile)
          - vulnérable aux attaques de désérialisation si les données
            viennent d'une source non fiable
        """
        await self.redis.setex(
            f"report:{scan_id}",
            REPORT_TTL_SECONDS,
            json.dumps(report),
        )

    async def exists(self, scan_id: str) -> bool:
        """
        Vérifie si un rapport existe SANS le charger en mémoire.

        Plus efficace que get_report() quand on veut juste savoir
        si un scan a été fait — pas besoin de désérialiser le JSON.
        Redis.exists() retourne 0 (absent) ou 1 (présent).
        """
        result = await self.redis.exists(f"report:{scan_id}")
        return result > 0

    # ── ICacheRepository ─────────────────────────────────────────────────
    # Ces méthodes répondent à la question :
    # "est-ce que ce domaine a été scanné récemment ?"
    # Objectif : éviter de relancer un scan réseau coûteux si le
    # résultat est encore frais (< 1h)

    async def get_scan(self, domain: str) -> dict[str, Any] | None:
        """
        Récupère le dernier scan d'un domaine si encore valide.

        Préfixe "cache:" — distinct de "report:" pour clarté.
        La clé est le DOMAINE (stable), pas le scan_id (unique).
        Deux scans du même domaine partagent la même clé cache.

        Si le TTL a expiré, Redis retourne None automatiquement —
        pas besoin de vérifier la date manuellement.
        """
        data = await self.redis.get(f"cache:{domain}")
        if data is None:
            return None
        return json.loads(data)

    async def set_scan(
        self,
        domain: str,
        report: dict[str, Any],
        ttl_seconds: int = SCAN_CACHE_TTL_SECONDS,
    ) -> None:
        """
        Met en cache le résultat d'un scan pour 1h par défaut.

        TTL paramétrable — permet d'ajuster selon le contexte :
          set_scan(domain, report, ttl_seconds=300)   # 5 min en dev
          set_scan(domain, report, ttl_seconds=3600)  # 1h en prod
          set_scan(domain, report, ttl_seconds=86400) # 24h si rare

        Écrase silencieusement le cache existant si présent.
        setex remet le TTL à zéro — le compteur repart de 1h.
        """
        await self.redis.setex(
            f"cache:{domain}",
            ttl_seconds,
            json.dumps(report),
        )

    async def invalidate(self, domain: str) -> None:
        """
        Supprime le cache d'un domaine pour forcer un nouveau scan.

        Cas d'usage :
          - Le site vient d'être corrigé et l'utilisateur veut
            vérifier immédiatement sans attendre l'expiration du TTL
          - Un admin veut forcer un re-scan en dehors du cycle normal
          - Les tests automatisés doivent toujours lancer un vrai scan

        Redis.delete() est silencieux si la clé n'existe pas.
        Pas d'erreur si le cache était déjà vide.
        """
        await self.redis.delete(f"cache:{domain}")
