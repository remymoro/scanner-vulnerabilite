"""
Gestionnaire de connexions aux bases de données.

C'est ton DatabaseManager Singleton du stage, simplifié.

Pourquoi plus de Singleton explicite ?
→ Dans ton stage, le Singleton garantissait une seule instance
  des connexions. Ici, le lifespan de FastAPI fait ce travail :
  il crée les connexions au démarrage (une seule fois) et les
  ferme à l'arrêt. Pas besoin de mécanique Singleton en plus.

On stocke les clients et repositories dans app.state — un
dictionnaire attaché à l'instance FastAPI, accessible partout
via la requête. C'est l'équivalent du container d'injection
de dépendances en NestJS.
"""

from motor.motor_asyncio import AsyncIOMotorClient
from redis.asyncio import Redis

from scanner.infrastructure.config import settings
from scanner.repositories.mongo import MongoReportRepository
from scanner.repositories.redis import RedisReportRepository


async def init_databases() -> tuple[MongoReportRepository, RedisReportRepository]:
    """
    Ouvre les connexions et crée les repositories.

    Retourne un tuple (mongo_repo, redis_repo) prêt à l'emploi.
    Appelé une seule fois au démarrage dans le lifespan.
    """
    # --- MongoDB ---
    # AsyncIOMotorClient ne se connecte pas immédiatement — il est
    # "lazy". La vraie connexion se fait au premier appel.
    mongo_client = AsyncIOMotorClient(settings.mongo_url)
    mongo_db = mongo_client[settings.mongo_db]
    mongo_repo = MongoReportRepository(mongo_db)

    # --- Redis ---
    # from_url() parse la connection string (redis://localhost:6379)
    # decode_responses=False parce qu'on stocke du JSON en bytes
    redis_client = Redis.from_url(settings.redis_url, decode_responses=False)

    # Vérifie que Redis répond — échoue vite plutôt que planter
    # plus tard au milieu d'un scan
    await redis_client.ping()
    redis_repo = RedisReportRepository(redis_client)

    return mongo_repo, redis_repo


async def close_databases(
    mongo_repo: MongoReportRepository,
    redis_repo: RedisReportRepository,
) -> None:
    """
    Ferme proprement les connexions.

    Appelé une seule fois à l'arrêt dans le lifespan.
    Sans ça, les connexions resteraient ouvertes après l'arrêt
    de l'app — MongoDB/Redis verraient des connexions "fantômes".
    """
    redis_repo.redis.close()
    await redis_repo.redis.aclose()

    # motor.close() ferme le pool de connexions MongoDB
    mongo_repo.collection.database.client.close()
