"""
Point d'entrée de l'application FastAPI.

C'est l'équivalent de main.ts en NestJS :
    const app = await NestFactory.create(AppModule);
    app.enableCors();
    await app.listen(3000);

Trois responsabilités :
1. Lifespan — ouvrir/fermer les connexions DB au démarrage/arrêt
2. CORS — autoriser le frontend à appeler l'API
3. Inclusion des routers — brancher les endpoints

Évolution depuis Phase 3 :
  Phase 3 → mongo_repo + redis_repo dans app.state
  Maintenant → cache_repo ajouté dans app.state
    redis_repo  : IReportRepository — rapports par scan_id
    cache_repo  : ICacheRepository  — cache anti-spam par domaine
    Même objet RedisReportRepository, deux interfaces différentes.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from scanner.api.routers import scan as scan_router
from scanner.api.routers import stream as stream_router
from scanner.infrastructure.config import settings
from scanner.infrastructure.database import close_databases, init_databases


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gère le cycle de vie de l'application.

    Tout ce qui est AVANT le yield s'exécute au démarrage.
    Tout ce qui est APRÈS le yield s'exécute à l'arrêt.

    En NestJS, c'est l'équivalent de :
        onModuleInit()    → avant le yield
        onModuleDestroy() → après le yield

    app.state est un dictionnaire libre attaché à l'instance FastAPI.
    On y stocke les repositories pour les rendre accessibles aux
    endpoints via l'injection de dépendances (Depends).

    Pourquoi trois entrées pour deux objets ?
    → redis_repo et cache_repo pointent vers le même objet
      RedisReportRepository, mais sous deux interfaces différentes.

      redis_repo  : IReportRepository → save/get par scan_id (24h)
      cache_repo  : ICacheRepository  → get/set par domaine (1h)

      C'est le principe Interface Segregation — le ScanService
      ne voit de Redis que ce dont il a besoin selon son rôle.
      Deux "vues" du même objet, deux contrats distincts.
    """
    print(f"Scanner API starting... (log_level={settings.log_level})")

    mongo_repo, redis_repo = await init_databases()

    # Attache les repositories à l'état global de l'app
    # Accessibles dans tous les endpoints via request.app.state
    app.state.mongo_repo = mongo_repo
    app.state.redis_repo = redis_repo

    # Même objet Redis, exposé sous l'interface ICacheRepository
    # Le router passera cet objet au ScanService comme cache_repo
    # ScanService voit ICacheRepository — pas Redis directement
    app.state.cache_repo = redis_repo

    print("Connected to MongoDB and Redis")
    yield

    # Arrêt propre — ferme les connexions DB
    # Évite les connexions "zombies" qui restent ouvertes
    await close_databases(mongo_repo, redis_repo)
    print("Scanner API shutting down...")


app = FastAPI(
    title="Scanner de vulnérabilités",
    description="API de scan de sécurité web — headers HTTP, SSL/TLS, DNS",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS : autorise le frontend (Angular, Nuxt, n'importe quoi)
# à appeler l'API depuis un autre domaine.
# allow_origins=["*"] → OK en dev, à restreindre en prod
# En prod : allow_origins=["https://monsite.fr"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Branche les routers — tous les endpoints sont accessibles sous /scan
# scan_router   → POST /scan/ + GET /scan/{id}  (BackgroundTasks)
# stream_router → POST /scan/stream             (SSE temps réel)
app.include_router(scan_router.router)
app.include_router(stream_router.router)


@app.get("/health")
async def health_check() -> dict:
    """
    Endpoint de santé — utilisé par Docker, Kubernetes, load balancer.

    Retourne { "status": "ok" } si l'API répond.
    Ne vérifie pas MongoDB ni Redis — juste que le process tourne.
    Pour une santé complète, on ferait aussi ping MongoDB et Redis.
    """
    return {"status": "ok"}
