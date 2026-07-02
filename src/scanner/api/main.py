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
        onModuleInit()  → avant le yield
        onModuleDestroy() → après le yield

    app.state est un dictionnaire libre attaché à l'instance FastAPI.
    On y stocke les repositories pour les rendre accessibles aux
    endpoints via l'injection de dépendances (Depends).
    """
    # --- Démarrage ---
    print(f"Scanner API starting... (log_level={settings.log_level})")
    mongo_repo, redis_repo = await init_databases()
    app.state.mongo_repo = mongo_repo
    app.state.redis_repo = redis_repo
    print("Connected to MongoDB and Redis")
    yield
    # --- Arrêt ---
    await close_databases(mongo_repo, redis_repo)
    print("Scanner API shutting down...")


app = FastAPI(
    title="Scanner de vulnérabilités",
    description="API de scan de sécurité web — headers HTTP, SSL/TLS",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS : autorise le frontend (Nuxt, Angular, n'importe quoi)
# à appeler l'API depuis un autre domaine.
# En prod, on restreindrait à l'URL exacte du frontend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Branche le router de scan — tous ses endpoints sont maintenant
# accessibles sous /scan (POST /scan/, GET /scan/{id})
app.include_router(scan_router.router)
app.include_router(stream_router.router)


@app.get("/health")
async def health_check() -> dict:
    """
    Endpoint de santé — utilisé par Docker, Kubernetes, ou un
    load balancer pour vérifier que l'API répond.

    Retourne juste { "status": "ok" }. Simple mais indispensable.
    """
    return {"status": "ok"}
