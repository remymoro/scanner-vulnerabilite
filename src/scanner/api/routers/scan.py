"""
Router pour les endpoints de scan.

Maintenant connecté aux vrais repositories MongoDB et Redis.

L'injection de dépendances FastAPI fonctionne via Depends() :

    NestJS                                  FastAPI
    ──────                                  ───────
    @Inject(MongoRepo) repo: MongoRepo      Depends(get_mongo_repo)
    constructor injection                   function parameter injection

La différence : NestJS injecte via le constructeur de la classe,
FastAPI injecte via les paramètres de chaque fonction endpoint.
Le principe est le même — l'endpoint ne crée pas ses dépendances,
il les reçoit de l'extérieur.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from scanner.api.schemas.scan import ScanRequest, ScanResponse
from scanner.core.interfaces.report_repository import IReportRepository

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
)


def get_redis_repo(request: Request) -> IReportRepository:
    """
    Fonction d'injection — récupère le repository Redis
    depuis app.state (où le lifespan l'a stocké).

    Pourquoi une fonction et pas un import direct ?
    → Parce que le repository n'existe pas encore quand le module
      est importé — il est créé au démarrage dans le lifespan.
      La fonction est appelée à chaque requête, quand l'app est
      déjà démarrée et les connexions ouvertes.
    """
    return request.app.state.redis_repo


def get_mongo_repo(request: Request) -> IReportRepository:
    """Même principe pour MongoDB."""
    return request.app.state.mongo_repo


@router.post("/", response_model=ScanResponse)
async def start_scan(request: ScanRequest) -> ScanResponse:
    """
    Lance un scan de sécurité sur l'URL fournie.

    Pour l'instant on génère juste un ID — le vrai scan
    arrivera en Phase 6 (orchestration avec asyncio.gather).
    """
    scan_id = str(uuid.uuid4())

    # TODO Phase 6 : lancer ScanOrchestrator en arrière-plan

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scan started for {request.url}",
    )


@router.get("/{scan_id}")
async def get_report(
    scan_id: str,
    redis_repo: IReportRepository = Depends(get_redis_repo),
    mongo_repo: IReportRepository = Depends(get_mongo_repo),
) -> dict:
    """
    Récupère le rapport d'un scan — cherche dans Redis puis MongoDB.

    C'est le même flow que dans ton stage :
    1. Chercher dans Redis (cache rapide, TTL 24h)
    2. Si absent → chercher dans MongoDB (persistance)
    3. Si absent partout → 404

    La seule différence : c'est async, et les repositories
    sont injectés via Depends() au lieu d'être créés ici.
    """
    # 1. Redis d'abord — réponse en ~1ms
    report = await redis_repo.get_report(scan_id)
    if report is not None:
        return report

    # 2. MongoDB ensuite — réponse en ~5-20ms
    report = await mongo_repo.get_report(scan_id)
    if report is not None:
        # On remet en cache Redis pour les prochains accès
        await redis_repo.save_report(scan_id, report)
        return report

    # 3. Rien trouvé nulle part
    raise HTTPException(
        status_code=404,
        detail=f"No report found for scan_id: {scan_id}",
    )
