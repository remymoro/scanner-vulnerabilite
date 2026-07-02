"""
Router pour les endpoints de scan.

Le POST /scan lance les checks en arrière-plan via BackgroundTasks
et retourne immédiatement un scan_id au client. Le client récupère
le rapport plus tard via GET /scan/{scan_id}.

Pourquoi BackgroundTasks et pas un await direct ?
→ Un scan SSL prend 5-15 secondes. Si on fait await dans le POST,
  le client attend 15 secondes avant d'avoir une réponse — mauvaise UX.
  Avec BackgroundTasks, le POST répond en ~50ms avec le scan_id,
  et le scan tourne en arrière-plan.

En NestJS, l'équivalent serait un EventEmitter ou un Bull queue :
  this.eventEmitter.emit('scan.start', { scanId, url });
"""

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request

from scanner.api.schemas.scan import ScanRequest, ScanResponse
from scanner.checks.headers import HeadersCheck
from scanner.checks.ssl_tls import SslCheck
from scanner.core.interfaces.report_repository import IReportRepository
from scanner.services.scan_service import ScanService

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
)


def get_redis_repo(request: Request) -> IReportRepository:
    return request.app.state.redis_repo


def get_mongo_repo(request: Request) -> IReportRepository:
    return request.app.state.mongo_repo


def get_scan_service(request: Request) -> ScanService:
    """
    Crée le ScanService avec les vrais checks et repositories.

    Pourquoi créer le service à chaque requête plutôt qu'une seule
    fois au démarrage ?
    → Parce que la liste des checks pourrait varier par requête
      (ex: un paramètre ?checks=headers,ssl). Pour l'instant c'est
      fixe, mais la structure est prête pour évoluer.

    Les checks sont instanciés ici — ce sont des objets légers
    sans état, donc les recréer ne coûte rien.
    """
    return ScanService(
        checks=[HeadersCheck(), SslCheck()],
        mongo_repo=request.app.state.mongo_repo,
        redis_repo=request.app.state.redis_repo,
    )


@router.post("/", response_model=ScanResponse)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    scan_service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    """
    Lance un scan en arrière-plan et retourne immédiatement le scan_id.

    Le client n'attend pas la fin du scan — il récupère le rapport
    via GET /scan/{scan_id} quand il est prêt.
    """
    scan_id = str(uuid.uuid4())
    url = str(request.url)

    # Lance le scan en arrière-plan — le POST retourne tout de suite
    background_tasks.add_task(scan_service.run_scan, scan_id, url)

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scan started for {url}",
    )


@router.get("/{scan_id}")
async def get_report(
    scan_id: str,
    redis_repo: IReportRepository = Depends(get_redis_repo),
    mongo_repo: IReportRepository = Depends(get_mongo_repo),
) -> dict:
    """
    Récupère le rapport d'un scan — Redis (cache) puis MongoDB (persistance).
    """
    report = await redis_repo.get_report(scan_id)
    if report is not None:
        return report

    report = await mongo_repo.get_report(scan_id)
    if report is not None:
        await redis_repo.save_report(scan_id, report)
        return report

    raise HTTPException(
        status_code=404,
        detail=f"No report found for scan_id: {scan_id}",
    )
