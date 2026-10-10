"""
Router pour les endpoints de scan.

POST /scan dépose le scan dans une file ARQ (Redis) et répond tout de suite
avec un scan_id. Un worker séparé exécute les checks ; le client suit
l'avancement via GET /scan/{scan_id}/events ou lit le rapport final via
GET /scan/{scan_id}.

Pourquoi une file plutôt que BackgroundTasks ?
→ BackgroundTasks tourne dans le process de l'API : un redémarrage ou un
  crash perd le scan. Avec la file, le job survit et on peut ajouter des
  workers pour absorber la charge.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from scanner.api.schemas.scan import ScanRequest, ScanResponse
from scanner.api.security import guard_scan_target
from scanner.core.interfaces.report_repository import IReportRepository

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
)


def get_redis_repo(request: Request) -> IReportRepository:
    return request.app.state.redis_repo


def get_mongo_repo(request: Request) -> IReportRepository:
    return request.app.state.mongo_repo


@router.post("/", response_model=ScanResponse)
async def start_scan(request: ScanRequest, http_request: Request) -> ScanResponse:
    """
    Dépose le scan dans la file ARQ et retourne immédiatement le scan_id.

    Un worker exécute le scan dans un autre process. Le client suit l'avancement
    avec GET /scan/{scan_id}/events (SSE) ou récupère le rapport final avec
    GET /scan/{scan_id}.
    """
    url = str(request.url)
    await guard_scan_target(url, http_request)
    scan_id = str(uuid.uuid4())
    await http_request.app.state.queue.enqueue_job("run_scan_job", scan_id, url)
    return ScanResponse(scan_id=scan_id, status="pending", message=f"Scan started for {url}")


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
