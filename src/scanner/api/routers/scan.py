"""
Router pour les endpoints de scan.

En NestJS, c'est un @Controller('scan') avec des @Post() et @Get().
En FastAPI, c'est un APIRouter avec des @router.post() et @router.get().

La correspondance :

    NestJS                              FastAPI
    ──────                              ───────
    @Controller('scan')                 router = APIRouter(prefix="/scan")
    @Post()                             @router.post("/")
    @Get(':id')                         @router.get("/{scan_id}")
    @Body() dto: CreateScanDto          request: ScanRequest
    @Param('id') id: string             scan_id: str

Pour l'instant, ces endpoints retournent des données de test.
On les connectera aux vrais services en Phase 3 et 6.
"""

import uuid

from fastapi import APIRouter

from scanner.api.schemas.scan import ScanRequest, ScanResponse

router = APIRouter(
    prefix="/scan",
    tags=["scan"],
)


@router.post("/", response_model=ScanResponse)
async def start_scan(request: ScanRequest) -> ScanResponse:
    """
    Lance un scan de sécurité sur l'URL fournie.

    Pourquoi async def et pas juste def ?
    → FastAPI gère les deux, mais avec une différence cruciale :
      - async def → tourne directement sur l'event loop (non-bloquant)
      - def       → FastAPI le lance dans un thread pool (bloquant isolé)
      On veut async parce que nos checks feront des appels réseau async.

    Pour l'instant on génère juste un ID et on retourne "pending".
    Le vrai scan arrivera en Phase 6 (orchestration).
    """
    # uuid4() génère un identifiant unique aléatoire — impossible
    # que deux scans aient le même ID, même avec des millions de scans
    scan_id = str(uuid.uuid4())

    # TODO Phase 6 : ici on lancera ScanOrchestrator en arrière-plan
    # au lieu de juste retourner un ID

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scan started for {request.url}",
    )


@router.get("/{scan_id}")
async def get_report(scan_id: str) -> dict:
    """
    Récupère le rapport d'un scan par son ID.

    Même flow que dans ton stage :
    1. Chercher dans Redis (cache rapide)
    2. Si absent, chercher dans MongoDB (persistance)
    3. Si absent partout, 404

    Pour l'instant on retourne un stub.
    La vraie logique arrivera en Phase 3 (repositories).
    """
    # TODO Phase 3 : chercher dans Redis puis MongoDB
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Report not yet implemented — Phase 3",
    }
