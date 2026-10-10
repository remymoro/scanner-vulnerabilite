"""
Endpoint SSE pour le streaming des résultats de scan en temps réel.

Server-Sent Events (SSE) est un standard W3C simple :
- Le client ouvre une connexion HTTP classique
- Le serveur garde la connexion ouverte
- Le serveur envoie des événements au format texte
- Le client les reçoit via l'API EventSource du navigateur

Format SSE (chaque événement) :
    event: check_complete
    data: {"check_name": "Headers", "score": 83}

    event: scan_complete
    data: {"scan_id": "...", "overall_score": 75}

En NestJS, c'est l'équivalent de :
    @Sse('stream/:id')
    stream(@Param('id') id: string): Observable<MessageEvent> {
        return this.scanService.streamResults(id);
    }

En FastAPI, on utilise StreamingResponse avec un async generator.
"""

import json
import time
import uuid

from fastapi import APIRouter, Header, Request
from fastapi.responses import StreamingResponse

from scanner.api.schemas.scan import ScanRequest
from scanner.api.security import guard_scan_target
from scanner.core.interfaces.event_stream import TERMINAL_EVENTS, IScanEventStream
from scanner.services.check_registry import default_checks
from scanner.services.scan_service import ScanService

router = APIRouter(
    prefix="/scan",
    tags=["scan-stream"],
)


def _get_scan_service(request: Request) -> ScanService:
    return ScanService(
        checks=default_checks(),
        mongo_repo=request.app.state.mongo_repo,
        redis_repo=request.app.state.redis_repo,
        cache_repo=request.app.state.redis_repo,  # ← même objet Redis
    )


async def _sse_generator(scan_service: ScanService, scan_id: str, url: str):
    """
    Async generator qui produit des événements SSE.

    Chaque yield est une string au format SSE :
        event: <type>\ndata: <json>\n\n

    Le double \\n\\n à la fin est obligatoire — c'est le séparateur
    d'événements SSE. Sans ça, le client ne sait pas où un
    événement finit et où le suivant commence.

    Pourquoi un generator et pas une boucle classique ?
    → StreamingResponse de FastAPI consomme un async generator.
      À chaque yield, FastAPI envoie immédiatement les données
      au client via la connexion HTTP ouverte. C'est le mécanisme
      qui permet le streaming en temps réel.
    """
    async for event in scan_service.run_scan_stream(scan_id, url):
        event_type = event["event"]
        event_data = json.dumps(event["data"])
        yield f"event: {event_type}\ndata: {event_data}\n\n"


@router.post("/stream")
async def start_scan_stream(
    scan_request: ScanRequest,
    request: Request,
) -> StreamingResponse:
    """
    Lance un scan ET stream les résultats en temps réel.

    Contrairement à POST /scan (qui retourne un ID et lance en background),
    cet endpoint garde la connexion ouverte et envoie les résultats
    au fur et à mesure que chaque check termine.

    Le client reçoit :
    1. event: check_complete  → dès que le HeadersCheck finit (~3s)
    2. event: check_complete  → dès que le SslCheck finit (~12s)
    3. event: scan_complete   → le rapport complet avec le score global

    Côté client JavaScript :
        const source = new EventSource('/scan/stream?url=https://github.com');
        // Non — EventSource ne supporte que GET. Pour POST, utiliser fetch :

        const response = await fetch('/scan/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: 'https://github.com' })
        });
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            console.log(decoder.decode(value));
        }
    """
    url = str(scan_request.url)
    await guard_scan_target(url, request)
    scan_id = str(uuid.uuid4())
    scan_service = _get_scan_service(request)
    return StreamingResponse(
        _sse_generator(scan_service, scan_id, url),
        media_type="text/event-stream",
        headers={
            # Empêche les proxys/CDN de bufferiser le flux
            # Sans ça, Nginx pourrait accumuler les événements
            # et les envoyer tous d'un coup à la fin
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


MAX_STREAM_SECONDS = 600


async def _stream_events(stream: IScanEventStream, scan_id: str, last_id: str):
    """Relit le flux du scan et le renvoie en SSE, avec un `id:` par événement."""
    deadline = time.monotonic() + MAX_STREAM_SECONDS
    while time.monotonic() < deadline:
        events = await stream.read(scan_id, last_id)
        if not events:
            yield ": keepalive\n\n"  # commentaire SSE : garde la connexion ouverte
            continue
        for event in events:
            last_id = event.id
            yield f"id: {event.id}\nevent: {event.event}\ndata: {json.dumps(event.data)}\n\n"
            if event.event in TERMINAL_EVENTS:
                return


@router.get("/{scan_id}/events")
async def scan_events(
    scan_id: str,
    request: Request,
    last_event_id: str | None = Header(default=None),
) -> StreamingResponse:
    """
    Suit un scan lancé avec POST /scan/ (SSE).

    Si la connexion tombe, le navigateur (EventSource) se reconnecte tout seul
    avec l'en-tête Last-Event-ID et reprend après le dernier événement reçu.
    """
    return StreamingResponse(
        _stream_events(request.app.state.event_stream, scan_id, last_event_id or "0-0"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
