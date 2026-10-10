"""
Job exécuté par le worker ARQ : lance le scan et publie chaque événement.

L'API ne fait que déposer (scan_id, url) dans la file. Tout le travail se
passe ici, dans un autre process : si le client HTTP se déconnecte, le scan
va quand même au bout et le rapport est sauvegardé.
"""

import logging
from typing import Any

from scanner.services.check_registry import default_checks
from scanner.services.scan_service import ScanService

logger = logging.getLogger(__name__)


async def run_scan_job(ctx: dict[str, Any], scan_id: str, url: str) -> None:
    stream = ctx["event_stream"]
    service = ScanService(
        checks=default_checks(),
        mongo_repo=ctx["mongo_repo"],
        redis_repo=ctx["redis_repo"],
        cache_repo=ctx["redis_repo"],
    )
    try:
        async for event in service.run_scan_stream(scan_id, url):
            await stream.publish(scan_id, event["event"], event["data"])
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        # Le client doit toujours recevoir un événement terminal.
        await stream.publish(scan_id, "scan_error", {"scan_id": scan_id, "error": str(exc)})
