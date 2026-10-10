"""
Protection du scanner lui-même.

1. Anti-SSRF : un scanner qui accepte n'importe quelle URL peut être
   détourné pour sonder le réseau interne (localhost, 169.254.169.254,
   10.x.x.x...). On résout le nom de domaine et on refuse toute adresse
   qui n'est pas publique.
2. Limitation par IP : au plus `max_scans` scans par fenêtre de temps.
   Implémentation en mémoire, suffisante pour une instance unique ;
   pour plusieurs instances il faudra la déplacer dans Redis.
"""

import asyncio
import ipaddress
import socket
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from scanner.core.exceptions import TargetUnreachableError, UnsafeTargetError


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not ip.is_multicast


async def ensure_public_target(url: str) -> None:
    """Lève UnsafeTargetError / TargetUnreachableError si l'URL ne vise pas un hôte public."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"Schéma interdit : {parsed.scheme!r}")
    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("URL sans nom d'hôte")

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetUnreachableError(f"Nom de domaine introuvable : {host}") from exc

    for info in infos:
        address = info[4][0].split("%")[0]
        if not _is_public(address):
            raise UnsafeTargetError(f"{host} pointe vers une adresse non publique ({address})")


class ScanRateLimiter:
    """Fenêtre glissante : `max_scans` scans par IP toutes les `window` secondes."""

    def __init__(self, max_scans: int = 10, window: float = 60.0) -> None:
        self.max_scans = max_scans
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, client_ip: str) -> None:
        now = time.monotonic()
        hits = self._hits[client_ip]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.max_scans:
            raise HTTPException(
                status_code=429,
                detail="Trop de scans, réessayez dans un instant.",
                headers={"Retry-After": str(int(self.window))},
            )
        hits.append(now)


scan_rate_limiter = ScanRateLimiter()


async def guard_scan_target(url: str, request: Request) -> None:
    """Dépendance commune aux routers : limite par IP puis anti-SSRF → erreurs HTTP."""
    scan_rate_limiter.check(request.client.host if request.client else "unknown")
    try:
        await ensure_public_target(url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except TargetUnreachableError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
