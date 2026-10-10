"""
RateLimitCheck — vérifie si la cible limite le nombre de requêtes.

On envoie une courte rafale (30 requêtes, 10 en parallèle) vers l'URL.
Ce n'est pas un test de charge : c'est de quoi déclencher une limite
raisonnable sans mettre le site en difficulté.

Signaux recherchés :
  - code 429 (Too Many Requests) ou 503 pendant la rafale → limite active
  - en-têtes X-RateLimit-* / RateLimit-* / Retry-After → limite annoncée

Score : blocage observé = 100, limite annoncée seulement = 70, rien = 30.
"""

import asyncio

import httpx

from scanner.core.entities.check_result import CheckDetail, CheckResult, Severity, Status
from scanner.core.interfaces.base_check import BaseCheck

THROTTLE_STATUSES = {429, 503}
RATE_LIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "ratelimit-limit",
    "retry-after",
)


class RateLimitCheck(BaseCheck):
    """Envoie une petite rafale et cherche un blocage ou des en-têtes de limite."""

    def __init__(self, burst: int = 30, concurrency: int = 10) -> None:
        self.burst = burst
        self.concurrency = concurrency

    @property
    def name(self) -> str:
        return "Rate Limiting"

    @property
    def severity(self) -> str:
        return Severity.MEDIUM

    async def run(self, url: str) -> CheckResult:
        semaphore = asyncio.Semaphore(self.concurrency)

        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:

            async def hit() -> httpx.Response | None:
                async with semaphore:
                    try:
                        return await client.get(url)
                    except httpx.RequestError:
                        return None

            responses = [r for r in await asyncio.gather(*[hit() for _ in range(self.burst)]) if r]

        if not responses:
            return CheckResult(
                check_name=self.name,
                severity=Severity.MEDIUM,
                score=0,
                grade="F",
                details=[
                    CheckDetail(
                        name="Connection",
                        status=Status.FAIL,
                        description="Aucune réponse de la cible pendant la rafale.",
                    )
                ],
            )

        throttled = [r for r in responses if r.status_code in THROTTLE_STATUSES]
        announced = sorted(
            {h for r in responses for h in RATE_LIMIT_HEADERS if h in r.headers}
        )

        details = [
            CheckDetail(
                name="Blocage pendant la rafale",
                status=Status.OK if throttled else Status.FAIL,
                value=f"{len(throttled)}/{len(responses)} requêtes limitées",
                description=(
                    "La cible a répondu 429/503 : un rate-limiter est actif."
                    if throttled
                    else f"{len(responses)} requêtes rapprochées sont toutes passées."
                ),
            ),
            CheckDetail(
                name="En-têtes de limite",
                status=Status.OK if announced else Status.WARN,
                value=", ".join(announced) or None,
                description=(
                    "La cible annonce sa limite dans ses en-têtes."
                    if announced
                    else "Aucun en-tête X-RateLimit / Retry-After."
                ),
            ),
        ]

        score = 100 if throttled else 70 if announced else 30
        return CheckResult(
            check_name=self.name,
            severity=Severity.MEDIUM,
            score=score,
            grade=CheckResult.compute_grade(score),
            details=details,
        )
