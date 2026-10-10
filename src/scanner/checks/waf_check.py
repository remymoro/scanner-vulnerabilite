"""
WafCheck — détecte la présence d'un pare-feu applicatif web (WAF).

Deux méthodes combinées :
  1. Passive : on cherche la signature d'un WAF/CDN connu dans les
     en-têtes et cookies d'une requête normale.
  2. Active : on envoie UNE requête avec une chaîne de type XSS/SQLi
     (jamais exécutée, simple texte dans la query string). Si la requête
     normale passe (2xx/3xx) et que celle-ci est rejetée (403, 406, 429,
     501), un filtrage actif est en place.

Score : un WAF détecté protège (100), un filtrage sans signature connue
est probable (85), aucun WAF visible est un point faible (30).
"""

import httpx

from scanner.core.entities.check_result import CheckDetail, CheckResult, Severity, Status
from scanner.core.interfaces.base_check import BaseCheck

PROBE_QUERY = {"q": "<script>alert(1)</script>' OR '1'='1"}
BLOCK_STATUSES = {403, 406, 429, 501}

# (nom du WAF, en-têtes qui le trahissent, valeurs de Server, préfixes de cookies)
WAF_SIGNATURES: list[tuple[str, set[str], set[str], tuple[str, ...]]] = [
    ("Cloudflare", {"cf-ray", "cf-cache-status"}, {"cloudflare"}, ("__cf_bm", "cf_clearance")),
    ("AWS CloudFront / WAF", {"x-amz-cf-id", "x-amz-cf-pop"}, {"cloudfront"}, ("awsalb",)),
    ("Akamai", {"x-akamai-transformed", "akamai-grn"}, {"akamaighost"}, ("ak_bmsc",)),
    ("Imperva Incapsula", {"x-iinfo", "x-cdn"}, {"incapsula"}, ("incap_ses", "visid_incap")),
    ("Sucuri", {"x-sucuri-id", "x-sucuri-cache"}, {"sucuri/cloudproxy"}, ("sucuri_cloudproxy",)),
    ("F5 BIG-IP ASM", set(), {"big-ip"}, ("ts0", "bigipserver")),
    ("BunkerWeb", {"x-bunkerweb"}, {"bunkerweb"}, ()),
    ("ModSecurity", set(), {"mod_security", "modsecurity"}, ()),
]


def fingerprint_waf(headers: httpx.Headers) -> str | None:
    """Retourne le nom du WAF reconnu dans les en-têtes/cookies, sinon None."""
    names = {h.lower() for h in headers}
    server = headers.get("server", "").lower()
    cookies = " ".join(headers.get_list("set-cookie")).lower()
    for waf, header_names, servers, cookie_prefixes in WAF_SIGNATURES:
        if names & header_names:
            return waf
        if any(s in server for s in servers):
            return waf
        if any(p in cookies for p in cookie_prefixes):
            return waf
    return None


class WafCheck(BaseCheck):
    """Détecte un WAF par signature (passif) et par comportement (actif)."""

    @property
    def name(self) -> str:
        return "Web Application Firewall"

    @property
    def severity(self) -> str:
        return Severity.MEDIUM

    async def run(self, url: str) -> CheckResult:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
                baseline = await client.get(url)
                probe = await client.get(url, params=PROBE_QUERY)
        except httpx.RequestError as exc:
            return self._error(f"Impossible de joindre la cible : {exc}")

        waf_name = fingerprint_waf(baseline.headers) or fingerprint_waf(probe.headers)
        baseline_ok = baseline.status_code < 400
        probe_blocked = probe.status_code in BLOCK_STATUSES and baseline_ok

        details: list[CheckDetail] = []
        if waf_name:
            details.append(
                CheckDetail(
                    name="Signature WAF",
                    status=Status.OK,
                    value=waf_name,
                    description=f"WAF/CDN détecté dans les en-têtes : {waf_name}.",
                )
            )
        else:
            details.append(
                CheckDetail(
                    name="Signature WAF",
                    status=Status.WARN,
                    description="Aucune signature de WAF connu dans les en-têtes ou cookies.",
                )
            )

        details.append(
            CheckDetail(
                name="Filtrage actif",
                status=Status.OK if probe_blocked else Status.WARN,
                value=f"HTTP {baseline.status_code} → {probe.status_code}",
                description=(
                    "Une requête contenant du XSS/SQLi factice a été rejetée : "
                    "un filtrage est actif."
                    if probe_blocked
                    else "Une requête contenant du XSS/SQLi factice n'a pas été bloquée."
                ),
            )
        )

        if waf_name:
            score = 100
        elif probe_blocked:
            score = 85
        else:
            score = 30

        return CheckResult(
            check_name=self.name,
            severity=Severity.MEDIUM,
            score=score,
            grade=CheckResult.compute_grade(score),
            details=details,
        )

    def _error(self, message: str) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            severity=Severity.MEDIUM,
            score=0,
            grade="F",
            details=[CheckDetail(name="Connection", status=Status.FAIL, description=message)],
        )
