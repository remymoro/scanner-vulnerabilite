"""
Service d'orchestration des scans.

C'est la couche "application" de l'architecture hexagonale — elle
coordonne les checks et les repositories sans contenir de logique
métier ni de détails techniques.

En NestJS, c'est l'équivalent d'un @Injectable() service :
    @Injectable()
    export class ScanService {
        constructor(
            private readonly checks: BaseCheck[],
            private readonly mongoRepo: IReportRepository,
            private readonly cacheRepo: ICacheRepository,
        ) {}
    }

Le service ne connaît que des interfaces.
Il ne sait pas que derrière il y a httpx, sslyze, motor ou redis-py.

Évolution depuis Phase 6 :
  Phase 6 → run_scan() + asyncio.gather()
  Phase 7 → run_scan_stream() + asyncio.as_completed() + SSE
  Maintenant → cache ICacheRepository branché en lecture ET écriture
"""

import asyncio
import logging
from urllib.parse import urlparse

from scanner.core.entities.check_result import CheckResult
from scanner.core.entities.scan_report import ScanReport, ScanStatus
from scanner.core.interfaces.base_check import BaseCheck
from scanner.core.interfaces.cache_repository import ICacheRepository
from scanner.core.interfaces.report_repository import IReportRepository

logger = logging.getLogger(__name__)


class ScanService:
    """
    Orchestre le scan complet d'une URL.

    Responsabilités :
    1. Vérifier le cache avant de lancer un scan (ICacheRepository)
    2. Lancer tous les checks en parallèle (asyncio.gather/as_completed)
    3. Agréger les résultats dans un ScanReport
    4. Sauvegarder dans Redis (cache) et MongoDB (persistance)

    Ce qui n'est PAS sa responsabilité :
    - Savoir comment fonctionne un check (c'est dans checks/)
    - Savoir comment fonctionne MongoDB (c'est dans repositories/)
    - Savoir comment fonctionne Redis (c'est dans repositories/)
    - Valider l'URL (c'est le rôle de Pydantic dans le router)

    Pourquoi trois dépendances maintenant ?
    → mongo_repo  : stockage permanent des rapports (IReportRepository)
    → redis_repo  : historique temporaire par scan_id (IReportRepository)
    → cache_repo  : cache anti-spam par domaine (ICacheRepository)

    Redis implémente les deux interfaces — mais le service ne le sait pas.
    Il reçoit deux "vues" différentes du même objet Redis :
    une pour les rapports, une pour le cache.
    """

    def __init__(
        self,
        checks: list[BaseCheck],
        mongo_repo: IReportRepository,
        redis_repo: IReportRepository,
        cache_repo: ICacheRepository,
    ) -> None:
        """
        Constructor injection — exactement comme NestJS.

        En test, on injecte des faux repositories.
        En prod, on injecte les vrais.
        ScanService ne crée jamais ses dépendances lui-même.

        Pourquoi redis_repo ET cache_repo séparés alors que c'est
        le même objet RedisReportRepository en prod ?
        → Principe Interface Segregation (SOLID "I").
          ScanService ne voit de Redis que ce dont il a besoin :
          - Pour les rapports : IReportRepository (save/get par scan_id)
          - Pour le cache URL : ICacheRepository (get/set par domaine)
          Deux contrats, deux responsabilités, même implémentation.
        """
        self.checks = checks
        self.mongo_repo = mongo_repo
        self.redis_repo = redis_repo
        self.cache_repo = cache_repo

    def _normalize_cached_report(
        self,
        scan_id: str,
        url: str,
        cached_report: dict,
    ) -> tuple[ScanReport, dict]:
        report_dict = dict(cached_report)
        report_dict["scan_id"] = scan_id
        report_dict["url"] = url

        report = ScanReport(
            scan_id=scan_id,
            url=url,
            status=ScanStatus.DONE,
            overall_score=report_dict.get("overall_score", 0),
            overall_grade=report_dict.get("overall_grade", "F"),
        )
        return report, report_dict

    async def run_scan(self, scan_id: str, url: str) -> ScanReport:
        """
        Lance un scan complet et retourne le rapport en une fois.

        Utilisé par BackgroundTasks — le client reçoit un scan_id
        et peut venir chercher le résultat plus tard.

        Pourquoi asyncio.gather et pas asyncio.TaskGroup ?
        → gather(return_exceptions=True) continue même si un check plante.
          TaskGroup annule tout au premier échec.
          On veut le rapport partiel : si SSL timeout mais headers OK,
          on retourne quand même les headers. Plus utile qu'un échec total.

        En NestJS :
            await Promise.allSettled(checks.map(c => c.run(url)))
        (allSettled pas all — pour ne pas tout annuler au premier rejet)
        """
        domain = urlparse(url).hostname or url
        cached = await self.cache_repo.get_scan(domain)
        if cached:
            logger.info("Cache HIT pour %s — scan réutilisé", domain)
            report, report_dict = self._normalize_cached_report(scan_id, url, cached)
            await asyncio.gather(
                self.redis_repo.save_report(scan_id, report_dict),
                self.mongo_repo.save_report(scan_id, report_dict),
                self.cache_repo.set_scan(domain, report_dict),
            )
            return report

        logger.info("Cache MISS pour %s — lancement des checks", domain)
        report = ScanReport(scan_id=scan_id, url=url, status=ScanStatus.RUNNING)
        logger.info("Scan %s started for %s (%d checks)", scan_id, url, len(self.checks))

        # Lance tous les checks en parallèle
        # return_exceptions=True : un check qui plante retourne l'exception
        # au lieu de faire planter tout le gather
        results = await asyncio.gather(
            *[check.run(url) for check in self.checks],
            return_exceptions=True,
        )

        # Traite les résultats — sépare les succès des erreurs
        for check, result in zip(self.checks, results, strict=True):
            if isinstance(result, Exception):
                logger.error("Check %s failed: %s", check.name, result)
            else:
                report.checks.append(result)

        report.compute_overall()
        report.status = ScanStatus.DONE

        logger.info(
            "Scan %s done: %s (%d/%d checks OK)",
            scan_id,
            report.overall_grade,
            len(report.checks),
            len(self.checks),
        )

        # Sauvegarde en parallèle dans Redis ET MongoDB
        report_dict = report.to_dict()
        domain = urlparse(url).hostname or url
        await asyncio.gather(
            self.redis_repo.save_report(scan_id, report_dict),
            self.mongo_repo.save_report(scan_id, report_dict),
            self.cache_repo.set_scan(domain, report_dict),
        )

        return report

    async def run_scan_stream(self, scan_id: str, url: str):
        """
        Lance un scan et YIELD chaque résultat dès qu'il est prêt.

        Utilise asyncio.as_completed() — le check le plus rapide
        arrive en premier. Le client SSE voit les résultats s'afficher
        au fur et à mesure, pas tous à la fin.

        NOUVEAU : vérifie le cache avant de lancer quoi que ce soit.
        Si le domaine a été scanné il y a moins d'1h → retourne
        le cache immédiatement sans aucun appel réseau.

        Pourquoi un wrapper _run_check ?
        → En Python 3.13, as_completed() retourne des objets internes
          différents des tasks originales. Le mapping task→check par
          identité d'objet ne fonctionne plus. Le wrapper inclut le
          nom du check directement dans le résultat — plus de mapping.
        """
        # Extraire le domaine depuis l'URL
        # "https://test/page" → "test.fr"
        # C'est la clé stable pour le cache — indépendante du chemin
        domain = urlparse(url).hostname or url
        cached = await self.cache_repo.get_scan(domain)
        if cached:
            logger.info("Cache HIT pour %s — résultats depuis Redis", domain)
            _, cached_report = self._normalize_cached_report(scan_id, url, cached)
            yield {
                "event": "scan_complete",
                "data": cached_report,
            }
            return  # ← stop ici, pas de checks réseau

        logger.info("Cache MISS pour %s — lancement des checks", domain)
        report = ScanReport(scan_id=scan_id, url=url, status=ScanStatus.RUNNING)

        async def _run_check(
            check: BaseCheck,
        ) -> tuple[str, CheckResult | Exception]:
            """
            Wrapper qui retourne (check_name, résultat ou exception).

            Le tuple permet à as_completed() de savoir quel check
            a terminé sans mapping externe — le nom est dans le résultat.
            """
            try:
                result = await check.run(url)
                return check.name, result
            except Exception as exc:
                return check.name, exc

        coros = [_run_check(check) for check in self.checks]
        completed = 0
        total = len(self.checks)

        for future in asyncio.as_completed(coros):
            completed += 1
            check_name, result = await future

            if isinstance(result, Exception):
                logger.error("Check %s failed: %s", check_name, result)
                yield {
                    "event": "check_error",
                    "data": {
                        "check_name": check_name,
                        "error": str(result),
                        "progress": f"{completed}/{total}",
                    },
                }
            else:
                report.checks.append(result)
                yield {
                    "event": "check_complete",
                    "data": {
                        "check_name": result.check_name,
                        "score": result.score,
                        "grade": result.grade,
                        "severity": result.severity,
                        "details": [
                            {
                                "name": d.name,
                                "status": d.status.value,
                                "value": d.value,
                                "description": d.description,
                            }
                            for d in result.details
                        ],
                        "progress": f"{completed}/{total}",
                    },
                }

        # Tous les checks sont terminés
        report.compute_overall()
        report.status = ScanStatus.DONE

        # Sauvegarde en parallèle — trois destinations :
        # redis_repo.save_report  → historique par scan_id (24h)
        #   "retrouve ce scan précis par son UUID"
        # mongo_repo.save_report  → stockage permanent
        #   "historique sur le long terme, requêtes complexes"
        # cache_repo.set_scan     → cache anti-spam par domaine (1h)
        #   "évite de rescanner le même site dans l'heure"
        report_dict = report.to_dict()
        await asyncio.gather(
            self.redis_repo.save_report(scan_id, report_dict),
            self.mongo_repo.save_report(scan_id, report_dict),
            self.cache_repo.set_scan(domain, report_dict),
        )

        # Événement final — le client SSE reçoit le rapport complet
        yield {
            "event": "scan_complete",
            "data": report_dict,
        }
