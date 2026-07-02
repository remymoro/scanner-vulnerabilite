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
            private readonly redisRepo: IReportRepository,
        ) {}
    }

Le service ne connaît que des interfaces (BaseCheck, IReportRepository).
Il ne sait pas que derrière il y a httpx, sslyze, motor ou redis-py.
"""

import asyncio
import logging

from scanner.core.entities.check_result import CheckResult
from scanner.core.entities.scan_report import ScanReport, ScanStatus
from scanner.core.interfaces.base_check import BaseCheck
from scanner.core.interfaces.report_repository import IReportRepository

logger = logging.getLogger(__name__)


class ScanService:
    """
    Orchestre le scan complet d'une URL.

    Responsabilités :
    1. Lancer tous les checks en parallèle (asyncio.gather)
    2. Agréger les résultats dans un ScanReport
    3. Sauvegarder dans Redis (cache) et MongoDB (persistance)

    Ce qui n'est PAS sa responsabilité :
    - Savoir comment fonctionne un check (c'est dans checks/)
    - Savoir comment fonctionne MongoDB (c'est dans repositories/)
    - Valider l'URL (c'est le rôle de Pydantic dans le router)
    """

    def __init__(
        self,
        checks: list[BaseCheck],
        mongo_repo: IReportRepository,
        redis_repo: IReportRepository,
    ) -> None:
        """
        Pourquoi recevoir les dépendances en paramètre ?
        → Inversion de contrôle. Le service ne crée rien lui-même.
          En test, on lui passe des faux checks et des faux repos.
          En prod, on lui passe les vrais.
          C'est exactement le constructor injection de NestJS.
        """
        self.checks = checks
        self.mongo_repo = mongo_repo
        self.redis_repo = redis_repo

    async def run_scan(self, scan_id: str, url: str) -> ScanReport:
        """
        Lance un scan complet sur l'URL et retourne le rapport.

        Le flow :
        1. Créer un rapport "pending"
        2. Lancer TOUS les checks en parallèle avec asyncio.gather
        3. Collecter les résultats (même si certains checks échouent)
        4. Calculer le score global
        5. Sauvegarder dans Redis + MongoDB
        6. Retourner le rapport complet

        Pourquoi asyncio.gather et pas asyncio.TaskGroup ?
        → gather() avec return_exceptions=True continue même si un
          check plante. TaskGroup annule tout au premier échec.
          On veut le rapport partiel : si le scan SSL timeout mais
          que les headers sont OK, on retourne quand même les headers.
          C'est plus utile qu'un échec total.

        En NestJS, l'équivalent serait :
            await Promise.allSettled(checks.map(c => c.run(url)))
          (allSettled, pas all — pour ne pas tout annuler au premier rejet)
        """
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
                # Le check a planté — on log l'erreur et on continue
                logger.error("Check %s failed: %s", check.name, result)
            else:
                report.checks.append(result)

        # Calcule le score global (moyenne des checks réussis)
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
        await asyncio.gather(
            self.redis_repo.save_report(scan_id, report_dict),
            self.mongo_repo.save_report(scan_id, report_dict),
        )

        return report

    async def run_scan_stream(self, scan_id: str, url: str):
        """
        Lance un scan et YIELD chaque résultat dès qu'il est prêt.

        Utilise asyncio.as_completed() pour yield dans l'ordre de
        complétion (le check le plus rapide arrive en premier).

        Pourquoi un wrapper _run_check au lieu d'un mapping task→check ?
        → En Python 3.13, as_completed() retourne des objets internes
          différents des tasks originales. Le mapping par identité
          d'objet ne fonctionne plus. Le wrapper résout ce problème
          en incluant le nom du check directement dans le résultat.
        """
        report = ScanReport(scan_id=scan_id, url=url, status=ScanStatus.RUNNING)
        logger.info("Scan stream %s started for %s", scan_id, url)

        async def _run_check(check: BaseCheck) -> tuple[str, CheckResult | Exception]:
            """Wrapper qui retourne (check_name, résultat ou exception)."""
            try:
                result = await check.run(url)
                return check.name, result
            except Exception as exc:
                return check.name, exc

        # Lance tous les checks en parallèle via le wrapper
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

        # Tous les checks sont terminés — calcule le score global
        report.compute_overall()
        report.status = ScanStatus.DONE

        # Sauvegarde
        report_dict = report.to_dict()
        await asyncio.gather(
            self.redis_repo.save_report(scan_id, report_dict),
            self.mongo_repo.save_report(scan_id, report_dict),
        )

        # Yield l'événement final avec le rapport complet
        yield {
            "event": "scan_complete",
            "data": report_dict,
        }
