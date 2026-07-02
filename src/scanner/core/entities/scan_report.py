"""
Entité du rapport de scan complet.

Un ScanReport contient le résultat de TOUS les checks lancés sur une URL.
C'est ce qui est sauvegardé dans MongoDB et Redis, et renvoyé au client.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from scanner.core.entities.check_result import CheckResult


class ScanStatus(StrEnum):
    """
    Cycle de vie d'un scan :
      pending  → le scan vient d'être lancé, aucun check terminé
      running  → au moins un check est en cours
      done     → tous les checks sont terminés
      error    → le scan a échoué (URL injoignable, erreur interne)
    """

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


@dataclass
class ScanReport:
    """
    Rapport complet d'un scan de sécurité.

    scan_id : identifiant unique du scan (UUID)
    url : l'URL scannée
    status : état du scan (pending/running/done/error)
    checks : liste des résultats de chaque check individuel
    overall_score : moyenne pondérée des scores de tous les checks
    overall_grade : note globale dérivée du overall_score
    """

    scan_id: str
    url: str
    status: ScanStatus = ScanStatus.PENDING
    checks: list[CheckResult] = field(default_factory=list)
    overall_score: int = 0
    overall_grade: str = "F"

    def compute_overall(self) -> None:
        """
        Calcule le score global à partir des scores individuels.

        Pourquoi une moyenne simple et pas une pondération ?
        → Pour un premier MVP, la moyenne suffit. On pourra
          pondérer par sévérité plus tard (un check CRITICAL
          pèse plus qu'un check LOW). Mais la structure est
          prête : chaque CheckResult a déjà un champ severity.
        """
        if not self.checks:
            self.overall_score = 0
            self.overall_grade = "F"
            return

        total = sum(check.score for check in self.checks)
        self.overall_score = total // len(self.checks)
        self.overall_grade = CheckResult.compute_grade(self.overall_score)

    def to_dict(self) -> dict:
        """
        Convertit le rapport en dict pour le stockage MongoDB/Redis.

        Pourquoi pas juste dataclasses.asdict() ?
        → asdict() fait une copie récursive profonde qui convertit
          les StrEnum en strings brutes. En contrôlant la conversion,
          on garantit un format JSON stable et prévisible.
        """
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "status": self.status.value,
            "overall_score": self.overall_score,
            "overall_grade": self.overall_grade,
            "checks": [
                {
                    "check_name": c.check_name,
                    "severity": c.severity.value if hasattr(c.severity, "value") else c.severity,
                    "score": c.score,
                    "grade": c.grade,
                    "details": [
                        {
                            "name": d.name,
                            "status": d.status.value,
                            "value": d.value,
                            "description": d.description,
                        }
                        for d in c.details
                    ],
                }
                for c in self.checks
            ],
        }
