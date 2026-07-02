"""
Entités du domaine pour les résultats de checks.

Ces classes représentent les CONCEPTS métier — elles ne connaissent
ni FastAPI, ni MongoDB, ni aucune librairie externe.
En NestJS/DDD, c'est l'équivalent de tes fichiers dans domain/entities/.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """
    Pourquoi un Enum et pas juste des strings ?

    Avec des strings libres, rien n'empêche un dev d'écrire "CRITIC"
    au lieu de "CRITICAL" — le bug est silencieux et le scoring sera faux.
    L'Enum force un vocabulaire fermé : si tu tapes Severity.CRITIC,
    Python plante immédiatement avec une AttributeError.

    En NestJS, c'est exactement le même principe avec les enums TypeScript.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(StrEnum):
    """
    État d'un test individuel : ok (la protection est en place),
    fail (absente ou mal configurée), ou warn (présente mais partielle).
    """

    OK = "ok"
    FAIL = "fail"
    WARN = "warn"


@dataclass
class CheckDetail:
    """
    Un test individuel au sein d'un check.

    Exemple pour le HeadersCheck :
        CheckDetail(
            name="Content-Security-Policy",
            status=Status.FAIL,
            value=None,
            description="Protège contre les injections XSS"
        )

    Pourquoi un dataclass et pas un dict ?
    → Autocomplétion dans l'éditeur (detail.name vs detail["nmae"])
    → Typage vérifié par ruff/mypy
    → Immutabilité du contrat : impossible d'ajouter une clé "surprise"
    """

    name: str
    status: Status
    value: str | None = None
    description: str = ""


@dataclass
class CheckResult:
    """
    Le résultat complet d'un check. C'est le "formulaire standardisé"
    que chaque scanner remplit, quelle que soit la technologie utilisée.

    Dans ton stage, IScannerInterface retournait un dict avec
    "category_name", "score", "notation", "tests". Ici c'est la même
    idée, mais typée — impossible de retourner un résultat incomplet
    sans que Python ne le détecte.

    score: 0 (tout est cassé) à 100 (tout est parfait)
    grade: la note lisible (A/B/C/D/F), calculée à partir du score
    """

    check_name: str
    severity: Severity
    score: int
    grade: str
    details: list[CheckDetail] = field(default_factory=list)

    @staticmethod
    def compute_grade(score: int) -> str:
        """
        Convertit un score numérique en note lisible.

        Pourquoi une méthode statique sur l'entité plutôt qu'une
        fonction utilitaire séparée ? Parce que la règle de notation
        EST une règle métier — elle fait partie du domaine. La mettre
        ailleurs séparerait artificiellement des choses qui vont ensemble.

        C'est ton get_score_notation() du stage, avec des seuils précis.
        """
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"
