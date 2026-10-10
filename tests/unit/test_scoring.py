from scanner.core.entities.check_result import CheckResult, Severity
from scanner.core.entities.scan_report import ScanReport


def _check(score: int, severity: Severity) -> CheckResult:
    return CheckResult("c", severity, score, CheckResult.compute_grade(score))


def test_empty_report_is_F():
    report = ScanReport("id", "https://x.test")
    report.compute_overall()
    assert (report.overall_score, report.overall_grade) == (0, "F")


def test_high_severity_weighs_more_than_low():
    report = ScanReport("id", "https://x.test")
    report.checks = [_check(0, Severity.HIGH), _check(100, Severity.LOW)]
    report.compute_overall()
    # (0*4 + 100*2) / 6 = 33, et non 50 comme avec une moyenne simple
    assert report.overall_score == 33


def test_uppercase_severity_string_is_accepted():
    report = ScanReport("id", "https://x.test")
    report.checks = [_check(80, "HIGH")]  # type: ignore[arg-type]
    report.compute_overall()
    assert report.overall_score == 80
    assert report.overall_grade == "B"
