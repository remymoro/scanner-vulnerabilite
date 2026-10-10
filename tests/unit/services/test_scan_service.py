from scanner.core.entities.check_result import CheckResult, Severity
from scanner.core.interfaces.base_check import BaseCheck
from scanner.services.check_registry import default_checks
from scanner.services.scan_service import ScanService


class FakeRepo:
    def __init__(self):
        self.reports, self.cache = {}, {}

    async def save_report(self, scan_id, report):
        self.reports[scan_id] = report

    async def get_report(self, scan_id):
        return self.reports.get(scan_id)

    async def get_scan(self, domain):
        return self.cache.get(domain)

    async def set_scan(self, domain, report):
        self.cache[domain] = report


class OkCheck(BaseCheck):
    name = "ok"
    severity = "low"

    async def run(self, url):
        return CheckResult("ok", Severity.LOW, 100, "A")


class BrokenCheck(BaseCheck):
    name = "broken"
    severity = "low"

    async def run(self, url):
        raise RuntimeError("boom")


def _service(checks, repo):
    return ScanService(checks=checks, mongo_repo=repo, redis_repo=repo, cache_repo=repo)


async def test_partial_report_when_a_check_fails():
    repo = FakeRepo()
    report = await _service([OkCheck(), BrokenCheck()], repo).run_scan("id1", "https://x.test")
    assert len(report.checks) == 1
    assert repo.reports["id1"]["overall_score"] == 100


async def test_second_scan_of_same_domain_hits_cache():
    repo = FakeRepo()
    service = _service([OkCheck()], repo)
    await service.run_scan("id1", "https://x.test")
    repo.cache["x.test"]["overall_score"] = 42  # marqueur : prouve qu'on relit le cache
    report = await service.run_scan("id2", "https://x.test")
    assert report.overall_score == 42


async def test_stream_emits_check_events_then_scan_complete():
    events = [e async for e in _service([OkCheck(), BrokenCheck()], FakeRepo()).run_scan_stream(
        "id1", "https://x.test")]
    assert [e["event"] for e in events].count("check_complete") == 1
    assert [e["event"] for e in events].count("check_error") == 1
    assert events[-1]["event"] == "scan_complete"


def test_registry_contains_all_checks():
    names = {c.name for c in default_checks()}
    assert {"Web Application Firewall", "Rate Limiting"} <= names
    assert len(names) == 5
