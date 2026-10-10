import fakeredis

from scanner.repositories.redis_stream import RedisScanEventStream
from scanner.services import scan_jobs
from tests.unit.services.test_scan_service import BrokenCheck, FakeRepo, OkCheck


class _Ctx(dict):
    pass


def _ctx():
    repo = FakeRepo()
    return _Ctx(
        mongo_repo=repo,
        redis_repo=repo,
        event_stream=RedisScanEventStream(fakeredis.FakeAsyncRedis()),
    )


async def test_job_publishes_events_and_ends_with_scan_complete(monkeypatch):
    monkeypatch.setattr(scan_jobs, "default_checks", lambda: [OkCheck(), BrokenCheck()])
    ctx = _ctx()

    await scan_jobs.run_scan_job(ctx, "s1", "https://x.test")

    events = await ctx["event_stream"].read("s1", block_ms=10)
    assert {e.event for e in events} == {"check_complete", "check_error", "scan_complete"}
    assert events[-1].event == "scan_complete"
    assert ctx["mongo_repo"].reports["s1"]["overall_score"] == 100


async def test_job_publishes_scan_error_when_service_crashes(monkeypatch):
    class Boom:
        def __init__(self, *args, **kwargs):
            pass

        async def run_scan_stream(self, scan_id, url):
            raise RuntimeError("redis down")
            yield  # pragma: no cover

    monkeypatch.setattr(scan_jobs, "ScanService", Boom)
    ctx = _ctx()

    await scan_jobs.run_scan_job(ctx, "s1", "https://x.test")

    events = await ctx["event_stream"].read("s1", block_ms=10)
    assert [e.event for e in events] == ["scan_error"]
    assert "redis down" in events[0].data["error"]
