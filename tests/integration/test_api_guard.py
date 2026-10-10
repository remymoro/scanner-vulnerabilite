import pytest
from fastapi.testclient import TestClient

from scanner.api import security
from scanner.api.main import app


@pytest.fixture
def client():
    # Pas de lifespan (donc pas de Mongo/Redis) : on pose des faux repositories.
    app.state.mongo_repo = app.state.redis_repo = app.state.cache_repo = object()
    security.scan_rate_limiter._hits.clear()
    return TestClient(app)


@pytest.mark.parametrize("path", ["/scan/", "/scan/stream"])
def test_scan_endpoints_refuse_internal_targets(client, path):
    response = client.post(path, json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 400


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_rate_limit_returns_429(client):
    security.scan_rate_limiter.max_scans = 2
    try:
        body = {"url": "http://127.0.0.1/"}
        codes = [client.post("/scan/", json=body).status_code for _ in range(3)]
    finally:
        security.scan_rate_limiter.max_scans = 10
    assert codes == [400, 400, 429]


class _FakeQueue:
    def __init__(self):
        self.jobs = []

    async def enqueue_job(self, name, *args):
        self.jobs.append((name, args))


def test_post_scan_enqueues_a_job(client):
    queue = app.state.queue = _FakeQueue()
    response = client.post("/scan/", json={"url": "https://8.8.8.8/"})
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    assert queue.jobs == [("run_scan_job", (scan_id, "https://8.8.8.8/"))]


async def test_events_endpoint_streams_sse_until_terminal_event():
    import fakeredis
    import httpx

    from scanner.repositories.redis_stream import RedisScanEventStream

    stream = RedisScanEventStream(fakeredis.FakeAsyncRedis())
    await stream.publish("abc", "check_complete", {"check_name": "WAF"})
    await stream.publish("abc", "scan_complete", {"overall_score": 90})
    app.state.event_stream = stream

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/scan/abc/events")

    assert "event: check_complete" in response.text
    assert response.text.rstrip().endswith('data: {"overall_score": 90}')
