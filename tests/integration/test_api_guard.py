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
