import httpx
import respx

from scanner.checks.rate_limit_check import RateLimitCheck

URL = "https://example.test/"


@respx.mock
async def test_blocking_rate_limiter_scores_100():
    respx.get(URL).mock(side_effect=[httpx.Response(200)] * 5 + [httpx.Response(429)] * 5)
    result = await RateLimitCheck(burst=10, concurrency=1).run(URL)
    assert result.score == 100
    assert result.details[0].value == "5/10 requêtes limitées"


@respx.mock
async def test_announced_limit_without_blocking_scores_70():
    respx.get(URL).mock(return_value=httpx.Response(200, headers={"X-RateLimit-Limit": "100"}))
    result = await RateLimitCheck(burst=5).run(URL)
    assert result.score == 70


@respx.mock
async def test_no_rate_limit_scores_30():
    respx.get(URL).mock(return_value=httpx.Response(200))
    result = await RateLimitCheck(burst=5).run(URL)
    assert result.score == 30


@respx.mock
async def test_no_response_scores_0():
    respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    result = await RateLimitCheck(burst=3).run(URL)
    assert result.score == 0
