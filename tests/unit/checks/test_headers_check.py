import httpx
import respx

from scanner.checks.headers import SECURITY_HEADERS, HeadersCheck

URL = "https://example.test/"


@respx.mock
async def test_all_headers_present_scores_100():
    headers = {name: "x" for name, _ in SECURITY_HEADERS}
    respx.get(URL).mock(return_value=httpx.Response(200, headers=headers))
    result = await HeadersCheck().run(URL)
    assert result.score == 100
    assert result.grade == "A"


@respx.mock
async def test_missing_headers_lower_the_score():
    respx.get(URL).mock(
        return_value=httpx.Response(200, headers={"Content-Security-Policy": "default-src 'self'"})
    )
    result = await HeadersCheck().run(URL)
    assert result.score == 16  # 1 en-tête sur 6
    assert sum(d.status.value == "fail" for d in result.details) == 5


@respx.mock
async def test_network_error_scores_0():
    respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    result = await HeadersCheck().run(URL)
    assert result.score == 0
