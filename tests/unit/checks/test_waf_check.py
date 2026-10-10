import httpx
import respx

from scanner.checks.waf_check import WafCheck, fingerprint_waf

URL = "https://example.test/"


def test_fingerprint_detects_cloudflare_by_header():
    assert fingerprint_waf(httpx.Headers({"cf-ray": "abc"})) == "Cloudflare"


def test_fingerprint_detects_by_server_and_cookie():
    assert fingerprint_waf(httpx.Headers({"server": "AkamaiGHost"})) == "Akamai"
    assert fingerprint_waf(httpx.Headers({"set-cookie": "incap_ses_1=x"})) == "Imperva Incapsula"


def test_fingerprint_returns_none_for_plain_server():
    assert fingerprint_waf(httpx.Headers({"server": "nginx"})) is None


@respx.mock
async def test_known_waf_scores_100():
    respx.get(URL).mock(return_value=httpx.Response(200, headers={"cf-ray": "abc"}))
    result = await WafCheck().run(URL)
    assert result.score == 100
    assert result.details[0].value == "Cloudflare"


@respx.mock
async def test_unknown_filtering_scores_85():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403 if request.url.params else 200)

    respx.get(URL).mock(side_effect=handler)
    result = await WafCheck().run(URL)
    assert result.score == 85


@respx.mock
async def test_no_waf_scores_30():
    respx.get(URL).mock(return_value=httpx.Response(200))
    result = await WafCheck().run(URL)
    assert result.score == 30
    assert result.grade == "F"


@respx.mock
async def test_unreachable_target_scores_0():
    respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    result = await WafCheck().run(URL)
    assert result.score == 0
