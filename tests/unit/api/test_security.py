import pytest
from fastapi import HTTPException

from scanner.api.security import ScanRateLimiter, ensure_public_target
from scanner.core.exceptions import UnsafeTargetError


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost:8000/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "ftp://example.com/",
    ],
)
async def test_internal_targets_are_refused(url):
    with pytest.raises(UnsafeTargetError):
        await ensure_public_target(url)


async def test_public_ip_is_accepted():
    await ensure_public_target("https://8.8.8.8/")


def test_rate_limiter_blocks_after_max_scans():
    limiter = ScanRateLimiter(max_scans=2, window=60)
    limiter.check("1.2.3.4")
    limiter.check("1.2.3.4")
    with pytest.raises(HTTPException) as exc:
        limiter.check("1.2.3.4")
    assert exc.value.status_code == 429
    limiter.check("5.6.7.8")  # une autre IP n'est pas touchée
