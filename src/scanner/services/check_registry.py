"""
Registre des checks : l'unique endroit qui connaît la liste des scanners.

Ajouter un scanner = écrire une classe BaseCheck + l'ajouter dans
`default_checks()`. Les routers n'ont plus rien à modifier.
"""

from scanner.checks.dns_check import DnsCheck
from scanner.checks.headers import HeadersCheck
from scanner.checks.rate_limit_check import RateLimitCheck
from scanner.checks.ssl_tls import SslCheck
from scanner.checks.waf_check import WafCheck
from scanner.core.interfaces.base_check import BaseCheck


def default_checks() -> list[BaseCheck]:
    """Instancie les checks actifs. Les checks sont légers et sans état."""
    return [
        HeadersCheck(),
        SslCheck(),
        DnsCheck(),
        WafCheck(),
        RateLimitCheck(),
    ]
