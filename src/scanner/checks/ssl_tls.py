"""
SslCheck — vérifie la configuration SSL/TLS d'un serveur.

Utilise SSLyze pour analyser :
- Protocoles dépréciés (SSL 2/3, TLS 1.0/1.1)
- Protocoles sécurisés (TLS 1.2/1.3)
- Cipher suites : analyse structurelle basée sur les standards publics
- Certificat (validité, expiration, taille de clé)
- Vulnérabilités connues (Heartbleed)

Chaque règle de classification des cipher suites est justifiée par
une source publique (RFC, NIST, CVE) — aucune donnée sous licence tierce.

Références :
  - RFC 8446 (TLS 1.3) : https://datatracker.ietf.org/doc/html/rfc8446
  - RFC 7465 (interdiction RC4) : https://datatracker.ietf.org/doc/html/rfc7465
  - NIST SP 800-52 Rev.2 : recommandations TLS
  - OWASP TLS Cheat Sheet : https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cheat_Sheet.html
"""

import asyncio
from datetime import UTC, datetime
from urllib.parse import urlparse

from sslyze import (
    ScanCommand,
    Scanner,
    ServerScanRequest,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved

from scanner.core.entities.check_result import (
    CheckDetail,
    CheckResult,
    Severity,
    Status,
)
from scanner.core.interfaces.base_check import BaseCheck

DEPRECATED_PROTOCOLS = {
    ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL 2.0",
    ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL 3.0",
    ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS 1.0",
    ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS 1.1",
}

SECURE_PROTOCOLS = {
    ScanCommand.TLS_1_2_CIPHER_SUITES: "TLS 1.2",
    ScanCommand.TLS_1_3_CIPHER_SUITES: "TLS 1.3",
}

# ── Algorithmes cassés (sources publiques) ──────────────────────────
# Chaque entrée est justifiée par une RFC ou un CVE public.
INSECURE_CIPHERS = {
    "RC4": "Biais statistiques prouvés — RFC 7465 interdit RC4",
    "DES": "Clé 56 bits, cassable par force brute — retiré par NIST",
    "3DES": "Clé 112 bits, attaque SWEET32 — CVE-2016-2183",
    "EXPORT": "Clé 40-56 bits, attaque FREAK — CVE-2015-0204",
    "NULL": "Aucun chiffrement, trafic en clair",
    "MD5": "Collisions prouvées depuis 2004 — NIST déprécié",
}

# ── Propriétés d'échange de clé sans forward secrecy ────────────────
# Source : RFC 8446 section 1.2, NIST SP 800-52 Rev.2
NO_PFS_KEX = {"RSA", "DH", "ECDH", "KRB5", "PSK", "SRP"}

# ── Préfixes qui garantissent PFS (échange éphémère) ────────────────
PFS_PREFIXES = ("ECDHE", "DHE")


def _analyze_cipher_suite(cipher_name: str) -> tuple[str, list[str]]:
    """
    Analyse une cipher suite par sa structure, pas par une base tierce.

    Trois niveaux de vérification, chacun justifié par un standard public :

    1. INSECURE — algorithme cassé (RC4, DES, NULL, MD5, EXPORT)
       Sources : RFC 7465, CVE-2016-2183, CVE-2015-0204, NIST
       → Score : un seul suffit pour classer "insecure"

    2. WEAK — propriété structurelle dangereuse
       a) Mode CBC : vulnérable aux padding oracles (POODLE CVE-2014-3566)
       b) Pas de forward secrecy : si la clé privée fuite, le passé aussi
       c) Auth "anon" : aucune vérification d'identité, MITM trivial
       Sources : RFC 8446, NIST SP 800-52

    3. SECURE/RECOMMENDED — aucun problème détecté
       Les suites TLS 1.3 (TLS_AES_*, TLS_CHACHA*) sont recommandées
       par design : PFS obligatoire, AEAD uniquement.

    Retourne (niveau, liste_de_raisons).
    """
    problems = []
    is_insecure = False

    # ── 1. Algorithmes cassés ──
    for keyword, reason in INSECURE_CIPHERS.items():
        if keyword in cipher_name:
            problems.append(reason)
            is_insecure = True

    if is_insecure:
        return "insecure", problems

    # ── 2. Auth anonyme (pas dans les keywords car c'est un rôle, pas un algo) ──
    if "_anon_" in cipher_name or cipher_name.startswith("TLS_ECDH_anon"):
        problems.append("authentification anonyme — MITM trivial")
        return "insecure", problems

    # ── 3. TLS 1.3 suites — sûres par design ──
    # En TLS 1.3, PFS est obligatoire et seuls les modes AEAD sont permis.
    # Les suites commencent par TLS_AES_ ou TLS_CHACHA20_
    if cipher_name.startswith(("TLS_AES_", "TLS_CHACHA20_")):
        return "recommended", []

    # ── 4. Mode CBC — padding oracle (POODLE, Lucky13) ──
    # Source : CVE-2014-3566, RFC 8446 retire CBC de TLS 1.3
    if "CBC" in cipher_name:
        problems.append("mode CBC — vulnérable aux padding oracles (CVE-2014-3566)")

    # ── 5. Forward secrecy ──
    # Sans ECDHE ou DHE, la clé de session est dérivée de la clé
    # privée du serveur. Si elle fuite (vol, saisie), tout le
    # trafic passé enregistré est déchiffrable.
    has_pfs = any(
        cipher_name.startswith(f"TLS_{p}_") or f"_{p}_" in cipher_name for p in PFS_PREFIXES
    )
    if not has_pfs:
        problems.append("pas de forward secrecy — le passé est déchiffrable si la clé fuite")

    if problems:
        return "weak", problems

    return "secure", []


class SslCheck(BaseCheck):
    """
    Vérifie la configuration SSL/TLS d'un serveur.

    SSLyze est synchrone — on le lance dans un thread séparé
    via asyncio.to_thread() pour ne pas bloquer l'event loop.
    """

    @property
    def name(self) -> str:
        return "SSL/TLS Configuration"

    @property
    def severity(self) -> str:
        return Severity.CRITICAL

    async def run(self, url: str) -> CheckResult:
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return self._error_result(f"URL invalide : {url}")

            return await asyncio.to_thread(self._scan_sync, hostname)

        except ServerHostnameCouldNotBeResolved:
            return self._error_result(f"Impossible de résoudre : {hostname}")
        except Exception as exc:
            return self._error_result(f"Erreur SSL scan : {exc}")

    def _scan_sync(self, hostname: str) -> CheckResult:
        details: list[CheckDetail] = []
        score_deductions = 0

        scan_request = ServerScanRequest(hostname)
        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for result in scanner.get_results():
            if result.scan_status != ServerScanStatusEnum.COMPLETED:
                return self._error_result(f"Scan incomplet pour {hostname}")

            # 1. PROTOCOLES DÉPRÉCIÉS
            for scan_cmd, proto_name in DEPRECATED_PROTOCOLS.items():
                cmd_result = result.scan_result.get(scan_cmd)
                if cmd_result and cmd_result.result:
                    accepted = cmd_result.result.accepted_cipher_suites
                    if accepted:
                        details.append(
                            CheckDetail(
                                name=f"Protocole {proto_name}",
                                status=Status.FAIL,
                                description=(
                                    f"{proto_name} accepté ({len(accepted)} suites). "
                                    "Vulnérable aux attaques de downgrade."
                                ),
                            )
                        )
                        score_deductions += 25
                    else:
                        details.append(
                            CheckDetail(
                                name=f"Protocole {proto_name}",
                                status=Status.OK,
                                description=f"{proto_name} désactivé.",
                            )
                        )

            # 2. PROTOCOLES SÉCURISÉS + ANALYSE DES CIPHERS
            has_secure = False
            insecure_count = 0
            weak_count = 0

            for scan_cmd, proto_name in SECURE_PROTOCOLS.items():
                cmd_result = result.scan_result.get(scan_cmd)
                if cmd_result and cmd_result.result:
                    accepted = cmd_result.result.accepted_cipher_suites
                    if accepted:
                        has_secure = True
                        details.append(
                            CheckDetail(
                                name=f"Protocole {proto_name}",
                                status=Status.OK,
                                value=f"{len(accepted)} cipher suites",
                                description=f"{proto_name} actif.",
                            )
                        )

                        for cipher in accepted:
                            cipher_name = cipher.cipher_suite.name
                            level, problems = _analyze_cipher_suite(cipher_name)

                            if level == "insecure":
                                insecure_count += 1
                                details.append(
                                    CheckDetail(
                                        name=f"Cipher {cipher_name}",
                                        status=Status.FAIL,
                                        description=f"{proto_name} : {', '.join(problems)}.",
                                    )
                                )
                            elif level == "weak":
                                weak_count += 1
                                details.append(
                                    CheckDetail(
                                        name=f"Cipher {cipher_name}",
                                        status=Status.WARN,
                                        description=f"{proto_name} : {', '.join(problems)}.",
                                    )
                                )

            if insecure_count > 0:
                score_deductions += min(insecure_count * 10, 40)
            if weak_count > 0:
                score_deductions += min(weak_count * 5, 20)

            if not has_secure:
                details.append(
                    CheckDetail(
                        name="Protocoles sécurisés",
                        status=Status.FAIL,
                        description="Ni TLS 1.2 ni TLS 1.3 n'est actif.",
                    )
                )
                score_deductions += 50

            # 3. CERTIFICAT
            cert_result = result.scan_result.get(ScanCommand.CERTIFICATE_INFO)
            if cert_result and cert_result.result:
                for deployment in cert_result.result.certificate_deployments:
                    cert = deployment.received_certificate_chain[0]

                    expiry = cert.not_valid_after_utc
                    now = datetime.now(UTC)
                    days_left = (expiry - now).days

                    if days_left < 0:
                        details.append(
                            CheckDetail(
                                name="Certificat expiré",
                                status=Status.FAIL,
                                value=f"expiré depuis {abs(days_left)} jours",
                                description="Avertissement de sécurité dans le navigateur.",
                            )
                        )
                        score_deductions += 30
                    elif days_left < 30:
                        details.append(
                            CheckDetail(
                                name="Certificat bientôt expiré",
                                status=Status.WARN,
                                value=f"expire dans {days_left} jours",
                                description="Renouvellement urgent.",
                            )
                        )
                        score_deductions += 10
                    else:
                        details.append(
                            CheckDetail(
                                name="Certificat valide",
                                status=Status.OK,
                                value=f"expire dans {days_left} jours",
                                description="Date de validité correcte.",
                            )
                        )

                    pub_key = cert.public_key()
                    key_size = getattr(pub_key, "key_size", None)
                    if key_size is not None:
                        key_type = type(pub_key).__name__
                        if "RSA" in key_type and key_size < 2048:
                            details.append(
                                CheckDetail(
                                    name="Clé du certificat",
                                    status=Status.FAIL,
                                    value=f"{key_type} {key_size} bits",
                                    description=f"RSA {key_size} bits insuffisant (min 2048).",
                                )
                            )
                            score_deductions += 20
                        else:
                            details.append(
                                CheckDetail(
                                    name="Clé du certificat",
                                    status=Status.OK,
                                    value=f"{key_type} {key_size} bits",
                                    description="Taille de clé suffisante.",
                                )
                            )

                    for validation in deployment.path_validation_results:
                        if not validation.was_validation_successful:
                            details.append(
                                CheckDetail(
                                    name="Chaîne de certificats",
                                    status=Status.FAIL,
                                    description="Chaîne de certificats invalide.",
                                )
                            )
                            score_deductions += 20
                            break

            # 4. HEARTBLEED
            heartbleed_result = result.scan_result.get(ScanCommand.HEARTBLEED)
            if heartbleed_result and heartbleed_result.result:
                if heartbleed_result.result.is_vulnerable_to_heartbleed:
                    details.append(
                        CheckDetail(
                            name="Heartbleed (CVE-2014-0160)",
                            status=Status.FAIL,
                            description="Vulnérable — fuite mémoire serveur possible.",
                        )
                    )
                    score_deductions += 40
                else:
                    details.append(
                        CheckDetail(
                            name="Heartbleed",
                            status=Status.OK,
                            description="Non vulnérable.",
                        )
                    )

        score = max(0, 100 - score_deductions)
        return CheckResult(
            check_name=self.name,
            severity=self.severity,
            score=score,
            grade=CheckResult.compute_grade(score),
            details=details,
        )

    def _error_result(self, message: str) -> CheckResult:
        return CheckResult(
            check_name=self.name,
            severity=self.severity,
            score=0,
            grade="F",
            details=[
                CheckDetail(
                    name="Connection",
                    status=Status.FAIL,
                    description=message,
                )
            ],
        )
