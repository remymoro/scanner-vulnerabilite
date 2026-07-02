"""
DnsCheck — Phase 8 du scanner.

Interroge les enregistrements DNS de la cible pour identifier
les vecteurs d'attaque liés à la configuration DNS.

Pourquoi DNS comme surface d'attaque ?
  Le DNS est l'annuaire public d'internet. N'importe qui peut
  l'interroger. Un domaine mal configuré révèle son infrastructure,
  expose ses serveurs mail au spoofing, ou laisse son zone transfer
  ouvert — ce qui donne à un attaquant la carte complète du domaine
  en une seule requête.

Librairie : dnspython
  - dns.resolver  → requêtes DNS standard (A, MX, TXT, NS)
  - dns.zone      → tentative de zone transfer (AXFR)
  - dns.query     → requête directe au serveur NS autoritaire

Pattern identique à SslCheck :
  - méthodes internes synchrones (_check_a, _check_mx, etc.)
  - run() les enveloppe dans asyncio.to_thread()
  - l'event loop n'est jamais bloqué
"""

import asyncio
from urllib.parse import urlparse

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from scanner.core.entities.check_result import CheckDetail, CheckResult, Severity, Status
from scanner.core.interfaces.base_check import BaseCheck


class DnsCheck(BaseCheck):
    """
    Check DNS — analyse la surface d'attaque liée aux enregistrements DNS.

    Ce check ne teste pas l'application web mais son infrastructure DNS.
    C'est la couche en dessous de HTTP — avant même qu'une requête
    arrive sur le serveur, le DNS a déjà révélé des informations.
    """

    @property
    def name(self) -> str:
        return "DNS Configuration"

    @property
    def severity(self) -> str:
        # HIGH car un zone transfer ouvert ou un SPF absent
        # expose toute l'infrastructure d'un coup
        return "HIGH"

    async def run(self, url: str) -> CheckResult:
        """
        Point d'entrée async.

        On extrait le domaine depuis l'URL (https://monsite.fr/page
        → monsite.fr) puis on délègue à _run_sync() dans un thread
        pour ne pas bloquer l'event loop pendant les requêtes DNS.

        Pourquoi extraire le domaine ?
          dns.resolver.resolve() attend un nom de domaine pur,
          pas une URL complète avec https:// et chemin.
        """
        domain = urlparse(url).hostname or url
        return await asyncio.to_thread(self._run_sync, domain)

    def _run_sync(self, domain: str) -> CheckResult:
        """
        Orchestre les 5 checks DNS de façon synchrone.

        Appelé depuis un thread séparé — peut bloquer librement.
        Agrège les résultats et calcule le score global.
        """
        tests = {}

        tests["a_record"] = self._check_a(domain)
        tests["mx_record"] = self._check_mx(domain)
        tests["txt_record"] = self._check_txt(domain)
        tests["ns_record"] = self._check_ns(domain)
        tests["zone_transfer"] = self._check_axfr(domain)

        score = self._calculate_score(tests)

        return CheckResult(
            check_name=self.name,
            severity=Severity.HIGH,
            score=score,
            grade=CheckResult.compute_grade(score),
            details=self._build_details(tests),
        )

    def _build_details(self, tests: dict) -> list:
        """
        Convertit les résultats internes (dicts) en CheckDetail typés.

        Pourquoi cette conversion ?
        CheckResult.details attend des CheckDetail — l'entité du domaine.
        Nos méthodes _check_*() retournent des dicts simples pour rester
        lisibles en interne. Cette méthode fait le pont entre les deux.
        C'est le même rôle qu'un DTO converter dans ton architecture NestJS.
        """
        status_map = {
            "ok": Status.OK,
            "warning": Status.WARN,
            "warn": Status.WARN,
            "error": Status.FAIL,
            "info": Status.OK,
        }

        labels = {
            "a_record": "Enregistrement A (IPv4)",
            "mx_record": "Enregistrement MX (mail)",
            "txt_record": "Enregistrement TXT (SPF/DKIM)",
            "ns_record": "Enregistrement NS (autoritaire)",
            "zone_transfer": "Zone Transfer AXFR",
        }

        details = []
        for key, result in tests.items():
            details.append(
                CheckDetail(
                    name=labels.get(key, key),
                    status=status_map.get(result.get("result", "ok"), Status.OK),
                    value=str(result.get("value", "")) or None,
                    description=result.get("message", ""),
                )
            )
        return details

    def _check_a(self, domain: str) -> dict:
        """
        Enregistrement A — adresse IPv4 du serveur.

        Ce n'est pas une faille en soi — l'IP est publique par nature.
        Mais elle confirme à un attaquant que le domaine est actif
        et lui donne l'IP pour des scans de ports ultérieurs.

        On note 'ok' si l'enregistrement existe (domaine actif),
        on note 'error' si le domaine ne résout pas du tout.
        """
        try:
            answers = dns.resolver.resolve(domain, "A")
            ips = [rdata.address for rdata in answers]
            return {
                "result": "ok",
                "message": f"{len(ips)} adresse(s) trouvée(s)",
                "value": ips,
            }
        except dns.exception.DNSException:
            return {
                "result": "error",
                "message": "Aucun enregistrement A — domaine inactif ou DNS mal configuré",
                "value": [],
            }

    def _check_txt(self, domain: str) -> dict:
        """
        Interroge les TXT sur le domaine racine ET le sous-domaine.

        SPF/DMARC vivent sur le domaine racine (remymoro.fr).
        DKIM vit sur un sous-domaine spécifique (mail._domainkey.remymoro.fr).
        On extrait la racine en prenant les deux derniers labels du domaine.
        """
        # Extraire le domaine racine : collecte-staging.remymoro.fr → remymoro.fr
        parts = domain.rstrip(".").split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        records = []
        domains_to_check = list(dict.fromkeys([root_domain, domain]))

        for d in domains_to_check:
            try:
                answers = dns.resolver.resolve(d, "TXT")
                records.extend([rdata.to_text().strip('"') for rdata in answers])
            except dns.exception.DNSException:
                continue

        if not records:
            return {
                "result": "error",
                "message": "Aucun enregistrement TXT trouvé",
                "value": [],
            }

        spf_present = any("v=spf1" in r for r in records)
        dmarc_present = any("v=DMARC1" in r for r in records)

        if not spf_present:
            return {
                "result": "error",
                "message": f"SPF absent sur {root_domain} — email spoofing possible",
                "value": records,
            }

        if not dmarc_present:
            return {
                "result": "warning",
                "message": f"SPF présent mais DMARC absent sur {root_domain}",
                "value": records,
            }

        return {
            "result": "ok",
            "message": "SPF et DMARC présents",
            "value": records,
        }

    def _check_ns(self, domain: str) -> dict:
        """
        Enregistrement NS — serveurs DNS autoritaires du domaine.

        Révèle quel hébergeur DNS gère le domaine (OVH, Cloudflare,
        AWS Route53...). Nécessaire pour la tentative de zone transfer
        ci-dessous — on doit connaître les NS avant de les interroger.
        """
        try:
            answers = dns.resolver.resolve(domain, "NS")
            ns_records = [str(rdata.target) for rdata in answers]
            return {
                "result": "ok",
                "message": f"{len(ns_records)} serveur(s) NS trouvé(s)",
                "value": ns_records,
            }
        except dns.exception.DNSException:
            return {
                "result": "error",
                "message": "Aucun enregistrement NS",
                "value": [],
            }

    def _check_axfr(self, domain: str) -> dict:
        """
        Zone Transfer (AXFR) — tentative de récupérer TOUS les
        enregistrements DNS du domaine en une seule requête.

        C'est la check la plus critique du DnsCheck.

        Pourquoi c'est grave si c'est ouvert ?
          Un zone transfer expose d'un coup tous les sous-domaines,
          toutes les IPs, tous les serveurs — même ceux non publiés
          (staging, admin, api-interne...). C'est la carte complète
          de l'infrastructure DNS.

        On va directement au serveur NS autoritaire (pas au résolveur
        local) parce que c'est lui qui possède la zone et peut la
        transférer. Le résolveur ne fait que retransmettre des
        questions individuelles, il ne détient pas la zone entière.

        Timeout court (3s) — si le serveur refuse, il répond vite.
        """
        try:
            # D'abord récupérer les serveurs NS autoritaires
            ns_answers = dns.resolver.resolve(domain, "NS")
            ns_records = [str(rdata.target) for rdata in ns_answers]
        except dns.exception.DNSException:
            return {
                "result": "info",
                "message": "NS introuvable — zone transfer impossible à tester",
                "value": None,
            }

        for ns in ns_records:
            try:
                # Résoudre l'IP du serveur NS
                ns_ip_answers = dns.resolver.resolve(ns, "A")
                ns_ip = ns_ip_answers[0].address

                # Tenter le zone transfer directement sur le NS autoritaire
                # dns.query.xfr() fait la requête AXFR en TCP
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=3))

                # Si on arrive ici, le zone transfer a réussi — c'est critique
                records_count = len(list(zone.nodes.keys()))
                return {
                    "result": "error",
                    "message": (
                        f"Zone transfer OUVERT sur {ns} — "
                        f"{records_count} enregistrements exposés"
                    ),
                    "value": ns,
                }

            except Exception:
                # Refusé, timeout, ou autre erreur — c'est le comportement normal
                continue

        return {
            "result": "ok",
            "message": "Zone transfer refusé sur tous les serveurs NS",
            "value": None,
        }

    def _check_mx(self, domain: str) -> dict:
        parts = domain.rstrip(".").split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        try:
            answers = dns.resolver.resolve(root_domain, "MX")
            mx_records = [
                {"priority": rdata.preference, "host": str(rdata.exchange)} for rdata in answers
            ]
            return {
                "result": "ok",
                "message": f"{len(mx_records)} serveur(s) mail sur {root_domain}",
                "value": mx_records,
            }
        except dns.exception.DNSException:
            return {
                "result": "info",
                "message": "Aucun enregistrement MX",
                "value": [],
            }

    def _calculate_score(self, tests: dict) -> int:
        """
        Score global basé sur les résultats des 5 checks.

        Pondération par criticité :
          zone_transfer ouvert = -40 (critique)
          txt_record absent    = -25 (SPF manquant = spoofing)
          a_record absent      = -15 (domaine inactif)
          ns_record absent     = -10
          mx_record info       =   0 (neutre, pas obligatoire)
        """
        score = 100

        penalties = {
            "zone_transfer": {"error": 40},
            "txt_record": {"error": 25, "warning": 10},
            "a_record": {"error": 15},
            "ns_record": {"error": 10},
        }

        for check_name, penalty_map in penalties.items():
            result = tests.get(check_name, {}).get("result", "ok")
            score -= penalty_map.get(result, 0)

        return max(0, score)
