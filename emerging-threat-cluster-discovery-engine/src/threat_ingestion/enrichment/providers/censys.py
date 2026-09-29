from __future__ import annotations

import asyncio
from typing import Any

from threat_ingestion.config import Settings
from threat_ingestion.domain.models import EnrichmentResult

from .base import EnrichmentProvider

HOST_LOOKUP_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
HOST_ACCEPT = "application/vnd.censys.api.v3.host.v1+json"
CERT_HISTORY_URL = "https://api.platform.censys.io/v3/threat-hunting/certificate/{certificate_id}/observations/hosts"


class CensysProvider(EnrichmentProvider):
    """Free-wallet host lookup for ASN, DNS, services, TLS, and host context.
    Censys permits one concurrent request for Free accounts, so requests through
    this provider instance are serialized. Add an organization id only when one exists."""

    provider = "censys"
    applies_to = {"ip"}

    def __init__(self, settings: Settings, client=None) -> None:
        super().__init__(settings, client)
        self._request_lock = asyncio.Lock()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.censys_personal_access_token}"}

    def _org_params(self) -> dict[str, str]:
        if self.settings.censys_organization_id:
            return {"organization_id": self.settings.censys_organization_id}
        return {}

    async def _lookup(self, indicator_type: str, indicator_value: str) -> EnrichmentResult:
        if not self.settings.censys_personal_access_token:
            return EnrichmentResult(
                provider=self.provider,
                indicator_type="ip",
                indicator_value=indicator_value,
                error="CENSYS_PERSONAL_ACCESS_TOKEN not configured; skipped",
            )
        headers = {
            **self._headers(),
            "Accept": HOST_ACCEPT,
        }
        async with self._request_lock:
            response = await self.client.get(
                HOST_LOOKUP_URL.format(ip=indicator_value),
                headers=headers,
                params=self._org_params(),
            )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        host_asset = payload.get("result") or {}
        resource = host_asset.get("resource") or {}
        if not resource:
            nested_result = (host_asset.get("result") or {}).get("result") or {}
            resource = nested_result.get("resource") or {}

        routing = resource.get("autonomous_system") or {}
        location = resource.get("location") or {}
        greynoise = resource.get("greynoise") or {}
        dns = resource.get("dns") or {}
        privacy_entries = resource.get("privacy") or []
        network_entries = resource.get("network") or []
        services = resource.get("services") or []

        tags: set[str] = set()
        ports: set[int] = set()
        cert_fingerprints: set[str] = set()
        service_names: set[str] = set()
        for service in services:
            if service.get("port") is not None:
                ports.add(int(service["port"]))
            service_name = service.get("service_name") or service.get("protocol")
            if service_name:
                service_names.add(str(service_name))
            tls = service.get("tls") or {}
            fingerprint = tls.get("fingerprint_sha256")
            if fingerprint:
                cert_fingerprints.add(str(fingerprint).lower())
        if any(entry.get("vpn") for entry in privacy_entries):
            tags.add("vpn")
        if any(entry.get("tor") for entry in privacy_entries):
            tags.add("tor-exit-node")
        if any(entry.get("proxy") for entry in privacy_entries):
            tags.add("open-proxy")
        if any(entry.get("hosting") for entry in network_entries):
            tags.add("hosting-provider")
        for service in services:
            for threat in service.get("threats") or []:
                if threat.get("name"):
                    tags.add(str(threat["name"]))
        tags.update(service_names)

        nameservers = dns.get("names") or []

        return EnrichmentResult(
            provider=self.provider,
            indicator_type="ip",
            indicator_value=indicator_value,
            asn=routing.get("asn"),
            asn_name=routing.get("name"),
            country=location.get("country_code"),
            classification=greynoise.get("classification"),
            tags=sorted(tags),
            resolved_ips=[indicator_value],
            related_domains=sorted({str(name).lower() for name in nameservers if name}),
            cert_fingerprints=sorted(cert_fingerprints),
            raw={
                "service_count": resource.get("service_count", len(services)),
                "ports": sorted(ports),
            },
        )

    async def expand_certificate_hosts(self, fingerprint: str) -> list[str]:
        """Finds other hosts that have presented the same TLS certificate over time.
        Requires the paid Adversary Investigation module and CENSYS_ENABLE_CERT_PIVOT;
        returns an empty list (never raises) if unavailable so callers can degrade."""
        if (
            not self.settings.censys_personal_access_token
            or not self.settings.censys_enable_cert_pivot
        ):
            return []
        try:
            async with self._request_lock:
                response = await self.client.get(
                    CERT_HISTORY_URL.format(certificate_id=fingerprint),
                    headers=self._headers(),
                    params={**self._org_params(), "page_size": 50},
                )
            response.raise_for_status()
        except Exception:
            return []
        payload: dict[str, Any] = response.json()
        ranges = ((payload.get("result") or {}).get("result") or {}).get("ranges") or []
        return sorted({str(entry["ip"]) for entry in ranges if entry.get("ip")})
