from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_ingestion.application.kev_correlation import kev_exposure_matches
from threat_ingestion.persistence.models import (
    ClusterMemberRecord,
    EnrichmentRecord,
    IndicatorRecord,
    InfrastructureClusterRecord,
)

# Maps our confidence label onto the companion project's Admiralty-style
# source_reliability scale (A=fully reliable .. F=cannot be judged).
_RELIABILITY_BY_CONFIDENCE = {"high": "B", "medium": "C", "low": "D"}


def build_manual_signals(session: Session) -> list[dict[str, Any]]:
    """Builds a list of dicts matching the `Signal` schema consumed by
    Daily-Cyber-Threat-Intelligence-Briefing's `data/manual_signals.json`, so that
    project's live report can incorporate Threat-Ingest's independently
    discovered infrastructure clusters and directly observed KEV exposure —
    evidence its own live mode has no source for on its own."""
    today = date.today().isoformat()
    collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    signals: list[dict[str, Any]] = []

    clusters = session.scalars(select(InfrastructureClusterRecord)).all()
    for cluster in clusters:
        indicator_ids = [
            member.indicator_id
            for member in session.scalars(
                select(ClusterMemberRecord).where(ClusterMemberRecord.cluster_id == cluster.id)
            ).all()
        ]
        member_values = sorted(
            indicator.canonical_value
            for indicator in (
                session.scalars(select(IndicatorRecord).where(IndicatorRecord.id.in_(indicator_ids))).all()
                if indicator_ids
                else []
            )
        )
        reasons = "; ".join(f"{entry['kind']}: {entry['detail']}" for entry in (cluster.evidence_json or []))
        observed = cluster.first_observed or cluster.generated_at
        signals.append(
            {
                "signal_type": "multi_source_corroboration",
                "subject": cluster.cluster_key,
                "source": "threat-ingest-cluster",
                "source_reliability": _RELIABILITY_BY_CONFIDENCE.get(cluster.confidence_label, "C"),
                "confidence": round(min(max(cluster.confidence_score, 0.0), 1.0), 2),
                "detail": (
                    f"Threat-Ingest infrastructure cluster {cluster.cluster_key} "
                    f"({len(member_values)} indicators: {', '.join(member_values) or 'none'}). {reasons}"
                ),
                "observed_at": observed.date().isoformat(),
                "collected_at": collected_at,
                "upstream_id": f"threat-ingest-cluster:{cluster.cluster_key}",
            }
        )

    for indicator_value, cve_id, provider in kev_exposure_matches(session):
        signals.append(
            {
                "signal_type": "environment_reachable",
                "subject": cve_id,
                "source": f"threat-ingest-{provider}",
                "source_reliability": "B",
                "confidence": 0.75,
                "detail": (
                    f"{provider} observed {indicator_value} exposing {cve_id}, which is also in the "
                    "local CISA KEV catalog. This is direct scan evidence, not a self-declared "
                    "watchlist entry."
                ),
                "observed_at": today,
                "collected_at": collected_at,
                "upstream_id": f"threat-ingest-exposure:{indicator_value}:{cve_id}",
            }
        )

    indicators = {
        indicator.id: indicator
        for indicator in session.scalars(select(IndicatorRecord)).all()
    }
    latest_provider_observation: set[tuple[int, str]] = set()
    enrichments = session.scalars(
        select(EnrichmentRecord)
        .where(EnrichmentRecord.provider.in_({"greynoise", "censys", "shodan"}))
        .order_by(EnrichmentRecord.observed_at.desc(), EnrichmentRecord.id.desc())
    ).all()
    for enrichment in enrichments:
        if enrichment.error or (enrichment.indicator_id, enrichment.provider) in latest_provider_observation:
            continue
        indicator = indicators.get(enrichment.indicator_id)
        if indicator is None or not indicator.canonical_value.strip():
            continue
        has_context = any(
            (
                enrichment.asn,
                enrichment.asn_name,
                enrichment.country,
                enrichment.classification,
                enrichment.tags,
                enrichment.resolved_ips,
                enrichment.related_domains,
                enrichment.cert_fingerprints,
                (enrichment.raw_json or {}).get("ports"),
                (enrichment.raw_json or {}).get("service_count"),
            )
        )
        if not has_context:
            continue

        latest_provider_observation.add((enrichment.indicator_id, enrichment.provider))
        context: list[str] = []
        if enrichment.classification:
            context.append(f"classification={enrichment.classification}")
        if enrichment.asn:
            context.append(f"ASN=AS{enrichment.asn}")
        if enrichment.asn_name:
            context.append(f"network={enrichment.asn_name}")
        if enrichment.country:
            context.append(f"country={enrichment.country}")
        if enrichment.tags:
            context.append(f"tags={', '.join(str(tag) for tag in enrichment.tags[:8])}")
        if enrichment.resolved_ips:
            context.append(f"resolved_ips={', '.join(enrichment.resolved_ips[:8])}")
        if enrichment.related_domains:
            context.append(f"related_domains={', '.join(enrichment.related_domains[:8])}")
        if enrichment.cert_fingerprints:
            context.append(f"TLS fingerprints={', '.join(enrichment.cert_fingerprints[:4])}")
        raw_json = enrichment.raw_json or {}
        if raw_json.get("ports"):
            context.append(f"open_ports={', '.join(str(port) for port in raw_json['ports'][:16])}")
        if raw_json.get("service_count") is not None:
            context.append(f"service_count={raw_json['service_count']}")

        signals.append(
            {
                "signal_type": "infrastructure_observation",
                "subject": indicator.canonical_value,
                "source": f"threat-ingest-{enrichment.provider}",
                "source_reliability": "C",
                "confidence": 0.35,
                "detail": (
                    f"{enrichment.provider} enrichment context for {indicator.canonical_value}: "
                    f"{'; '.join(context)}. Context only; this observation alone does not establish maliciousness."
                ),
                "observed_at": enrichment.observed_at.date().isoformat(),
                "collected_at": collected_at,
                "upstream_id": (
                    f"threat-ingest-enrichment:{enrichment.provider}:"
                    f"{indicator.canonical_value}:{enrichment.observed_at.isoformat()}"
                ),
            }
        )

    return signals


def write_manual_signals(session: Session, output_path: Path) -> int:
    signals = build_manual_signals(session)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(signals, indent=2), encoding="utf-8")
    return len(signals)
