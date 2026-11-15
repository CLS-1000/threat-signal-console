"""CISA Known Exploited Vulnerabilities catalog (JSON feed)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from threat_signal_console.models import CVE_RE, Observation, Source, parse_time, to_iso


def normalize(source: Source, document: Any, now: datetime | None = None):
    from threat_signal_console.ingest import IngestError, NormalizeResult

    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), list):
        raise IngestError(f"{source.id}: expected a KEV catalog object with a 'vulnerabilities' list")

    result = NormalizeResult()
    cutoff = None
    if source.max_age_days is not None:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=source.max_age_days)

    for position, entry in enumerate(document["vulnerabilities"]):
        if not isinstance(entry, dict):
            result.rejected.append(f"entry {position}: not an object")
            continue
        cve_id = str(entry.get("cveID", "")).strip().upper()
        if not CVE_RE.fullmatch(cve_id):
            result.rejected.append(f"entry {position}: missing or malformed cveID {cve_id!r}")
            continue
        try:
            added = parse_time(entry["dateAdded"])
        except (KeyError, ValueError):
            result.rejected.append(f"{cve_id}: missing or malformed dateAdded")
            continue
        if cutoff is not None and added < cutoff:
            result.skipped_old += 1
            continue

        title = str(entry.get("vulnerabilityName") or cve_id).strip()
        attributes = {
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "due_date": entry.get("dueDate"),
            "required_action": entry.get("requiredAction"),
            "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
            "cwes": entry.get("cwes") or [],
            "catalog_version": document.get("catalogVersion"),
        }
        result.observations.append(
            Observation(
                source_id=source.id,
                source_name=source.name,
                source_uri=source.location,
                source_tier=source.tier,
                object_key=cve_id,
                subject_key=f"cve:{cve_id}",
                title=title,
                description=str(entry.get("shortDescription") or "").strip(),
                observed_at=to_iso(added),
                raw=entry,
                cve_ids=[cve_id],
                indicators=[{"type": "cve", "value": cve_id}],
                reference_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                attributes={key: value for key, value in attributes.items() if value not in (None, "", [])},
            )
        )
    return result
