"""STIX 2.1 bundles (JSON).

This is a light structural reader, not a full STIX validator: it checks that each
object has a matching ``type`` and ``id`` and reads the common fields. Relationship
objects are not followed.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from threat_signal_console.models import (
    CVE_RE,
    Observation,
    Source,
    dedupe_indicators,
    indicators_from_text,
    parse_time,
    to_iso,
)

STIX_ID_RE = re.compile(r"^([a-z0-9][a-z0-9-]*)--[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

# Object types that describe a threat and become observations.
SIGNAL_TYPES = {
    "attack-pattern",
    "campaign",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "malware",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
}

# [ipv4-addr:value = '198.51.100.7'], [file:hashes.'SHA-256' = '...'], and so on.
PATTERN_TERM_RE = re.compile(r"([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s*=\s*'([^']*)'")
PATTERN_TYPES = {
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "domain-name:value": "domain",
    "url:value": "url",
    "email-addr:value": "email",
    "file:hashes.sha-256": "sha256",
    "file:hashes.sha-1": "sha1",
    "file:hashes.md5": "md5",
    "file:name": "filename",
}
TIME_FIELDS = ("published", "modified", "created", "valid_from")


def normalize(source: Source, document: Any, now: datetime | None = None):
    from threat_signal_console.ingest import IngestError, NormalizeResult

    if isinstance(document, dict) and document.get("type") == "bundle":
        objects = document.get("objects")
        if not isinstance(objects, list):
            raise IngestError(f"{source.id}: STIX bundle has no 'objects' list")
    elif isinstance(document, list):
        objects = document
    elif isinstance(document, dict) and "type" in document:
        objects = [document]
    else:
        raise IngestError(f"{source.id}: expected a STIX bundle, a list of objects, or one object")

    result = NormalizeResult()
    cutoff = None
    if source.max_age_days is not None:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=source.max_age_days)

    for position, obj in enumerate(objects):
        if not isinstance(obj, dict):
            result.rejected.append(f"object {position}: not an object")
            continue
        object_type = obj.get("type")
        object_id = obj.get("id")
        if not isinstance(object_type, str) or not isinstance(object_id, str):
            result.rejected.append(f"object {position}: missing type or id")
            continue
        if object_type not in SIGNAL_TYPES:
            continue  # identities, markings, relationships, observables: not signals
        match = STIX_ID_RE.match(object_id)
        if not match or match.group(1) != object_type:
            result.rejected.append(f"object {position}: id {object_id!r} does not match type {object_type!r}")
            continue

        observed = None
        for name in TIME_FIELDS:
            if obj.get(name):
                try:
                    observed = parse_time(obj[name])
                    break
                except ValueError:
                    continue
        if observed is None:
            result.rejected.append(f"{object_id}: no readable timestamp ({', '.join(TIME_FIELDS)})")
            continue
        if cutoff is not None and observed < cutoff:
            result.skipped_old += 1
            continue

        name = str(obj.get("name") or "").strip()
        description = str(obj.get("description") or "").strip()
        pattern = str(obj.get("pattern") or "")
        references = [ref for ref in obj.get("external_references") or [] if isinstance(ref, dict)]

        indicators: list[dict[str, str]] = []
        techniques: list[str] = []
        reference_url = None
        for ref in references:
            external_id = str(ref.get("external_id") or "")
            source_name = str(ref.get("source_name") or "").lower()
            if source_name == "cve" or CVE_RE.fullmatch(external_id):
                if CVE_RE.fullmatch(external_id):
                    indicators.append({"type": "cve", "value": external_id.upper()})
            if source_name == "mitre-attack" and external_id:
                techniques.append(external_id)
            if reference_url is None and str(ref.get("url") or "").startswith(("http://", "https://")):
                reference_url = ref["url"]
        indicators.extend(_indicators_from_pattern(pattern))
        indicators.extend(indicators_from_text(f"{name}\n{description}"))
        indicators = dedupe_indicators(indicators)

        tactics = sorted(
            {
                str(phase.get("phase_name"))
                for phase in obj.get("kill_chain_phases") or []
                if isinstance(phase, dict) and phase.get("phase_name")
            }
        )
        cve_ids = [item["value"] for item in indicators if item["type"] == "cve"]

        result.observations.append(
            Observation(
                source_id=source.id,
                source_name=source.name,
                source_uri=source.location,
                source_tier=source.tier,
                object_key=object_id,
                subject_key=_subject_key(name, cve_ids, object_id),
                title=name or (pattern[:120] if pattern else f"{object_type} {object_id[-12:]}"),
                description=description,
                observed_at=to_iso(observed),
                raw=obj,
                cve_ids=cve_ids,
                indicators=indicators,
                techniques=sorted(set(techniques)),
                tactics=tactics,
                reference_url=reference_url,
                attributes={"stix_type": object_type, "stix_id": object_id},
            )
        )
    return result


def _subject_key(name: str, cve_ids: list[str], object_id: str) -> str:
    """Decide what a STIX object is about.

    A CVE named in the title wins; otherwise a single CVE anywhere in the object;
    otherwise the object stands as its own subject.
    """
    in_name = CVE_RE.search(name)
    if in_name:
        return f"cve:{in_name.group(0).upper()}"
    if len(cve_ids) == 1:
        return f"cve:{cve_ids[0]}"
    return f"stix:{object_id}"


def _indicators_from_pattern(pattern: str) -> list[dict[str, str]]:
    if not pattern:
        return []
    found = []
    for object_type, path, value in PATTERN_TERM_RE.findall(pattern):
        kind = PATTERN_TYPES.get(f"{object_type}:{path}".replace("'", "").lower())
        if kind and value:
            found.append({"type": kind, "value": value.lower() if kind in ("sha256", "sha1", "md5") else value})
    if not found:
        found.append({"type": "stix-pattern", "value": pattern[:500]})
    return found
