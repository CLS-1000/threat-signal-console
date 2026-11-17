"""Shared data shapes and small helpers used across ingestion, gates and storage."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

# Source tiers. Lower number = more authoritative.
TIER_LABELS = {
    1: "Tier 1: authoritative catalog",
    2: "Tier 2: vendor or CERT advisory",
    3: "Tier 3: open-source reporting",
    4: "Tier 4: unverified chatter",
}


def utc_now() -> str:
    return to_iso(datetime.now(UTC))


def to_iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> datetime:
    """Parse an ISO 8601 date or datetime into an aware UTC datetime.

    Date-only values (CISA KEV's ``dateAdded``) are read as midnight UTC.
    """
    text = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        text += "T00:00:00+00:00"
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python < 3.11 only accepts 0, 3 or 6 fractional digits; trim to microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def indicator_key(indicator: dict[str, str]) -> str:
    return f"{indicator['type']}:{indicator['value']}".lower()


def indicators_from_text(text: str) -> list[dict[str, str]]:
    """Pull CVE IDs, IPv4 addresses and file hashes out of free text."""
    found: list[dict[str, str]] = []
    for match in CVE_RE.findall(text or ""):
        found.append({"type": "cve", "value": match.upper()})
    for match in IPV4_RE.findall(text or ""):
        found.append({"type": "ipv4", "value": match})
    for match in HASH_RE.findall(text or ""):
        kind = {64: "sha256", 40: "sha1", 32: "md5"}[len(match)]
        found.append({"type": kind, "value": match.lower()})
    return dedupe_indicators(found)


def dedupe_indicators(indicators: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for indicator in indicators:
        key = indicator_key(indicator)
        if key not in seen:
            seen.add(key)
            unique.append({"type": indicator["type"], "value": indicator["value"]})
    return unique


def signal_id_for(subject_key: str) -> str:
    return "sig-" + sha256_hex(subject_key)[:16]


@dataclass
class Source:
    """One configured feed."""

    id: str
    name: str
    kind: str  # "kev" or "stix"
    tier: int
    location: str  # URL or local path
    max_age_days: int | None = None
    enabled: bool = True


@dataclass
class Observation:
    """One normalized item from one source.

    Several observations about the same subject (usually a CVE) form one signal.
    """

    source_id: str
    source_name: str
    source_uri: str
    source_tier: int
    object_key: str  # the item's stable ID inside its source
    subject_key: str
    title: str
    description: str
    observed_at: str
    raw: dict[str, Any]
    cve_ids: list[str] = field(default_factory=list)
    indicators: list[dict[str, str]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    reference_url: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        return sha256_hex(canonical_json(self.raw))

    @property
    def observation_id(self) -> str:
        return "obs-" + sha256_hex(f"{self.source_id}\n{self.object_key}")[:20]

    @property
    def signal_id(self) -> str:
        return signal_id_for(self.subject_key)

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observation_id"] = self.observation_id
        payload["signal_id"] = self.signal_id
        payload["content_hash"] = self.content_hash
        return payload
