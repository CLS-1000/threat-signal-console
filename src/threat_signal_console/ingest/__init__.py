"""Source adapters. Each adapter turns one feed format into Observation objects."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from threat_signal_console import __version__
from threat_signal_console.ingest import kev, stix
from threat_signal_console.models import Observation, Source

MAX_FEED_BYTES = 50 * 1024 * 1024
ADAPTERS = {"kev": kev.normalize, "stix": stix.normalize}


class IngestError(RuntimeError):
    """A feed could not be fetched or parsed at all."""


@dataclass
class NormalizeResult:
    observations: list[Observation] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)  # one reason per item the adapter refused
    skipped_old: int = 0


def fetch(location: str, timeout: float = 30.0, attempts: int = 3) -> bytes:
    """Read a feed from an http(s) URL or a local file."""
    if not location.startswith(("http://", "https://")):
        path = Path(location)
        if not path.is_file():
            raise IngestError(f"Feed file not found: {path}")
        if path.stat().st_size > MAX_FEED_BYTES:
            raise IngestError(f"Feed file is larger than {MAX_FEED_BYTES} bytes: {path}")
        return path.read_bytes()

    request = urllib.request.Request(
        location,
        headers={
            "Accept": "application/json, application/stix+json;version=2.1",
            "User-Agent": f"threat-signal-console/{__version__}",
        },
    )
    delay = 1.0
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(MAX_FEED_BYTES + 1)
            if len(body) > MAX_FEED_BYTES:
                raise IngestError(f"Feed is larger than {MAX_FEED_BYTES} bytes: {location}")
            return body
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            if attempt < attempts:
                time.sleep(delay)
                delay *= 2
    raise IngestError(f"Could not fetch {location} after {attempts} attempts: {last_error}")


def normalize(source: Source, body: bytes, now: datetime | None = None) -> NormalizeResult:
    """Parse a fetched feed with the adapter for the source's kind."""
    try:
        document = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IngestError(f"{source.id}: feed is not valid JSON ({error})") from error
    try:
        adapter = ADAPTERS[source.kind]
    except KeyError:
        raise IngestError(f"{source.id}: no adapter for kind {source.kind!r}") from None
    return adapter(source, document, now)
