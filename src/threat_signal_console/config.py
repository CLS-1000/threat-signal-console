"""Where data lives and which sources are configured."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from threat_signal_console.models import Source

DEFAULT_SOURCES_FILE = Path("config/sources.toml")


class ConfigError(ValueError):
    pass


def data_dir(override: str | Path | None = None) -> Path:
    return Path(override or os.environ.get("TSC_DATA_DIR") or "data").resolve()


def sources_file(override: str | Path | None = None) -> Path:
    return Path(override or os.environ.get("TSC_SOURCES") or DEFAULT_SOURCES_FILE)


def load_sources(path: str | Path | None = None) -> list[Source]:
    """Read sources from a TOML file. Relative paths resolve against the file's folder."""
    file = sources_file(path)
    if not file.exists():
        raise ConfigError(f"Sources file not found: {file}")
    with open(file, "rb") as handle:
        document = tomllib.load(handle)

    sources: list[Source] = []
    seen: set[str] = set()
    for entry in document.get("source", []):
        try:
            source_id = str(entry["id"])
            kind = str(entry["kind"])
            tier = int(entry["tier"])
            name = str(entry.get("name", source_id))
        except (KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"Bad source entry in {file}: {entry!r} ({error})") from error
        if kind not in ("kev", "stix"):
            raise ConfigError(f"Source {source_id}: kind must be 'kev' or 'stix', got {kind!r}")
        if tier not in (1, 2, 3, 4):
            raise ConfigError(f"Source {source_id}: tier must be 1 to 4, got {tier}")
        if source_id in seen:
            raise ConfigError(f"Duplicate source id: {source_id}")
        seen.add(source_id)

        if "url" in entry:
            location = str(entry["url"])
        elif "path" in entry:
            location = str((file.parent / str(entry["path"])).resolve())
        else:
            raise ConfigError(f"Source {source_id}: needs a url or a path")

        max_age = entry.get("max_age_days")
        sources.append(
            Source(
                id=source_id,
                name=name,
                kind=kind,
                tier=tier,
                location=location,
                max_age_days=int(max_age) if max_age is not None else None,
                enabled=bool(entry.get("enabled", True)),
            )
        )
    return sources
