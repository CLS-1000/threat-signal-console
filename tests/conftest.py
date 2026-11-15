from pathlib import Path

import pytest

from threat_signal_console import config, pipeline
from threat_signal_console.store import Store

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


@pytest.fixture
def loaded(store):
    """A store with the three synthetic example feeds ingested."""
    for source in config.load_sources(EXAMPLES / "sources.toml"):
        run = pipeline.ingest_source(store, source)
        assert "error" not in run
    return store


def by_label(store):
    return {signal["label"]: signal for signal in pipeline.list_signals(store)["signals"]}
