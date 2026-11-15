import json

import pytest
from conftest import by_label

from threat_signal_console import pipeline
from threat_signal_console.store import Store, StoreError


def test_log_and_index_agree_after_ingest(loaded):
    result = loaded.verify()
    assert result["ok"] and result["events"] == result["indexed_events"] > 0 and not result["apply_errors"]


def test_edited_log_line_is_detected(loaded):
    lines = loaded.log_path.read_bytes().split(b"\n")
    lines[3] = lines[3].replace(b"Synthetic", b"Authentic", 1)
    loaded.log_path.write_bytes(b"\n".join(lines))
    result = loaded.verify()
    assert not result["ok"]
    assert any("prev_hash" in problem or "differs" in problem for problem in result["problems"])


def test_removed_log_line_is_detected(loaded):
    lines = loaded.log_path.read_bytes().split(b"\n")
    del lines[5]
    loaded.log_path.write_bytes(b"\n".join(lines))
    assert not loaded.verify()["ok"]
    with pytest.raises(StoreError):  # a shorter log than the index expects is refused, not silently accepted
        Store(loaded.dir)


def test_rebuild_reproduces_the_index(loaded):
    before = by_label(loaded)
    status = loaded.status()
    assert loaded.rebuild() == status["audit_events"]
    after = by_label(loaded)
    assert {k: (v["state"], v["reason"], v["scores"]) for k, v in before.items()} == {k: (v["state"], v["reason"], v["scores"]) for k, v in after.items()}
    assert loaded.verify()["ok"]


def test_unindexed_lines_are_replayed_on_open(loaded):
    """Simulates a crash after the log fsync but before the index commit."""
    events = loaded.status()["audit_events"]
    loaded.db_path.unlink()
    for suffix in ("-wal", "-shm"):
        path = loaded.db_path.with_name(loaded.db_path.name + suffix)
        if path.exists():
            path.unlink()
    reopened = Store(loaded.dir)
    assert reopened.recovered_on_open == events
    assert reopened.verify()["ok"] and len(by_label(reopened)) == 7


def test_torn_final_line_is_dropped(loaded):
    size = loaded.log_path.stat().st_size
    with open(loaded.log_path, "ab") as handle:
        handle.write(b'{"seq": 999, "event_type": "VERD')
    reopened = Store(loaded.dir)
    assert reopened.log_path.stat().st_size == size and reopened.verify()["ok"]
    pipeline.record_verdict(reopened, by_label(reopened)["CVE-2099-0001"]["signal_id"], "tester", "THREAT")
    assert reopened.verify()["ok"]


def test_rejected_event_writes_nothing(store):
    with pytest.raises(StoreError):
        store.write([("VERDICT", {"verdict_id": "verd-x"})])  # missing required fields
    assert not store.log_path.exists() or store.log_path.stat().st_size == 0
    assert store.status()["audit_events"] == 0


def test_events_are_hash_chained(loaded):
    previous = "0" * 64
    import hashlib

    for line in loaded.log_path.read_bytes().splitlines(keepends=True):
        assert json.loads(line)["prev_hash"] == previous
        previous = hashlib.sha256(line).hexdigest()
    assert previous == loaded.status()["audit_head_hash"]
