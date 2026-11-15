"""Auditable storage.

Two files live in the data directory:

``audit_log.jsonl``
    The record of truth. Append-only, one JSON event per line. Every event carries
    a sequence number and the SHA-256 of the line before it, so an edited, removed
    or reordered line breaks the chain and ``verify`` reports it.

``index.sqlite``
    A queryable copy built from the log. It can be deleted and rebuilt at any time
    with ``rebuild``; nothing lives only here.

Writes check the events against the index first, then append to the log and fsync,
then commit the index. If the process dies between the fsync and the commit, the
next start replays the missing lines into the index.

The hash chain shows tampering inside the file. It is not a signature: someone who
can rewrite the whole log can rewrite the chain too. Keep a copy of the head hash
somewhere else if that matters to you.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from threat_signal_console.gates import Thresholds
from threat_signal_console.models import indicator_key, sha256_hex, utc_now

try:  # POSIX only; on Windows the in-process lock is the only guard.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

GENESIS_HASH = "0" * 64
EVENT_TYPES = ("OBSERVATION", "EVALUATION", "VERDICT", "THRESHOLDS", "INGEST_RUN")

SCHEMA = """
CREATE TABLE IF NOT EXISTS manifest (
    seq          INTEGER PRIMARY KEY,
    event_type   TEXT NOT NULL,
    byte_offset  INTEGER NOT NULL,
    byte_length  INTEGER NOT NULL,
    line_hash    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    apply_error  TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    signal_id      TEXT NOT NULL,
    source_id      TEXT NOT NULL,
    source_name    TEXT NOT NULL,
    source_uri     TEXT NOT NULL,
    source_tier    INTEGER NOT NULL CHECK (source_tier BETWEEN 1 AND 4),
    object_key     TEXT NOT NULL,
    subject_key    TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL,
    observed_at    TEXT NOT NULL,
    ingested_at    TEXT NOT NULL,
    revised_at     TEXT,
    revision       INTEGER NOT NULL DEFAULT 1,
    first_seq      INTEGER NOT NULL,
    last_seq       INTEGER NOT NULL,
    content_hash   TEXT NOT NULL,
    cve_ids        TEXT NOT NULL,
    indicators     TEXT NOT NULL,
    techniques     TEXT NOT NULL,
    tactics        TEXT NOT NULL,
    reference_url  TEXT,
    attributes     TEXT NOT NULL,
    raw            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_signal ON observations (signal_id);
CREATE TABLE IF NOT EXISTS signals (
    signal_id         TEXT PRIMARY KEY,
    subject_key       TEXT NOT NULL,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL,
    best_tier         INTEGER NOT NULL,
    observation_count INTEGER NOT NULL,
    source_count      INTEGER NOT NULL,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    evaluation_seq    INTEGER,
    state             TEXT,
    reason            TEXT,
    evaluation        TEXT
);
CREATE TABLE IF NOT EXISTS evaluations (
    seq        INTEGER PRIMARY KEY,
    signal_id  TEXT NOT NULL,
    trigger    TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('ESCALATED', 'WATCHED', 'DROPPED')),
    reason     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evaluations_signal ON evaluations (signal_id, seq);
CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id        TEXT PRIMARY KEY,
    seq               INTEGER NOT NULL,
    signal_id         TEXT NOT NULL,
    analyst_id        TEXT NOT NULL,
    call              TEXT NOT NULL CHECK (call IN ('THREAT', 'NOISE', 'WRONG_TIER')),
    outcome           TEXT CHECK (outcome IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'TRUE_NEGATIVE')),
    state_at_verdict  TEXT NOT NULL,
    reason_at_verdict TEXT NOT NULL,
    evaluation_seq    INTEGER NOT NULL,
    snapshot          TEXT NOT NULL,
    notes             TEXT,
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_signal ON verdicts (signal_id, seq);
CREATE TABLE IF NOT EXISTS thresholds (
    seq        INTEGER PRIMARY KEY,
    settings   TEXT NOT NULL,
    set_by     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_runs (
    seq        INTEGER PRIMARY KEY,
    source_id  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


class StoreError(RuntimeError):
    """The log or index could not be written, or the log failed an integrity check."""


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


class Store:
    def __init__(self, data_dir: str | Path):
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "audit_log.jsonl"
        self.db_path = self.dir / "index.sqlite"
        self._lock_path = self.dir / ".lock"
        self._thread_lock = threading.RLock()
        self.recovered_on_open = 0
        with self._locked():
            conn = self._connect()
            try:
                conn.executescript(SCHEMA)
                self.recovered_on_open = self._sync(conn)
            finally:
                conn.close()

    # ------------------------------------------------------------------ plumbing

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """One writer at a time, across threads and across processes."""
        with self._thread_lock:
            handle = open(self._lock_path, "a+")
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    @contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _head(conn: sqlite3.Connection) -> tuple[int, str, int]:
        """(last sequence number, last line hash, byte offset where the next line goes)."""
        row = conn.execute(
            "SELECT seq, line_hash, byte_offset + byte_length AS end FROM manifest ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row["seq"], row["line_hash"], row["end"]) if row else (0, GENESIS_HASH, 0)

    # ------------------------------------------------------------------- writing

    def write(self, events: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        """Append events to the log and the index as one unit. Returns the stored envelopes."""
        if not events:
            return []
        with self._locked():
            conn = self._connect()
            try:
                self._sync(conn)
                seq, prev_hash, offset = self._head(conn)
                start_offset = offset
                envelopes: list[dict[str, Any]] = []
                lines: list[bytes] = []
                conn.execute("BEGIN IMMEDIATE;")
                try:
                    for event_type, payload in events:
                        if event_type not in EVENT_TYPES:
                            raise StoreError(f"Unknown event type: {event_type}")
                        seq += 1
                        envelope = {
                            "seq": seq,
                            "event_type": event_type,
                            "created_at": utc_now(),
                            "prev_hash": prev_hash,
                            "payload": payload,
                        }
                        line = (_dumps(envelope) + "\n").encode("utf-8")
                        line_hash = sha256_hex(line)
                        _apply_event(conn, envelope)
                        conn.execute(
                            "INSERT INTO manifest (seq, event_type, byte_offset, byte_length, line_hash, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (seq, event_type, offset, len(line), line_hash, envelope["created_at"]),
                        )
                        envelopes.append(envelope)
                        lines.append(line)
                        offset += len(line)
                        prev_hash = line_hash
                except (sqlite3.Error, KeyError, TypeError, ValueError) as error:
                    conn.execute("ROLLBACK;")
                    raise StoreError(f"Event rejected, nothing was written: {error}") from error

                try:
                    with open(self.log_path, "ab") as handle:
                        handle.write(b"".join(lines))
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError as error:
                    conn.execute("ROLLBACK;")
                    try:  # leave no partial lines behind
                        if self.log_path.exists():
                            os.truncate(self.log_path, start_offset)
                    except OSError:
                        pass
                    raise StoreError(f"Could not append to the audit log: {error}") from error
                conn.execute("COMMIT;")
                return envelopes
            finally:
                conn.close()

    def _sync(self, conn: sqlite3.Connection) -> int:
        """Replay log lines the index has not seen. Returns how many were replayed."""
        size = self.log_path.stat().st_size if self.log_path.exists() else 0
        seq, prev_hash, offset = self._head(conn)
        if size < offset:
            raise StoreError(
                f"The audit log ({size} bytes) is shorter than the index expects ({offset} bytes). "
                "The log was truncated or replaced. Run `verify`, then `rebuild` if the log is the one you trust."
            )
        if size == offset:
            return 0

        with open(self.log_path, "rb") as handle:
            handle.seek(offset)
            pending = handle.read()
        complete, _, tail = pending.rpartition(b"\n")
        if tail:
            # A write that died before its newline was never acknowledged to anyone. Drop it.
            os.truncate(self.log_path, size - len(tail))
        replayed = 0
        conn.execute("BEGIN IMMEDIATE;")
        try:
            for raw in complete.split(b"\n") if complete else []:
                line = raw + b"\n"
                try:
                    envelope = json.loads(line)
                    line_seq, line_prev = envelope["seq"], envelope["prev_hash"]
                except (json.JSONDecodeError, KeyError, TypeError) as error:
                    raise StoreError(f"Audit log line at byte {offset} is not a valid event: {error}") from error
                if line_seq != seq + 1 or line_prev != prev_hash:
                    raise StoreError(
                        f"Audit log chain is broken at byte {offset} (expected seq {seq + 1} after hash {prev_hash[:12]}...)."
                    )
                apply_error = None
                conn.execute("SAVEPOINT replay;")
                try:
                    _apply_event(conn, envelope)
                    conn.execute("RELEASE replay;")
                except (sqlite3.Error, KeyError, TypeError, ValueError) as error:
                    conn.execute("ROLLBACK TO replay;")
                    conn.execute("RELEASE replay;")
                    apply_error = f"{type(error).__name__}: {error}"
                line_hash = sha256_hex(line)
                conn.execute(
                    "INSERT INTO manifest (seq, event_type, byte_offset, byte_length, line_hash, created_at, apply_error) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (line_seq, envelope.get("event_type", "?"), offset, len(line), line_hash, envelope.get("created_at", ""), apply_error),
                )
                seq, prev_hash, offset = line_seq, line_hash, offset + len(line)
                replayed += 1
        except BaseException:
            conn.execute("ROLLBACK;")
            raise
        conn.execute("COMMIT;")
        return replayed

    def rebuild(self) -> int:
        """Throw the index away and rebuild it from the log."""
        with self._locked():
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(self.db_path) + suffix)
                if path.exists():
                    path.unlink()
            conn = self._connect()
            try:
                conn.executescript(SCHEMA)
                return self._sync(conn)
            finally:
                conn.close()

    def verify(self) -> dict[str, Any]:
        """Walk the whole log, check the hash chain, and compare it with the index."""
        problems: list[str] = []
        events = 0
        prev_hash = GENESIS_HASH
        offset = 0
        with self._locked(), self.reader() as conn:
            manifest = {row["seq"]: row for row in conn.execute("SELECT * FROM manifest")}
            if self.log_path.exists():
                with open(self.log_path, "rb") as handle:
                    for line in handle:
                        if not line.endswith(b"\n"):
                            problems.append(f"byte {offset}: incomplete final line (interrupted write)")
                            break
                        try:
                            envelope = json.loads(line)
                            seq = envelope["seq"]
                            line_prev = envelope["prev_hash"]
                        except (json.JSONDecodeError, KeyError, TypeError):
                            problems.append(f"byte {offset}: not a valid event; chain cannot be followed past here")
                            break
                        if seq != events + 1:
                            problems.append(f"byte {offset}: expected seq {events + 1}, found {seq}")
                        if line_prev != prev_hash:
                            problems.append(f"seq {seq}: prev_hash does not match the line before it (edited or removed line)")
                        line_hash = sha256_hex(line)
                        indexed = manifest.get(seq)
                        if indexed is None:
                            problems.append(f"seq {seq}: in the log but not in the index")
                        elif indexed["line_hash"] != line_hash or indexed["byte_offset"] != offset:
                            problems.append(f"seq {seq}: log line differs from what the index recorded")
                        prev_hash = line_hash
                        offset += len(line)
                        events += 1
            for seq in sorted(set(manifest) - set(range(1, events + 1))):
                problems.append(f"seq {seq}: in the index but not in the log")
            apply_errors = [f"seq {row['seq']}: {row['apply_error']}" for row in manifest.values() if row["apply_error"]]
        return {
            "ok": not problems,
            "events": events,
            "indexed_events": len(manifest),
            "head_hash": prev_hash if events else None,
            "problems": problems,
            "apply_errors": apply_errors,
        }

    # ------------------------------------------------------------------- reading

    def current_thresholds(self) -> Thresholds:
        with self.reader() as conn:
            row = conn.execute("SELECT settings FROM thresholds ORDER BY seq DESC LIMIT 1").fetchone()
        return Thresholds.from_dict(json.loads(row["settings"])) if row else Thresholds()

    def observation_hashes(self, source_id: str) -> dict[str, str]:
        with self.reader() as conn:
            rows = conn.execute("SELECT observation_id, content_hash FROM observations WHERE source_id = ?", (source_id,))
            return {row["observation_id"]: row["content_hash"] for row in rows}

    def signal_ids(self) -> list[str]:
        with self.reader() as conn:
            return [row[0] for row in conn.execute("SELECT signal_id FROM signals ORDER BY first_seen, signal_id")]

    def observations_for(self, signal_id: str, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        def load(connection: sqlite3.Connection) -> list[dict[str, Any]]:
            rows = connection.execute(
                "SELECT * FROM observations WHERE signal_id = ? ORDER BY source_tier, observed_at, observation_id", (signal_id,)
            )
            return [_observation_row(row) for row in rows]

        if conn is not None:
            return load(conn)
        with self.reader() as own:
            return load(own)

    def signal_documents(self) -> list[dict[str, Any]]:
        """Everything the novelty gate needs about every signal: text, indicators, dates."""
        documents: dict[str, dict[str, Any]] = {}
        with self.reader() as conn:
            for row in conn.execute("SELECT signal_id, title, first_seen, last_seen FROM signals"):
                documents[row["signal_id"]] = {
                    "signal_id": row["signal_id"],
                    "title": row["title"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "texts": [],
                    "indicator_keys": set(),
                }
            for row in conn.execute("SELECT signal_id, title, description, indicators FROM observations ORDER BY observation_id"):
                document = documents[row["signal_id"]]
                for text in (row["title"], row["description"]):
                    if text and text not in document["texts"]:
                        document["texts"].append(text)
                document["indicator_keys"].update(indicator_key(item) for item in json.loads(row["indicators"]))
        for document in documents.values():
            document["text"] = "\n".join(document.pop("texts"))
        return sorted(documents.values(), key=lambda item: (item["first_seen"], item["signal_id"]))

    def latest_evaluations(self) -> dict[str, dict[str, Any]]:
        with self.reader() as conn:
            rows = conn.execute("SELECT signal_id, evaluation_seq, evaluation FROM signals WHERE evaluation IS NOT NULL")
            return {row["signal_id"]: {"seq": row["evaluation_seq"], **json.loads(row["evaluation"])} for row in rows}

    def list_signals(self) -> list[dict[str, Any]]:
        with self.reader() as conn:
            sources: dict[str, list[dict[str, Any]]] = {}
            for row in conn.execute(
                "SELECT DISTINCT signal_id, source_id, source_name, source_tier FROM observations ORDER BY source_tier, source_name"
            ):
                sources.setdefault(row["signal_id"], []).append(
                    {"id": row["source_id"], "name": row["source_name"], "tier": row["source_tier"]}
                )
            verdict_counts = {
                row["signal_id"]: row["n"] for row in conn.execute("SELECT signal_id, COUNT(*) AS n FROM verdicts GROUP BY signal_id")
            }
            signals = []
            for row in conn.execute("SELECT * FROM signals ORDER BY last_seen DESC, signal_id"):
                signals.append(_signal_row(row, sources.get(row["signal_id"], []), verdict_counts.get(row["signal_id"], 0)))
            return signals

    def get_signal(self, signal_id: str) -> dict[str, Any] | None:
        with self.reader() as conn:
            row = conn.execute("SELECT * FROM signals WHERE signal_id = ?", (signal_id,)).fetchone()
            if row is None:
                return None
            observations = self.observations_for(signal_id, conn)
            seen: dict[str, dict[str, Any]] = {}
            for obs in observations:
                seen.setdefault(obs["source_id"], {"id": obs["source_id"], "name": obs["source_name"], "tier": obs["source_tier"]})
            verdicts = [_verdict_row(item) for item in conn.execute("SELECT * FROM verdicts WHERE signal_id = ? ORDER BY seq DESC", (signal_id,))]
            history = [
                {"seq": item["seq"], "created_at": item["created_at"], "trigger": item["trigger"], **json.loads(item["payload"])}
                for item in conn.execute("SELECT * FROM evaluations WHERE signal_id = ? ORDER BY seq DESC", (signal_id,))
            ]
            signal = _signal_row(row, list(seen.values()), len(verdicts))
        signal["observations"] = observations
        signal["verdicts"] = verdicts
        signal["evaluation_history"] = [
            {key: item[key] for key in ("seq", "created_at", "trigger", "state", "reason", "scores", "thresholds", "summary")}
            for item in history
        ]
        return signal

    def list_verdicts(self, limit: int | None = None) -> list[dict[str, Any]]:
        query = "SELECT v.*, s.title AS signal_title, s.subject_key FROM verdicts v LEFT JOIN signals s USING (signal_id) ORDER BY v.seq DESC"
        with self.reader() as conn:
            rows = conn.execute(query + (" LIMIT ?" if limit else ""), (limit,) if limit else ())
            return [{**_verdict_row(row), "signal_title": row["signal_title"], "subject_key": row["subject_key"]} for row in rows]

    def read_event(self, seq: int) -> dict[str, Any] | None:
        with self.reader() as conn:
            row = conn.execute("SELECT * FROM manifest WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            return None
        with open(self.log_path, "rb") as handle:
            handle.seek(row["byte_offset"])
            line = handle.read(row["byte_length"])
        return {**json.loads(line), "line_hash": row["line_hash"], "apply_error": row["apply_error"]}

    def audit_tail(self, limit: int = 50) -> list[dict[str, Any]]:
        """The newest events, read back from the log file itself, newest first."""
        with self.reader() as conn:
            rows = conn.execute("SELECT * FROM manifest ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        if not rows:
            return []
        events = []
        with open(self.log_path, "rb") as handle:
            for row in rows:
                handle.seek(row["byte_offset"])
                envelope = json.loads(handle.read(row["byte_length"]))
                events.append(
                    {
                        "seq": row["seq"],
                        "event_type": row["event_type"],
                        "created_at": row["created_at"],
                        "line_hash": row["line_hash"],
                        "byte_offset": row["byte_offset"],
                        "summary": _summarize(envelope),
                    }
                )
        return events

    def status(self) -> dict[str, Any]:
        with self.reader() as conn:
            counts = {row["state"] or "UNEVALUATED": row["n"] for row in conn.execute("SELECT state, COUNT(*) AS n FROM signals GROUP BY state")}
            seq, head_hash, size = self._head(conn)
            last_run = conn.execute("SELECT payload, created_at FROM ingest_runs ORDER BY seq DESC LIMIT 1").fetchone()
            sources = [
                dict(row)
                for row in conn.execute(
                    "SELECT source_id AS id, source_name AS name, source_tier AS tier, COUNT(*) AS observations, "
                    "MAX(ingested_at) AS last_ingested FROM observations GROUP BY source_id ORDER BY source_tier, source_name"
                )
            ]
            return {
                "signals": sum(counts.values()),
                "by_state": counts,
                "observations": conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
                "verdicts": conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0],
                "audit_events": seq,
                "audit_head_hash": head_hash if seq else None,
                "audit_log_bytes": size,
                "last_ingest": {"at": last_run["created_at"], **json.loads(last_run["payload"])} if last_run else None,
                "sources": sources,
            }


# ---------------------------------------------------------------- event handling


def new_verdict_id() -> str:
    return "verd-" + uuid.uuid4().hex[:16]


def _apply_event(conn: sqlite3.Connection, envelope: dict[str, Any]) -> None:
    """Update the index for one event. Used for live writes and for replay alike."""
    seq, payload, created_at = envelope["seq"], envelope["payload"], envelope["created_at"]
    event_type = envelope["event_type"]

    if event_type == "OBSERVATION":
        conn.execute(
            """
            INSERT INTO observations (
                observation_id, signal_id, source_id, source_name, source_uri, source_tier, object_key, subject_key,
                title, description, observed_at, ingested_at, first_seq, last_seq, content_hash,
                cve_ids, indicators, techniques, tactics, reference_url, attributes, raw
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (observation_id) DO UPDATE SET
                source_name = excluded.source_name, source_uri = excluded.source_uri, source_tier = excluded.source_tier,
                title = excluded.title, description = excluded.description,
                revised_at = excluded.ingested_at, revision = observations.revision + 1, last_seq = excluded.last_seq,
                content_hash = excluded.content_hash, cve_ids = excluded.cve_ids, indicators = excluded.indicators,
                techniques = excluded.techniques, tactics = excluded.tactics, reference_url = excluded.reference_url,
                attributes = excluded.attributes, raw = excluded.raw
            """,
            (
                payload["observation_id"], payload["signal_id"], payload["source_id"], payload["source_name"],
                payload["source_uri"], int(payload["source_tier"]), payload["object_key"], payload["subject_key"],
                payload["title"], payload["description"], payload["observed_at"], created_at, seq, seq,
                payload["content_hash"], _dumps(payload["cve_ids"]), _dumps(payload["indicators"]),
                _dumps(payload["techniques"]), _dumps(payload["tactics"]), payload.get("reference_url"),
                _dumps(payload.get("attributes", {})), _dumps(payload["raw"]),
            ),
        )  # fmt: skip
        _refresh_signal(conn, payload["signal_id"], payload["subject_key"])

    elif event_type == "EVALUATION":
        conn.execute(
            "INSERT INTO evaluations (seq, signal_id, trigger, state, reason, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (seq, payload["signal_id"], payload["trigger"], payload["state"], payload["reason"], _dumps(payload), created_at),
        )
        conn.execute(
            "UPDATE signals SET evaluation_seq = ?, state = ?, reason = ?, evaluation = ? WHERE signal_id = ?",
            (seq, payload["state"], payload["reason"], _dumps(payload), payload["signal_id"]),
        )

    elif event_type == "VERDICT":
        conn.execute(
            """
            INSERT INTO verdicts (
                verdict_id, seq, signal_id, analyst_id, call, outcome, state_at_verdict, reason_at_verdict,
                evaluation_seq, snapshot, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["verdict_id"], seq, payload["signal_id"], payload["analyst_id"], payload["call"],
                payload.get("outcome"), payload["state_at_verdict"], payload["reason_at_verdict"],
                int(payload["evaluation_seq"]), _dumps(payload["snapshot"]), payload.get("notes"), created_at,
            ),
        )  # fmt: skip

    elif event_type == "THRESHOLDS":
        conn.execute(
            "INSERT INTO thresholds (seq, settings, set_by, created_at) VALUES (?, ?, ?, ?)",
            (seq, _dumps(payload["settings"]), payload["set_by"], created_at),
        )

    elif event_type == "INGEST_RUN":
        conn.execute(
            "INSERT INTO ingest_runs (seq, source_id, payload, created_at) VALUES (?, ?, ?, ?)",
            (seq, payload["source_id"], _dumps(payload), created_at),
        )

    else:
        raise ValueError(f"Unknown event type: {event_type}")


def _refresh_signal(conn: sqlite3.Connection, signal_id: str, subject_key: str) -> None:
    """Recompute a signal's headline fields from its observations."""
    summary = conn.execute(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT source_id) AS sources, MIN(source_tier) AS best_tier, "
        "MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen FROM observations WHERE signal_id = ?",
        (signal_id,),
    ).fetchone()
    lead = conn.execute(
        "SELECT title, description FROM observations WHERE signal_id = ? ORDER BY source_tier, observed_at, observation_id LIMIT 1",
        (signal_id,),
    ).fetchone()
    conn.execute(
        """
        INSERT INTO signals (signal_id, subject_key, title, description, best_tier, observation_count, source_count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (signal_id) DO UPDATE SET
            title = excluded.title, description = excluded.description, best_tier = excluded.best_tier,
            observation_count = excluded.observation_count, source_count = excluded.source_count,
            first_seen = excluded.first_seen, last_seen = excluded.last_seen
        """,
        (
            signal_id, subject_key, lead["title"], lead["description"], summary["best_tier"], summary["n"],
            summary["sources"], summary["first_seen"], summary["last_seen"],
        ),
    )  # fmt: skip


def _observation_row(row: sqlite3.Row) -> dict[str, Any]:
    observation = dict(row)
    for column in ("cve_ids", "indicators", "techniques", "tactics", "attributes", "raw"):
        observation[column] = json.loads(observation[column])
    return observation


def _signal_row(row: sqlite3.Row, sources: list[dict[str, Any]], verdict_count: int) -> dict[str, Any]:
    evaluation = json.loads(row["evaluation"]) if row["evaluation"] else None
    return {
        "signal_id": row["signal_id"],
        "subject_key": row["subject_key"],
        "label": row["subject_key"].split(":", 1)[1] if row["subject_key"].startswith("cve:") else row["signal_id"],
        "title": row["title"],
        "description": row["description"],
        "best_tier": row["best_tier"],
        "observation_count": row["observation_count"],
        "source_count": row["source_count"],
        "sources": sources,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "verdict_count": verdict_count,
        "evaluation_seq": row["evaluation_seq"],
        "evaluation": evaluation,
    }


def _verdict_row(row: sqlite3.Row) -> dict[str, Any]:
    verdict = {key: row[key] for key in (
        "verdict_id", "seq", "signal_id", "analyst_id", "call", "outcome", "state_at_verdict",
        "reason_at_verdict", "evaluation_seq", "notes", "created_at",
    )}  # fmt: skip
    verdict["snapshot"] = json.loads(row["snapshot"])
    return verdict


def _summarize(envelope: dict[str, Any]) -> str:
    payload = envelope.get("payload", {})
    kind = envelope.get("event_type")
    if kind == "OBSERVATION":
        return f"{payload.get('source_name')}: {payload.get('title')}"
    if kind == "EVALUATION":
        return f"{payload.get('subject_label', payload.get('signal_id'))} is {payload.get('state')} ({payload.get('reason')}), trigger: {payload.get('trigger')}"
    if kind == "VERDICT":
        outcome = f", {payload['outcome']}" if payload.get("outcome") else ""
        return f"{payload.get('analyst_id')} called {payload.get('subject_label', payload.get('signal_id'))} {payload.get('call')}{outcome}"
    if kind == "THRESHOLDS":
        settings = payload.get("settings", {})
        return f"{payload.get('set_by')} set velocity {settings.get('velocity')}, credibility {settings.get('credibility')}"
    if kind == "INGEST_RUN":
        return (
            f"{payload.get('source_id')}: {payload.get('new', 0)} new, {payload.get('revised', 0)} revised, "
            f"{payload.get('unchanged', 0)} unchanged, {payload.get('rejected', 0)} rejected"
            + (f", error: {payload['error']}" if payload.get("error") else "")
        )
    return str(kind)
