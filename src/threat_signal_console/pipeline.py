"""The end-to-end flow: fetch a source, store what is new, score it, record the result."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from threat_signal_console import gates, ingest
from threat_signal_console.gates import Thresholds
from threat_signal_console.models import Source, parse_time, sha256_hex, to_iso
from threat_signal_console.store import Store, new_verdict_id
from threat_signal_console.textsim import Corpus

VERDICT_CALLS = ("THREAT", "NOISE", "WRONG_TIER")


def subject_label(subject_key: str, signal_id: str) -> str:
    return subject_key.split(":", 1)[1] if subject_key.startswith("cve:") else signal_id


def ingest_source(store: Store, source: Source, now: datetime | None = None) -> dict[str, Any]:
    """Fetch one source and run everything new through the gates. Returns the run summary."""
    run: dict[str, Any] = {
        "source_id": source.id,
        "source_name": source.name,
        "kind": source.kind,
        "tier": source.tier,
        "location": source.location,
        "new": 0,
        "revised": 0,
        "unchanged": 0,
        "rejected": 0,
        "skipped_old": 0,
        "signals_evaluated": 0,
    }
    try:
        body = ingest.fetch(source.location)
        result = ingest.normalize(source, body, now)
    except ingest.IngestError as error:
        run["error"] = str(error)
        store.write([("INGEST_RUN", run)])
        return run

    run["feed_bytes"] = len(body)
    run["feed_sha256"] = sha256_hex(body)
    run["rejected"] = len(result.rejected)
    run["rejected_examples"] = result.rejected[:5]
    run["skipped_old"] = result.skipped_old

    known = store.observation_hashes(source.id)
    latest = {obs.observation_id: obs for obs in result.observations}  # last one wins on repeats in a feed
    events = []
    affected: set[str] = set()
    for observation in latest.values():
        previous_hash = known.get(observation.observation_id)
        if previous_hash == observation.content_hash:
            run["unchanged"] += 1
            continue
        run["revised" if previous_hash else "new"] += 1
        events.append(("OBSERVATION", observation.to_payload()))
        affected.add(observation.signal_id)

    store.write(events)
    run["signals_evaluated"] = len(evaluate_signals(store, affected, trigger="observation"))
    store.write([("INGEST_RUN", run)])
    return run


def evaluate_signals(store: Store, signal_ids: set[str] | list[str], trigger: str) -> list[dict[str, Any]]:
    """Score the given signals and log an EVALUATION for each one whose result changed."""
    wanted = set(signal_ids)
    if not wanted:
        return []
    thresholds = store.current_thresholds()
    documents = store.signal_documents()  # ordered by (first_seen, signal_id)
    corpus = Corpus({doc["signal_id"]: doc["text"] for doc in documents})
    previous = store.latest_evaluations()

    events = []
    with store.reader() as conn:
        for position, document in enumerate(documents):
            signal_id = document["signal_id"]
            if signal_id not in wanted:
                continue
            observations = store.observations_for(signal_id, conn)
            cutoff = to_iso(parse_time(document["last_seen"]) - timedelta(days=gates.NOVELTY_WINDOW_DAYS))
            earlier = [doc for doc in documents[:position] if doc["last_seen"] >= cutoff]
            evaluation = gates.evaluate(signal_id, observations, earlier, corpus, thresholds)
            subject_key = observations[0]["subject_key"]
            evaluation["trigger"] = trigger
            evaluation["subject_key"] = subject_key
            evaluation["subject_label"] = subject_label(subject_key, signal_id)
            before = previous.get(signal_id)
            if before and all(before[key] == evaluation[key] for key in ("scores", "state", "reason", "observation_ids", "detail")):
                continue
            events.append(("EVALUATION", evaluation))
    store.write(events)
    return [payload for _, payload in events]


def present(signal: dict[str, Any], thresholds: Thresholds) -> dict[str, Any]:
    """Flatten a stored signal for the API, deciding its state under the given thresholds."""
    evaluation = signal.pop("evaluation", None)
    if evaluation is None:
        signal.update({"state": None, "reason": "NOT_EVALUATED", "failing_gate": None, "summary": "Not evaluated yet.", "scores": None, "detail": None, "as_of": None})
        return signal
    decision = gates.decide(evaluation["scores"], evaluation["detail"]["novelty"], thresholds)
    signal.update(decision)
    signal["scores"] = evaluation["scores"]
    signal["detail"] = evaluation["detail"]
    signal["as_of"] = evaluation["as_of"]
    return signal


def list_signals(store: Store, overrides: dict[str, float] | None = None) -> dict[str, Any]:
    """All signals with their triage state. ``overrides`` previews other thresholds without saving them."""
    saved = store.current_thresholds()
    active = Thresholds.from_dict({**saved.to_dict(), **(overrides or {})})
    signals = [present(signal, active) for signal in store.list_signals()]
    counts = {gates.ESCALATED: 0, gates.WATCHED: 0, gates.DROPPED: 0}
    for signal in signals:
        if signal["state"] in counts:
            counts[signal["state"]] += 1
    return {
        "thresholds": active.to_dict(),
        "saved_thresholds": saved.to_dict(),
        "preview": active != saved,
        "counts": counts,
        "signals": signals,
    }


def set_thresholds(store: Store, changes: dict[str, float], set_by: str) -> dict[str, Any]:
    """Save new thresholds and re-triage every signal against its stored scores."""
    set_by = _clean_text(set_by, "set_by", 64)
    current = store.current_thresholds()
    updated = Thresholds.from_dict({**current.to_dict(), **changes})
    if updated == current:
        return {"changed": False, "thresholds": current.to_dict(), "signals_changed": 0}
    store.write([("THRESHOLDS", {"settings": updated.to_dict(), "previous": current.to_dict(), "set_by": set_by})])

    events = []
    for evaluation in store.latest_evaluations().values():
        decision = gates.decide(evaluation["scores"], evaluation["detail"]["novelty"], updated)
        if (decision["state"], decision["reason"]) == (evaluation["state"], evaluation["reason"]):
            continue
        evaluation = {key: value for key, value in evaluation.items() if key != "seq"}
        evaluation.update(decision)
        evaluation["thresholds"] = updated.to_dict()
        evaluation["trigger"] = "thresholds"
        events.append(("EVALUATION", evaluation))
    store.write(events)
    return {"changed": True, "thresholds": updated.to_dict(), "signals_changed": len(events)}


def record_verdict(store: Store, signal_id: str, analyst_id: str, call: str, notes: str | None = None) -> dict[str, Any]:
    """Log an analyst's call on a signal, with the scores and thresholds it was made against.

    The analyst only says what the signal is (a real threat, noise, or mis-tiered).
    Whether that makes the triage a true or false positive is worked out here from
    the state the signal was in, so the two can never disagree.
    """
    analyst_id = _clean_text(analyst_id, "analyst_id", 64)
    if call not in VERDICT_CALLS:
        raise ValueError(f"call must be one of {', '.join(VERDICT_CALLS)}")
    notes = (notes or "").strip() or None
    if notes and len(notes) > 2000:
        raise ValueError("notes must be 2,000 characters or fewer")

    signal = store.get_signal(signal_id)
    if signal is None:
        raise LookupError(f"No signal with id {signal_id}")
    evaluation = signal.get("evaluation")
    if evaluation is None:
        raise LookupError(f"Signal {signal_id} has not been evaluated yet")

    escalated = evaluation["state"] == gates.ESCALATED
    outcome = None
    if call == "THREAT":
        outcome = "TRUE_POSITIVE" if escalated else "FALSE_NEGATIVE"
    elif call == "NOISE":
        outcome = "FALSE_POSITIVE" if escalated else "TRUE_NEGATIVE"

    payload = {
        "verdict_id": new_verdict_id(),
        "signal_id": signal_id,
        "subject_label": signal["label"],
        "analyst_id": analyst_id,
        "call": call,
        "outcome": outcome,
        "state_at_verdict": evaluation["state"],
        "reason_at_verdict": evaluation["reason"],
        "evaluation_seq": signal["evaluation_seq"],
        "snapshot": {
            "scores": evaluation["scores"],
            "thresholds": store.current_thresholds().to_dict(),
            "novelty": {key: evaluation["detail"]["novelty"][key] for key in ("max_similarity", "most_similar_signal", "new_indicator_count")},
            "best_tier": signal["best_tier"],
            "sources": [source["id"] for source in signal["sources"]],
        },
        "notes": notes,
    }
    envelope = store.write([("VERDICT", payload)])[0]
    return {**payload, "seq": envelope["seq"], "created_at": envelope["created_at"]}


def _clean_text(value: str, name: str, limit: int) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"{name} is required")
    if len(text) > limit:
        raise ValueError(f"{name} must be {limit} characters or fewer")
    return text
