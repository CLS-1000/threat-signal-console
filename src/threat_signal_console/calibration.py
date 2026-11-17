"""Calibration: measure triage against analyst verdicts.

The report is a reading aid, not an autopilot. It never changes thresholds; it
shows how the saved thresholds have performed on the signals analysts judged, and
what a different pair of pass marks would have done on those same signals.
"""

from __future__ import annotations

from typing import Any

from threat_signal_console import gates
from threat_signal_console.gates import Thresholds
from threat_signal_console.store import Store

MIN_JUDGED = 20  # below this, no threshold suggestion is made
MIN_PER_CLASS = 5  # ...and there must be at least this many THREAT and this many NOISE calls
SWEEP = [round(0.10 + 0.05 * step, 2) for step in range(18)]  # 0.10 to 0.95


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def _matrix(pairs: list[tuple[bool, bool]]) -> dict[str, Any]:
    """pairs = (escalated by triage, analyst called it a threat)."""
    tp = sum(1 for escalated, threat in pairs if escalated and threat)
    fp = sum(1 for escalated, threat in pairs if escalated and not threat)
    fn = sum(1 for escalated, threat in pairs if not escalated and threat)
    tn = sum(1 for escalated, threat in pairs if not escalated and not threat)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else (0.0 if tp + fp + fn else None)
    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": _ratio(fp, fp + tn),
        "f1": f1,
    }


def report(store: Store) -> dict[str, Any]:
    verdicts = store.list_verdicts()  # newest first
    current = store.current_thresholds()

    latest: dict[str, dict[str, Any]] = {}
    wrong_tier: dict[str, int] = {}
    for verdict in verdicts:
        if verdict["call"] == "WRONG_TIER":
            for source_id in verdict["snapshot"].get("sources", []):
                wrong_tier[source_id] = wrong_tier.get(source_id, 0) + 1
            continue
        latest.setdefault(verdict["signal_id"], verdict)  # an analyst's newest call on a signal stands
    judged = list(latest.values())

    as_recorded = _matrix([(verdict["state_at_verdict"] == gates.ESCALATED, verdict["call"] == "THREAT") for verdict in judged])
    misses: dict[str, int] = {}
    for verdict in judged:
        if verdict["outcome"] in ("FALSE_NEGATIVE", "FALSE_POSITIVE"):
            key = f"{verdict['outcome']}: {verdict['reason_at_verdict']}"
            misses[key] = misses.get(key, 0) + 1

    def replay(thresholds: Thresholds) -> dict[str, Any]:
        pairs = []
        for verdict in judged:
            snapshot = verdict["snapshot"]
            decision = gates.decide(snapshot["scores"], snapshot["novelty"], thresholds)
            pairs.append((decision["state"] == gates.ESCALATED, verdict["call"] == "THREAT"))
        return _matrix(pairs)

    threats = sum(1 for verdict in judged if verdict["call"] == "THREAT")
    noise = len(judged) - threats
    at_current = replay(current) if judged else None

    suggestion = None
    if len(judged) < MIN_JUDGED or min(threats, noise) < MIN_PER_CLASS:
        note = (
            f"No suggestion yet: {len(judged)} judged signal(s) ({threats} threat, {noise} noise). "
            f"Needs at least {MIN_JUDGED}, with {MIN_PER_CLASS} or more of each."
        )
    else:
        best = (at_current["f1"] or 0.0, 0.0, current.velocity, current.credibility)
        for velocity in SWEEP:
            for credibility in SWEEP:
                candidate = Thresholds.from_dict({**current.to_dict(), "velocity": velocity, "credibility": credibility})
                f1 = replay(candidate)["f1"] or 0.0
                distance = -(abs(velocity - current.velocity) + abs(credibility - current.credibility))
                if (f1, distance) > (best[0], best[1]):
                    best = (f1, distance, velocity, credibility)
        if best[0] > (at_current["f1"] or 0.0):
            proposed = Thresholds.from_dict({**current.to_dict(), "velocity": best[2], "credibility": best[3]})
            suggestion = {
                "velocity": best[2],
                "credibility": best[3],
                "performance": replay(proposed),
                "based_on_judged_signals": len(judged),
            }
            note = (
                f"On the {len(judged)} judged signals, velocity {best[2]:.2f} and credibility {best[3]:.2f} would have scored "
                f"F1 {best[0]:.2f} against {at_current['f1'] or 0.0:.2f} now. This is a fit to past verdicts, not a forecast, "
                "and nothing is changed until someone saves new thresholds."
            )
        else:
            note = f"On the {len(judged)} judged signals, no other pair of pass marks beats the saved ones."

    return {
        "judged_signals": len(judged),
        "threat_calls": threats,
        "noise_calls": noise,
        "total_verdicts": len(verdicts),
        "thresholds": current.to_dict(),
        "as_recorded": as_recorded,
        "at_saved_thresholds": at_current,
        "misses_by_reason": dict(sorted(misses.items(), key=lambda item: -item[1])),
        "wrong_tier_reports_by_source": wrong_tier,
        "suggestion": suggestion,
        "note": note,
    }
