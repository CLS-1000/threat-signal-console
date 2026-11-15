"""The four gates and the triage decision.

Every function here is pure: the same observations and thresholds always give the
same scores and the same decision. Each gate returns a score from 0 to 1 plus the
inputs it used, so the console can show an analyst exactly why a signal landed
where it did.

A *signal* is every observation about one subject (usually one CVE). Gates look at
the signal as of its newest observation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Any

from threat_signal_console.models import indicator_key, parse_time
from threat_signal_console.textsim import Corpus

# Gate 01: how much one mention counts toward volume, by source tier.
TIER_WEIGHT = {1: 4.0, 2: 2.0, 3: 1.0, 4: 0.5}
VOLUME_WINDOW_DAYS = 7
VOLUME_SATURATION = 4.0  # weighted mentions that give a score of 1.0

# Gate 02
VELOCITY_RECENT_HOURS = 24
VELOCITY_BASELINE_DAYS = 7
VELOCITY_Z_SATURATION = 3.0  # z-score that gives a score of 1.0

# Gate 03: starting credibility from the best source tier, plus corroboration.
TIER_CREDIBILITY = {1: 0.90, 2: 0.75, 3: 0.50, 4: 0.20}
CORROBORATION_STEP = 0.05
CORROBORATION_MAX = 0.10

# Gate 04: earlier signals older than this are not compared.
NOVELTY_WINDOW_DAYS = 30

ESCALATED = "ESCALATED"
WATCHED = "WATCHED"
DROPPED = "DROPPED"


@dataclass(frozen=True)
class Thresholds:
    velocity: float = 0.65  # adjustable: Gate 02 pass mark
    credibility: float = 0.65  # adjustable: Gate 03 pass mark
    volume_floor: float = 0.50  # Gate 01 floor
    provenance_floor: float = 0.40  # Gate 03 hard floor, checked before the pass mark
    similarity_ceiling: float = 0.85  # Gate 04: at or above this with nothing new = redundant

    def to_dict(self) -> dict[str, float]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> Thresholds:
        known = {key: float(values[key]) for key in cls.__dataclass_fields__ if values.get(key) is not None}
        thresholds = cls(**known)
        for name, value in thresholds.to_dict().items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1, got {value}")
        return thresholds


def _times(observations: list[dict[str, Any]]) -> list[tuple[datetime, dict[str, Any]]]:
    return [(parse_time(obs["observed_at"]), obs) for obs in observations]


def gate_volume(observations: list[dict[str, Any]], as_of: datetime) -> tuple[float, dict[str, Any]]:
    """Gate 01: is there enough reporting to bother with?

    Counts mentions in the last 7 days, weighted by source tier. One Tier 1 mention
    saturates the score; Tier 4 chatter needs eight.
    """
    start = as_of - timedelta(days=VOLUME_WINDOW_DAYS)
    in_window = [obs for moment, obs in _times(observations) if start < moment <= as_of]
    by_tier: dict[str, int] = {}
    weighted = 0.0
    for obs in in_window:
        tier = int(obs["source_tier"])
        by_tier[str(tier)] = by_tier.get(str(tier), 0) + 1
        weighted += TIER_WEIGHT[tier]
    score = min(1.0, weighted / VOLUME_SATURATION)
    return round(score, 3), {
        "window_days": VOLUME_WINDOW_DAYS,
        "mentions": len(in_window),
        "mentions_by_tier": by_tier,
        "weighted_mentions": weighted,
        "explanation": (
            f"{len(in_window)} mention(s) in the last {VOLUME_WINDOW_DAYS} days, "
            f"weighted {weighted:g} of {VOLUME_SATURATION:g} by source tier."
        ),
    }


def gate_velocity(observations: list[dict[str, Any]], as_of: datetime) -> tuple[float, dict[str, Any]]:
    """Gate 02: is reporting spiking right now?

    Compares mentions in the last 24 hours with the daily counts of the 7 days
    before that, as a z-score. The standard deviation is floored at 1 so a single
    mention on a quiet subject is not treated as a large spike.
    """
    moments = [moment for moment, _ in _times(observations)]
    recent_start = as_of - timedelta(hours=VELOCITY_RECENT_HOURS)
    recent = sum(1 for moment in moments if recent_start < moment <= as_of)
    baseline = []
    for day in range(1, VELOCITY_BASELINE_DAYS + 1):
        end = recent_start - timedelta(days=day - 1)
        begin = end - timedelta(days=1)
        baseline.append(sum(1 for moment in moments if begin < moment <= end))
    baseline_mean = mean(baseline)
    baseline_std = pstdev(baseline)
    z_score = (recent - baseline_mean) / max(baseline_std, 1.0)
    score = min(1.0, max(0.0, z_score / VELOCITY_Z_SATURATION))
    return round(score, 3), {
        "recent_hours": VELOCITY_RECENT_HOURS,
        "recent_mentions": recent,
        "baseline_days": VELOCITY_BASELINE_DAYS,
        "baseline_daily_counts": baseline,
        "baseline_mean": round(baseline_mean, 3),
        "baseline_std": round(baseline_std, 3),
        "z_score": round(z_score, 3),
        "explanation": (
            f"{recent} mention(s) in the last {VELOCITY_RECENT_HOURS} hours against a baseline of "
            f"{baseline_mean:.2f} per day (z = {z_score:+.2f})."
        ),
    }


def gate_credibility(observations: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Gate 03: how far can the sourcing be trusted?

    Starts from the best source tier, then adds a little for each extra
    independent source. Chatter alone can never reach the pass mark.
    """
    best = min(observations, key=lambda obs: (int(obs["source_tier"]), obs["observed_at"], obs["observation_id"]))
    best_tier = int(best["source_tier"])
    sources: dict[str, dict[str, Any]] = {}
    for obs in observations:
        sources.setdefault(obs["source_id"], {"id": obs["source_id"], "name": obs["source_name"], "tier": int(obs["source_tier"])})
    others = len(sources) - 1
    bonus = min(CORROBORATION_MAX, CORROBORATION_STEP * others)
    score = min(1.0, TIER_CREDIBILITY[best_tier] + bonus)
    return round(score, 3), {
        "best_tier": best_tier,
        "best_source": best["source_name"],
        "base": TIER_CREDIBILITY[best_tier],
        "corroboration_bonus": round(bonus, 3),
        "sources": sorted(sources.values(), key=lambda item: (item["tier"], item["name"])),
        "explanation": (
            f"Best source is {best['source_name']} (Tier {best_tier}, base {TIER_CREDIBILITY[best_tier]:.2f})"
            + (f", corroborated by {others} other source(s) (+{bonus:.2f})." if others else ", with no corroborating source.")
        ),
    }


def gate_novelty(
    signal_id: str,
    indicators: list[dict[str, str]],
    earlier: list[dict[str, Any]],
    corpus: Corpus | None,
) -> tuple[float, dict[str, Any]]:
    """Gate 04: does this tell us anything we don't already have?

    Finds the most similar earlier signal by text (TF-IDF cosine). The signal is
    only redundant if it is near-identical to an earlier one *and* brings no
    indicator that the earlier one lacks.

    ``earlier`` holds dicts with ``signal_id``, ``title`` and ``indicator_keys``.
    """
    own_keys = {indicator_key(item) for item in indicators}
    best_similarity = 0.0
    best_match: dict[str, Any] | None = None
    if corpus is not None:
        for candidate in earlier:
            similarity = corpus.similarity(signal_id, candidate["signal_id"])
            if similarity > best_similarity or (
                similarity == best_similarity and best_match is not None and candidate["signal_id"] < best_match["signal_id"]
            ):
                best_similarity, best_match = similarity, candidate
    if best_match is None or best_similarity == 0.0:
        best_match = None
        new_keys = sorted(own_keys)
    else:
        new_keys = sorted(own_keys - set(best_match["indicator_keys"]))
    best_similarity = round(min(1.0, best_similarity), 3)
    score = round(1.0 - best_similarity, 3)
    if best_match is None:
        explanation = f"No similar earlier signal among {len(earlier)} compared."
    else:
        explanation = (
            f"Closest earlier signal is \"{best_match['title']}\" (similarity {best_similarity:.2f}); "
            f"{len(new_keys)} indicator(s) here that it lacks."
        )
    return score, {
        "window_days": NOVELTY_WINDOW_DAYS,
        "compared_against": len(earlier),
        "max_similarity": best_similarity,
        "most_similar_signal": best_match["signal_id"] if best_match else None,
        "most_similar_title": best_match["title"] if best_match else None,
        "new_indicators": new_keys,
        "new_indicator_count": len(new_keys),
        "explanation": explanation,
    }


def decide(scores: dict[str, float], novelty: dict[str, Any], thresholds: Thresholds) -> dict[str, Any]:
    """Turn four scores into ESCALATED, WATCHED or DROPPED. First matching rule wins."""
    volume, velocity, credibility = scores["volume"], scores["velocity"], scores["credibility"]
    redundant = (
        novelty.get("most_similar_signal") is not None
        and novelty.get("max_similarity", 0.0) >= thresholds.similarity_ceiling
        and novelty.get("new_indicator_count", 0) == 0
    )

    def outcome(state: str, reason: str, failing_gate: str | None, summary: str) -> dict[str, Any]:
        return {"state": state, "reason": reason, "failing_gate": failing_gate, "summary": summary}

    if volume < thresholds.volume_floor:
        return outcome(
            DROPPED,
            "VOLUME_BELOW_FLOOR",
            "VOLUME",
            f"Dropped: volume {volume:.2f} is under the {thresholds.volume_floor:.2f} floor, so there is too little reporting to act on.",
        )
    if credibility < thresholds.provenance_floor:
        return outcome(
            DROPPED,
            "PROVENANCE_BELOW_FLOOR",
            "CREDIBILITY",
            f"Dropped: credibility {credibility:.2f} is under the {thresholds.provenance_floor:.2f} provenance floor. "
            "No amount of activity escalates sourcing this weak.",
        )
    if redundant:
        return outcome(
            DROPPED,
            "REDUNDANT",
            "NOVELTY",
            f"Dropped: {novelty['max_similarity']:.2f} similar to an earlier signal "
            f"(\"{novelty.get('most_similar_title')}\") and adds no new indicator.",
        )
    credible = credibility >= thresholds.credibility
    fast = velocity >= thresholds.velocity
    if credible and fast:
        return outcome(
            ESCALATED,
            "PASSED_ALL_GATES",
            None,
            f"Escalated: credibility {credibility:.2f} and velocity {velocity:.2f} both meet their pass marks "
            f"({thresholds.credibility:.2f} and {thresholds.velocity:.2f}).",
        )
    if credible:
        return outcome(
            WATCHED,
            "VELOCITY_BELOW_THRESHOLD",
            "VELOCITY",
            f"Watched: the sourcing is credible ({credibility:.2f}) but reporting is not spiking "
            f"(velocity {velocity:.2f}, pass mark {thresholds.velocity:.2f}).",
        )
    if fast:
        return outcome(
            WATCHED,
            "CREDIBILITY_BELOW_THRESHOLD",
            "CREDIBILITY",
            f"Watched: reporting is spiking (velocity {velocity:.2f}) but the sourcing is not yet credible enough "
            f"({credibility:.2f}, pass mark {thresholds.credibility:.2f}). Needs an analyst or a better source.",
        )
    return outcome(
        DROPPED,
        "BELOW_BOTH_THRESHOLDS",
        "VELOCITY_AND_CREDIBILITY",
        f"Dropped: neither credibility ({credibility:.2f}) nor velocity ({velocity:.2f}) meets its pass mark.",
    )


def evaluate(
    signal_id: str,
    observations: list[dict[str, Any]],
    earlier: list[dict[str, Any]],
    corpus: Corpus | None,
    thresholds: Thresholds,
) -> dict[str, Any]:
    """Run all four gates over one signal and decide its triage state."""
    as_of = max(moment for moment, _ in _times(observations))
    indicators = [item for obs in observations for item in obs["indicators"]]
    volume, volume_detail = gate_volume(observations, as_of)
    velocity, velocity_detail = gate_velocity(observations, as_of)
    credibility, credibility_detail = gate_credibility(observations)
    novelty, novelty_detail = gate_novelty(signal_id, indicators, earlier, corpus)
    scores = {"volume": volume, "velocity": velocity, "credibility": credibility, "novelty": novelty}
    decision = decide(scores, novelty_detail, thresholds)
    return {
        "signal_id": signal_id,
        "as_of": as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scores": scores,
        "thresholds": thresholds.to_dict(),
        **decision,
        "detail": {
            "volume": volume_detail,
            "velocity": velocity_detail,
            "credibility": credibility_detail,
            "novelty": novelty_detail,
        },
        "observation_ids": sorted(obs["observation_id"] for obs in observations),
    }
