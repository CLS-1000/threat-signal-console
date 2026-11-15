from datetime import UTC, datetime

import pytest

from threat_signal_console import gates
from threat_signal_console.gates import Thresholds
from threat_signal_console.textsim import Corpus


def obs(tier, when, source="s", oid=None, indicators=()):
    return {
        "observation_id": oid or f"{source}-{when}",
        "source_id": source,
        "source_name": source.upper(),
        "source_tier": tier,
        "observed_at": when,
        "indicators": list(indicators),
    }


AS_OF = datetime(2026, 11, 10, 12, tzinfo=UTC)


def test_volume_weights_mentions_by_tier():
    assert gates.gate_volume([obs(1, "2026-11-10T12:00:00Z")], AS_OF)[0] == 1.0
    assert gates.gate_volume([obs(2, "2026-11-10T12:00:00Z")], AS_OF)[0] == 0.5
    assert gates.gate_volume([obs(3, "2026-11-10T12:00:00Z")], AS_OF)[0] == 0.25
    assert gates.gate_volume([obs(4, "2026-11-10T12:00:00Z")], AS_OF)[0] == 0.125


def test_volume_ignores_mentions_outside_the_window():
    score, detail = gates.gate_volume([obs(1, "2026-11-01T00:00:00Z"), obs(3, "2026-11-10T12:00:00Z")], AS_OF)
    assert detail["mentions"] == 1 and score == 0.25


def test_velocity_single_mention_is_not_a_spike():
    score, detail = gates.gate_velocity([obs(1, "2026-11-10T12:00:00Z")], AS_OF)
    assert detail["z_score"] == 1.0 and score == pytest.approx(0.333)


def test_velocity_burst_saturates_and_steady_stream_does_not():
    burst = [obs(3, f"2026-11-10T{hour:02d}:00:00Z") for hour in (1, 5, 9)]
    assert gates.gate_velocity(burst, AS_OF)[0] == 1.0
    steady = [obs(3, f"2026-11-{day:02d}T06:00:00Z") for day in range(3, 11)]
    score, detail = gates.gate_velocity(steady, AS_OF)
    assert detail["recent_mentions"] == 1 and detail["baseline_mean"] == 1.0 and score == 0.0


def test_credibility_uses_best_tier_and_caps_corroboration():
    assert gates.gate_credibility([obs(1, "2026-11-10T00:00:00Z")])[0] == 0.9
    two = [obs(3, "2026-11-10T00:00:00Z", "a"), obs(2, "2026-11-10T01:00:00Z", "b")]
    assert gates.gate_credibility(two)[0] == 0.8
    many = [obs(4, "2026-11-10T00:00:00Z", name) for name in "abcdef"]
    score, detail = gates.gate_credibility(many)
    assert score == 0.3 and detail["corroboration_bonus"] == 0.1  # chatter never clears the 0.40 floor


def test_novelty_redundant_only_without_new_indicators():
    corpus = Corpus({"old": "loader contacts server and installs tool", "new": "loader contacts server and installs tool"})
    earlier = [{"signal_id": "old", "title": "Old", "indicator_keys": {"ipv4:192.0.2.1"}}]
    score, detail = gates.gate_novelty("new", [{"type": "ipv4", "value": "192.0.2.1"}], earlier, corpus)
    assert detail["max_similarity"] == 1.0 and detail["new_indicator_count"] == 0 and score == 0.0
    _, fresh = gates.gate_novelty("new", [{"type": "ipv4", "value": "192.0.2.9"}], earlier, corpus)
    assert fresh["new_indicators"] == ["ipv4:192.0.2.9"]


NOVEL = {"most_similar_signal": None, "max_similarity": 0.0, "new_indicator_count": 1}


@pytest.mark.parametrize(
    "scores, novelty, state, reason",
    [
        ({"volume": 0.4, "velocity": 1.0, "credibility": 1.0}, NOVEL, "DROPPED", "VOLUME_BELOW_FLOOR"),
        ({"volume": 1.0, "velocity": 1.0, "credibility": 0.3}, NOVEL, "DROPPED", "PROVENANCE_BELOW_FLOOR"),
        ({"volume": 1.0, "velocity": 1.0, "credibility": 0.9}, {"most_similar_signal": "x", "max_similarity": 0.9, "new_indicator_count": 0, "most_similar_title": "X"}, "DROPPED", "REDUNDANT"),
        ({"volume": 1.0, "velocity": 0.7, "credibility": 0.9}, NOVEL, "ESCALATED", "PASSED_ALL_GATES"),
        ({"volume": 1.0, "velocity": 0.3, "credibility": 0.9}, NOVEL, "WATCHED", "VELOCITY_BELOW_THRESHOLD"),
        ({"volume": 1.0, "velocity": 0.9, "credibility": 0.5}, NOVEL, "WATCHED", "CREDIBILITY_BELOW_THRESHOLD"),
        ({"volume": 1.0, "velocity": 0.3, "credibility": 0.5}, NOVEL, "DROPPED", "BELOW_BOTH_THRESHOLDS"),
    ],
)
def test_decision_rules(scores, novelty, state, reason):
    decision = gates.decide({**scores, "novelty": 1.0}, novelty, Thresholds())
    assert (decision["state"], decision["reason"]) == (state, reason)


def test_no_slider_setting_escalates_weak_provenance():
    loose = Thresholds(velocity=0.0, credibility=0.0)
    decision = gates.decide({"volume": 1.0, "velocity": 1.0, "credibility": 0.3, "novelty": 1.0}, NOVEL, loose)
    assert decision["state"] == "DROPPED"


def test_thresholds_reject_out_of_range():
    with pytest.raises(ValueError):
        Thresholds.from_dict({"velocity": 1.5})
