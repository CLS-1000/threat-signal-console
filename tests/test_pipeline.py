import json

import pytest
from conftest import EXAMPLES, by_label

from threat_signal_console import calibration, config, pipeline
from threat_signal_console.models import Source

EXPECTED = {
    "CVE-2099-0001": ("ESCALATED", "PASSED_ALL_GATES"),
    "CVE-2099-0002": ("WATCHED", "VELOCITY_BELOW_THRESHOLD"),
    "CVE-2099-0003": ("WATCHED", "CREDIBILITY_BELOW_THRESHOLD"),
    "CVE-2099-0004": ("DROPPED", "VOLUME_BELOW_FLOOR"),
    "CVE-2099-0005": ("DROPPED", "PROVENANCE_BELOW_FLOOR"),
}


def test_example_feeds_triage_as_documented(loaded):
    signals = by_label(loaded)
    for label, expected in EXPECTED.items():
        assert (signals[label]["state"], signals[label]["reason"]) == expected, label
    others = sorted((s["title"], s["state"], s["reason"]) for label, s in signals.items() if label not in EXPECTED)
    assert others == [
        ("ExampleLoader phishing campaign", "WATCHED", "VELOCITY_BELOW_THRESHOLD"),
        ("ExampleLoader phishing campaign (reissued)", "DROPPED", "REDUNDANT"),
    ]


def test_signal_combines_sources_and_keeps_provenance(loaded):
    signal = loaded.get_signal(by_label(loaded)["CVE-2099-0001"]["signal_id"])
    assert signal["source_count"] == 2 and signal["observation_count"] == 3
    assert {obs["source_tier"] for obs in signal["observations"]} == {2, 3}
    for obs in signal["observations"]:
        assert obs["raw"]["id"] == obs["object_key"] and len(obs["content_hash"]) == 64
    assert signal["evaluation"]["detail"]["credibility"]["corroboration_bonus"] == 0.05


def test_reingest_is_idempotent(loaded):
    events = loaded.status()["audit_events"]
    for source in config.load_sources(EXAMPLES / "sources.toml"):
        run = pipeline.ingest_source(loaded, source)
        assert run["new"] == 0 and run["revised"] == 0 and run["signals_evaluated"] == 0
    assert loaded.status()["audit_events"] == events + 3  # one INGEST_RUN record per source, nothing else


def test_revised_item_does_not_count_as_a_new_mention(store, tmp_path):
    feed = tmp_path / "kev.json"
    source = Source(id="kev", name="KEV", kind="kev", tier=1, location=str(feed))
    entry = {"cveID": "CVE-2026-4242", "vulnerabilityName": "Example Flaw", "dateAdded": "2026-11-10", "shortDescription": "A flaw."}
    feed.write_text(json.dumps({"vulnerabilities": [entry]}))
    assert pipeline.ingest_source(store, source)["new"] == 1
    feed.write_text(json.dumps({"vulnerabilities": [{**entry, "notes": "updated"}]}))
    run = pipeline.ingest_source(store, source)
    assert run["revised"] == 1 and run["new"] == 0
    signal = by_label(store)["CVE-2026-4242"]
    assert signal["observation_count"] == 1 and signal["detail"]["velocity"]["recent_mentions"] == 1
    assert store.get_signal(signal["signal_id"])["observations"][0]["revision"] == 2


def test_failed_fetch_is_recorded_not_raised(store, tmp_path):
    run = pipeline.ingest_source(store, Source(id="gone", name="Gone", kind="stix", tier=3, location=str(tmp_path / "nope.json")))
    assert "error" in run and store.status()["last_ingest"]["error"]


def test_preview_does_not_change_anything(loaded):
    events = loaded.status()["audit_events"]
    preview = pipeline.list_signals(loaded, {"credibility": 0.45})
    assert preview["preview"] and preview["counts"]["ESCALATED"] == 2
    assert loaded.status()["audit_events"] == events and by_label(loaded)["CVE-2099-0003"]["state"] == "WATCHED"


def test_saving_thresholds_retriages_and_logs(loaded):
    result = pipeline.set_thresholds(loaded, {"credibility": 0.45}, "tester")
    assert result["changed"] and result["signals_changed"] == 1
    signal = loaded.get_signal(by_label(loaded)["CVE-2099-0003"]["signal_id"])
    assert signal["evaluation"]["state"] == "ESCALATED" and signal["evaluation_history"][0]["trigger"] == "thresholds"
    assert by_label(loaded)["CVE-2099-0005"]["state"] == "DROPPED"  # provenance floor still holds
    assert pipeline.set_thresholds(loaded, {"credibility": 0.45}, "tester")["changed"] is False
    assert loaded.verify()["ok"]


def test_verdict_outcome_is_derived_from_state(loaded):
    signals = by_label(loaded)
    hit = pipeline.record_verdict(loaded, signals["CVE-2099-0001"]["signal_id"], "tester", "THREAT", "confirmed")
    miss = pipeline.record_verdict(loaded, signals["CVE-2099-0003"]["signal_id"], "tester", "THREAT")
    quiet = pipeline.record_verdict(loaded, signals["CVE-2099-0005"]["signal_id"], "tester", "NOISE")
    tier = pipeline.record_verdict(loaded, signals["CVE-2099-0002"]["signal_id"], "tester", "WRONG_TIER")
    assert [hit["outcome"], miss["outcome"], quiet["outcome"], tier["outcome"]] == ["TRUE_POSITIVE", "FALSE_NEGATIVE", "TRUE_NEGATIVE", None]
    assert hit["snapshot"]["scores"]["credibility"] == 0.8 and hit["snapshot"]["thresholds"]["velocity"] == 0.65

    report = calibration.report(loaded)
    assert report["judged_signals"] == 3 and report["total_verdicts"] == 4
    assert report["as_recorded"]["true_positive"] == 1 and report["as_recorded"]["false_negative"] == 1
    assert report["as_recorded"]["recall"] == 0.5 and report["as_recorded"]["precision"] == 1.0
    assert report["misses_by_reason"] == {"FALSE_NEGATIVE: CREDIBILITY_BELOW_THRESHOLD": 1}
    assert report["wrong_tier_reports_by_source"] == {"example-vendor": 1}
    assert report["suggestion"] is None and "No suggestion yet" in report["note"]


def test_verdict_validation(loaded):
    signal_id = by_label(loaded)["CVE-2099-0001"]["signal_id"]
    with pytest.raises(ValueError):
        pipeline.record_verdict(loaded, signal_id, "tester", "MAYBE")
    with pytest.raises(ValueError):
        pipeline.record_verdict(loaded, signal_id, "  ", "THREAT")
    with pytest.raises(LookupError):
        pipeline.record_verdict(loaded, "sig-missing", "tester", "THREAT")


def test_latest_verdict_on_a_signal_stands(loaded):
    signal_id = by_label(loaded)["CVE-2099-0001"]["signal_id"]
    pipeline.record_verdict(loaded, signal_id, "tester", "THREAT")
    pipeline.record_verdict(loaded, signal_id, "tester", "NOISE")
    report = calibration.report(loaded)
    assert report["judged_signals"] == 1 and report["as_recorded"]["false_positive"] == 1


def test_calibration_makes_no_suggestion_when_scores_cannot_separate(store, tmp_path):
    """Twenty-four judged signals with identical scores: no pair of pass marks can tell threat from noise."""
    objects = []
    for number in range(24):
        hour = number % 12
        objects.append({
            "type": "report", "spec_version": "2.1", "id": f"report--00000000-0000-4000-8000-{number:012d}",
            "created": f"2026-11-10T{hour:02d}:00:00Z", "published": f"2026-11-10T{hour:02d}:00:00Z",
            "name": f"CVE-2098-{1000 + number} advisory {number}", "description": f"distinct text number {number} " * 3,
        })
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"type": "bundle", "id": "bundle--x", "objects": objects}))
    pipeline.ingest_source(store, Source(id="vendor", name="Vendor", kind="stix", tier=2, location=str(feed)))
    pipeline.set_thresholds(store, {"velocity": 0.30}, "tester")  # single mentions (0.33) now escalate at credibility 0.75
    signals = by_label(store)
    assert all(signal["state"] == "ESCALATED" for signal in signals.values())
    for number, signal in enumerate(sorted(signals.values(), key=lambda item: item["label"])):
        pipeline.record_verdict(store, signal["signal_id"], "tester", "THREAT" if number < 8 else "NOISE")
    report = calibration.report(store)
    assert report["as_recorded"]["precision"] == pytest.approx(0.333)
    # Every signal has the same scores, so no pass marks can separate them: the honest answer is "no better pair".
    assert report["suggestion"] is None and "no other pair" in report["note"]


def test_calibration_suggests_pass_marks_that_fit_the_verdicts(store, tmp_path):
    """Threats are corroborated by a second source; noise is not. Higher pass marks separate them."""

    def report_object(number, source_number):
        return {
            "type": "report", "spec_version": "2.1", "id": f"report--00000000-0000-4000-8{source_number:03d}-{number:012d}",
            "created": f"2026-11-10T{number % 12:02d}:00:00Z", "published": f"2026-11-10T{number % 12:02d}:00:00Z",
            "name": f"CVE-2098-{2000 + number} advisory {number}", "description": f"distinct text number {number} " * 3,
        }

    vendor, second = tmp_path / "vendor.json", tmp_path / "second.json"
    vendor.write_text(json.dumps([report_object(number, 1) for number in range(24)]))
    second.write_text(json.dumps([report_object(number, 2) for number in range(8)]))  # corroborates the first eight
    pipeline.ingest_source(store, Source(id="vendor", name="Vendor", kind="stix", tier=2, location=str(vendor)))
    pipeline.ingest_source(store, Source(id="second", name="Second", kind="stix", tier=2, location=str(second)))
    pipeline.set_thresholds(store, {"velocity": 0.30}, "tester")
    signals = by_label(store)
    assert all(signal["state"] == "ESCALATED" for signal in signals.values())
    for signal in signals.values():
        pipeline.record_verdict(store, signal["signal_id"], "tester", "THREAT" if signal["source_count"] == 2 else "NOISE")

    report = calibration.report(store)
    assert report["as_recorded"]["precision"] == pytest.approx(0.333) and report["at_saved_thresholds"]["f1"] == 0.5
    suggestion = report["suggestion"]
    assert suggestion and suggestion["performance"]["f1"] == 1.0 and suggestion["based_on_judged_signals"] == 24
    assert suggestion["velocity"] > 0.333 or suggestion["credibility"] > 0.75
    assert store.current_thresholds().velocity == 0.30  # a suggestion never applies itself
