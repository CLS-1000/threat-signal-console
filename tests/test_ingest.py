from datetime import UTC, datetime

import pytest

from threat_signal_console import ingest
from threat_signal_console.models import Source

KEV = Source(id="kev", name="KEV", kind="kev", tier=1, location="memory")
STIX = Source(id="feed", name="Feed", kind="stix", tier=3, location="memory")
NOW = datetime(2026, 11, 14, tzinfo=UTC)


def kev_doc(*entries):
    return {"catalogVersion": "test", "vulnerabilities": list(entries)}


def kev_entry(cve="CVE-2026-1234", added="2026-11-10", **extra):
    return {"cveID": cve, "vendorProject": "Example", "product": "Thing", "vulnerabilityName": "Example Thing Flaw",
            "dateAdded": added, "shortDescription": "A flaw.", "dueDate": "2026-12-01", **extra}


def test_kev_entry_becomes_an_observation():
    result = ingest.kev.normalize(KEV, kev_doc(kev_entry()), NOW)
    (observation,) = result.observations
    assert observation.subject_key == "cve:CVE-2026-1234"
    assert observation.observed_at == "2026-11-10T00:00:00Z"
    assert observation.indicators == [{"type": "cve", "value": "CVE-2026-1234"}]
    assert observation.attributes["vendor"] == "Example"
    assert observation.raw["cveID"] == "CVE-2026-1234"


def test_kev_rejects_bad_entries_and_skips_old_ones():
    source = Source(id="kev", name="KEV", kind="kev", tier=1, location="memory", max_age_days=30)
    document = kev_doc(kev_entry(), kev_entry(cve="not-a-cve"), kev_entry(cve="CVE-2026-2", added="soon"), kev_entry(cve="CVE-2020-11111", added="2021-01-01"), "junk")
    result = ingest.kev.normalize(source, document, NOW)
    assert len(result.observations) == 1 and len(result.rejected) == 3 and result.skipped_old == 1


def test_kev_wrong_shape_is_an_error():
    with pytest.raises(ingest.IngestError):
        ingest.kev.normalize(KEV, {"nope": []}, NOW)


def test_observation_id_is_stable_across_revisions():
    first = ingest.kev.normalize(KEV, kev_doc(kev_entry()), NOW).observations[0]
    second = ingest.kev.normalize(KEV, kev_doc(kev_entry(notes="edited")), NOW).observations[0]
    assert first.observation_id == second.observation_id and first.content_hash != second.content_hash


def stix_obj(kind="vulnerability", name="CVE-2026-5555", **extra):
    return {"type": kind, "spec_version": "2.1", "id": f"{kind}--11111111-2222-4333-8444-555555555555",
            "created": "2026-11-09T10:00:00.000Z", "modified": "2026-11-09T10:00:00.000Z", "name": name, **extra}


def test_stix_reads_cve_pattern_and_attack_references():
    obj = stix_obj(
        "indicator", "Exploit source for CVE-2026-5555",
        description="Seen from 198.51.100.7.",
        pattern="[ipv4-addr:value = '198.51.100.9'] OR [file:hashes.'SHA-256' = 'AA" + "0" * 62 + "']",
        kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
        external_references=[{"source_name": "mitre-attack", "external_id": "T1190", "url": "https://attack.mitre.org/techniques/T1190/"}],
    )
    (observation,) = ingest.stix.normalize(STIX, {"type": "bundle", "id": "bundle--x", "objects": [obj]}, NOW).observations
    kinds = {(item["type"], item["value"]) for item in observation.indicators}
    assert ("cve", "CVE-2026-5555") in kinds and ("ipv4", "198.51.100.9") in kinds and ("ipv4", "198.51.100.7") in kinds
    assert ("sha256", "aa" + "0" * 62) in kinds
    assert observation.subject_key == "cve:CVE-2026-5555"
    assert observation.techniques == ["T1190"] and observation.tactics == ["initial-access"]
    assert observation.reference_url.startswith("https://attack.mitre.org/")


def test_stix_without_cve_stands_as_its_own_subject():
    (observation,) = ingest.stix.normalize(STIX, [stix_obj("malware", "ExampleLoader")], NOW).observations
    assert observation.subject_key.startswith("stix:malware--")


def test_stix_skips_non_signal_types_and_rejects_bad_ids():
    objects = [
        {"type": "identity", "id": "identity--11111111-2222-4333-8444-555555555555", "name": "Org"},
        {"type": "relationship", "id": "relationship--11111111-2222-4333-8444-555555555555"},
        {"type": "malware", "id": "tool--11111111-2222-4333-8444-555555555555", "created": "2026-11-09T10:00:00Z", "name": "x"},
        {"type": "malware", "id": "malware--11111111-2222-4333-8444-555555555555", "name": "no timestamp"},
        "junk",
    ]
    result = ingest.stix.normalize(STIX, objects, NOW)
    assert result.observations == [] and len(result.rejected) == 3


def test_normalize_rejects_non_json():
    with pytest.raises(ingest.IngestError):
        ingest.normalize(STIX, b"<html>not json</html>")


def test_fetch_missing_file_is_an_ingest_error(tmp_path):
    with pytest.raises(ingest.IngestError):
        ingest.fetch(str(tmp_path / "missing.json"))
