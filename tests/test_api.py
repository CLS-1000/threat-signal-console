import pytest
from fastapi.testclient import TestClient

from threat_signal_console.web.app import create_app


@pytest.fixture
def client(loaded):
    return TestClient(create_app(loaded.dir))


def find(client, label):
    return next(signal for signal in client.get("/api/v1/signals").json()["signals"] if signal["label"] == label)


def test_console_page_is_self_contained(client):
    page = client.get("/")
    assert page.status_code == 200 and "Threat Signal Console" in page.text
    assert "https://" not in page.text.replace("https?:", "") and "http://www.w3.org/2000/svg" in page.text  # no CDN, no remote fonts


def test_signals_and_preview(client):
    body = client.get("/api/v1/signals").json()
    assert body["preview"] is False and body["counts"] == {"ESCALATED": 1, "WATCHED": 3, "DROPPED": 3}
    preview = client.get("/api/v1/signals", params={"credibility": 0.45}).json()
    assert preview["preview"] is True and preview["counts"]["ESCALATED"] == 2
    assert client.get("/api/v1/signals", params={"credibility": 2}).status_code == 422


def test_signal_detail_carries_evidence(client):
    signal = find(client, "CVE-2099-0001")
    detail = client.get(f"/api/v1/signals/{signal['signal_id']}").json()
    assert detail["state"] == "ESCALATED" and len(detail["observations"]) == 3
    assert detail["detail"]["velocity"]["explanation"].startswith("3 mention(s)")
    assert client.get("/api/v1/signals/sig-nope").status_code == 404


def test_verdict_round_trip(client):
    signal = find(client, "CVE-2099-0001")
    created = client.post("/api/v1/verdicts", json={"signal_id": signal["signal_id"], "analyst_id": "tester", "call": "THREAT", "notes": "<script>x</script>"})
    assert created.status_code == 201 and created.json()["outcome"] == "TRUE_POSITIVE"
    assert client.get("/api/v1/verdicts").json()[0]["notes"] == "<script>x</script>"  # stored as text; the page renders it as text
    assert client.get("/api/v1/calibration").json()["as_recorded"]["true_positive"] == 1
    newest = client.get("/api/v1/audit", params={"limit": 1}).json()[0]
    assert newest["event_type"] == "VERDICT"
    assert client.get(f"/api/v1/audit/{newest['seq']}").json()["payload"]["analyst_id"] == "tester"

    bad = {"signal_id": signal["signal_id"], "analyst_id": "tester", "call": "MAYBE"}
    assert client.post("/api/v1/verdicts", json=bad).status_code == 422
    assert client.post("/api/v1/verdicts", json={**bad, "call": "NOISE", "signal_id": "sig-nope"}).status_code == 404
    assert client.post("/api/v1/verdicts", json={**bad, "call": "NOISE", "analyst_id": ""}).status_code == 422


def test_thresholds_round_trip(client):
    saved = client.put("/api/v1/thresholds", json={"set_by": "tester", "credibility": 0.45})
    assert saved.status_code == 200 and saved.json()["signals_changed"] == 1
    assert client.get("/api/v1/thresholds").json()["credibility"] == 0.45
    assert client.get("/api/v1/signals").json()["counts"]["ESCALATED"] == 2
    assert client.put("/api/v1/thresholds", json={"set_by": "tester", "velocity": 7}).status_code == 422
    assert client.put("/api/v1/thresholds", json={"credibility": 0.5}).status_code == 422  # must say who


def test_status(client):
    status = client.get("/api/v1/status").json()
    assert status["signals"] == 7 and status["observations"] == 15 and len(status["sources"]) == 3
    assert status["audit_events"] > 0 and len(status["audit_head_hash"]) == 64
