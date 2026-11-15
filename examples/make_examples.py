"""Regenerate the synthetic example feeds in this folder.

Everything here is made up: the vendor ("Example Networks"), the CVE IDs (year
2099), and the indicators (documentation-only IP ranges from RFC 5737). The feeds
exist so the whole pipeline can be exercised offline and so tests have fixed input.

    python examples/make_examples.py
"""

import json
import uuid
from pathlib import Path

HERE = Path(__file__).parent
NAMESPACE = uuid.UUID("6f1c5d7e-0c1a-4d1e-9a55-0d6f8f3b2a10")
NOTE = "Synthetic example, not a real advisory. "


def stix(kind: str, key: str, when: str, name: str, description: str, **extra) -> dict:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid5(NAMESPACE, key)}",
        "created": when,
        "modified": when,
        "name": name,
        "description": NOTE + description,
        **extra,
    }


def cve_ref(cve: str) -> dict:
    return {"source_name": "cve", "external_id": cve}


def attack_ref(technique: str) -> dict:
    return {"source_name": "mitre-attack", "external_id": technique, "url": f"https://attack.mitre.org/techniques/{technique}/"}


def bundle(key: str, objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid5(NAMESPACE, key)}", "objects": objects}


LOADER_TEXT = (
    "ExampleLoader is delivered through invoices attached to phishing mail. The attachment drops a loader "
    "that contacts 198.51.100.23 and installs a remote access tool."
)

vendor = bundle("vendor", [
    stix("vulnerability", "v1", "2026-11-10T09:00:00Z", "CVE-2099-0001",
         "Example Networks Gateway contains an authentication bypass in its management interface that lets a remote attacker run commands.",
         external_references=[cve_ref("CVE-2099-0001"), attack_ref("T1190")]),
    stix("vulnerability", "v2", "2026-11-08T14:00:00Z", "CVE-2099-0002",
         "Example Mail Server contains a heap overflow in its message parser. No exploitation has been reported.",
         external_references=[cve_ref("CVE-2099-0002")]),
    stix("malware", "v3", "2026-11-06T08:00:00Z", "ExampleLoader phishing campaign", LOADER_TEXT,
         is_family=False, external_references=[attack_ref("T1566.001")]),
    stix("malware", "v4", "2026-11-07T08:00:00Z", "ExampleLoader phishing campaign (reissued)", LOADER_TEXT,
         is_family=False, external_references=[attack_ref("T1566.001")]),
])

osint = bundle("osint", [
    stix("report", "o1", "2026-11-10T15:00:00Z", "Exploitation of CVE-2099-0001 seen against exposed gateways",
         "Researchers report scanning and exploitation of Example Networks Gateway from 192.0.2.44 and 192.0.2.61.",
         published="2026-11-10T15:00:00Z", report_types=["threat-report"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0001")]),
    stix("indicator", "o2", "2026-11-10T18:00:00Z", "CVE-2099-0001 exploitation source",
         "Address seen delivering the gateway exploit.",
         pattern="[ipv4-addr:value = '192.0.2.44']", pattern_type="stix", valid_from="2026-11-10T18:00:00Z",
         external_references=[cve_ref("CVE-2099-0001")]),
    stix("report", "o3", "2026-11-09T10:00:00Z", "CVE-2099-0003: Example Paint crashes on malformed image",
         "A crafted image crashes Example Paint. A blog post claims code execution without proof.",
         published="2026-11-09T10:00:00Z", report_types=["vulnerability"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0003")]),
    stix("report", "o4", "2026-11-09T12:00:00Z", "More claims about CVE-2099-0003 in Example Paint",
         "A second post repeats the code execution claim for the Example Paint image parser.",
         published="2026-11-09T12:00:00Z", report_types=["vulnerability"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0003")]),
    stix("report", "o5", "2026-11-09T16:00:00Z", "CVE-2099-0003 test file circulates",
         "A sample file that triggers the Example Paint crash is being shared.",
         published="2026-11-09T16:00:00Z", report_types=["vulnerability"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0003")]),
    stix("report", "o6", "2026-11-05T11:00:00Z", "CVE-2099-0004 note on Example Console networking",
         "One write-up describes a low-impact flaw in Example Console networking.",
         published="2026-11-05T11:00:00Z", report_types=["vulnerability"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0004")]),
])

chatter = bundle("chatter", [
    stix("report", f"c{number}", f"2026-11-11T{hour:02d}:00:00Z", f"CVE-2099-0005 zero-day PoC dropped (post {number})",
         "An anonymous paste claims a working exploit. Nobody has confirmed it.",
         published=f"2026-11-11T{hour:02d}:00:00Z", report_types=["vulnerability"], object_refs=[],
         external_references=[cve_ref("CVE-2099-0005")])
    for number, hour in enumerate((2, 5, 9, 13, 17), start=1)
])

for filename, document in (
    ("synthetic_vendor_advisories.stix.json", vendor),
    ("synthetic_osint_reports.stix.json", osint),
    ("synthetic_chatter.stix.json", chatter),
):
    (HERE / filename).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print("wrote", filename, len(document["objects"]), "objects")
