# Review of the first draft

The console started from a draft package named "Cache-22 CTI Triage Pipeline" plus a standalone dashboard page. This note records what that draft claimed, what it actually did, and what happened to each piece. It is here so nobody later mistakes a draft claim for a working feature.

## Stale branding removed

| Where | Draft | Now |
|---|---|---|
| Product name, page title, header badge | Cache-22 // CTI Triage Matrix, "C22" | Threat Signal Console |
| Python package | `cache22` | `threat_signal_console` |
| Class name | `STIX22IngestionEngine` | adapter functions in `ingest/` |
| Record IDs | `c22-…`, `vurd-…` | `obs-…`, `sig-…`, `verd-…` |
| Paths and env vars | `/opt/cache22`, `CACHE22_*` | `./data`, `TSC_DATA_DIR`, `TSC_SOURCES` |
| Service names | `cache22-web`, `cache22-ingest`, `cache22.internal` | not carried over (see below) |

## Gaps between what the draft said and what it did

| Draft claim | What was there | Now |
|---|---|---|
| Four progressive scoring gates | Only Gate 04 had code. Gates 01–03 did not exist, and nothing ran a signal through any gate. | All four gates and the decision rules are in `gates.py`. |
| Ingestion service started by `entrypoint.sh` | `stage01_ingest.py` had no command-line entry point, so the service could not start. It could parse a bundle but nothing stored the result. | `ingest` command; KEV and STIX adapters; results stored and scored. |
| "STIX 2.1 bundles, CVE advisories, EDR alerts, and OSINT chatter" | A STIX parser only. | STIX and CISA KEV. EDR alerts and other formats are not built and not claimed. |
| Crash-safe dual-write (JSONL + SQLite WAL) | The app only created the manifest table. The verdicts table it wrote to was never created unless a separate SQL file was applied by hand, and verdicts had a foreign key to a signals table nothing filled. Every verdict write would have failed. | One store creates its own schema. Events are checked against the index, appended and fsynced, then committed. Crash recovery and tamper detection are tested. |
| Deterministic scoring | Gate 04 named new clusters with Python's `hash()`, which changes on every run. | Pure-Python TF-IDF; same input, same output. |
| Calibration engine | Counted "analyst says threat, system did not escalate" as a true negative. Assumed the threshold was always 0.65. Reported percentiles of false-positive scores as a "confidence interval". Could only ever recommend raising a threshold. | Outcomes are derived from recorded state. The report replays judged signals under other pass marks and says so plainly when there are too few verdicts. |
| Analysts pick TRUE_POSITIVE / FALSE_POSITIVE / FALSE_NEGATIVE | The analyst could pick an outcome that contradicted the signal's state. | The analyst says "real threat" or "noise"; the outcome is worked out. |
| Dashboard: "PIPELINE ACTIVE", "Dual-Write Ready", "Verdict committed to JSONL + SQLite WAL", "z-score 20m sliding window" | A static page with 11 hardcoded signals. It never called the API. Verdicts lived in browser memory. | The page reads and writes through the API. Those labels are gone. |
| Dashboard data described as a November 2026 KEV dataset | Hand-entered records with invented scores. Some CVE IDs match real KEV entries, the scores and indicators did not come from any feed. | Removed. Real KEV data comes from the feed; made-up data lives in `examples/` and is labelled synthetic. |
| nginx and systemd deployment | Untested units pointing at `/opt/cache22` and at the ingest command that could not start. | Not carried over. Deployment is listed as not built. |
| Dependencies | fastapi, uvicorn, gunicorn, pydantic, httpx, stix2, numpy, scikit-learn | fastapi and uvicorn. Tests add pytest and httpx. |
| Tests | An empty folder. | 50 tests. |

## Draft ideas kept

- Modular ingestion with a normalized record per item.
- Four gates in a fixed order, each with a score from 0 to 1.
- A hard provenance floor that the sliders cannot override.
- Gate 04's rule: redundant only when the text is near-identical **and** no new indicator appears.
- An append-only JSONL log as the record of truth, with SQLite as an index and a reconcile step on start.
- Analyst verdicts stored with the thresholds in force, feeding calibration.
- The console layout: threshold sliders, credibility × velocity chart, signal table, inspector, audit stream.

## Decisions made here that are worth a second look

- **A signal is a subject, not an item.** Observations about one CVE are scored together. The draft scored each item alone.
- **Volume is weighted by tier.** Without that, either a single authoritative entry gets dropped for low volume or the gate does nothing.
- **A single mention scores 0.33 on velocity.** So a KEV entry alone is watched, not escalated. If a Tier 1 listing should escalate on its own, that is a rule to add, not a threshold to tune.
- **Verdict vocabulary changed** from outcome labels to analyst calls.
