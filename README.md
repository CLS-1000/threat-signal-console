# Threat Signal Console

A console for triaging cyber threat signals. It pulls items from threat feeds, groups them by what they are about, scores each group through four gates, and sorts it into **escalated**, **watched** or **dropped**. For every signal it shows why it landed there, the evidence behind it and where that evidence came from. Analysts record verdicts, and the console measures its own triage against them.

It runs locally: one Python package, one SQLite file, one append-only log. The page needs no internet connection and loads nothing from a CDN.

## What works and what doesn't

| Area | State |
|---|---|
| Ingest: CISA KEV catalog | Works. Tested against the live feed on 2026-11-14. |
| Ingest: STIX 2.1 bundles from a URL or file | Works on the bundled synthetic feeds and in tests. Not yet run against a third-party production feed. It is a structural reader, not a full STIX validator, and it does not follow relationship objects. |
| Four gates and the triage decision | Works. Deterministic; covered by tests. |
| Console page | Works. Checked in headless Chromium. |
| Analyst verdicts and calibration report | Works. |
| Audit log with hash chain, verify, rebuild | Works. |
| Login / access control | **Not built.** The API trusts whoever can reach it and takes the analyst's name on their word. Keep it on `127.0.0.1`. |
| Scheduled ingest | **Not built.** Ingest runs when you run the command. Use cron or a systemd timer. |
| TAXII, NVD, RSS and other feed types | **Not built.** Only `kev` and `stix` adapters exist. |
| Deployment (nginx, systemd, containers) | **Not built.** |
| Windows without WSL | Untested. Cross-process locking uses `fcntl`, which is POSIX-only. |

## Quick start

```bash
git clone https://github.com/CLS-1000/threat-signal-console
cd threat-signal-console
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Try it offline with the synthetic example feeds (everything in them is made up):

```bash
threat-signal-console --data-dir demo-data ingest --sources examples/sources.toml
threat-signal-console --data-dir demo-data serve
```

Then open `http://127.0.0.1:8000`.

Use real data: `config/sources.toml` ships with the CISA KEV catalog enabled, limited to entries added in the last 30 days.

```bash
threat-signal-console ingest
threat-signal-console serve
```

Data goes to `./data` unless you pass `--data-dir` or set `TSC_DATA_DIR`.

## How triage works

An **observation** is one item from one source: one KEV entry, one STIX object. A **signal** is every observation about the same subject. The subject is the CVE ID when there is one, otherwise the STIX object itself. Gates score the signal as of its newest observation, so a second source reporting the same CVE changes the scores of the signal that is already there.

### Source tiers

You assign each source a tier in the sources file. It is your judgement of that source.

| Tier | Meaning | Volume weight | Starting credibility |
|---|---|---|---|
| 1 | Authoritative catalog | 4 | 0.90 |
| 2 | Vendor or CERT advisory | 2 | 0.75 |
| 3 | Open-source reporting | 1 | 0.50 |
| 4 | Unverified chatter | 0.5 | 0.20 |

### The four gates

Each gate gives a score from 0 to 1 and records the inputs it used.

| Gate | Question | Score |
|---|---|---|
| 01 Volume | Is there enough reporting to bother with? | Mentions in the last 7 days, weighted by tier, divided by 4, capped at 1. |
| 02 Velocity | Is reporting spiking right now? | z-score of mentions in the last 24 hours against the daily counts of the 7 days before, divided by 3, clamped to 0–1. The standard deviation is floored at 1. |
| 03 Credibility | How far can the sourcing be trusted? | Starting credibility of the best tier, plus 0.05 for each additional independent source, up to +0.10. |
| 04 Novelty | Does this add anything? | 1 minus the text similarity (TF-IDF cosine) to the closest earlier signal seen in the last 30 days. Also lists indicators the closest signal lacks. |

### The decision

Rules are checked in this order and the first match wins.

| # | Condition | State | Reason code |
|---|---|---|---|
| 1 | Volume under the volume floor (0.50) | Dropped | `VOLUME_BELOW_FLOOR` |
| 2 | Credibility under the provenance floor (0.40) | Dropped | `PROVENANCE_BELOW_FLOOR` |
| 3 | Similarity at or over 0.85 to an earlier signal, with no new indicator | Dropped | `REDUNDANT` |
| 4 | Credibility and velocity both meet their pass marks (0.65 each) | Escalated | `PASSED_ALL_GATES` |
| 5 | Credibility meets its pass mark, velocity doesn't | Watched | `VELOCITY_BELOW_THRESHOLD` |
| 6 | Velocity meets its pass mark, credibility doesn't | Watched | `CREDIBILITY_BELOW_THRESHOLD` |
| 7 | Neither meets its pass mark | Dropped | `BELOW_BOTH_THRESHOLDS` |

What this means in practice, at the defaults:

- One Tier 1 or Tier 2 mention clears the volume floor. Tier 3 needs two mentions in a week; Tier 4 needs four.
- Tier 4 chatter tops out at 0.30 credibility, so it can never clear the provenance floor on its own, however loud it gets.
- **A single mention is never a spike.** One KEV entry with no other reporting scores 0.33 on velocity and lands on the watch list. It escalates when a second source reports the same CVE within 24 hours. With KEV as the only source, expect everything to be watched.

All numbers above are constants at the top of `src/threat_signal_console/gates.py`. They are starting values, not tuned ones.

### Thresholds

The two pass marks (velocity, credibility) can be moved from the page. Dragging a slider is a **preview**: it re-triages on screen and saves nothing. "Save and re-triage" stores the new pass marks, logs who changed them, and logs a new evaluation for every signal whose state changed. The three fixed values (volume floor, provenance floor, similarity ceiling) change from the command line:

```bash
threat-signal-console thresholds
threat-signal-console thresholds --provenance-floor 0.45 --set-by matt
```

## Sources

`config/sources.toml` lists what `ingest` fetches. Each entry has an `id`, a `name`, a `kind` (`kev` or `stix`), a `tier`, and a `url` or `path`. `max_age_days` skips items older than that.

```bash
threat-signal-console ingest                      # every enabled source
threat-signal-console ingest --source cisa-kev    # one source
threat-signal-console ingest --file feed.json --kind stix --tier 3 --name "My feed"
```

Running ingest again is safe. Unchanged items are skipped. An item whose content changed is stored as a revision of the same observation, so an edited advisory does not count as a second mention.

## Verdicts and calibration

In the inspector, an analyst calls a signal a **real threat**, **noise**, or flags a **wrong source tier**. The console works out the outcome itself from the state the signal was in:

| | Analyst: real threat | Analyst: noise |
|---|---|---|
| Was escalated | True positive | False positive |
| Was not escalated | False negative | True negative |

Each verdict is stored with the scores and thresholds in force at that moment. The newest verdict on a signal is the one that counts.

The calibration panel (and `threat-signal-console calibrate`) reports the confusion matrix, precision, recall, which reason codes the misses fall under, and wrong-tier reports per source. Once there are at least 20 judged signals, with 5 or more of each call, it replays the judged signals under other pass marks and reports the pair with the best F1. That is a fit to past verdicts, not a forecast, and it is never applied automatically.

## Audit log

Everything the console knows is in `data/audit_log.jsonl`: one JSON event per line, append-only. Event types are `OBSERVATION`, `EVALUATION`, `VERDICT`, `THRESHOLDS` and `INGEST_RUN`. Each event carries a sequence number and the SHA-256 of the line before it.

`data/index.sqlite` is a queryable copy. It can be deleted and rebuilt from the log.

```bash
threat-signal-console verify     # check the hash chain and compare the log with the index
threat-signal-console rebuild    # rebuild the index from the log
threat-signal-console status
```

`verify` exits non-zero if a line was edited, removed or reordered, or if the log and index disagree. If the process dies mid-write, the next start replays what the index missed and drops a half-written final line.

The hash chain detects changes inside the file. It is not a signature: someone who can rewrite the whole log can rewrite the chain. If that matters, keep a copy of the head hash (`status` prints it) somewhere else.

## API

Interactive docs are at `/docs` when the server is running.

| Method and path | Purpose |
|---|---|
| `GET /api/v1/signals` | All signals with scores, state, reason and gate detail. `?velocity=` and `?credibility=` preview other pass marks. |
| `GET /api/v1/signals/{id}` | One signal with its observations, verdicts and evaluation history. |
| `POST /api/v1/verdicts` | Record a verdict: `signal_id`, `analyst_id`, `call` (`THREAT`, `NOISE`, `WRONG_TIER`), `notes`. |
| `GET /api/v1/verdicts` | Recent verdicts. |
| `GET` / `PUT /api/v1/thresholds` | Read or save thresholds. `PUT` needs `set_by`. |
| `GET /api/v1/calibration` | The calibration report. |
| `GET /api/v1/audit`, `GET /api/v1/audit/{seq}` | Recent audit events, or one event as stored. |
| `GET /api/v1/status` | Counts, sources, last ingest, audit log head. |

## Tests

```bash
pytest
```

50 tests cover the gates, both adapters, the store (tamper detection, crash recovery, rebuild), the pipeline on the example feeds, calibration, and the API.

## Layout

```
config/sources.toml              sources to ingest
examples/                        synthetic feeds and the script that makes them
src/threat_signal_console/
    ingest/                      kev.py, stix.py: one adapter per feed format
    gates.py                     the four gates and the decision rules
    textsim.py                   TF-IDF similarity for the novelty gate
    pipeline.py                  ingest → store → evaluate; thresholds; verdicts
    calibration.py               triage measured against verdicts
    store.py                     audit log, hash chain, SQLite index
    web/app.py                   API
    web/static/index.html        the console page
    cli.py                       command line
docs/draft-review.md             what the first draft claimed, and what changed
```

## License

Apache 2.0. See `LICENSE`.
