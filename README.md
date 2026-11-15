# Cache-22 // CTI Triage Matrix

A single-page console for triaging cyber threat intelligence (CTI) signals. It plots each signal by how credible its source is and how fast chatter about it is spiking, then sorts it into escalate, review, or drop. Two sliders let you move the cutoffs and watch every signal re-sort live.

Everything is in `index.html`. There is no backend and no build step.

> The 11 signals in the page are sample data. The CVE IDs, titles and indicators are illustrative, not real advisories.

## Run it

```bash
git clone https://github.com/CLS-1000/threat-signal-console
cd threat-signal-console
python3 -m http.server 8000
```

Then open `http://localhost:8000`. Opening `index.html` directly in a browser also works. The page needs an internet connection, because Tailwind, D3 and the fonts load from CDNs.

## How a signal gets triaged

Each signal carries four scores between 0 and 1, one per gate:

| Gate | Score | What it measures | Role in triage |
|---|---|---|---|
| 01 | `volumeScore` | How much mention volume the signal has | Fixed floor of 0.50 |
| 02 | `velocity` | How sharply mentions are spiking (normalized z-score) | Slider `θ_vel` |
| 03 | `credibility` | Source provenance and corroboration | Fixed floor of 0.40, then slider `θ_cred` |
| 04 | `novelty` | How new the indicators are versus what's already known | Display only (bubble size) |

`evaluateSignal()` applies the checks in this order, and the first match wins:

1. **Volume below 0.50** → `DROPPED // VOLUME_BELOW_FLOOR`
2. **Credibility below 0.40** → `DROPPED // SRC_TIER_BELOW_MIN`
3. **Credibility and velocity both at or above their sliders** → `ESCALATED // PASS ALL GATES`
4. **Credibility passes, velocity doesn't** → `WATCHLIST // VELOCITY_BELOW_FLOOR`
5. **Velocity passes, credibility doesn't** → `REVIEW QUEUE // CRED_BELOW_FLOOR`
6. **Neither passes** → `DROPPED // MULTI_GATE_FAIL`

The two fixed floors can't be moved from the page. That is deliberate: no slider setting can escalate an unverified, loud rumor. Both sliders run from 0.10 to 0.95 and start at 0.65.

Outcomes 4 and 5 are counted together as "Review/Watch" in the header.

## Reading the screen

**Header counters.** Escalated, Review/Watch and Dropped totals. They count only the signals that match the current tier and search filter.

**Controls.** The two threshold sliders, tier buttons (Tier 1 to Tier 4, or all), and a search box that matches CVE ID, title, vendor or tier label.

**Correlation matrix.** One bubble per signal:

- Across: Gate 03 credibility. The shaded background bands mark the rough credibility range of each source tier.
- Up: Gate 02 velocity.
- Bubble size: Gate 04 novelty.
- Bubble color: red escalated, amber review/watch, grey dropped.
- The dashed lines are the two slider cutoffs. The red box in the top-right corner is the escalation zone.

Hover a bubble for its scores. Click it to select it.

**Signal queue.** The same signals as a table, with the triage state for the current cutoffs. Scores that fail their slider turn grey. Click a row to select it.

**Signal inspector.** Details for the selected signal: summary, a bar per gate with pass/fail against the active cutoff, MITRE ATT&CK technique IDs, the gate it failed (if any), and its extracted indicators. If a filter hides the selected signal, selection moves to the first visible one.

**Analyst verdict.** Three buttons record a call on the selected signal: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `MISCLASSIFIED_TIER`.

**Audit log.** Each verdict appends one JSON line. "Copy Log" copies the whole log as JSONL.

## Verdict record

```json
{
  "log_offset": 1168,
  "verdict_id": "verd-3fa9c21b",
  "signal_id": "c22-8f91d20a",
  "cve_id": "CVE-2026-125350",
  "analyst_id": "soc-analyst-01",
  "event_type": "VERDICT",
  "verdict_outcome": "TRUE_POSITIVE",
  "attributed_gate": "CROSS_GATE",
  "thresholds_active": { "velocity": 0.65, "credibility": 0.65 },
  "reviewed_at": "2026-11-15T05:40:00.000Z"
}
```

- `attributed_gate` is the gate the signal failed at the time of the verdict, or `CROSS_GATE` if it passed everything.
- `thresholds_active` captures where the sliders were, so a verdict can be read against the cutoffs that produced the triage state.
- `log_offset` is the byte position the line would have in a JSONL file: the previous offset plus the previous line's length plus a newline.

## What is simulated

- **Data.** The signals are a hardcoded array (`cveDataset`). Nothing is ingested from a feed.
- **Scores.** The gate scores are fixed values on each record. The page does not compute z-scores, credibility or cosine similarity.
- **Persistence.** The audit log lives in memory and resets on reload. Nothing is written to a JSONL file or a database, despite the "Dual-Write Ready" label.
- **Analyst.** `analyst_id` is always `soc-analyst-01`.
- **Status.** The "PIPELINE ACTIVE" badge is static.

## Changing things

- Signals: edit `cveDataset` near the top of the script.
- Fixed floors: `VOLUME_FLOOR` and `PROVENANCE_FLOOR`, just above `evaluateSignal()`.
- Default slider positions: `state.velThreshold` and `state.credThreshold`, plus the slider `value` attributes and the reset handler.

All record fields are HTML-escaped before they are rendered, so signal text from an untrusted source can't inject markup into the page.

## License

Apache 2.0. See `LICENSE`.
