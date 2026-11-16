# AegisGate — Analysis Core (detection, behaviour, correlation, risk, policy)

Status: implemented and unit-tested as pure Python in `backend/app/core/`.
**Not yet connected** to the FastAPI service, the database or the dashboard.
The prototype's `risk_engine.py`, `access_decision.py` and `policy_engine.py`
are still the code the running API uses until the consolidation phase replaces them.

Versions: `core-1.0.0`, rules `DET-00x@1.0`, `correlation-1.0`, `risk-1.0`, `policy-academic-1.0`.

## Pipeline

    CanonicalEvent -> DetectionEngine -> correlate -> assess (risk) -> decide (policy)

`app.core.pipeline.analyse(events, assets, history)` runs all stages. Demo Lab
replay must call this same function.

## Canonical event (`events.py`, schema `canonical-event-1.0`)

Observed fields only; anything the sensor did not report stays `None`.
Internal addresses are RFC 1918, loopback and link-local. Documentation ranges
(198.51.100.0/24 and similar) count as external because the lab datasets use
them for external hosts. Direction is `None` when either address is missing.

## Detection rules (`detection.py`)

| Rule | Category | Default window | Default threshold | Severity | Confidence |
|---|---|---|---|---|---|
| DET-001 | port_scan | 60 s | 15 distinct destination ports | medium; high at 45+ | 0.60 at threshold, rising to 0.90 at twice the threshold |
| DET-002 | destination_scan | 60 s | 10 distinct destination hosts | medium; high at 30+ | 0.60 to 0.90, same scale |
| DET-003 | suspicious_outbound | 600 s | 8 connections to one external host, interval variation (CV) at most 0.2 | medium | 0.50 to 0.80 |
| DET-004 | potential_exfiltration | 300 s | 50 MB outbound, or 5 times the asset's median when a baseline exists | medium; high at 5 times the threshold | 0.50 to 0.80 |
| DET-005 | ids_alert | 300 s | any Suricata alert, grouped by source and signature | Suricata 1/2/3 maps to high/medium/low | fixed 0.60 |

All thresholds are constructor arguments. Detection identifiers are a hash of
rule, version, source and supporting event identifiers, so the same evidence
always gives the same identifier.

Calibration evidence so far is limited to generated traffic: with the DET-003
defaults, 1 of 300 two-hour sessions of irregular browsing was flagged and 5 of
5 one-minute beacons with up to 12 s of jitter were caught. With 6 connections
instead of 8 the false-positive count was 12 of 300. These numbers come from a
generator written for the tests, not from recorded traffic, and must be
repeated on laboratory captures.

Known limitations: TCP and UDP ports are not distinguished; DET-003 flags any
strictly periodic client (updaters, NTP); DET-004 does not inspect content;
DET-005 does not yet use Zeek notices; none of the rules has been run on
recorded Suricata or Zeek captures yet.

## Behaviour baseline (`behaviour.py`)

Metrics per source in 5-minute buckets: destination diversity, port diversity,
connection count, outbound bytes, outbound and non-outbound connection counts.
Baseline = median of the source's earlier buckets; spread = MAD x 1.4826;
deviation = (observed - median) / spread; "above baseline" at 3.5 or more.
Fewer than 8 historical buckets gives `insufficient_baseline_data`, and no
normal range is assumed. A flat history (MAD 0) uses 10% of the median, floor 1.

## Correlation (`correlation.py`)

Detections for the same source whose windows are at most 600 s apart form one
group. Named patterns: reconnaissance (port scan, destination scan, IDS alert
in any pair), command and control (regular outbound plus IDS alert), data
exfiltration (volume plus regular outbound or IDS alert). A group keeps every
contributing detection and its explanation states that coincidence is not intent.

## Risk model (`risk.py`)

    evidence      = severity points (low 20, medium 40, high 60, critical 80) x confidence, strongest detection
    corroboration = 15 x confidence for each further indicator type, capped at 30
    baseline      = +10 above baseline, -10 within baseline, 0 when unknown
    criticality   = subtotal x (multiplier - 1); low 0.8, medium 1.0, high 1.15, critical 1.3
    identity      = +5 when the source matches no inventory record
    score         = the sum, rounded and bounded to 0..100

Levels: 0-19 informational, 20-39 low, 40-59 medium, 60-79 high, 80-100 critical.
Reported confidence combines indicator types as 1 - product(1 - confidence), capped at 0.99.
Missing context (baseline, criticality, identity) is listed, never filled in.

Scores produced by the test scenarios:

| Scenario | Score | Decision |
|---|---|---|
| Irregular office traffic | no finding | none |
| Port scan just over threshold, known asset | 25 low | allow_with_monitoring |
| Port scan with history (above baseline) | 38 low | allow_with_monitoring |
| Large port scan (50 ports) | 54 medium | manual_review |
| Regular outbound connections only | 23 low | allow_with_monitoring |
| 60 MB upload from a critical asset | 29 low | allow_with_monitoring |
| Port scan + host sweep + IDS alert, no history | 57 medium | manual_review |
| Same, with history | 67 high | step_up_authentication |
| Same, with history, critical asset | 88 critical | deny (simulated) |
| Same, source not in inventory | 62 high | manual_review |

Run over the 112 alerts in the development database, the new core produces 2
detections (both DET-005) and 2 findings, scored 47 and 41, both manual_review.
The prototype engine scored 93 of those alerts at 100.

## Policy (`policy.py`, `policy-academic-1.0`)

| Condition | Decision |
|---|---|
| score below 20 | allow |
| source not an identified asset (score 20 or more) | manual_review |
| 20-39 | allow_with_monitoring |
| 40-59 | manual_review |
| 60-79 and confidence at least 0.6 | step_up_authentication (a recommendation; no MFA challenge occurs) |
| 80 or more, confidence at least 0.8 and at least 2 indicator types | deny (simulated only) |
| 80 or more without those conditions | manual_review |

## Ingestion (`app/ingestion.py`, `app/api_ingest.py`, `app/zeek_tsv.py`)

Ingestion normalises each record (Suricata EVE, Zeek JSON or Zeek tab-separated
ASCII logs) and correlates the source with the asset inventory. It makes no
security decision: every stored event is `pending_analysis`, or `manual_review`
when the source is not in the inventory. The per-event risk engine of the first
prototype was removed and is preserved in git under the tag `prototype-v1`.

File import (`POST /api/v1/ingest/upload`) accepts up to 10 MB and 20,000
records, skips records already imported (SHA-256 fingerprint), reports every
rejected line and can run the analysis afterwards. The Zeek reader follows the
`#separator`, `#set_separator`, `#empty_field`, `#unset_field`, `#path`,
`#fields` and `#types` headers and produces the same record as Zeek's JSON
writer, so both formats share one adapter.

## Approved-activity allowlist (`allowlist.py`, `allowlist-1.0`)

An entry names one source, exact destinations (addresses or ranges up to /24),
optional ports, the detection categories it covers and a reason. A detection
is suppressed only when every supporting event is covered; one event outside
the entry keeps the whole detection. IDS signature alerts cannot be
allowlisted. Suppressions are returned with each run (`suppressed_count`,
`suppressed`) and audited; entries are disabled, never deleted
(`/api/v1/allowlist`, administrators only for changes).

Effect in the comparative evaluation (65 synthetic cases, 40 malicious, 25
benign; three entries for the finance host's backup jobs and update service):

| Approach | FP without | FP with | Recall without | Recall with | F1 without | F1 with |
|---|---|---|---|---|---|---|
| Rule-based | 13 | 0 | 0.875 | 0.750 | 0.795 | 0.857 |
| Anomaly-based | 15 | 5 | 0.750 | 0.625 | 0.706 | 0.714 |
| Combined | 10 | 0 | 0.750 | 0.625 | 0.750 | 0.769 |

The recall loss is the `backup_path_exfiltration` family: exfiltration through
the approved backup destination is no longer detected. The allowlist was
written for these benign families, so the false-positive gain is an upper
bound.

## Tests

`tests/test_core_detection.py`, `tests/test_core_behaviour.py`,
`tests/test_core_correlation_risk_policy.py`: 68 tests, run with `python -m pytest tests -k core`.
They need only the standard library and pytest.
