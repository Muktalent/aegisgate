"""Comparative detection evaluation (Objective 6).

Runs a fixed set of labelled synthetic cases through three detection
approaches and reports precision, recall, false-positive rate and detection
latency for each:

* rule-based  - any structured detection rule (DET-001..005) fires for the case source;
* anomaly-based - any behavioural metric of the source exceeds its own baseline
  (median/MAD robust deviation, ``app.core.behaviour``); no rules involved;
* combined    - the full pipeline (rules, correlation, baseline, risk, policy)
  escalates the source: manual review, step-up or (simulated) denial.

Every case is synthetic generated data in Suricata EVE format, normalised by
the same adapters as real telemetry. Results describe behaviour on these
cases only; they are not a measure of performance on a real network.
"""
from __future__ import annotations

import random
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.core.allowlist import AllowEntry, events_outside
from app.core.behaviour import METRICS, bucket_metrics, compare_to_baseline, history_for
from app.core.events import CanonicalEvent, event_from_stored_telemetry
from app.core.pipeline import analyse
from app.core.risk import AssetContext
from app.core.scenarios import DNS_SERVER, EXTERNAL, FINANCE, MEGABYTE, UNKNOWN_DEVICE, WORKSTATION, _Builder
from telemetry_adapters import normalize_network_telemetry

EVALUATION_VERSION = "evaluation-1.1"
VARIANTS = 5
BASE_START = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
ESCALATING = ("manual_review", "step_up_authentication", "deny")
APPROACHES = ("rule_based", "anomaly_based", "combined")
BUCKET_SECONDS = 300


@dataclass(frozen=True)
class Family:
    family: str
    label: str                     # "malicious" | "benign"
    source_ip: str
    description: str
    with_history: bool
    build: Callable[[_Builder, str, int, random.Random], float | None]   # returns attack start (s)


def _browse(b: _Builder, source: str, begin: float, minutes: int, seed: int) -> None:
    b.browsing(source, begin, minutes, seed)


def _port_scan(b, src, v, rng):
    ports = 20 + 6 * v                                   # 20..44 ports, one per second
    for i in range(ports):
        b.flow(i, src, "10.10.10.80", 20 + i * 7, 60, 0)
    return 0.0


def _slow_port_scan(b, src, v, rng):
    gap = 15 + 2.5 * v                                   # one new port every 15-25 s
    for i in range(30):
        b.flow(i * gap, src, "10.10.10.80", 1000 + i * 13, 60, 0)
    return 0.0


def _destination_scan(b, src, v, rng):
    for i in range(11 + 2 * v):                          # 11..19 hosts
        b.flow(i * 3, src, f"10.10.10.{110 + i}", 445, 180, 0)
    return 0.0


def _beacon(b, src, v, rng):
    interval = (30, 45, 60, 60, 75)[v]
    for i in range(12):
        b.flow(i * interval + rng.uniform(-0.05, 0.05) * interval, src, "198.51.100.23", 443, 420, 380)
    return 0.0


def _exfiltration(b, src, v, rng):
    total, moment = 40 + 20 * v, 0.0                     # 40..120 MB, irregular chunks
    for _ in range(8):
        b.flow(moment, src, "198.51.100.77", 443, total * MEGABYTE // 8, 2400)
        moment += rng.uniform(5, 35)
    return 0.0


def _multi_stage(b, src, v, rng):
    for i in range(30 + 4 * v):
        b.flow(i, src, "10.10.10.80", 20 + i * 7, 60, 0)
    for i in range(14):
        b.flow(60 + i * 3, src, f"10.10.10.{110 + i}", 445, 180, 0)
    b.alert(110, src, "10.10.10.80", 80, "ET SCAN Nmap Scripting Engine User-Agent Detected", 2009358, 1)
    return 0.0


def _backup_path_exfiltration(b, src, v, rng):
    total, moment = 150 + 25 * v, 0.0                    # 150..250 MB over the approved backup path
    for _ in range(8):
        b.flow(moment, src, "198.51.100.90", 443, total * MEGABYTE // 8, 2400)
        moment += rng.uniform(5, 30)
    return 0.0


def _normal(b, src, v, rng):
    _browse(b, src, 0, 20, seed=100 + v)
    return None


def _backup_job(b, src, v, rng):
    for i in range(12 + v):                              # 12..16 file servers, large transfers
        b.flow(i * 4, src, f"10.10.10.{110 + i}", 445, 900_000, 12_000)
    return None


def _updater(b, src, v, rng):
    interval = (60, 60, 120, 300, 30)[v]                 # strictly periodic software update checks
    for i in range(12):
        b.flow(i * interval, src, "198.51.100.40", 443, 300, 900)
    return None


def _cloud_backup(b, src, v, rng):
    total, moment = 60 + 15 * v, 0.0                     # 60..120 MB to a backup provider
    for _ in range(10):
        b.flow(moment, src, "198.51.100.90", 443, total * MEGABYTE // 10, 3000)
        moment += rng.uniform(8, 40)
    return None


def _busy_browsing(b, src, v, rng):
    for i in range(40):                                  # many page loads across a few sites
        b.flow(i * rng.uniform(3, 9), src, EXTERNAL[i % 3], 443, rng.randint(800, 4000), 40_000)
        if i % 5 == 0:
            b.flow(i * 6 + 1, src, DNS_SERVER, 53, 80, 200)
    return None


FAMILIES: tuple[Family, ...] = (
    Family("port_scan", "malicious", WORKSTATION, "Fast port scan of one internal server.", True, _port_scan),
    Family("slow_port_scan", "malicious", WORKSTATION,
           "Stealthy scan: 30 ports, one every 15-25 seconds.", True, _slow_port_scan),
    Family("destination_scan", "malicious", WORKSTATION, "Sweep of 11-19 internal hosts on one port.", True,
           _destination_scan),
    Family("beacon", "malicious", FINANCE, "Regular connections to one external host (command and control).",
           True, _beacon),
    Family("exfiltration", "malicious", FINANCE, "40-120 MB sent to one external host in a few minutes.", True,
           _exfiltration),
    Family("backup_path_exfiltration", "malicious", FINANCE,
           "Exfiltration through the approved off-site backup destination (abuses the allowlist).", True,
           _backup_path_exfiltration),
    Family("multi_stage", "malicious", WORKSTATION, "Port scan, host sweep and an IDS alert.", True, _multi_stage),
    Family("unknown_device_scan", "malicious", UNKNOWN_DEVICE,
           "Port scan from a device with no inventory record and no history.", False, _port_scan),
    Family("normal_browsing", "benign", WORKSTATION, "Ordinary browsing and DNS.", True, _normal),
    Family("busy_browsing", "benign", WORKSTATION, "Heavy but ordinary browsing.", True, _busy_browsing),
    Family("backup_job", "benign", FINANCE, "Backup job contacting many file servers (scan look-alike).", True,
           _backup_job),
    Family("software_updater", "benign", FINANCE, "Strictly periodic update checks (beacon look-alike).", True,
           _updater),
    Family("cloud_backup", "benign", FINANCE, "Large upload to a backup provider (exfiltration look-alike).", True,
           _cloud_backup),
)


def _canonical(raw_events: list[dict[str, Any]], prefix: str) -> list[CanonicalEvent]:
    """Raw sensor records -> canonical events through the ingestion adapters."""
    events = []
    for index, raw in enumerate(raw_events):
        telemetry = normalize_network_telemetry(raw).model_dump(mode="json", exclude={"raw_event"})
        events.append(event_from_stored_telemetry(f"{prefix}-{index:05d}", telemetry))
    return events


def build_case(family: Family, variant: int) -> dict[str, Any]:
    case_id = f"{family.family}-v{variant + 1}"
    start = BASE_START + timedelta(hours=variant)
    rng = random.Random(f"{family.family}:{variant}")
    history = _Builder(family.family, f"{case_id}.baseline", start)
    if family.with_history:
        history.browsing(family.source_ip, -3600, 55, seed=1000 + variant)
    run = _Builder(family.family, case_id, start)
    attack = family.build(run, family.source_ip, variant, rng)
    return {
        "case_id": case_id, "family": family.family, "label": family.label, "source_ip": family.source_ip,
        "start": start, "attack_start": None if attack is None else start + timedelta(seconds=attack),
        "history": _canonical(history.events, f"{case_id}-h"), "events": _canonical(run.events, f"{case_id}-e"),
    }


# Approved activity an analyst would record for the laboratory finance host: its
# nightly backup to the file-server range, its off-site backup provider and its
# software update service. Malicious sources are never covered.
EVALUATION_ALLOWLIST: tuple[AllowEntry, ...] = (
    AllowEntry("AL-EVAL-1", FINANCE, ("10.10.10.96/27",), ("destination_scan",),
               "Nightly backup job to the file-server range (SMB).", (445,)),
    AllowEntry("AL-EVAL-2", FINANCE, ("198.51.100.90",), ("potential_exfiltration",),
               "Approved off-site backup provider.", (443,)),
    AllowEntry("AL-EVAL-3", FINANCE, ("198.51.100.40",), ("suspicious_outbound",),
               "Software update service polled on a fixed schedule.", (443,)),
)


def _anomaly(case: dict[str, Any], allowlist: tuple[AllowEntry, ...] = ()) -> tuple[bool, datetime | None, list[str]]:
    """Flag the source when any metric of any current bucket is above its baseline.
    Events covered by the allowlist are left out of the current buckets."""
    past = bucket_metrics(case["history"], BUCKET_SECONDS)
    flagged_at: datetime | None = None
    metrics: set[str] = set()
    for bucket in bucket_metrics(events_outside(case["events"], allowlist), BUCKET_SECONDS):
        if bucket.source_ip != case["source_ip"]:
            continue
        for metric in METRICS:
            observed = getattr(bucket, metric)
            if observed is None:
                continue
            result = compare_to_baseline(case["source_ip"], metric, float(observed),
                                         history_for(past, case["source_ip"], metric, bucket.bucket_start))
            if result.status == "above_baseline":
                metrics.add(metric)
                closes = bucket.bucket_start + timedelta(seconds=bucket.bucket_seconds)
                flagged_at = closes if flagged_at is None else min(flagged_at, closes)
    return flagged_at is not None, flagged_at, sorted(metrics)


def evaluate_case(case: dict[str, Any], assets: dict[str, AssetContext],
                  allowlist: tuple[AllowEntry, ...] = ()) -> dict[str, Any]:
    result = analyse(case["events"], assets, case["history"], allowlist=allowlist)
    source = case["source_ip"]
    rules = [d for d in result.detections if d.source_ip == source]
    escalated = [f for f in result.findings
                 if f.group.source_ip == source and f.decision.decision in ESCALATING]
    anomalous, anomaly_at, metrics = _anomaly(case, allowlist)
    top = max((f for f in result.findings if f.group.source_ip == source),
              key=lambda f: f.assessment.risk_score, default=None)

    def latency(moment: datetime | None) -> float | None:
        if moment is None or case["attack_start"] is None:
            return None
        return round(max(0.0, (moment - case["attack_start"]).total_seconds()), 1)

    return {
        "case_id": case["case_id"], "family": case["family"], "label": case["label"],
        "source_ip": source, "event_count": len(case["events"]), "history_events": len(case["history"]),
        "suppressed_by": sorted({s.entry_id for s in result.suppressed if s.detection.source_ip == source}),
        "rule_based": {"flagged": bool(rules), "rules": sorted({d.rule_id for d in rules}),
                       "latency_seconds": latency(min((d.window_end for d in rules), default=None))},
        "anomaly_based": {"flagged": anomalous, "metrics": metrics, "latency_seconds": latency(anomaly_at)},
        "combined": {"flagged": bool(escalated),
                     "decision": top.decision.decision if top else None,
                     "risk_score": top.assessment.risk_score if top else None,
                     "latency_seconds": latency(min((f.group.window_end for f in escalated), default=None))},
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(numerator / denominator, 3)


def summarise(cases: list[dict[str, Any]], approach: str) -> dict[str, Any]:
    tp = sum(1 for c in cases if c["label"] == "malicious" and c[approach]["flagged"])
    fn = sum(1 for c in cases if c["label"] == "malicious" and not c[approach]["flagged"])
    fp = sum(1 for c in cases if c["label"] == "benign" and c[approach]["flagged"])
    tn = sum(1 for c in cases if c["label"] == "benign" and not c[approach]["flagged"])
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    latencies = [c[approach]["latency_seconds"] for c in cases
                 if c["label"] == "malicious" and c[approach]["flagged"] and c[approach]["latency_seconds"] is not None]
    return {
        "approach": approach, "true_positives": tp, "false_positives": fp, "true_negatives": tn,
        "false_negatives": fn, "precision": precision, "recall": recall,
        "false_positive_rate": _ratio(fp, fp + tn),
        "f1": None if not precision or not recall else round(2 * precision * recall / (precision + recall), 3),
        "median_latency_seconds": round(statistics.median(latencies), 1) if latencies else None,
        "max_latency_seconds": max(latencies) if latencies else None,
    }


def run_evaluation(assets: dict[str, AssetContext], variants: int = VARIANTS) -> dict[str, Any]:
    if not 1 <= variants <= 10:
        raise ValueError("variants must be between 1 and 10.")
    built = [build_case(family, v) for family in FAMILIES for v in range(variants)]
    cases = [evaluate_case(case, assets) for case in built]
    allowed = [evaluate_case(case, assets, EVALUATION_ALLOWLIST) for case in built]
    by_family = _by_family(cases)
    changed = [{"case_id": a["case_id"], "family": a["family"], "label": a["label"],
                "suppressed_by": a["suppressed_by"],
                **{approach: {"before": c[approach]["flagged"], "after": a[approach]["flagged"]}
                   for approach in APPROACHES}}
               for c, a in zip(cases, allowed)
               if any(c[approach]["flagged"] != a[approach]["flagged"] for approach in APPROACHES)]
    return {
        "evaluation_version": EVALUATION_VERSION, "data_provenance": "Synthetic generated data",
        "variants_per_family": variants, "case_count": len(cases),
        "malicious_cases": sum(1 for c in cases if c["label"] == "malicious"),
        "benign_cases": sum(1 for c in cases if c["label"] == "benign"),
        "definitions": {
            "rule_based": "At least one detection rule (DET-001 to DET-005) fired for the case source.",
            "anomaly_based": ("At least one behavioural metric of a 5-minute bucket was above the source's own "
                              "baseline (robust deviation 3.5 or more, 8 or more historical buckets). "
                              "No detection rules are used."),
            "combined": ("The full pipeline (rules, correlation, baseline, risk and policy) chose manual review, "
                         "step-up or a simulated denial for the case source."),
            "latency": ("Event-time seconds from the first attack event to the end of the earliest evidence "
                        "window: the rule window, the closing of the 5-minute bucket, or the correlated finding."),
        },
        "metrics": [summarise(cases, approach) for approach in APPROACHES],
        "by_family": by_family,
        "cases": cases,
        "allowlist_comparison": {
            "description": ("The same cases analysed again with an approved-activity allowlist for the "
                            "finance host. A detection is suppressed only when every one of its supporting "
                            "events is covered by an entry; the anomaly approach leaves covered events out."),
            "entries": [entry.to_dict() for entry in EVALUATION_ALLOWLIST],
            "metrics": [summarise(allowed, approach) for approach in APPROACHES],
            "by_family": _by_family(allowed),
            "changed_cases": changed,
        },
        "limitations": [
            "All cases are synthetic and generated by AegisGate itself; they are not recorded traffic.",
            "The cases were written knowing the detection rules, which favours the rule-based approach.",
            "Each family varies only in a few parameters, so cases within a family are not independent samples.",
            "The anomaly approach needs history; cases without history cannot be flagged by it.",
            ("The allowlist was written for these benign families, so its gain is an upper bound; the "
             "backup_path_exfiltration family shows the cost when an approved path is abused."),
        ],
    }


def _by_family(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for family in FAMILIES:
        own = [c for c in cases if c["family"] == family.family]
        if not own:
            continue
        rows.append({
            "family": family.family, "label": family.label, "description": family.description,
            "cases": len(own),
            **{approach: sum(1 for c in own if c[approach]["flagged"]) for approach in APPROACHES}})
    return rows
