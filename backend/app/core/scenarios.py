"""Demo Lab scenarios (AG-14): reproducible synthetic telemetry.

Every scenario produces raw Suricata EVE-style events. They are ingested and
analysed through the same pipeline as any other telemetry; a scenario carries
no precomputed result, only the outcome it is expected to produce, so a run
can be compared with the expectation.

Timing inside a scenario is fixed relative to ``start``; irregular traffic uses
a seeded generator, so the same start time always gives the same events.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

WORKSTATION = "10.10.10.25"      # LAB-WS-001 in the laboratory inventory
FINANCE = "10.10.10.50"          # LAB-FINANCE-001
UNKNOWN_DEVICE = "10.10.10.99"   # not in the inventory
EXTERNAL = ("198.51.100.10", "198.51.100.11", "198.51.100.12")
DNS_SERVER = "10.10.10.2"
MEGABYTE = 1024 * 1024


@dataclass(frozen=True)
class Expected:
    rules: tuple[str, ...]
    finding: str | None
    decision: str | None


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    description: str
    ground_truth: str            # "malicious" or "benign"
    expected: Expected
    source_ip: str
    with_baseline: bool = True
    notes: str = ""

    def describe(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id, "title": self.title, "description": self.description,
            "ground_truth": self.ground_truth, "source_ip": self.source_ip,
            "expected": {"rules": list(self.expected.rules), "finding": self.expected.finding,
                         "decision": self.expected.decision},
            "notes": self.notes,
        }


@dataclass
class _Builder:
    scenario_id: str
    run_id: str
    start: datetime
    events: list[dict[str, Any]] = field(default_factory=list)

    def _base(self, seconds: float, source: str, destination: str, port: int) -> dict[str, Any]:
        return {
            "timestamp": (self.start + timedelta(seconds=seconds)).isoformat(),
            "src_ip": source, "dest_ip": destination, "dest_port": port, "proto": "TCP",
            "aegisgate_lab": {"synthetic": True, "scenario": self.scenario_id,
                              "sequence": len(self.events) + 1, "run_id": self.run_id},
        }

    def flow(self, seconds: float, source: str, destination: str, port: int,
             sent: int = 1200, received: int = 4800) -> None:
        event = self._base(seconds, source, destination, port)
        event.update({"event_type": "flow", "flow": {"bytes_toserver": sent, "bytes_toclient": received}})
        self.events.append(event)

    def alert(self, seconds: float, source: str, destination: str, port: int,
              signature: str, signature_id: int, severity: int) -> None:
        event = self._base(seconds, source, destination, port)
        event.update({"event_type": "alert", "alert": {
            "action": "allowed", "signature": signature, "signature_id": signature_id,
            "category": "Attempted Information Leak", "severity": severity}})
        self.events.append(event)

    def browsing(self, source: str, begin: float, minutes: int, seed: int) -> None:
        """Irregular everyday traffic: a few external sites and DNS."""
        rng = random.Random(seed)
        moment = begin
        while True:
            moment += rng.uniform(4, 40)
            if moment >= begin + minutes * 60:
                break
            choice = rng.randrange(4)
            if choice == 3:
                self.flow(moment, source, DNS_SERVER, 53, rng.randint(60, 120), rng.randint(120, 400))
            else:
                self.flow(moment, source, EXTERNAL[choice], 443, rng.randint(800, 4000), rng.randint(4000, 90000))


SCENARIOS: dict[str, Scenario] = {s.scenario_id: s for s in (
    Scenario("normal_traffic", "Normal office traffic",
             "Twenty minutes of ordinary browsing and DNS from a workstation.",
             "benign", Expected((), None, None), WORKSTATION, with_baseline=False),
    Scenario("port_scan", "Port scan",
             "A workstation contacts 40 different ports on one internal server in 40 seconds.",
             "malicious", Expected(("DET-001",), "port_scan", "manual_review"), WORKSTATION),
    Scenario("destination_scan", "Repeated destination scan",
             "A workstation contacts 14 different internal hosts on the same port in under a minute.",
             "malicious", Expected(("DET-002",), "destination_scan", "manual_review"), WORKSTATION),
    Scenario("suspicious_outbound", "Suspicious outbound connections",
             "A finance host connects to one external address every 60 seconds for ten minutes.",
             "malicious", Expected(("DET-003",), "suspicious_outbound", "allow_with_monitoring"), FINANCE),
    Scenario("potential_exfiltration", "Potential data exfiltration",
             "A finance host sends about 80 MB to an external address in under five minutes.",
             "malicious",
             Expected(("DET-003", "DET-004"), "potential_data_exfiltration", "step_up_authentication"), FINANCE,
             notes="The upload is sent in regular chunks, so the regular-connection rule fires on the "
                   "same flows. The risk engine does not count it as independent corroboration."),
    Scenario("multi_stage", "Mixed multi-stage activity",
             "Port scan, host sweep and an IDS alert from the same workstation within a few minutes.",
             "malicious",
             Expected(("DET-001", "DET-002", "DET-005"), "potential_network_reconnaissance",
                      "step_up_authentication"), WORKSTATION),
    Scenario("benign_backup", "Benign look-alike: backup job",
             "A server contacts 14 internal hosts on the file-sharing port, as a backup job would.",
             "benign", Expected(("DET-002",), "destination_scan", "manual_review"), FINANCE,
             notes="Expected false positive: the detection fires on legitimate behaviour and costs an "
                   "analyst review, but the policy must not recommend a restriction."),
    Scenario("unknown_device", "Unknown device",
             "A device with no inventory record scans ports on an internal server.",
             "malicious", Expected(("DET-001",), "port_scan", "manual_review"), UNKNOWN_DEVICE,
             with_baseline=False),
)}


def build(scenario_id: str, run_id: str, start: datetime) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (baseline events, scenario events). Baseline events carry the run
    identifier with a ``.baseline`` suffix: they are earlier ordinary traffic
    used only as behavioural history."""
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    if start.tzinfo is None:
        raise ValueError("start must be timezone-aware.")
    start = start.astimezone(timezone.utc)
    scenario = SCENARIOS[scenario_id]
    source = scenario.source_ip

    baseline = _Builder(scenario_id, f"{run_id}.baseline", start)
    if scenario.with_baseline:
        baseline.browsing(source, -3600, 55, seed=11)

    run = _Builder(scenario_id, run_id, start)
    if scenario_id == "normal_traffic":
        run.browsing(source, 0, 20, seed=5)
    elif scenario_id in ("port_scan", "unknown_device"):
        for i in range(40):
            run.flow(i, source, "10.10.10.80", 20 + i * 7, 60, 0)
    elif scenario_id == "destination_scan":
        for i in range(14):
            run.flow(i * 3, source, f"10.10.10.{110 + i}", 445, 180, 0)
    elif scenario_id == "suspicious_outbound":
        for i in range(10):
            run.flow(i * 60, source, "198.51.100.23", 443, 420, 380)
    elif scenario_id == "potential_exfiltration":
        for i in range(8):
            run.flow(i * 30, source, "198.51.100.77", 443, 10 * MEGABYTE, 2400)
    elif scenario_id == "multi_stage":
        for i in range(40):
            run.flow(i, source, "10.10.10.80", 20 + i * 7, 60, 0)
        for i in range(14):
            run.flow(60 + i * 3, source, f"10.10.10.{110 + i}", 445, 180, 0)
        run.alert(110, source, "10.10.10.80", 80,
                  "ET SCAN Nmap Scripting Engine User-Agent Detected", 2009358, 1)
    elif scenario_id == "benign_backup":
        for i in range(14):
            run.flow(i * 4, source, f"10.10.10.{110 + i}", 445, 900_000, 12_000)
    return baseline.events, run.events


def compare(scenario_id: str, rules_found: list[str], finding: str | None,
            decision: str | None) -> dict[str, Any]:
    """Compare what the pipeline produced with what the scenario expects."""
    expected = SCENARIOS[scenario_id].expected
    checks = {
        "rules": sorted(set(rules_found)) == sorted(expected.rules),
        "finding": finding == expected.finding,
        "decision": decision == expected.decision,
    }
    return {"matches_expected": all(checks.values()), "checks": checks,
            "expected": {"rules": list(expected.rules), "finding": expected.finding,
                         "decision": expected.decision},
            "actual": {"rules": sorted(set(rules_found)), "finding": finding, "decision": decision}}
