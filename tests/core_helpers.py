"""Shared builders for the analysis-core tests."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.events import CanonicalEvent  # noqa: E402

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
_counter = 0


def ev(seconds=0.0, src="10.10.10.25", dst="10.10.10.80", port=443, **kw):
    global _counter
    _counter += 1
    kw.setdefault("event_id", f"evt-{_counter:05d}")
    kw.setdefault("source", "zeek")
    kw.setdefault("event_type", "network_connection")
    kw.setdefault("protocol", "tcp")
    return CanonicalEvent(timestamp=T0 + timedelta(seconds=seconds), source_ip=src,
                          destination_ip=dst, destination_port=port, **kw)


def port_scan(count=20, src="10.10.10.25", dst="10.10.10.80", start=0.0, step=1.0):
    return [ev(start + i * step, src, dst, 1000 + i) for i in range(count)]


def host_sweep(count=12, src="10.10.10.25", start=0.0):
    return [ev(start + i, src, f"10.10.10.{100 + i}", 445) for i in range(count)]


def beacon(count=8, src="10.10.10.25", dst="198.51.100.23", interval=60.0, start=0.0, jitter=0.0):
    return [ev(start + i * interval + (jitter if i % 2 else 0), src, dst, 443, bytes_out=400)
            for i in range(count)]


def upload(total_mb=60, src="10.10.10.50", dst="198.51.100.77", flows=6, start=0.0):
    size = total_mb * 1024 * 1024 // flows
    return [ev(start + i * 10, src, dst, 443, bytes_out=size) for i in range(flows)]


def ids_alert(seconds=0.0, src="10.10.10.25", dst="10.10.10.80", severity=1, sid=2027758,
              signature="ET SCAN Nmap Scripting Engine User-Agent Detected"):
    return ev(seconds, src, dst, 80, source="suricata", event_type="alert", severity=severity,
              signature=signature, signature_id=sid, category="Attempted Information Leak")


def office_traffic(src="10.10.10.25", minutes=40, start=-2400.0, seed=7):
    """Ordinary browsing: a few destinations, common ports, small transfers,
    irregular timing (deterministic pseudo-random gaps)."""
    import random
    rng = random.Random(seed)
    hosts = ["198.51.100.10", "198.51.100.11", "198.51.100.12", "10.10.10.2"]
    events, t = [], start
    while len(events) < minutes * 3:
        t += rng.uniform(2, 38)
        if t >= start + minutes * 60:
            break
        i = rng.randrange(4)
        events.append(ev(t, src, hosts[i], 53 if i == 3 else 443, bytes_out=rng.randint(800, 4000)))
    return events
