# AegisGate — Project Record

## Project purpose

AegisGate is a cybersecurity incident intelligence and response-assistance platform.
It ingests network telemetry, correlates it with known assets, evaluates risk using
explainable rules, recommends an access decision, creates auditable cases, and presents
the result through an interactive SOC-style web dashboard.

The system is designed as:

- A final degree project candidate.
- A portfolio-grade cybersecurity application.
- A possible basis for a future security product.
- A laboratory-safe system before any real external response integrations are enabled.

## Current development principles

- Build incrementally and preserve passing tests.
- Do not replace stable components without a migration reason.
- Keep security decisions explainable and auditable.
- Default to safe simulation for blocking, isolation, MFA, and response actions.
- Do not perform active scanning or unauthorized tracking.
- Use real integrations only with authorization, least privilege, audit logging,
  human approval for high-impact actions, and reversal capability.
- Preserve privacy by minimizing, masking, and retaining sensitive data only when needed.

## Functional scope

### Telemetry and risk

- Normalize Suricata EVE JSON events.
- Normalize Zeek JSON events.
- Correlate source IP addresses with an asset inventory.
- Convert normalized telemetry and asset context into a ConnectionEvent.
- Evaluate risk through an existing explainable risk engine.
- Return an access recommendation:
  - allow
  - allow_with_monitoring
  - step_up_authentication
  - deny
  - manual_review

### Threat Intelligence & Investigation

AegisGate will provide an investigation interface for suspicious indicators.

For an IP address, the interface will support:

- Local evidence: alert history, assets affected, first/last seen, destinations,
  signatures, indicators, decisions, cases, and prior actions.
- Passive network context: ASN, network owner, CIDR/range, RDAP/WHOIS data,
  and DNS PTR where permitted.
- Threat-intelligence results from configured and authorized providers.
- Approximate geolocation presented as an estimate, with source, timestamp,
  confidence, and explicit accuracy limitations.
- Relationship graph between IPs, domains, assets, alerts, and cases.
- Investigation timeline and auditable source queries.

For an IMEI, the system will support only authorized corporate-device workflows:

- Masked IMEI by default.
- Corporate owner, device posture, UEM/MDM state, last check-in, and
  authorized last corporate-network or MDM location data.
- Explicit unresolved-device state when no authorized inventory record exists.
- No unauthorised public tracking, personal surveillance, or claims of
  physical real-time location.

### Operational user interface

The product will include:

- SOC dashboard with live metrics and recent alerts.
- Alert queue with search, filters, severity, score, decision, and status.
- Alert detail with telemetry, correlated asset, risk explanations, and timeline.
- Case lifecycle: open, acknowledged, resolved, false_positive.
- Asset inventory and asset detail pages.
- Simulation lab for benign, suspicious DNS, C2, and unknown-asset events.
- Investigation pages for IPs and authorized corporate IMEIs.
- Audited simulated actions: local IP blocklist, require MFA, isolate asset,
  unblock, acknowledge, resolve, and mark false positive.

## Development history

### Phase 1 — Domain and decision engine

Completed:

- Defined ConnectionEvent and supporting enums in backend/models.py.
- Implemented the explainable risk engine in backend/risk_engine.py.
- Added access decision thresholds in backend/access_decision.py.
- Added unit tests for decision thresholds.

### Phase 2 — Network telemetry

Completed:

- Added NetworkTelemetryEvent canonical model.
- Added Suricata EVE JSON adapter.
- Added Zeek JSON adapter for DNS and notice logs.
- Created a laboratory asset inventory in data/assets.json.
- Added IP-to-asset correlation.
- Added conversion from telemetry to ConnectionEvent.
- Added telemetry processing pipeline and command-line processor.
- Added sample Suricata, Zeek DNS, Zeek notice, and unknown-asset events.
- Added structured unresolved_asset/manual_review handling.
- Added automated tests for known and unknown assets.

### Verification milestone

The test suite passed with:

```text
17 passed
```

This result must be revalidated after each subsequent feature.

## Next implementation milestone

Build the persistent FastAPI backend with SQLite:

1. Add database schema and repository layer.
2. Persist alerts, risk assessments, decisions, cases, actions, and audit entries.
3. Expose read-only health, dashboard, alert, asset, case, and investigation endpoints.
4. Add a safe simulation endpoint to inject laboratory events.
5. Add controlled state-changing endpoints for local simulated actions.
6. Add API tests.
7. Build a Next.js interactive SOC dashboard on top of the API.

## Safety and legal boundaries

- AegisGate is not an active scanning system.
- The application must only process organizational telemetry, systems, devices,
  and data for which authorization exists.
- IP geolocation is an estimate, never proof of a person's physical position.
- IMEI records are sensitive device identifiers and must be masked, access-controlled,
  and handled only under an authorized corporate-device policy.
- Real-world response integrations remain disabled until controls, approvals,
  authentication, authorization, auditing, and rollback are implemented.