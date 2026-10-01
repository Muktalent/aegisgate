# AegisGate

AegisGate is a laboratory-safe cybersecurity incident-intelligence and response-assistance platform. It ingests network telemetry, correlates events with known assets, evaluates connection risk through explainable rules, recommends access decisions, records auditable cases, and presents the results in a SOC-style web dashboard.

> **Safety note:** AegisGate is a demonstration and research project. Containment and response actions are simulated by design. Do not connect it to production security controls or use it to scan, track, or act on systems without explicit authorization.

## Features

- Normalizes sample Suricata EVE JSON and Zeek telemetry.
- Correlates source IP addresses with a local laboratory asset inventory.
- Evaluates risk using explainable, rule-based logic.
- Produces access recommendations including `allow`, `allow_with_monitoring`, `step_up_authentication`, `deny`, and `manual_review`.
- Stores alerts, access decisions, and incident cases in a local SQLite database.
- Provides a React and TypeScript SOC dashboard with:
  - Security posture metrics.
  - An alert queue with search and severity labels.
  - Access-decision context and persisted evidence.
  - Case creation for investigations.
- Includes safe, synthetic telemetry samples for normal activity, suspicious DNS, suspected command-and-control traffic, infected endpoints, and unknown assets.

## Architecture

```text
Sample telemetry and asset inventory
            |
            v
Python telemetry normalization and correlation
            |
            v
Explainable risk and access-decision engines
            |
            v
FastAPI backend and local SQLite persistence
            |
            v
React + TypeScript SOC dashboard
```

## Project structure

```text
backend/              Python application, risk logic, API, and persistence
backend/app/          FastAPI application and SQLite models
data/                 Synthetic asset and telemetry datasets
data/telemetry/       Suricata and Zeek example events
docs/                 Project record and technical documentation
frontend/             React, TypeScript, and Vite dashboard
tests/                Automated Python test suite
```

## Prerequisites

- Python 3.11 or later.
- Node.js 20 or later and npm.

## Backend setup

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` only for local development. Do not commit it.

Start the API:

```powershell
uvicorn backend.app.main:app --reload
```

The API will normally be available at:

```text
http://127.0.0.1:8000
```

## Frontend setup

In a second PowerShell terminal:

```powershell
Set-Location .\frontend
npm install
npm run dev
```

Vite will display the local dashboard URL, normally:

```text
http://localhost:5173
```

The dashboard requires a JWT issued by an authorized local laboratory user with the `soc_analyst` or `security_admin` role.

## Testing and validation

Run the Python test suite from the repository root:

```powershell
python -m pytest
```

Build the frontend for production:

```powershell
Set-Location .\frontend
npm run build
Set-Location ..
```

## Demo data

The repository contains synthetic, laboratory-only data under `data/`.

- Private network addresses use the `10.10.10.0/24` laboratory range.
- Documentation destination addresses use `198.51.100.0/24` (TEST-NET-2).
- DNS examples use the reserved `.test` namespace.
- Accounts, devices, events, alert signatures, and locations are demo identifiers.

The project intentionally does not include local databases, runtime audit reports, credentials, tokens, build output, dependency folders, packet captures, certificates, or private keys.

## Security and ethics

AegisGate is designed around the following principles:

- Obtain authorization before integrating with external systems.
- Apply least privilege to integrations and credentials.
- Keep decisions explainable, auditable, and reviewable.
- Require human approval for high-impact actions.
- Support reversal or rollback where actions can affect access.
- Minimize and protect sensitive data.
- Do not perform active scanning, unauthorized tracking, or real-world containment through this demonstration project.

See [`docs/00-project-record.md`](docs/00-project-record.md) for the current project scope and development record.

## License

No license has been selected yet. All rights reserved until a license is added.