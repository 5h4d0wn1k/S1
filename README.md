> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# S1 — Next-Gen SIEM Toolkit

Consolidated security research toolkit — a FastAPI + Next.js 14 platform that pairs offensive and
defensive automation with ML-based threat detection: Metasploit/Nuclei-driven scanning, Wazuh +
Suricata detection integration, IsolationForest + PyTorch/transformers analytics, event pipelines,
and Kubernetes deployment scaffolding.

![CI](https://github.com/5h4d0wn1k/S1/actions/workflows/ci.yml/badge.svg)
![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/S1)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/S1)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/S1)

## Why

Modern detection pairs offense and defense: understand how an attacker breaks in, then build the
detection that catches it. S1 consolidates both sides in one research platform. The offensive
engine drives Metasploit and Nuclei scans into structured vulnerability records; the defensive
engine integrates Wazuh and Suricata; an ML layer (IsolationForest anomaly detection, transformer
sequence classification) surfaces signals from logs and alerts; and Kafka + Elasticsearch connect
the pipeline together. It is an educational infosec research platform — use it only against systems
you own or hold explicit written authorization to assess.

## Features

- **Offensive engine** — `engines/offensive/` schedules Metasploit (via `pymetasploit3` RPC) and
  Nuclei scans, maps CVE/CVSS, and deduplicates findings.
- **Defensive engine** — `engines/defensive/` integrates Wazuh and Suricata for detection rules and
  threat indicators.
- **ML analytics** — anomaly detection (IsolationForest), transformer classification (PyTorch +
  Hugging Face), threat prediction, and alert analysis.
- **Event pipeline** — Elasticsearch and Kafka connectors, log ingestion, alert and incident
  correlation services.
- **API surface** — FastAPI modules for auth, scans, alerts, incidents, offensive/defensive
  operations, AI analysis, and WebSocket updates; SlowAPI rate limiting + trusted-host middleware.
- **Frontend** — Next.js 14 dashboards (ECharts, Shadcn UI + Tailwind, WebSocket live updates).
- **Platform stories** — Docker Compose local dev, Alembic migrations, and Kubernetes manifests.

## Quickstart

Prerequisites: Docker + Docker Compose, Python 3.11+, Node.js 20+, Make.

```bash
make install                 # frontend npm install + backend pip install
make db-migrate              # alembic upgrade head
make dev                     # docker compose up + uvicorn + next dev
make test                    # jest + pytest
make lint
make build
```

Direct commands: backend API runs via `uvicorn src.main:app --reload --port 8000` (in
`backend/`); frontend via `npm run dev` (in `frontend/`).

## Project structure

- `backend/` — FastAPI app (`src/`): `core/` (api, routers, auth, websocket, monitoring),
  `engines/` (offensive, defensive, ai), `data/` (connectors, pipeline, models, migrations),
  `services/` (alert, incident, correlation, log ingestion, reporting).
- `frontend/` — Next.js 14 App Router, components, and lib.
- `infrastructure/kubernetes/` — deployment, service, ingress, configmap, and secret manifests.
- `docker-compose.yml`, `Makefile` — local orchestration.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).