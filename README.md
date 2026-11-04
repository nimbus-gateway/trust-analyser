# Trust Analyser

A modular, distributed system for evaluating the trustworthiness of a system from multiple independant tools that can use to analyse system's ***Security, Reliability, Resilience, Threat Exposure, and Intentions***. Once it receives these tool inputs then it will perform its trust analysis based on the configurations. Then this computed trust score and system behaviour type is sent to ADI_Connector to record results on the distributed ledger and visualises everything through a live dashboard.

---

## System Overview

```
                       Tool Telemetry Ingestion
               ┌────────────────────────────────────┐
               │  Demo_Factory_Floor │ Real Tools   │
               └─────────────────────────────┬──────┘
                                   │ POST /submit
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           TA_API (FastAPI)                              │
│                                                                         │
│   ┌────────────────┐     ┌────────────────┐     ┌───────────────────┐   │
│   │ Routers        │     │ Services       │     │ Database (MongoDB)│   │
│   │ - /submit      │────▶│ - rules_engine │────▶│ - tool_reportings │   │
│   │ - /cycle       │     │ - trust_calc   │     │ - rule_eval_logs  │   │
│   │ - /mappings    │     │ - logger       │     │ - trust_score_logs│   │
│   │ - /reports     │     │ - rep_builder  │     │ - mappings/configs│   │
│   │ - /dashboard   │     │ - adi_connector│     └───────────────────┘   │
│   └───────┬────────┘     └────────┬───────┘                             │
│           │                                                             │
│           │ SSE Stream                                                  │
│           ▼                                                             │
│    Dashboard Web UI                                                     │
│    (http://localhost:8001)                                              │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
Trust Analyser/
│
├── TA_API/                     # Core backend — trust evaluation engine + dashboard
├── ADI_Connector/              # Distributed ledger integration (ADI / SmartQC)
├── Demo_Factory_Floor/         # 3D factory floor visualisation (React + Three.js)
├── Tool_Data_Generator/        # Mock tool data service (development use only)
│
├── trust-analyser-k3s.yaml     # Kubernetes (k3s) deployment manifest
└── README.md                   # This file
```

---

## Components

### 1. `TA_API/` — Trust Analyser API

The heart of the system. A **FastAPI** application backed by **MongoDB** that:

- Accepts tool reports via `POST /submit`
- Evaluates trust scores using a configurable rules engine
- Serves a built-in dashboard web application
- Streams live trust cycle updates via Server-Sent Events (SSE)
- Forwards evaluation reports to the ADI Connector for immutable ledger storage

**Key internals:**

```
TA_API/
├── api/
│   ├── main.py                 # App entry point, router registration, lifespan
│   ├── config.py               # Environment config (MongoDB URI, ADI URL, ports)
│   ├── database.py             # MongoDB connection + collection singletons
│   ├── models.py               # Pydantic request / response models
│   ├── adi_connector.py        # HTTP client for the ADI Connector service
│   ├── support_functions.py    # Shared utilities
│   │
│   ├── routers/
│   │   ├── submit.py           # POST /submit — ingest tool reports
│   │   ├── cycle.py            # Trust cycle management + SSE broadcast
│   │   ├── trust_config.py     # Tool/category configuration CRUD
│   │   ├── mappings.py         # Asset-to-tool mappings
│   │   ├── rules.py            # Trust rule management
│   │   ├── reports.py          # Historical report retrieval
│   │   ├── actions.py          # User actions / overrides
│   │   └── dashboard.py        # Dashboard data endpoints
│   │
│   └── services/
│       ├── trust_calculator.py # Core trust score computation
│       ├── rules_engine.py     # Rule evaluation logic
│       ├── report_builder.py   # Builds structured TA reports
│       └── analysis_logger.py  # Audit / analysis logging
│
├── webapp/                     # Pre-built dashboard SPA (served by the API)
├── Dockerfile.api              # API container
├── Dockerfile.mongo            # MongoDB container (custom init)
├── docker-compose.yml          # Local orchestration
├── requirements.txt
├── .env.example                # Configuration template
└── .env                        # Local secrets (gitignored)
```

**Environment variables** (see [`TA_API/.env.example`](TA_API/.env.example)):

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `DB_NAME` | `telemetry` | Database name |
| `SERVICE_IP` | `localhost` | IP used to build the ADI service URL |
| `ADI_SERVICE_URL` | `http://{SERVICE_IP}:9002` | Full ADI Connector URL |
| `API_PORT` | `8001` | FastAPI listen port |
| `CORS_ORIGINS` | `*` | Comma-separated allowed origins |

**API port:** `9001` (external) → `8001` (container)

---

### 3. `Demo_Factory_Floor/` — 3D Factory Floor Visualisation

A **React + Vite** single-page application that renders an interactive 3D factory floor using **Three.js** (`@react-three/fiber`). It visualises live trust status from the Trust Analyser in real time.

```
Demo_Factory_Floor/
├── src/
│   ├── components/             # 3D scene, trust gauge, UI components
│   ├── store/                  # Zustand state management
│   ├── App.jsx                 # Root component
│   └── main.jsx                # Vite entry point
├── public/                     # Static assets
├── Dockerfile                  # Nginx-based production container
├── package.json                # React 18, Three.js, Zustand, Lucide
└── vite.config.js
```

**Tech stack:** React 18 · Three.js · `@react-three/fiber` · `@react-three/drei` · Zustand · Vite

**Port:** `8080` (external) → `80` (container)


---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| Node.js | 18+ |
| MongoDB | 6.0+ |
| Docker & Docker Compose | Latest |
| k3s (production) | v1.28+ |

---

## Running Locally

### Option A — Run each service independently

#### 1. TA API

```bash
cd TA_API
cp .env.example .env
# Edit .env with your MongoDB URI and ADI service URL

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn api.main:app --reload --host 0.0.0.0 --port 9001
```

Dashboard available at: **http://localhost:8001**
API docs at: **http://localhost:8001/docs**



#### 2. Demo Factory Floor

```bash
cd Demo_Factory_Floor
npm install
npm run dev
```

Available at: **http://localhost:8002**


### Option B — Docker Compose (TA API + MongoDB)

```bash
docker compose up -d
```

Services:

| Container | Port |
|---|---|
| `telemetry-mongo` | 27017 |
| `telemetry-api` | 8001 → 8001 |
| `telemetry-webapp` | 8002 → 80 |



---

## Production Deployment (Kubernetes / k3s)

The file [`trust-analyser-k3s.yaml`](trust-analyser-k3s.yaml) contains a complete Kubernetes manifest for deploying all services into a `trust-analyser` namespace.

### Resources defined

| Resource | Image | External Port |
|---|---|---|
| `telemetry-mongo` | `mongo:6.0` | Internal only (27017) |
| `telemetry-api` | `kingalawaka/telemetry-api-2` | 9001 |
| `telemetry-webapp` | `kingalawaka/telemetry-webapp-2` | 8080 |

MongoDB uses a **10 Gi PersistentVolumeClaim** (k3s local-path provisioner).

### Deploy

```bash
# Apply the full stack
kubectl apply -f trust-analyser-k3s.yaml

# Check rollout status
kubectl rollout status deployment -n trust-analyser

# View all running pods
kubectl get pods -n trust-analyser

# View exposed services and their external IPs
kubectl get svc -n trust-analyser
```

### Tear down

```bash
kubectl delete -f trust-analyser-k3s.yaml
```

> ⚠️ Deleting the namespace will also delete the MongoDB PVC and **all stored data**. Back up the database before tearing down in production.


## Security Notes

- All private keys and credentials are stored in `.env` files which are **gitignored** in every component.
- Use the provided `.env.example` files as templates — they contain only placeholder values.
- For production, consider injecting secrets via **Kubernetes Secrets** or a secrets manager rather than environment variables directly in the pod spec.
- The `CORS_ORIGINS=*` default is suitable for development only. Set explicit origins in production.
