# Telemetry Trust Analyser API (TA_API)

The **Trust Analyser API (`TA_API`)** is the central orchestration and computation engine of the Trust Analyser platform. It ingests real-time telemetry from heterogeneous security, network, and operational monitoring tools, applies dynamic rules, computes multi-tier system trust scores, logs full audit trails in MongoDB.

It also serves an embedded, real-time web dashboard single-page application (SPA) with live Server-Sent Events (SSE) streaming.

---

## System Architecture

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

## The 3-Step Trust Evaluation Framework

`TA_API` calculates trustworthiness hierarchically to prevent single-tool bias and enable multi-dimensional security evaluation:

```
Raw Telemetry Event (Payload)
              │
              ▼
   [Step 1: Impact Assessment]
   - Evaluates configured rules against payload fields (get_by_path)
   - Assigns severity impact (none, low, medium, high, critical)
   - Maps tool event to Trust Category (Security, Reliability, Threat, etc.)
              │
              ▼
   [Step 2: Behavior Determination]
   - Evaluates tool reporting frequencies and anomaly counts
   - Determines component behavior: Trustworthy, Suspicious, Malicious, Degraded
   - Applies configurable overrides & threshold triggers
              │
              ▼
   [Step 3: Aggregate Trust Score & Behavior]
   - Applies category weight vectors (normalized across reporting tools)
   - Computes overall numeric Trust Score (0.0 – 100.0)
   - Synthesizes holistic system behavior rating
              │
              ▼
   [Report Generation & Ledger Notarization]
   - Constructs Trust Evaluation Report
   - Persists evaluation trace in MongoDB
```

---

## Directory Structure

```
TA_API/
├── api/
│   ├── main.py                     # FastAPI application entry point, lifespan, static file mounts
│   ├── config.py                   # Environment variable loader & settings defaults
│   ├── database.py                 # PyMongo connection singleton & collection handle definitions
│   ├── models.py                   # Pydantic request/response data models
│   ├── adi_connector.py            # Client interface for dispatching reports/actions to ADI
│   ├── clear_db.py                 # Utility script to purge MongoDB collections
│   ├── routers/
│   │   ├── submit.py               # POST /submit: Raw telemetry ingestion & instant evaluation
│   │   ├── cycle.py                # Periodic / on-demand trust evaluation cycle & SSE broadcast
│   │   ├── mappings.py             # Tool payload field mapping CRUD (/mappings, /map, /unmap)
│   │   ├── trust_config.py         # Trust calculation configuration (Step 1, Step 2, Step 3)
│   │   ├── rules.py                # Rule engine management and rule condition evaluation
│   │   ├── reports.py              # Querying, retrieval, and export of trust evaluation reports
│   │   ├── dashboard.py            # Aggregated statistics, active reporting tools, system health
│   │   └── actions.py              # Operator countermeasures and action audit logging
│   └── services/
│       ├── __init__.py             # Re-exports and get_by_path payload traversal utility
│       ├── rules_engine.py         # Multi-operator rule condition evaluation engine
│       ├── trust_calculator.py     # 3-step mathematical trust score calculation algorithms
│       ├── analysis_logger.py      # Structured audit logging into MongoDB collections
│       └── report_builder.py       # Assembles standardized JSON Trust Reports
├── webapp/
│   ├── dashboard.html              # Modern glassmorphism SPA dashboard interface
│   ├── test_modal.html             # UI modal testing template
│   ├── Dockerfile.webapp           # Dedicated Nginx container for web dashboard
│   ├── images/                     # Dashboard logos, diagrams, and icon assets
│   └── static/                     # CSS stylesheets, JavaScript modules, fonts
├── .env.example                    # Template for required environment variables
├── Dockerfile.api                  # Container build for the FastAPI backend
├── Dockerfile.mongo                # Container build for MongoDB initialization
├── mongo_backup.archive.gz         # Sample data dump to visualise trust analyser dashboard
└── requirements.txt                # Python package dependencies
```

---

## Core API Endpoints

### 1. Ingestion & Real-Time Processing
- **`POST /submit`**: Receives tool telemetry reports. Checks registered mappings, executes immediate rule evaluations, logs reporting status, updates `tool_most_recent_values`, and streams real-time SSE updates.
- **`GET /cycle/stream`**: Server-Sent Events (SSE) stream broadcasting cycle state, progress, and real-time trust evaluation results to connected dashboard clients.
- **`POST /cycle/trigger`**: Triggers an on-demand trust calculation cycle across all active tools.
- **`POST /cycle/config`**: Updates trust cycle settings (interval duration, time unit, auto-run enabled).

### 2. Configuration & Field Mappings
- **`GET /mappings`**: Lists all active tool-to-category mappings.
- **`POST /map`**: Registers a new tool mapping (tool name, category, unique ID path, value path, processing steps).
- **`POST /unmap`**: Removes an existing tool mapping.
- **`GET /trust-config/step1`**, **`POST /trust-config/step1`**: Manages Step 1 impact scoring rules.
- **`GET /trust-config/step2`**, **`POST /trust-config/step2`**: Manages Step 2 behavior classification rules and overrides.
- **`GET /trust-config/step3`**, **`POST /trust-config/step3`**: Manages Step 3 category weights.

### 3. Reporting & Auditing
- **`GET /reports`**: Retrieves historical trust evaluation reports with pagination and filtering.
- **`GET /reports/{report_id}`**: Retrieves a specific evaluation report by MongoDB ObjectId.
- **`GET /dashboard/summary`**: High-level telemetry summary (active tools, latest score, system status).
- **`POST /actions/log`**: Records operator actions, incident responses, or overrides.

Interactive Swagger API documentation is available at:
```
http://localhost:8001/docs
```

---

## Environment Variables

Create a `.env` file in the `TA_API` directory (or use `.env.example` as a template):

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017/` | Connection string for MongoDB |
| `DB_NAME` | `telemetry` | MongoDB database name |
| `API_PORT` | `8001` | Port on which FastAPI server listens |
| `SERVICE_IP` | `localhost` | Host IP for ADI Connector integration |
| `ADI_SERVICE_URL` | `http://localhost:9002` | Full base URL for ADI Connector HTTP service |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated or `*` for dev) |

---

## Getting Started

### Prerequisites

- Python **3.10+**
- MongoDB **6.0+** running locally or via Docker

### 1. Local Setup (Manual)

1. **Navigate to the directory**:
   ```bash
   cd TA_API
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure MongoDB is running**:
   ```bash
   # Using Docker to run MongoDB
   docker run -d \
     --name telemetry-mongo \
     -p 27017:27017 \
     -e MONGO_INITDB_DATABASE=telemetry \
     -v mongo-data:/data/db \
     mongo:6.0
   ```

5. **Start the API server**:
   ```bash
   uvicorn api.main:app --reload --host 0.0.0.0 --port 8001
   ```

6. **Access the application**:
   - Web Dashboard: **http://localhost:8001/**
   - Swagger OpenAPI Docs: **http://localhost:8001/docs**
   - ReDoc: **http://localhost:8001/redoc**

---

## Docker Deployment

### Multi-Container Stack (Docker Compose)

`docker-compose.yml` launches the complete TA backend stack:

```bash
docker-compose up -d
```

This provisions:
- **`mongo`**: MongoDB 6.0 on port `27017` with persistent volume `mongo-data`
- **`api`**: FastAPI application on port `8001`
- **`webapp`**: Nginx static web server on port `8080`

### Building Standalone Docker Images

```bash
# Build API container
docker build --platform linux/amd64 -f Dockerfile.api -t telemetry-api:latest .

# Run API container
docker run -d \
  --name telemetry-api \
  -p 8001:8001 \
  -e MONGO_URI=mongodb://host.docker.internal:27017/ \
  -e DB_NAME=telemetry \
  telemetry-api:latest
```

---

## Database Management & Maintenance

### Key Collections in MongoDB (`telemetry` database)

| Collection | Purpose |
|---|---|
| `tool_data` | Temporary incoming tool reports awaiting processing |
| `mapped_collection` | Registered mappings linking tool payloads to trust categories |
| `tool_most_recent_values` | Cached latest reading and status per tool |
| `current_reporting_tools` | Active reporting tool registrations |
| `trust_config_step1` | Step 1 impact configuration rules |
| `trust_config_step2` | Step 2 behavior classification parameters and thresholds |
| `trust_config_step3` | Step 3 category weights |
| `tool_reportings` | Historical log of every tool submission |
| `rule_evaluation_logs` | Evaluation trace of each rule executed against payloads |
| `trust_score_calculation_logs`| Full breakdown of each trust calculation cycle |
| `trust_cycle_config` | Cycle runtime configuration (duration, enabled state) |

### Resetting / Clearing Database

To purge all collections during testing or development, run:

```bash
python3 -c "from pymongo import MongoClient; c=MongoClient('mongodb://localhost:27017/'); db=c['telemetry']; [db[col].delete_many({}) for col in db.list_collection_names()]; print('Cleared all telemetry collections.')"
```
