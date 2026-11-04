# SPDX-License-Identifier: GPL-3.0-only ( contact authors for upgrade consent )
# Trust Analyzer - A service to evaluate the trustworthiness of a system
# using five trust evaluation categories: security, resilience, reliability,
# threat exposure, and intentions. Output is a trust score (0-100) and a
# behavior type (normal, suspicious, compromised).
#
# Copyright (c) 2026 Pasindu Kurupparachchi <pasindu.kurupparachchi@mtu.ie>, Nimbus Research Centre, Munster Technological University
#
# This work is partially supported by the Horizon Europe TELEMETRY project,
# funded by the European Commission under grant number 101119747, and by the
# Science Foundation Ireland Centre Advance CRT under grant number 18/CRT/6222.
#
# Trust analyzer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (subject to
# explicit consent) any later version.
#
# This tool is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE or SATISFACTORY QUALITY or PERFORMANCE,
# comply with any description or regulatory standard, or are safe, accurate,
# up to date or complete. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see [https://www.gnu.org/licenses/.](https://www.gnu.org/licenses/)

"""
api/main.py — Application entry point.

All heavy logic lives in:
  api/services/   — pure business logic (rules engine, trust calculator, etc.)
  api/routers/    — FastAPI route handlers grouped by feature
  api/database.py — MongoDB connection and collection singletons
  api/config.py   — Environment / settings loading
  api/models.py   — Pydantic request/response models
"""
from __future__ import annotations
import os
import sys
from contextlib import asynccontextmanager

# Ensure the api/ directory is on sys.path so all sibling modules
# (database, config, models, services/*, routers/*) resolve correctly
# regardless of whether uvicorn is launched from the project root or
# from inside api/.
_API_DIR = os.path.dirname(os.path.abspath(__file__))
if _API_DIR not in sys.path:
    sys.path.insert(0, _API_DIR)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from database import TRUST_CYCLE_CONFIG_COLLECTION
from routers.cycle import (
    trust_cycle_config,
    trust_cycle_state,
    broadcast_cycle_status,
)

# Import all routers
from routers import (
    submit,
    mappings,
    trust_config,
    dashboard,
    rules,
    reports,
    actions,
    cycle,
)

_WEBAPP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "webapp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Restore trust cycle configuration from DB on startup."""
    config = TRUST_CYCLE_CONFIG_COLLECTION.find_one({"config_name": "main_cycle"})
    if config:
        trust_cycle_config["enabled"] = config.get("enabled", False)
        trust_cycle_config["duration"] = config.get("duration", 5)
        trust_cycle_config["time_unit"] = config.get("time_unit", "minutes")
    print("Trust cycle config loaded:", trust_cycle_config)

    # Wire the SSE broadcast function into the submit router
    submit.set_broadcast_fn(broadcast_cycle_status)

    yield


app = FastAPI(
    title="Telemetry Trust Analyser API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def no_cache_static_middleware(request, call_next):
    """Ensure browser never caches static JS/CSS assets during development."""
    response = await call_next(request)
    if request.url.path.startswith("/static/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# ── Static files ──────────────────────────────────────────────────────────────
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(_WEBAPP_DIR, "static")),
    name="static",
)
app.mount(
    "/images",
    StaticFiles(directory=os.path.join(_WEBAPP_DIR, "images")),
    name="images",
)


# ── Serve the webapp at root ───────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the dashboard SPA at the root URL."""
    return FileResponse(os.path.join(_WEBAPP_DIR, "dashboard.html"))


# ── Register routers ──────────────────────────────────────────────────────────
app.include_router(submit.router)
app.include_router(mappings.router)
app.include_router(trust_config.router)
app.include_router(dashboard.router)
app.include_router(rules.router)
app.include_router(reports.router)
app.include_router(actions.router)
app.include_router(cycle.router)