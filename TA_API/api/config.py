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
config.py — Centralised application configuration.

All environment variables are loaded from .env (via python-dotenv) and
exposed as typed module-level constants.  Import from this module instead
of calling os.getenv() directly anywhere else.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# --- MongoDB ---
MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME: str = os.getenv("DB_NAME", "telemetry")
# Note: collection names are defined as constants in database.py, not here.

# --- External / ADI service ---
SERVICE_IP: str = os.getenv("SERVICE_IP", "localhost")
ADI_SERVICE_URL: str = os.getenv("ADI_SERVICE_URL", f"http://{SERVICE_IP}:9002")

# --- API server ---
API_PORT: int = int(os.getenv("API_PORT", "8001"))

# CORS — split comma-separated origins into a list; keep ["*"] as the default
_cors_raw: str = os.getenv("CORS_ORIGINS", "*")
CORS_ORIGINS: list[str] = [o.strip() for o in _cors_raw.split(",") if o.strip()]
