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
database.py — MongoDB client and collection handles.

Import the named collection constants from this module instead of
creating new MongoClient instances elsewhere.  The client is created once
at import time using values from config.py.
"""

from pymongo import MongoClient
from config import MONGO_URI, DB_NAME

# Single shared client
client: MongoClient = MongoClient(MONGO_URI)
db = client[DB_NAME]

# --- Core data collections ---
# These names are application constants, not environment config.
TOOL_DATA_COLLECTION = db.get_collection("tool_data")
MAPPED_COLLECTION = db.get_collection("mapped_requests")
REMOVED_MAPPED_COLLECTION = db.get_collection("removed_mapped_requests")

# --- Trust analyser configuration collections ---
TRUST_CONFIG_COLLECTION = db.get_collection("trust_analyser_config")
TRUST_CONFIG_STEP1_COLLECTION = db.get_collection("trust_analyser_step1_config")
TRUST_CONFIG_STEP2_COLLECTION = db.get_collection("trust_analyser_step2_config")
TRUST_CONFIG_STEP3_COLLECTION = db.get_collection("trust_analyser_step3_config")
TRUST_CONFIG_STEP4_COLLECTION = db.get_collection("trust_analyser_step4_config")
TOOL_CONFIG_STEP5_COLLECTION = db.get_collection("tool_config_step5")
TRUST_SCORE_WEIGHTS_COLLECTION = db.get_collection("trust_score_weights")
TRUST_CYCLE_CONFIG_COLLECTION = db.get_collection("trust_cycle_config")

# --- Analysis logging / traceability collections ---
TOOL_REPORTINGS_COLLECTION = db.get_collection("tool_reportings")
RULE_EVALUATION_LOGS_COLLECTION = db.get_collection("rule_evaluation_logs")
BEHAVIOR_DETERMINATION_LOGS_COLLECTION = db.get_collection("behavior_determination_logs")
TRUST_SCORE_CALCULATION_LOGS_COLLECTION = db.get_collection("trust_score_calculation_logs")
EVALUATION_REPORT_ANALYSIS_COLLECTION = db.get_collection("evaluation_report_analysis")
TOOL_MANUAL_IMPACTS_COLLECTION = db.get_collection("tool_manual_impacts")
CURRENT_REPORTING_TOOLS_COLLECTION = db.get_collection("current_reporting_tools")
