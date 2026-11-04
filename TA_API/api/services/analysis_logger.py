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
services/analysis_logger.py — Persists analysis trace data to the database.

All _save_* functions write logging/traceability records so that individual
analysis steps can be reviewed later through the Evaluation Reports UI.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional

# pyrefly: ignore [missing-import]
from bson import ObjectId

from services import get_by_path
from database import (
    TOOL_REPORTINGS_COLLECTION,
    RULE_EVALUATION_LOGS_COLLECTION,
    BEHAVIOR_DETERMINATION_LOGS_COLLECTION,
    TRUST_SCORE_CALCULATION_LOGS_COLLECTION,
)


def _to_datetime(ts) -> datetime:
    if isinstance(ts, str):
        return datetime.fromisoformat(ts)
    if isinstance(ts, datetime):
        return ts
    return datetime.utcnow()


def extract_tool_reporting_data(mapped_config: dict, payload: dict, timestamp: str) -> dict:
    """
    Extract tool reporting data from a payload using the mapped request configuration.

    Returns a dict with keys: ``tool_name``, ``unique_id``, ``value``,
    ``category``, ``timestamp``, ``supplement_data``, ``full_payload``.
    """
    tool_reporting = {
        "tool_name": mapped_config.get("tool_name"),
        "category": (mapped_config.get("trust_evaluation_category") or "Uncategorized").strip(),
        "timestamp": _to_datetime(timestamp),
        "unique_id": get_by_path(payload, mapped_config.get("unique_id_path", "")),
        "value": get_by_path(payload, mapped_config.get("value_path", "")),
        "full_payload": payload,
        "supplement_data": {},
    }

    if mapped_config.get("supplement") or mapped_config.get("supplement_data_paths"):
        for field_config in mapped_config.get("supplement_data_paths", []):
            field_name = field_config.get("field_name", "")
            field_path = field_config.get("field_path", "")
            if field_name and field_path:
                tool_reporting["supplement_data"][field_name] = get_by_path(payload, field_path)

    return tool_reporting


def save_tool_reporting(tool_reporting: dict, evaluation_report_id: Optional[str] = None) -> str:
    """
    Persist a tool reporting record to the database.

    Returns: inserted MongoDB ObjectId as a string.
    """
    if "timestamp" in tool_reporting and isinstance(tool_reporting["timestamp"], str):
        tool_reporting["timestamp"] = datetime.fromisoformat(tool_reporting["timestamp"])
    elif "timestamp" not in tool_reporting:
        tool_reporting["timestamp"] = datetime.utcnow()

    if evaluation_report_id:
        tool_reporting["evaluation_report_id"] = ObjectId(evaluation_report_id)

    result = TOOL_REPORTINGS_COLLECTION.insert_one(tool_reporting)
    return str(result.inserted_id)


def save_rule_evaluation_log(
    tool_name: str,
    category: str,
    timestamp,
    rules_evaluated: list,
    overall_result: bool,
    evaluation_report_id: Optional[str] = None,
) -> str:
    """
    Persist a rule evaluation log with full details.

    Returns: inserted MongoDB ObjectId as a string.
    """
    processed_rules = [
        {
            "rule_index": r.get("rule_index"),
            "rule_name": r.get("rule_name"),
            "matched": r.get("matched", False),
            "impact_level": r.get("impact_level"),
            "extracted_values": r.get("extracted_values", {}),
            "matched_groups": r.get("matched_groups", []),
        }
        for r in rules_evaluated
    ]

    log_doc = {
        "tool_name": tool_name,
        "category": category,
        "timestamp": _to_datetime(timestamp),
        "rules_evaluated": processed_rules,
        "overall_result": overall_result,
        "summary": {
            "total_rules": len(rules_evaluated),
            "rules_matched": sum(1 for r in processed_rules if r.get("matched", False)),
            "overall_result": overall_result,
        },
    }
    if evaluation_report_id:
        log_doc["evaluation_report_id"] = ObjectId(evaluation_report_id)

    result = RULE_EVALUATION_LOGS_COLLECTION.insert_one(log_doc)
    return str(result.inserted_id)


def save_behavior_determination_log(
    tool_name: str,
    category: str,
    timestamp,
    steps: list,
    final_behaviour: str,
    evaluation_report_id: Optional[str] = None,
    advanced_rules_result: Optional[dict] = None,
    value_source: Optional[str] = None,
) -> str:
    """
    Persist behavior determination steps to the database.

    Args:
        value_source: How the impact was determined — ``"new_report"``,
            ``"past_value"``, or ``"manual_impact"``.

    Returns: inserted MongoDB ObjectId as a string.
    """
    log_doc = {
        "tool_name": tool_name,
        "category": category,
        "timestamp": _to_datetime(timestamp),
        "steps": steps,
        "final_behaviour": final_behaviour,
        "confidence": 0.95,
        "value_source": value_source,
    }

    if advanced_rules_result:
        log_doc["advanced_rules"] = {
            "evaluated": True,
            "overall_result": advanced_rules_result.get("overall_result", False),
            "matched_count": advanced_rules_result.get("matched_count", 0),
            "total_rules": advanced_rules_result.get("rule_count", 0),
            "matched_rules": advanced_rules_result.get("matched_rules", []),
        }
    else:
        log_doc["advanced_rules"] = {"evaluated": False, "overall_result": False, "matched_count": 0, "total_rules": 0, "matched_rules": []}

    if evaluation_report_id:
        log_doc["evaluation_report_id"] = ObjectId(evaluation_report_id)

    result = BEHAVIOR_DETERMINATION_LOGS_COLLECTION.insert_one(log_doc)
    return str(result.inserted_id)


def save_trust_score_calculation_log(
    tool_name: str,
    category: str,
    timestamp,
    steps: list,
    final_score: float,
    final_max_score: float,
    final_percentage: float,
    evaluation_report_id: Optional[str] = None,
) -> str:
    """
    Persist trust score calculation steps to the database.

    Returns: inserted MongoDB ObjectId as a string.
    """
    log_doc = {
        "tool_name": tool_name,
        "category": category,
        "timestamp": _to_datetime(timestamp),
        "steps": steps,
        "final_score": final_score,
        "final_max_score": final_max_score,
        "final_percentage": final_percentage,
    }
    if evaluation_report_id:
        log_doc["evaluation_report_id"] = ObjectId(evaluation_report_id)

    result = TRUST_SCORE_CALCULATION_LOGS_COLLECTION.insert_one(log_doc)
    return str(result.inserted_id)
