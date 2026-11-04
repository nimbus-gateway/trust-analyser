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
routers/submit.py — Incoming tool data submission endpoint.
"""
from __future__ import annotations
import asyncio
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from bson import ObjectId

from services import get_by_path
import adi_connector
from database import (
    db,
    TOOL_DATA_COLLECTION,
    MAPPED_COLLECTION,
    TRUST_SCORE_WEIGHTS_COLLECTION,
    CURRENT_REPORTING_TOOLS_COLLECTION,
    TOOL_MANUAL_IMPACTS_COLLECTION,
    TOOL_REPORTINGS_COLLECTION,
    BEHAVIOR_DETERMINATION_LOGS_COLLECTION,
    TRUST_SCORE_CALCULATION_LOGS_COLLECTION,
    RULE_EVALUATION_LOGS_COLLECTION,
)
from models import ToolData
from services.rules_engine import evaluate_all_rules
from services.trust_calculator import calculate_trust_score_and_behaviour_with_steps
from services.analysis_logger import save_tool_reporting, save_rule_evaluation_log, save_behavior_determination_log, save_trust_score_calculation_log
from services.report_builder import build_simple_evaluation_report

router = APIRouter()

# Global cycle state — shared with cycle router via this module-level dict
trust_cycle_state: dict = {
    "is_running": False,
    "start_time": None,
    "end_time": None,
    "submissions": [],
    "user_stopped": False,
}

# SSE broadcast function injected at startup
_broadcast_fn = None

def set_broadcast_fn(fn):
    global _broadcast_fn
    _broadcast_fn = fn

async def _broadcast(status, data=None):
    if _broadcast_fn:
        await _broadcast_fn(status, data)


@router.post("/submit")
async def submit_data(data: ToolData):
    doc = data.model_dump()
    mapped = list(MAPPED_COLLECTION.find({}))

    # Check if incoming request matches any existing mapping
    is_mapped = False
    for m in mapped:
        unique_id_path = m.get("unique_id_path", "")
        mapped_uid = m.get("unique_id_value")
        incoming_uid = get_by_path(data.payload, unique_id_path)
        if (unique_id_path and mapped_uid is not None and incoming_uid is not None
                and str(incoming_uid) == str(mapped_uid)):
            is_mapped = True
            break

    if not mapped or not is_mapped:
        result = TOOL_DATA_COLLECTION.insert_one(doc)
        doc_copy = dict(doc)
        doc_copy["_id"] = str(result.inserted_id)
        return {"status": "ok", "results": "Saved for later mapping (no matching mappings found)", "submitted_payload": doc_copy}

    if trust_cycle_state["is_running"]:
        trust_cycle_state["submissions"].append(data.model_dump())
        return {"status": "ok", "message": "Data queued for batch analysis."}

    # Update most-recent value + value frequencies
    for m in mapped:
        unique_id_path = m.get("unique_id_path", "")
        mapped_uid = m.get("unique_id_value")
        new_uid = get_by_path(data.payload, unique_id_path)
        if unique_id_path and mapped_uid is not None and new_uid is not None and str(new_uid) == str(mapped_uid):
            db["tool_most_recent_values"].update_one(
                {"tool_name": m["tool_name"], "trust_evaluation_category": m.get("trust_evaluation_category")},
                {"$set": {"payload": data.payload, "time_stamp": data.time_stamp}},
                upsert=True,
            )
            tool_name = m.get("tool_name")
            cat = m.get("trust_evaluation_category")
            data_type = m.get("data_type")
            value_path = m.get("value_path")
            value = get_by_path(data.payload, value_path) if value_path else None

            from services.rules_engine import process_value
            if m.get("value_processing_required") and m.get("value_processing_steps"):
                value = process_value(value, m.get("value_processing_steps"))

            # Evaluate submitted rules only (never fall back to configured rules on submit)
            rule_evaluation_result = None
            if data.advanced_rules:
                rule_evaluation_result = evaluate_all_rules(data.payload, data.advanced_rules, data.between_rules_connector, mapping=m)
                db["rule_evaluation_results"].update_one(
                    {"tool_name": tool_name, "trust_evaluation_category": cat, "timestamp": datetime.utcnow()},
                    {"$set": {
                        "overall_result": rule_evaluation_result["overall_result"],
                        "matched_rules": rule_evaluation_result["matched_rules"],
                        "matched_count": rule_evaluation_result["matched_count"],
                        "rule_count": rule_evaluation_result["rule_count"],
                        "evaluations": rule_evaluation_result["evaluations"],
                    }},
                    upsert=True,
                )

            freq_coll = db["tool_value_frequencies"]
            if data_type in ["binary", "categorical"]:
                freq_coll.update_one(
                    {"tool_name": tool_name, "trust_evaluation_category": cat, "value": value},
                    {"$inc": {"count": 1}, "$set": {"data_type": data_type}},
                    upsert=True,
                )
            elif data_type == "continuous":
                freq_coll.update_one(
                    {"tool_name": tool_name, "trust_evaluation_category": cat},
                    {"$push": {"values": value}, "$set": {"data_type": data_type}},
                    upsert=True,
                )

    # Calculate trust scores
    results = []
    weights = TRUST_SCORE_WEIGHTS_COLLECTION.find_one({}) or {
        "category_weights": {"Security": 20, "Reliability": 20, "Resilience": 20, "Threat Exposure": 20, "Intentions": 20},
        "behaviour_weights": {"normal": 100, "suspicious": 50, "compromised": 0},
    }
    behaviour_weights = weights.get("behaviour_weights", {"normal": 100, "suspicious": 50, "compromised": 0})
    category_weights = weights.get("category_weights", {})

    cat_tools: dict = defaultdict(list)
    for m in mapped:
        cat = (m.get("trust_evaluation_category") or "Uncategorized").strip()
        cat_tools[cat].append(m)

    system_max_score = system_real_score = 0
    CURRENT_REPORTING_TOOLS_COLLECTION.delete_many({})

    for cat, tools in cat_tools.items():
        cat_weight = category_weights.get(cat, 20)
        max_beh_weight = max(behaviour_weights.values())
        num_tools = len(tools)
        cat_max_score = num_tools * max_beh_weight * cat_weight
        system_max_score += cat_max_score
        cat_real_score = 0

        for tool in tools:
            submitted_tool_mapping = None
            for m in mapped:
                uid_path = m.get("unique_id_path", "")
                uid_val = m.get("unique_id_value", "")
                sub_uid = get_by_path(data.payload, uid_path)
                if (m.get("tool_name") == tool["tool_name"]
                        and m.get("trust_evaluation_category") == cat
                        and sub_uid == uid_val):
                    submitted_tool_mapping = m
                    break

            payload = None
            tool_reporting_data = None
            tool_reporting_timestamp = None

            if submitted_tool_mapping:
                payload = data.payload
                tool_reporting_timestamp = datetime.fromisoformat(data.time_stamp) if isinstance(data.time_stamp, str) else data.time_stamp
                TOOL_MANUAL_IMPACTS_COLLECTION.delete_one({"tool_name": tool["tool_name"], "category": cat})
            else:
                most_recent_reporting = db["tool_reportings"].find_one(
                    {"tool_name": tool["tool_name"], "category": cat}, sort=[("timestamp", -1)]
                )
                if most_recent_reporting:
                    payload = most_recent_reporting.get("full_payload")
                    tool_reporting_timestamp = most_recent_reporting.get("timestamp")
                    tool_reporting_data = most_recent_reporting
                else:
                    most_recent = db["tool_most_recent_values"].find_one({"tool_name": tool["tool_name"], "trust_evaluation_category": cat})
                    payload = most_recent["payload"] if most_recent else None
                    tool_reporting_timestamp = datetime.utcnow()

            if payload:
                tool_rule_evaluation_result = None
                if data.advanced_rules:
                    tool_rule_evaluation_result = evaluate_all_rules(data.payload, data.advanced_rules, data.between_rules_connector, mapping=tool)
                elif tool.get("advanced_rules"):
                    tool_rule_evaluation_result = evaluate_all_rules(payload, tool.get("advanced_rules"), tool.get("between_rules_connector", "AND"), mapping=tool)

                res = calculate_trust_score_and_behaviour_with_steps(
                    tool, payload,
                    submitted_rules=data.advanced_rules,
                    between_rules_connector=data.between_rules_connector,
                    is_new_submission=bool(submitted_tool_mapping),
                )
                res["advanced_rules_evaluation"] = tool_rule_evaluation_result
                res["advanced_rules_matched"] = bool(tool_rule_evaluation_result and tool_rule_evaluation_result.get("overall_result"))
                res["data_type"] = tool.get("data_type")
                res["is_new_submission"] = bool(submitted_tool_mapping)

                beh_weight = behaviour_weights.get(res["behaviour"], 0)
                cat_real_score += beh_weight * cat_weight

                if submitted_tool_mapping:
                    timestamp = datetime.fromisoformat(data.time_stamp) if isinstance(data.time_stamp, str) else data.time_stamp
                    tool_reporting_id = save_tool_reporting({
                        "tool_name": res["tool_name"],
                        "unique_id": res["unique_id_value"],
                        "value": res["value"],
                        "category": res["trust_evaluation_category"],
                        "timestamp": timestamp,
                        "impact": res["impact"],
                        "full_payload": payload,
                    })
                    _asset_id = get_by_path(payload, "asset_id") if payload else None
                    CURRENT_REPORTING_TOOLS_COLLECTION.insert_one({
                        "tool_name": res["tool_name"], "category": res["trust_evaluation_category"],
                        "asset_id": _asset_id, "reported_at": timestamp, "source": "immediate",
                    })
                    res["tool_reporting_id"] = tool_reporting_id

                    if tool.get("evaluation_mode") == "advanced" and tool_rule_evaluation_result:
                        save_rule_evaluation_log(res["tool_name"], res["trust_evaluation_category"], timestamp, tool_rule_evaluation_result.get("evaluations", []), tool_rule_evaluation_result.get("overall_result", False))
                    save_behavior_determination_log(res["tool_name"], res["trust_evaluation_category"], timestamp, res.get("behavior_determination_steps", []), res["behaviour"], advanced_rules_result=tool_rule_evaluation_result, value_source="new_report")
                    save_trust_score_calculation_log(res["tool_name"], res["trust_evaluation_category"], timestamp, res.get("trust_score_calculation_steps", []), res["trust_score"], res["max_score"], res["percent"])
                else:
                    timestamp = tool_reporting_timestamp
                    if tool_reporting_data:
                        tool_reporting_id = str(tool_reporting_data["_id"])
                    else:
                        timestamp = datetime.utcnow()
                        tool_reporting_id = save_tool_reporting({
                            "tool_name": res["tool_name"], "unique_id": res["unique_id_value"], "value": res["value"],
                            "category": res["trust_evaluation_category"], "timestamp": timestamp, "impact": res["impact"], "full_payload": payload,
                        })
                    res["tool_reporting_id"] = tool_reporting_id

                db["tool_behaviour_results"].update_one(
                    {"tool_name": res["tool_name"], "trust_evaluation_category": res["trust_evaluation_category"]},
                    {"$set": {"behaviour": res["behaviour"], "unique_id_value": res["unique_id_value"], "value": res["value"], "count": res["count"]}},
                    upsert=True,
                )
                db["trust_score_results"].update_one(
                    {"tool_name": res["tool_name"], "trust_evaluation_category": res["trust_evaluation_category"]},
                    {"$set": {"trust_score": beh_weight * cat_weight, "max_score": cat_max_score, "percent": (beh_weight * cat_weight / cat_max_score * 100) if cat_max_score > 0 else 0}},
                    upsert=True,
                )
                db["tool_trust_score_history"].update_one(
                    {"tool_name": res["tool_name"], "trust_evaluation_category": res["trust_evaluation_category"]},
                    {"$push": {"scores": beh_weight * cat_weight}},
                    upsert=True,
                )
                res["submission_timestamp"] = data.time_stamp
                results.append(res)

        if results:
            db["category_behaviour_results"].update_one(
                {"trust_evaluation_category": cat},
                {"$set": {"behaviour": results[-1]["category_behaviour"]}},
                upsert=True,
            )
            db["category_behaviour_history"].update_one(
                {"trust_evaluation_category": cat},
                {"$push": {"history": results[-1]["category_behaviour"]}},
                upsert=True,
            )
        system_real_score += cat_real_score

    system_percent = (system_real_score / system_max_score * 100) if system_max_score > 0 else 0

    if results:
        db["system_behaviour_result"].update_one({}, {"$set": {"system_behaviour": results[-1]["system_behaviour"]}}, upsert=True)
        db["system_behaviour_history"].update_one({}, {"$push": {"history": results[-1]["system_behaviour"]}}, upsert=True)

    db["system_trust_score_history"].update_one({}, {"$push": {"scores": system_percent}}, upsert=True)

    report_id = None
    if results:
        evaluation_report = build_simple_evaluation_report(results, results[-1]["system_behaviour"], system_percent, category_weights, behaviour_weights)
        report_doc = {
            "timestamp": datetime.utcnow(), "cycle_submissions_count": 1,
            "evaluation_mode": "immediate", "report": evaluation_report,
            "system_behaviour": results[-1]["system_behaviour"], "system_trust_score_percentage": system_percent,
        }
        report_result = db["trust_evaluation_reports"].insert_one(report_doc)
        report_id = report_result.inserted_id

        newly_submitted_ids = []
        for result in results:
            for m in mapped:
                uid_path = m.get("unique_id_path", "")
                uid_val = m.get("unique_id_value", "")
                sub_uid = get_by_path(data.payload, uid_path)
                if (m.get("tool_name") == result.get("tool_name") and m.get("trust_evaluation_category") == result.get("trust_evaluation_category") and sub_uid == uid_val):
                    if result.get("tool_reporting_id"):
                        newly_submitted_ids.append(result.get("tool_reporting_id"))
                    break

        if newly_submitted_ids:
            TOOL_REPORTINGS_COLLECTION.update_many(
                {"_id": {"$in": [ObjectId(rid) if isinstance(rid, str) else rid for rid in newly_submitted_ids]}},
                {"$set": {"evaluation_report_id": report_id}},
            )

        tool_category_pairs = list({(r.get("tool_name", ""), r.get("trust_evaluation_category", "")) for r in results})
        for tn, cat in tool_category_pairs:
            BEHAVIOR_DETERMINATION_LOGS_COLLECTION.update_many({"tool_name": tn, "category": cat, "evaluation_report_id": {"$exists": False}}, {"$set": {"evaluation_report_id": report_id}})
            TRUST_SCORE_CALCULATION_LOGS_COLLECTION.update_many({"tool_name": tn, "category": cat, "evaluation_report_id": {"$exists": False}}, {"$set": {"evaluation_report_id": report_id}})
            RULE_EVALUATION_LOGS_COLLECTION.update_many({"tool_name": tn, "category": cat, "evaluation_report_id": {"$exists": False}}, {"$set": {"evaluation_report_id": report_id}})

    await run_in_threadpool(adi_connector.generate_TA_report_for_ADI, "Immediate")
    await _broadcast("evaluation_complete", {"analysis_type": "immediate", "report_id": str(report_id) if report_id else None})
    return {"status": "ok", "results": {"system_percent": system_percent}}
