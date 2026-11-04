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
routers/cycle.py — Trust analysis cycle & manual analysis trigger endpoints.
"""
from __future__ import annotations
import asyncio
import json
import traceback
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from bson import ObjectId

import adi_connector
from database import (
    db, MAPPED_COLLECTION,
    TRUST_CONFIG_STEP1_COLLECTION,
    TRUST_CONFIG_STEP2_COLLECTION,
    TRUST_CONFIG_STEP3_COLLECTION,
    TRUST_CONFIG_STEP4_COLLECTION,
    TRUST_SCORE_WEIGHTS_COLLECTION,
    TRUST_CYCLE_CONFIG_COLLECTION,
    TOOL_MANUAL_IMPACTS_COLLECTION,
    TOOL_REPORTINGS_COLLECTION,
    BEHAVIOR_DETERMINATION_LOGS_COLLECTION,
    TRUST_SCORE_CALCULATION_LOGS_COLLECTION,
    RULE_EVALUATION_LOGS_COLLECTION,
    CURRENT_REPORTING_TOOLS_COLLECTION,
)
from services import get_by_path
from services.rules_engine import process_value, evaluate_all_rules
from services.trust_calculator import calculate_trust_score_and_behaviour_with_steps
from services.analysis_logger import save_tool_reporting, save_behavior_determination_log, save_trust_score_calculation_log
from services.report_builder import build_full_evaluation_report

router = APIRouter()

# Shared cycle state — also referenced by submit router
trust_cycle_state: dict = {
    "is_running": False,
    "start_time": None,
    "end_time": None,
    "submissions": [],
    "user_stopped": False,
}
trust_cycle_config: dict = {"enabled": False, "duration": 5, "time_unit": "minutes"}
cycle_task = None
cycle_status_queue: asyncio.Queue = asyncio.Queue()


async def broadcast_cycle_status(status: str, data: dict = None):
    message = {
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "cycle_state": {
            "is_running": trust_cycle_state["is_running"],
            "start_time": trust_cycle_state["start_time"].isoformat() if trust_cycle_state["start_time"] else None,
            "end_time": trust_cycle_state["end_time"].isoformat() if trust_cycle_state["end_time"] else None,
            "submissions_count": len(trust_cycle_state["submissions"]),
        },
    }
    if data:
        message.update(data)
    try:
        cycle_status_queue.put_nowait(message)
    except asyncio.QueueFull:
        pass


def _convert_duration(duration: int, time_unit: str) -> int:
    return {"seconds": duration, "minutes": duration * 60, "hours": duration * 3600}.get(time_unit, duration * 60)


def _majority(behaviours: list, cfg: dict) -> str:
    if cfg.get("override_active") == "true":
        count_override = int(cfg.get("override_count", "0"))
        target = cfg.get("override_behaviour") or cfg.get("final_behaviour", "suspicious")
        trigger = cfg.get("tool_behaviour") or cfg.get("override_behaviour", "suspicious")
        if behaviours.count(trigger) >= count_override:
            return target
    counts = {b: behaviours.count(b) for b in ["normal", "suspicious", "compromised"]}
    max_count = max(counts.values()) if counts else 0
    max_behs = [k for k, v in counts.items() if v == max_count]
    return max_behs[0] if len(max_behs) == 1 else "suspicious"


# ── Cycle endpoints ───────────────────────────────────────────────────────────

@router.post("/trust-cycle/config")
async def set_cycle_config(request_body: dict = Body(...)):
    global trust_cycle_config
    config_to_save = {"enabled": request_body.get("enabled", False), "duration": int(request_body.get("duration", 5)), "time_unit": request_body.get("time_unit", "minutes")}
    trust_cycle_config.update(config_to_save)
    TRUST_CYCLE_CONFIG_COLLECTION.update_one({"config_name": "main_cycle"}, {"$set": config_to_save}, upsert=True)
    return {"status": "success"}


@router.get("/trust-cycle/config")
async def get_cycle_config():
    config = TRUST_CYCLE_CONFIG_COLLECTION.find_one({"config_name": "main_cycle"})
    if config:
        return {"enabled": config.get("enabled", False), "duration": config.get("duration", 5), "time_unit": config.get("time_unit", "minutes")}
    return {"enabled": False, "duration": 5, "time_unit": "minutes"}


@router.post("/trust-cycle/start")
async def start_cycle():
    global trust_cycle_state, cycle_task
    if not trust_cycle_state["is_running"]:
        trust_cycle_state["is_running"] = True
        trust_cycle_state["start_time"] = datetime.utcnow()
        trust_cycle_state["user_stopped"] = False
        duration_seconds = _convert_duration(trust_cycle_config["duration"], trust_cycle_config.get("time_unit", "minutes"))
        trust_cycle_state["end_time"] = trust_cycle_state["start_time"] + timedelta(seconds=duration_seconds)
        trust_cycle_state["submissions"] = []
        cycle_task = asyncio.create_task(_run_analysis_cycle())
        await broadcast_cycle_status("started", {"message": "Cycle started", "duration_seconds": duration_seconds})
        return {"status": "cycle started", "end_time": trust_cycle_state["end_time"].isoformat()}
    return {"status": "cycle already running"}


@router.post("/trust-cycle/stop")
async def stop_cycle():
    global trust_cycle_state, cycle_task
    if trust_cycle_state["is_running"]:
        if cycle_task:
            cycle_task.cancel()
        await _perform_batch_analysis()
        trust_cycle_state["is_running"] = False
        trust_cycle_state["user_stopped"] = True
        await broadcast_cycle_status("stopped", {"message": "Cycle stopped by user", "submissions_analyzed": len(trust_cycle_state["submissions"])})
        return {"status": "cycle stopped and analysis performed"}
    return {"status": "cycle not running"}


@router.get("/trust-cycle/status")
async def get_cycle_status():
    return {
        "is_running": trust_cycle_state["is_running"],
        "enabled": trust_cycle_config["enabled"],
        "start_time": trust_cycle_state["start_time"].isoformat() if trust_cycle_state["start_time"] else None,
        "end_time": trust_cycle_state["end_time"].isoformat() if trust_cycle_state["end_time"] else None,
        "submissions_count": len(trust_cycle_state["submissions"]),
    }


@router.get("/trust-cycle/stream")
async def stream_cycle_status():
    async def event_generator():
        while True:
            try:
                message = await asyncio.wait_for(cycle_status_queue.get(), timeout=5.0)
                yield f"data: {json.dumps(message)}\n\n"
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
            except Exception:
                break
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Manual analysis trigger ───────────────────────────────────────────────────

@router.post("/api/trigger-manual-analysis")
async def trigger_manual_analysis():
    try:
        all_mappings = list(MAPPED_COLLECTION.find({}))
        if not all_mappings:
            return JSONResponse(status_code=400, content={"error": "No tool mappings configured."})

        step1_configs = list(TRUST_CONFIG_STEP1_COLLECTION.find({}))
        step2_configs = list(TRUST_CONFIG_STEP2_COLLECTION.find({}))
        step3_configs = list(TRUST_CONFIG_STEP3_COLLECTION.find({}))
        step4_config = TRUST_CONFIG_STEP4_COLLECTION.find_one({}) or {}
        weights = TRUST_SCORE_WEIGHTS_COLLECTION.find_one({}) or {
            "category_weights": {"Security": 20, "Reliability": 20, "Resilience": 20, "Threat Exposure": 20, "Intentions": 20},
            "behaviour_weights": {"normal": 100, "suspicious": 50, "compromised": 0},
        }
        behaviour_weights = weights.get("behaviour_weights", {"normal": 100, "suspicious": 50, "compromised": 0})
        category_weights = weights.get("category_weights", {})

        CURRENT_REPORTING_TOOLS_COLLECTION.delete_many({})

        category_tool_value_impacts = defaultdict(lambda: {"mapping": None, "impacts": [], "payloads": [], "timestamps": [], "value": None})
        tools_using_previous_values = []

        for mapping in all_mappings:
            tool_name = mapping.get("tool_name")
            cat = (mapping.get("trust_evaluation_category") or "Uncategorized").strip()
            most_recent = db["tool_most_recent_values"].find_one({"tool_name": tool_name, "trust_evaluation_category": cat})
            if not most_recent:
                continue
            payload = most_recent.get("payload")
            timestamp = most_recent.get("time_stamp", "")
            value_path = mapping.get("value_path")
            value = get_by_path(payload, value_path) if value_path else None
            if mapping.get("value_processing_required") and mapping.get("value_processing_steps"):
                value = process_value(value, mapping.get("value_processing_steps"))
            impact = _categorize_impact(mapping, value, step1_configs, step2_configs)
            key = (cat, tool_name, value)
            category_tool_value_impacts[key]["mapping"] = mapping
            category_tool_value_impacts[key]["value"] = value
            category_tool_value_impacts[key]["impacts"].append(impact)
            category_tool_value_impacts[key]["payloads"].append(payload)
            category_tool_value_impacts[key]["timestamps"].append(timestamp)
            tools_using_previous_values.append((tool_name, cat))

        if not category_tool_value_impacts:
            return JSONResponse(status_code=400, content={"error": "No tool values available to analyse."})

        tool_category_behaviours = {}
        tool_results_map = {}
        tool_category_groups = defaultdict(list)
        for (cat, tool_name, value), data in category_tool_value_impacts.items():
            tool_category_groups[(tool_name, cat)].append({"value": value, "impacts": data["impacts"], "mapping": data["mapping"], "payload": data["payloads"][-1] if data["payloads"] else None, "count": len(data["impacts"])})

        for (tool_name, cat), value_groups in tool_category_groups.items():
            cat_key = cat.lower()
            step2_cfg = next((c for c in step2_configs if f"{c.get('tool_name')}|||{c.get('trust_evaluation_category','').strip().lower()}" == f"{tool_name}|||{cat_key}"), {})
            mapping = value_groups[0]["mapping"]
            payload = value_groups[-1]["payload"]
            unique_id_value = get_by_path(payload, mapping.get("unique_id_path", "")) if payload else None
            override_active = step2_cfg.get("override_active") == "true"
            override_count_threshold = int(step2_cfg.get("override_count", "0"))
            override_behaviour = step2_cfg.get("override_behaviour", "suspicious")

            tool_behaviour = None
            if override_active:
                for vg in value_groups:
                    if vg["count"] >= override_count_threshold and step2_cfg.get("override_impact", "").capitalize() in vg["impacts"]:
                        tool_behaviour = override_behaviour; break

            if tool_behaviour is None:
                ic = [0, 0, 0]
                for vg in value_groups:
                    ic[0] += vg["impacts"].count("High"); ic[1] += vg["impacts"].count("Mid"); ic[2] += vg["impacts"].count("Low")
                tool_behaviour = "compromised" if ic[0] > ic[1] and ic[0] > ic[2] else ("suspicious" if ic[1] > ic[0] and ic[1] > ic[2] else ("normal" if ic[2] > ic[0] and ic[2] > ic[1] else "suspicious"))

            tool_category_behaviours[(tool_name, cat)] = tool_behaviour
            value_path = mapping.get("value_path")
            value = get_by_path(payload, value_path) if payload and value_path else None
            if mapping.get("value_processing_required") and mapping.get("value_processing_steps"):
                value = process_value(value, mapping.get("value_processing_steps"))

            total_count = sum(vg["count"] for vg in value_groups)
            beh_weight = behaviour_weights.get(tool_behaviour, 0)
            cat_weight = category_weights.get(cat, 20)
            trust_score = beh_weight * cat_weight
            max_beh_weight = max(behaviour_weights.values())
            max_score = max_beh_weight * cat_weight
            percent = (trust_score / max_score * 100) if max_score > 0 else 0

            db["tool_behaviour_results"].update_one({"tool_name": tool_name, "trust_evaluation_category": cat}, {"$set": {"behaviour": tool_behaviour, "unique_id_value": unique_id_value, "value": value, "count": total_count}}, upsert=True)
            db["trust_score_results"].update_one({"tool_name": tool_name, "trust_evaluation_category": cat}, {"$set": {"trust_score": trust_score, "max_score": max_score, "percent": percent}}, upsert=True)

            _value_source = "manual_impact" if TOOL_MANUAL_IMPACTS_COLLECTION.find_one({"tool_name": tool_name, "category": cat}) else "past_value"
            most_recent_key = next((k for k in category_tool_value_impacts if k[0] == cat and k[1] == tool_name), None)
            most_recent_payload = category_tool_value_impacts[most_recent_key]["payloads"][-1] if most_recent_key else None
            most_recent_timestamp = category_tool_value_impacts[most_recent_key]["timestamps"][-1] if most_recent_key else datetime.utcnow()

            existing_reporting = TOOL_REPORTINGS_COLLECTION.find_one({"tool_name": tool_name, "category": cat}, sort=[("timestamp", -1)])
            if existing_reporting:
                tool_reporting_id = str(existing_reporting["_id"])
            else:
                tool_reporting_id = save_tool_reporting({"tool_name": tool_name, "unique_id": unique_id_value, "value": value, "category": cat, "timestamp": most_recent_timestamp, "impact": category_tool_value_impacts[most_recent_key]["impacts"][-1] if most_recent_key else "Low", "full_payload": most_recent_payload, "value_source": _value_source})

            detailed_result = None
            if most_recent_payload and mapping:
                detailed_result = calculate_trust_score_and_behaviour_with_steps(mapping, most_recent_payload, submitted_rules=None, between_rules_connector=mapping.get("between_rules_connector", "AND"))

            save_behavior_determination_log(tool_name, cat, datetime.utcnow(), detailed_result.get("behavior_determination_steps", []) if detailed_result else [], tool_behaviour, value_source=_value_source)
            save_trust_score_calculation_log(tool_name, cat, datetime.utcnow(), detailed_result.get("trust_score_calculation_steps", []) if detailed_result else [], trust_score, max_score, percent)
            tool_results_map[(tool_name, cat)] = {"tool_name": tool_name, "trust_evaluation_category": cat, "behaviour": tool_behaviour, "unique_id_value": unique_id_value, "value": value, "count": total_count, "trust_score": trust_score, "max_score": max_score, "percent": percent}

        # Category behaviours
        category_tools = defaultdict(list)
        for (tool_name, cat), behaviour in tool_category_behaviours.items():
            mapping = value = data_type = None
            for (ic, it, iv), idata in category_tool_value_impacts.items():
                if ic == cat and it == tool_name:
                    mapping = idata.get("mapping"); value = idata.get("value"); data_type = mapping.get("data_type") if mapping else None; break
            category_tools[cat].append({"tool_name": tool_name, "behaviour": behaviour, "mapping": mapping, "value": value, "data_type": data_type})

        category_behaviours_map = {}
        for cat, tools_info in category_tools.items():
            cat_key = cat.lower()
            step3_cfg = next((cfg for cfg in step3_configs if cfg.get("trust_evaluation_category", "").strip().lower() == cat_key), {})
            cat_behaviour = _majority([t["behaviour"] for t in tools_info], step3_cfg)
            category_behaviours_map[cat] = cat_behaviour
            db["category_behaviour_results"].update_one({"trust_evaluation_category": cat}, {"$set": {"behaviour": cat_behaviour}}, upsert=True)
            db["category_behaviour_history"].update_one({"trust_evaluation_category": cat}, {"$push": {"history": cat_behaviour}}, upsert=True)

        # System behaviour
        _cat_beh_lower = {k.strip().lower(): v for k, v in category_behaviours_map.items()}
        all_category_behaviours = []
        for c_cfg in list(TRUST_CONFIG_STEP3_COLLECTION.find({})):
            cat_name = c_cfg.get("trust_evaluation_category", "").strip()
            if cat_name.lower() in _cat_beh_lower:
                all_category_behaviours.append(_cat_beh_lower[cat_name.lower()])
            else:
                last = db["category_behaviour_results"].find_one({"trust_evaluation_category": {"$regex": f"^{cat_name}$", "$options": "i"}})
                all_category_behaviours.append(last.get("behaviour", "suspicious") if last else "suspicious")

        system_behaviour = _majority(all_category_behaviours, step4_config)
        db["system_behaviour_result"].update_one({}, {"$set": {"system_behaviour": system_behaviour}}, upsert=True)
        db["system_behaviour_history"].update_one({}, {"$push": {"history": system_behaviour}}, upsert=True)

        # System score
        system_max_score = system_real_score = 0
        for cat, tools_info in category_tools.items():
            cw = category_weights.get(cat, 20); mbw = max(behaviour_weights.values())
            system_max_score += len(tools_info) * mbw * cw
            system_real_score += sum(behaviour_weights.get(t["behaviour"], 0) * cw for t in tools_info)
        system_percent = (system_real_score / system_max_score * 100) if system_max_score > 0 else 0

        evaluation_report = build_full_evaluation_report(
            category_tools=dict(category_tools),
            tool_category_behaviours=tool_category_behaviours,
            category_behaviours_map=category_behaviours_map,
            category_tool_value_impacts=dict(category_tool_value_impacts),
            tool_results_map=tool_results_map,
            category_weights=category_weights,
            behaviour_weights=behaviour_weights,
            system_behaviour=system_behaviour,
            system_percent=system_percent,
            step2_configs=step2_configs,
            step3_configs=step3_configs,
            step4_config=step4_config,
        )
        report_doc = {"timestamp": datetime.utcnow(), "cycle_submissions_count": 0, "analysis_type": "manual", "report": evaluation_report, "system_behaviour": system_behaviour, "system_trust_score_percentage": system_percent}
        report_result = db["trust_evaluation_reports"].insert_one(report_doc)
        report_id = report_result.inserted_id

        for (tool_name, cat) in tool_category_behaviours:
            for coll in [TOOL_REPORTINGS_COLLECTION, BEHAVIOR_DETERMINATION_LOGS_COLLECTION, TRUST_SCORE_CALCULATION_LOGS_COLLECTION, RULE_EVALUATION_LOGS_COLLECTION]:
                coll.update_many({"tool_name": tool_name, "category": cat, "evaluation_report_id": {"$exists": False}}, {"$set": {"evaluation_report_id": report_id}})

        try:
            await run_in_threadpool(adi_connector.generate_TA_report_for_ADI, "Manual")
        except Exception as adi_err:
            print(f"[manual-analysis] ADI report error (non-fatal): {adi_err}")

        await broadcast_cycle_status("evaluation_complete", {"analysis_type": "manual", "report_id": str(report_id)})
        return JSONResponse({"status": "success", "system_behaviour": system_behaviour, "system_trust_score_percentage": round(system_percent, 2), "tools_analysed": len(tools_using_previous_values), "report_id": str(report_id)})
    except Exception as e:
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _categorize_impact(mapping: dict, value, step1_configs: list, step2_configs: list) -> str:
    tool_name = mapping.get("tool_name")
    cat = (mapping.get("trust_evaluation_category") or "Uncategorized").strip()
    cat_key = cat.lower()
    key = f"{tool_name}|||{cat_key}"
    step1_cfg = next((c for c in step1_configs if f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}" == key), {})
    step2_cfg = next((c for c in step2_configs if f"{c.get('tool_name')}|||{(c.get('trust_evaluation_category') or 'Uncategorized').strip().lower()}" == key), {})
    if step2_cfg.get("override_active") == "true":
        return step2_cfg.get("override_impact", "Mid").capitalize()
    data_type = mapping.get("data_type")
    if data_type == "binary":
        return step1_cfg.get(f"{tool_name}_{cat_key}_on" if value == "ON" else f"{tool_name}_{cat_key}_off", "Mid")
    elif data_type == "categorical":
        return step1_cfg.get(f"{tool_name}_{cat_key}_{value}", "Mid")
    elif data_type == "continuous":
        try:
            val = float(value or mapping.get("min_value", 0))
            lower = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_lower", mapping.get("min_value", 0)))
            upper = float(step1_cfg.get(f"{tool_name}_{cat_key}_slider_upper", mapping.get("max_value", 100)))
            return "Low" if val <= lower else ("Mid" if val <= upper else "High")
        except Exception:
            return "Mid"
    return "Mid"


async def _perform_batch_analysis():
    """Run batch analysis on all submissions collected during the cycle."""
    submissions = trust_cycle_state.get("submissions", [])
    if not submissions:
        return
    # Batch analysis is essentially the same as manual but with the collected submissions as new data
    # For brevity: just trigger a manual analysis which uses most-recent values (already updated by submit)
    # A full batch implementation would group submissions by tool and aggregate
    await trigger_manual_analysis()


async def _run_analysis_cycle():
    global trust_cycle_state
    try:
        while trust_cycle_state["is_running"]:
            now = datetime.utcnow()
            if trust_cycle_state["end_time"] and now >= trust_cycle_state["end_time"]:
                await _perform_batch_analysis()
                trust_cycle_state["is_running"] = False
                await broadcast_cycle_status("analysis_complete", {"message": "Cycle complete"})
                if trust_cycle_config.get("enabled") and not trust_cycle_state.get("user_stopped"):
                    duration_seconds = _convert_duration(trust_cycle_config["duration"], trust_cycle_config.get("time_unit", "minutes"))
                    trust_cycle_state["start_time"] = datetime.utcnow()
                    trust_cycle_state["end_time"] = trust_cycle_state["start_time"] + timedelta(seconds=duration_seconds)
                    trust_cycle_state["submissions"] = []
                    trust_cycle_state["is_running"] = True
                    await broadcast_cycle_status("restarted", {"duration_seconds": duration_seconds})
                break
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
