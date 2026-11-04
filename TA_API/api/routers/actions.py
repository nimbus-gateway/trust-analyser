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
routers/actions.py — Tool reporting action management endpoints.
"""
from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Body
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from bson import ObjectId

import adi_connector
from database import db, TOOL_MANUAL_IMPACTS_COLLECTION

router = APIRouter()


@router.post("/api/tool-reporting-action/{reporting_id}")
async def update_tool_reporting_action(reporting_id: str, action: dict):
    try:
        reporting_oid = ObjectId(reporting_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid reporting ID format"})

    try:
        valid_statuses = ["no action", "reviewing", "resolved", "dismiss"]
        status = action.get("status", "no action")
        if status not in valid_statuses:
            return JSONResponse(status_code=400, content={"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"})

        tool_name = action.get("tool_name")
        category = action.get("category")
        unique_id = action.get("unique_id")
        if not all([tool_name, category, unique_id]):
            return JSONResponse(status_code=400, content={"error": "Missing tool_name, category, or unique_id"})

        action_record = {"tool_name": tool_name, "category": category, "unique_id": unique_id, "status": status, "notes": action.get("notes", ""), "updated_at": datetime.utcnow(), "reporting_id": reporting_oid}
        db["tool_reporting_actions"].update_one({"tool_name": tool_name, "category": category, "unique_id": unique_id}, {"$set": action_record}, upsert=True)

        await run_in_threadpool(adi_connector.generate_user_action_report_for_ADI, "Trust Analyser User Action", f"{tool_name} Tool marked as: {status}", status)
        return {"status": "success", "message": f"Action status updated to '{status}'", "tool_name": tool_name, "category": category, "unique_id": unique_id, "action_status": status}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/tool-reporting-action/{reporting_id}")
async def get_tool_reporting_action(reporting_id: str):
    try:
        reporting_oid = ObjectId(reporting_id)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid reporting ID format"})

    try:
        tool_reporting = db["tool_reportings"].find_one({"_id": reporting_oid})
        if not tool_reporting:
            return JSONResponse(status_code=404, content={"error": "Tool reporting not found"})

        tool_name = tool_reporting.get("tool_name")
        category = tool_reporting.get("category")
        unique_id = tool_reporting.get("unique_id")
        action = db["tool_reporting_actions"].find_one({"tool_name": tool_name, "category": category, "unique_id": unique_id})
        if not action:
            return {"status": "success", "reporting_id": reporting_id, "action_status": "no action", "notes": ""}

        return {"status": "success", "reporting_id": reporting_id, "action_status": action.get("status", "no action"), "notes": action.get("notes", ""), "updated_at": action.get("updated_at").isoformat() if action.get("updated_at") else None}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/tool-action-by-identifier/{tool_name}/{category}/{unique_id}")
async def get_tool_action_by_identifier(tool_name: str, category: str, unique_id: str):
    try:
        action = db["tool_reporting_actions"].find_one({"tool_name": tool_name, "category": category, "unique_id": unique_id})
        if not action:
            return {"status": "success", "has_previous": False, "action_status": "no action"}
        return {"status": "success", "has_previous": True, "action_status": action.get("status", "no action"), "notes": action.get("notes", ""), "updated_at": action.get("updated_at").isoformat() if action.get("updated_at") else None}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/api/batch-tool-reporting-actions")
async def batch_update_tool_reporting_actions(actions: List[Dict[str, Any]] = Body(...)):
    try:
        valid_statuses = ["no action", "reviewing", "resolved", "dismiss"]
        updated_count = 0; errors = []
        for action in actions:
            try:
                status = action.get("status", "no action")
                tool_name = action.get("tool_name")
                category = action.get("category")
                unique_id = action.get("unique_id")
                if not all([tool_name, category, unique_id]):
                    errors.append("Missing tool_name, category, or unique_id for action"); continue
                if status not in valid_statuses:
                    errors.append(f"Invalid status '{status}' for tool {tool_name}"); continue
                db["tool_reporting_actions"].update_one(
                    {"tool_name": tool_name, "category": category, "unique_id": unique_id},
                    {"$set": {"tool_name": tool_name, "category": category, "unique_id": unique_id, "status": status, "notes": action.get("notes", ""), "updated_at": datetime.utcnow()}},
                    upsert=True,
                )
                updated_count += 1
            except Exception as e:
                errors.append(f"Error updating tool {action.get('tool_name')}: {str(e)}")

        await run_in_threadpool(adi_connector.generate_user_action_report_for_ADI, "Trust Analyser User Action", f"The status of {updated_count} tool(s) was updated in a batch action.", actions[-1].get("status", "") if actions else "")
        return {"status": "success", "updated_count": updated_count, "total_count": len(actions), "errors": errors}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/tool-report-management")
async def get_tool_report_management():
    try:
        from database import MAPPED_COLLECTION
        mapped = list(MAPPED_COLLECTION.find({}))
        seen = {}
        for m in mapped:
            key = (m.get("tool_name"), (m.get("trust_evaluation_category") or "Uncategorized").strip())
            if key not in seen:
                seen[key] = m

        behaviour_results = {(d.get("tool_name"), (d.get("trust_evaluation_category") or "Uncategorized").strip()): d for d in db["tool_behaviour_results"].find({})}
        most_recent_values = {(d.get("tool_name"), (d.get("trust_evaluation_category") or "Uncategorized").strip()): d for d in db["tool_most_recent_values"].find({})}
        tool_actions = {(d.get("tool_name"), (d.get("category") or "Uncategorized").strip()): d for d in db["tool_reporting_actions"].find({})}
        manual_overrides_index = {(d.get("tool_name"), (d.get("category") or "Uncategorized").strip()): d for d in TOOL_MANUAL_IMPACTS_COLLECTION.find({})}

        tools_report = []
        for (tool_name, category), m in seen.items():
            beh_doc = behaviour_results.get((tool_name, category))
            mrv_doc = most_recent_values.get((tool_name, category))
            action_doc = tool_actions.get((tool_name, category))
            current_status = beh_doc.get("behaviour", "No data") if beh_doc else "No data"
            ts = mrv_doc.get("time_stamp") if mrv_doc else None
            most_recent_submitted = ts.isoformat() if isinstance(ts, datetime) else str(ts) if ts else None
            current_action = action_doc.get("status", "no action") if action_doc else "no action"
            action_notes = action_doc.get("notes", "") if action_doc else ""
            _ts_candidates = []
            if action_doc and action_doc.get("updated_at"): _ts_candidates.append(action_doc["updated_at"])
            mo_early = manual_overrides_index.get((tool_name, category))
            if mo_early and mo_early.get("updated_at"): _ts_candidates.append(mo_early["updated_at"])
            action_updated_at = max((_ts_candidates), default=None)
            action_updated_at = action_updated_at.isoformat() if isinstance(action_updated_at, datetime) else None
            t = {"tool_name": tool_name, "trust_evaluation_category": category, "data_type": m.get("data_type", ""), "current_status": current_status, "most_recent_submitted": most_recent_submitted, "current_action": current_action, "action_notes": action_notes, "action_updated_at": action_updated_at}
            mo = manual_overrides_index.get((tool_name, category))
            if mo:
                t["manual_impact"] = mo.get("impact"); t["manual_impact_reason"] = mo.get("reason", ""); t["manual_impact_custom_reason"] = mo.get("custom_reason", ""); t["manual_impact_updated_at"] = mo.get("updated_at").isoformat() if isinstance(mo.get("updated_at"), datetime) else str(mo.get("updated_at", ""))
            else:
                t["manual_impact"] = None; t["manual_impact_reason"] = ""; t["manual_impact_custom_reason"] = ""; t["manual_impact_updated_at"] = None
            tools_report.append(t)

        tools_report.sort(key=lambda x: (x["tool_name"].lower(), x["trust_evaluation_category"].lower()))
        return JSONResponse({"tools": tools_report})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ── Manual Impact Override ─────────────────────────────────────────────────────

@router.post("/api/tool-manual-impact")
async def save_tool_manual_impact(body: dict = Body(...)):
    tool_name = body.get("tool_name", "").strip()
    category = body.get("category", "").strip()
    impact = (body.get("impact") or "").strip().capitalize()
    reason = body.get("reason", "").strip()
    custom_reason = body.get("custom_reason", "").strip()
    action = (body.get("action") or "").strip().lower()
    action_notes = body.get("action_notes", "").strip()

    if not tool_name or not category:
        return JSONResponse(status_code=400, content={"error": "tool_name and category are required"})
    if impact not in ("Low", "Mid", "High"):
        return JSONResponse(status_code=400, content={"error": "impact must be Low, Mid, or High"})
    if reason not in ("review_complete", "false_alarm", "other"):
        return JSONResponse(status_code=400, content={"error": "reason must be one of: review_complete, false_alarm, other"})
    if reason == "other" and not custom_reason:
        return JSONResponse(status_code=400, content={"error": "custom_reason is required when reason is 'other'"})
    if action and action not in ("no action", "reviewing", "resolved", "dismiss"):
        return JSONResponse(status_code=400, content={"error": "Invalid action"})

    try:
        TOOL_MANUAL_IMPACTS_COLLECTION.update_one({"tool_name": tool_name, "category": category}, {"$set": {"tool_name": tool_name, "category": category, "impact": impact, "reason": reason, "custom_reason": custom_reason, "updated_at": datetime.utcnow()}}, upsert=True)
        action_saved = False
        if action:
            existing_action = db["tool_reporting_actions"].find_one({"tool_name": tool_name, "category": category})
            unique_id = existing_action.get("unique_id", "") if existing_action else ""
            db["tool_reporting_actions"].update_one({"tool_name": tool_name, "category": category}, {"$set": {"tool_name": tool_name, "category": category, "unique_id": unique_id, "status": action, "notes": action_notes, "updated_at": datetime.utcnow()}}, upsert=True)
            action_saved = True

        msg = f"Manual impact '{impact}' saved for {tool_name}/{category}" + (f"; action set to '{action}'" if action_saved else "")
        await run_in_threadpool(adi_connector.generate_user_action_report_for_ADI, "Trust Analyser User Action", msg, action)
        return {"status": "success", "message": msg}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/tool-manual-impact/{tool_name}/{category}")
async def get_tool_manual_impact(tool_name: str, category: str):
    try:
        doc = TOOL_MANUAL_IMPACTS_COLLECTION.find_one({"tool_name": tool_name, "category": category})
        if not doc:
            return {"has_override": False}
        return {"has_override": True, "impact": doc.get("impact"), "reason": doc.get("reason", ""), "custom_reason": doc.get("custom_reason", ""), "updated_at": doc.get("updated_at").isoformat() if isinstance(doc.get("updated_at"), datetime) else str(doc.get("updated_at", ""))}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.delete("/api/tool-manual-impact/{tool_name}/{category}")
async def delete_tool_manual_impact(tool_name: str, category: str):
    try:
        result = TOOL_MANUAL_IMPACTS_COLLECTION.delete_one({"tool_name": tool_name, "category": category})
        if result.deleted_count == 0:
            return {"status": "success", "message": "No override existed"}
        return {"status": "success", "message": f"Manual impact override cleared for {tool_name}/{category}"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
